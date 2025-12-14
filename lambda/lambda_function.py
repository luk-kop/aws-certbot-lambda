import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Optional

import boto3
from acme import challenges, client, errors, messages
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from josepy import JWKRSA
from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities.typing import LambdaContext

logger = Logger()
logging.getLogger("botocore").setLevel(logging.WARNING)


def retry_with_backoff(max_attempts=3, base_delay=5, exceptions=(IOError, ValueError)):
    """
    Decorator that retries function calls with exponential backoff.

    Args:
        max_attempts: Maximum number of retry attempts
        base_delay: Base delay in seconds between retries
        exceptions: Tuple of exception types to catch and retry
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    if attempt == max_attempts:
                        raise
                    delay = base_delay * (2 ** (attempt - 1))
                    logger.warning(
                        f"{func.__name__} failed (attempt {attempt}/{max_attempts}): {e}. Retrying in {delay}s"
                    )
                    time.sleep(delay)
                except BaseException:
                    raise

        return wrapper

    return decorator


# Environment variables
ACME_DIRECTORY_URL = os.environ.get(
    "ACME_DIRECTORY_URL", "https://acme-v02.api.letsencrypt.org/directory"
)
ACME_EMAIL = os.environ.get("ACME_EMAIL", "")
DOMAINS = json.loads(os.environ.get("DOMAINS", "[]"))
HOSTED_ZONE_ID = os.environ.get("HOSTED_ZONE_ID", "")
SECRET_NAME_PREFIX = os.environ.get("SECRET_NAME_PREFIX", "")
RENEWAL_DAYS_BEFORE_EXPIRY = int(os.environ.get("RENEWAL_DAYS_BEFORE_EXPIRY", "30"))
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
EB_BUS_NAME = os.environ.get("EB_BUS_NAME", "")
POWERTOOLS_SERVICE_NAME = os.environ.get(
    "POWERTOOLS_SERVICE_NAME", "aws-certbot-lambda"
)

# Required keys in certificate secret JSON
REQUIRED_CERT_KEYS = {"private_key", "certificate", "expiry", "domains"}
RSA_KEY_SIZE = int(os.environ.get("RSA_KEY_SIZE", "2048"))
DNS_PROPAGATION_WAIT_SECONDS = int(os.environ.get("DNS_PROPAGATION_WAIT_SECONDS", "30"))
ACME_PERSIST_ACCOUNT_KEY = (
    os.environ.get("ACME_PERSIST_ACCOUNT_KEY", "true").lower() == "true"
)


def _validate_config() -> None:
    """
    Validate environment variables.
    """
    if not DOMAINS or not DOMAINS[0]:
        raise ValueError("DOMAINS environment variable must not be empty")
    if not HOSTED_ZONE_ID:
        raise ValueError("HOSTED_ZONE_ID environment variable is required")
    if not SECRET_NAME_PREFIX:
        raise ValueError("SECRET_NAME_PREFIX environment variable is required")
    if RENEWAL_DAYS_BEFORE_EXPIRY <= 0:
        raise ValueError("RENEWAL_DAYS_BEFORE_EXPIRY must be positive")
    if not HOSTED_ZONE_ID.startswith(("Z", "/hostedzone/")):
        raise ValueError(f"Invalid HOSTED_ZONE_ID format: {HOSTED_ZONE_ID}")


class CertificateManager:
    """
    Handles Let's Encrypt certificate lifecycle operations via ACME protocol.

    Manages certificate issuance, renewal, and storage using Route53 DNS-01 challenges
    and AWS Secrets Manager for certificate persistence.
    """

    def __init__(
        self,
        certificate_secret_name: str,
        acme_account_key_secret_name: Optional[str] = None,
    ):
        self._secrets_client = boto3.client("secretsmanager")
        self._route53_client = boto3.client("route53")
        self._acme_client: Optional[client.ClientV2] = None
        self.acme_account_key_secret_name = acme_account_key_secret_name
        self.certificate_secret_name = certificate_secret_name
        self.cleanup_errors: list[str] = []
        self.account_key = (
            self._get_or_create_account_key()
            if acme_account_key_secret_name
            else self._create_ephemeral_account_key()
        )

    def _create_ephemeral_account_key(self) -> JWKRSA:
        """
        Generate ephemeral ACME account key (not persisted).

        Returns:
            JWKRSA: JSON Web Key for ACME account authentication
        """
        logger.info("Creating ephemeral ACME account key")
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=RSA_KEY_SIZE, backend=default_backend()
        )
        return JWKRSA(key=private_key)

    def _get_or_create_account_key(self) -> JWKRSA:
        """
        Retrieve or generate persistent ACME account key for Let's Encrypt registration.

        Returns:
            JWKRSA: JSON Web Key for ACME account authentication
        """
        try:
            response = self._secrets_client.get_secret_value(
                SecretId=self.acme_account_key_secret_name
            )
            key_pem = response.get("SecretString", "")
            if not key_pem:
                raise ValueError("Secret value is empty")
            private_key = serialization.load_pem_private_key(
                key_pem.encode(), password=None, backend=default_backend()
            )
            logger.info("Loaded existing ACME account key")
            return JWKRSA(key=private_key)
        except self._secrets_client.exceptions.ResourceNotFoundException:
            logger.info("Creating new ACME account key")
        except (ValueError, TypeError, UnicodeDecodeError) as e:
            logger.warning(f"Invalid account key, generating new one: {e}")

        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=RSA_KEY_SIZE, backend=default_backend()
        )
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

        self._secrets_client.put_secret_value(
            SecretId=self.acme_account_key_secret_name,
            SecretString=key_pem,
        )
        return JWKRSA(key=private_key)

    def _register_account(self) -> client.ClientV2:
        """
        Register new ACME account or retrieve existing one from Let's Encrypt.

        Returns:
            client.ClientV2: Configured ACME client with registered account
        """
        network = client.ClientNetwork(
            self.account_key, user_agent="aws-certbot-lambda/1.0"
        )
        directory = messages.Directory.from_json(network.get(ACME_DIRECTORY_URL).json())
        acme_client = client.ClientV2(directory, net=network)

        try:
            reg_data = {"terms_of_service_agreed": True}
            if ACME_EMAIL:
                reg_data["email"] = ACME_EMAIL
            registration = messages.NewRegistration.from_data(**reg_data)
            regr = acme_client.new_account(registration)
            logger.info("Registered new ACME account")
        except errors.ConflictError as e:
            # Account exists, get account URL from the location attribute
            account_url = getattr(e, "location", None)
            logger.info(f"Account exists, URL: {account_url}")

            if account_url:
                # Create registration resource manually
                contact = tuple([f"mailto:{ACME_EMAIL}"] if ACME_EMAIL else [])
                regr = messages.RegistrationResource(
                    uri=account_url,
                    body=messages.Registration(
                        terms_of_service_agreed=True, contact=contact
                    ),
                )
                # Set the account on the client
                acme_client.net.account = regr
                logger.info(f"Using existing ACME account: {account_url}")
            else:
                logger.error("Could not extract account URL from ConflictError")
                raise
        except (errors.Error, IOError, ValueError) as e:
            logger.error(f"Error in account registration: {e}")
            raise

        return acme_client

    def _generate_csr(self, domains: list[str]) -> tuple[bytes, bytes]:
        """
        Generate RSA private key and Certificate Signing Request for domains.

        Args:
            domains: List of domain names for the certificate

        Returns:
            tuple: (private_key_pem, csr_pem) as bytes
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=RSA_KEY_SIZE, backend=default_backend()
        )

        # Build CSR with SAN
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(
            x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, domains[0])])
        )

        if len(domains) > 1:
            san = x509.SubjectAlternativeName(
                [x509.DNSName(domain) for domain in domains]
            )
            builder = builder.add_extension(san, critical=False)

        csr = builder.sign(private_key, hashes.SHA256(), default_backend())

        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        return private_key_pem, csr.public_bytes(serialization.Encoding.PEM)

    @retry_with_backoff(max_attempts=3, base_delay=10, exceptions=(IOError, ValueError))
    def _create_dns_record(self, domain: str, validation: str) -> str:
        """
        Create DNS TXT record for ACME DNS-01 challenge validation.

        Args:
            domain: Domain name for the challenge
            validation: ACME challenge validation string

        Returns:
            str: DNS record name that was created
        """
        record_name = f"_acme-challenge.{domain}"

        change_batch = {
            "Changes": [
                {
                    "Action": "UPSERT",
                    "ResourceRecordSet": {
                        "Name": record_name,
                        "Type": "TXT",
                        "TTL": 60,
                        "ResourceRecords": [{"Value": f'"{validation}"'}],
                    },
                }
            ]
        }

        response = self._route53_client.change_resource_record_sets(
            HostedZoneId=HOSTED_ZONE_ID, ChangeBatch=change_batch
        )

        change_id = response["ChangeInfo"]["Id"]
        logger.info(f"Created DNS record {record_name}, change ID: {change_id}")

        # Wait for DNS propagation
        waiter = self._route53_client.get_waiter("resource_record_sets_changed")
        waiter.wait(Id=change_id, WaiterConfig={"Delay": 10, "MaxAttempts": 30})
        logger.info(f"DNS record {record_name} propagated")

        return record_name

    def _cleanup_dns_record(self, domain: str, validation: str) -> None:
        """
        Remove DNS TXT record after ACME challenge completion.

        Args:
            domain: Domain name for the challenge
            validation: ACME challenge validation string
        """
        record_name = f"_acme-challenge.{domain}"

        try:
            change_batch = {
                "Changes": [
                    {
                        "Action": "DELETE",
                        "ResourceRecordSet": {
                            "Name": record_name,
                            "Type": "TXT",
                            "TTL": 60,
                            "ResourceRecords": [{"Value": f'"{validation}"'}],
                        },
                    }
                ]
            }

            self._route53_client.change_resource_record_sets(
                HostedZoneId=HOSTED_ZONE_ID, ChangeBatch=change_batch
            )
            logger.info(f"Cleaned up DNS record {record_name}")
        except (IOError, ValueError) as e:
            error_msg = f"Failed to cleanup DNS record {record_name}: {e}"
            logger.warning(error_msg)
            self.cleanup_errors.append(error_msg)

    def _perform_dns_challenge(
        self, order: messages.OrderResource, authz: messages.AuthorizationResource
    ) -> str:
        """
        Execute DNS-01 challenge for domain authorization.

        Args:
            order: ACME order resource
            authz: Authorization resource for specific domain

        Returns:
            str: Challenge validation string for cleanup
        """
        domain = authz.body.identifier.value

        # Find DNS-01 challenge
        dns_challenge = None
        for challenge_body in authz.body.challenges:
            if isinstance(challenge_body.chall, challenges.DNS01):
                dns_challenge = challenge_body
                break

        if not dns_challenge:
            raise ValueError(f"No DNS-01 challenge found for {domain}")

        # Get validation value
        validation = dns_challenge.chall.validation(self.account_key)

        # Create DNS record
        self._create_dns_record(domain, validation)

        # Additional wait for DNS propagation
        time.sleep(DNS_PROPAGATION_WAIT_SECONDS)

        # Answer the challenge
        self._acme_client.answer_challenge(
            dns_challenge, dns_challenge.response(self.account_key)
        )
        logger.info(f"Answered challenge for {domain}")

        return validation

    def issue_certificate(self, domains: list[str]) -> dict:
        """
        Issue new TLS certificate from Let's Encrypt.

        Args:
            domains: List of domain names for the certificate

        Returns:
            dict: Certificate data including private key, certificate, chain, and metadata
        """
        self._acme_client = self._register_account()

        # Generate key and CSR
        private_key_pem, csr_pem = self._generate_csr(domains)

        # Create order
        order = self._acme_client.new_order(csr_pem)
        logger.info(f"Created order for domains: {domains}")

        # Process each authorization
        validations = {}
        try:
            for authz in order.authorizations:
                domain = authz.body.identifier.value
                validation = self._perform_dns_challenge(order, authz)
                validations[domain] = validation

            # Poll for order completion
            deadline = datetime.now() + timedelta(minutes=5)
            while datetime.now() < deadline:
                order = self._acme_client.poll_authorizations(order, deadline)

                # Check if all authorizations are valid
                all_valid = all(
                    authz.body.status.name == "valid" for authz in order.authorizations
                )
                if all_valid:
                    break

                time.sleep(5)

            # Finalize order
            order = self._acme_client.finalize_order(
                order, deadline=datetime.now() + timedelta(minutes=2)
            )

            # Get certificate
            fullchain_pem = order.fullchain_pem
            logger.info("Certificate issued successfully")

            # Parse certificate to extract expiry and separate chain
            certs = fullchain_pem.split("-----END CERTIFICATE-----")
            certificate = certs[0] + "-----END CERTIFICATE-----\n"
            chain = "-----END CERTIFICATE-----".join(certs[1:]).strip()
            if chain:
                chain = chain + "\n"

            # Extract expiry from certificate
            cert = x509.load_pem_x509_certificate(
                certificate.encode(), default_backend()
            )
            expiry = cert.not_valid_after_utc.isoformat()

        finally:
            # Cleanup DNS records
            self.cleanup_errors = []
            for domain, validation in validations.items():
                self._cleanup_dns_record(domain, validation)

        return {
            "private_key": private_key_pem.decode(),
            "certificate": certificate,
            "chain": chain,
            "fullchain": fullchain_pem,
            "expiry": expiry,
            "domains": domains,
            "issued_at": datetime.now(timezone.utc).isoformat(),
        }

    @retry_with_backoff(max_attempts=2, base_delay=3, exceptions=(IOError, ValueError))
    def store_certificate(self, cert_data: dict) -> None:
        """
        Store certificate data in AWS Secrets Manager with metadata tags.

        Args:
            cert_data: Dictionary containing certificate, private key, and metadata
        """
        secret_value = json.dumps(cert_data)
        self._secrets_client.put_secret_value(
            SecretId=self.certificate_secret_name, SecretString=secret_value
        )
        logger.info(f"Stored certificate in {self.certificate_secret_name}")

        # Update secret tags with certificate metadata
        try:
            tags = [
                {"Key": "ExpirationDate", "Value": cert_data.get("expiry", "unknown")},
                {"Key": "IssuedAt", "Value": cert_data.get("issued_at", "unknown")},
                {
                    "Key": "Domains",
                    "Value": ",".join(cert_data.get("domains", []))[:256],
                },
            ]
            self._secrets_client.tag_resource(
                SecretId=self.certificate_secret_name, Tags=tags
            )
            logger.info(f"Updated tags for {self.certificate_secret_name}")
        except (IOError, ValueError) as e:
            logger.warning(f"Failed to update secret tags: {e}")

    def get_current_certificate(self) -> Optional[dict]:
        """
        Retrieve current certificate data from AWS Secrets Manager.

        Returns:
            Optional[dict]: Certificate data or None if empty/invalid

        Raises:
            ValueError: If the secret does not exist (must be created by Terraform)
        """
        try:
            response = self._secrets_client.get_secret_value(
                SecretId=self.certificate_secret_name
            )
            data = json.loads(response["SecretString"])

            # Validate required keys
            missing_keys = REQUIRED_CERT_KEYS - data.keys()
            if missing_keys:
                logger.warning(
                    f"Certificate secret missing required keys: {sorted(missing_keys)}"
                )
                return None

            return data
        except self._secrets_client.exceptions.ResourceNotFoundException:
            raise ValueError(
                f"Certificate secret '{self.certificate_secret_name}' does not exist. "
                "Ensure Terraform has been applied to create the required secrets."
            )
        except (ValueError, TypeError) as e:
            logger.error(f"Error parsing certificate data: {e}")
            return None

    def needs_renewal(self, cert_data: Optional[dict]) -> bool:
        """
        Determine if certificate requires renewal based on expiry date.

        Parses the actual certificate PEM to get the authoritative expiry date,
        rather than trusting the stored 'expiry' field which could be out of sync.

        Args:
            cert_data: Certificate data dictionary or None

        Returns:
            bool: True if certificate needs renewal, False otherwise
        """
        if not cert_data:
            return True

        cert_pem = cert_data.get("certificate") or cert_data.get("fullchain")
        if not cert_pem:
            logger.warning(
                "Certificate data missing 'certificate' or 'fullchain' field"
            )
            return True

        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            expiry = cert.not_valid_after_utc
            days_until_expiry = (expiry - datetime.now(timezone.utc)).days

            logger.info(f"Certificate expires in {days_until_expiry} days")

            # Warn if stored expiry doesn't match actual certificate expiry
            stored_expiry = cert_data.get("expiry")
            if stored_expiry:
                try:
                    stored_expiry_dt = datetime.fromisoformat(
                        stored_expiry.replace("Z", "+00:00")
                    )
                    if abs((stored_expiry_dt - expiry).total_seconds()) > 60:
                        logger.warning(
                            f"Stored expiry ({stored_expiry}) doesn't match "
                            f"certificate expiry ({expiry.isoformat()})"
                        )
                except (ValueError, TypeError):
                    logger.warning(f"Invalid stored expiry format: {stored_expiry}")

            return days_until_expiry <= RENEWAL_DAYS_BEFORE_EXPIRY
        except (ValueError, TypeError) as e:
            logger.error(f"Error parsing certificate: {e}")
            return True


def send_notification(topic_arn: str, subject: str, message: str) -> None:
    """Send notification via AWS SNS.

    Args:
        topic_arn: SNS topic ARN
        subject: Notification subject line
        message: Notification message body
    """
    try:
        sns_client = boto3.client("sns")
        sns_client.publish(TopicArn=topic_arn, Subject=subject, Message=message)
        logger.info(f"Sent notification: {subject}")
    except (IOError, ValueError) as e:
        logger.error(f"Failed to send notification: {e}")


def publish_event(bus_name: str, source: str, detail_type: str, detail: dict) -> None:
    """Publish event to EventBridge.

    Args:
        bus_name: EventBridge bus name
        source: Event source identifier
        detail_type: Event detail type
        detail: Event detail payload
    """
    try:
        events_client = boto3.client("events")
        events_client.put_events(
            Entries=[
                {
                    "Source": source,
                    "DetailType": detail_type,
                    "Detail": json.dumps(detail),
                    "EventBusName": bus_name,
                }
            ]
        )
        logger.info(f"Published event: {detail_type} from source: {source}")
    except (IOError, ValueError) as e:
        logger.error(f"Failed to publish event: {e}")


@logger.inject_lambda_context(log_event=True)
def lambda_handler(event: dict, context: LambdaContext) -> dict:
    """AWS Lambda function entry point for certificate management.

    Args:
        event: Lambda event data (supports 'force_renewal' parameter)
        context: Lambda runtime context

    Returns:
        dict: Response with status code and operation result
    """
    _validate_config()
    logger.info(f"Starting certificate check/renewal for domains: {DOMAINS}")

    function_name = context.function_name

    force_renewal = event.get("force_renewal", False)
    cert_secret_name = f"{SECRET_NAME_PREFIX}-certificate"
    acme_account_key_secret_name = f"{SECRET_NAME_PREFIX}-account-key"

    try:
        manager = CertificateManager(
            certificate_secret_name=cert_secret_name,
            acme_account_key_secret_name=acme_account_key_secret_name
            if ACME_PERSIST_ACCOUNT_KEY
            else None,
        )

        # Check current certificate
        current_cert = manager.get_current_certificate()

        if not force_renewal and not manager.needs_renewal(current_cert):
            logger.info("Certificate is still valid, no renewal needed")
            return {
                "statusCode": 200,
                "body": json.dumps(
                    {"message": "Certificate still valid", "renewed": False}
                ),
            }

        # Issue new certificate
        logger.info("Issuing new certificate...")
        cert_data: dict = manager.issue_certificate(DOMAINS)

        # Store certificate
        manager.store_certificate(cert_data)

        # Prepare success message
        success_msg = (
            f"Successfully renewed certificate for domains: {', '.join(DOMAINS)}"
        )
        if manager.cleanup_errors:
            success_msg += "\n\nWarnings during cleanup:\n" + "\n".join(
                manager.cleanup_errors
            )

        # Send success notification
        if SNS_TOPIC_ARN:
            send_notification(
                topic_arn=SNS_TOPIC_ARN,
                subject=f"Certificate renewed for {DOMAINS[0]}",
                message=success_msg,
            )

        # Publish success event to EventBridge
        if EB_BUS_NAME:
            publish_event(
                bus_name=EB_BUS_NAME,
                source=function_name,
                detail_type="Certificate Renewed",
                detail={
                    "status": "success",
                    "domains": DOMAINS,
                    "expiry": cert_data.get("expiry"),
                    "issued_at": cert_data.get("issued_at"),
                    "secret_name": cert_secret_name,
                },
            )

        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "message": "Certificate renewed successfully",
                    "renewed": True,
                    "domains": DOMAINS,
                }
            ),
        }

    except (errors.Error, IOError, ValueError) as e:
        logger.error(f"Certificate renewal failed: {e}", exc_info=True)

        # Send failure notification
        if SNS_TOPIC_ARN:
            send_notification(
                topic_arn=SNS_TOPIC_ARN,
                subject=f"Certificate renewal FAILED for {DOMAINS[0]}",
                message=f"Failed to renew certificate for {', '.join(DOMAINS)}.\nError: {str(e)}",
            )

        # Publish failure event to EventBridge
        if EB_BUS_NAME:
            publish_event(
                bus_name=EB_BUS_NAME,
                source=function_name,
                detail_type="Certificate Renewal Failed",
                detail={
                    "status": "failed",
                    "domains": DOMAINS,
                    "error": str(e),
                    "secret_name": cert_secret_name,
                },
            )

        return {
            "statusCode": 500,
            "body": json.dumps(
                {"message": "Certificate renewal failed", "error": str(e)}
            ),
        }
