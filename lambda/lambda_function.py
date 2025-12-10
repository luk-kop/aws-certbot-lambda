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


def retry_with_backoff(max_attempts=3, base_delay=5, exceptions=(Exception,)):
    """Decorator for retry with exponential backoff."""

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

        return wrapper

    return decorator


ACME_DIRECTORY_URL = os.environ.get(
    "ACME_DIRECTORY_URL", "https://acme-v02.api.letsencrypt.org/directory"
)
ACME_EMAIL = os.environ["ACME_EMAIL"]
DOMAINS = os.environ["DOMAINS"].split(",")
HOSTED_ZONE_ID = os.environ["HOSTED_ZONE_ID"]
SECRET_NAME_PREFIX = os.environ["SECRET_NAME_PREFIX"]
RENEWAL_DAYS_BEFORE_EXPIRY = int(os.environ.get("RENEWAL_DAYS_BEFORE_EXPIRY", "30"))
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
POWERTOOLS_SERVICE_NAME = os.environ.get(
    "POWERTOOLS_SERVICE_NAME", "aws-certbot-lambda"
)

secrets_client = boto3.client("secretsmanager")
route53_client = boto3.client("route53")
sns_client = boto3.client("sns") if SNS_TOPIC_ARN else None


class CertificateManager:
    """Manages ACME certificate operations."""

    def __init__(self):
        self.acme_client: Optional[client.ClientV2] = None
        self.account_key = self._get_or_create_account_key()

    def _get_or_create_account_key(self) -> JWKRSA:
        """Get existing account key from Secrets Manager or create new one."""
        account_secret_name = f"{SECRET_NAME_PREFIX}-account-key"

        try:
            response = secrets_client.get_secret_value(SecretId=account_secret_name)
            key_pem = response.get("SecretString", "")
            if not key_pem:
                raise ValueError("Secret value is empty")
            private_key = serialization.load_pem_private_key(
                key_pem.encode(), password=None, backend=default_backend()
            )
            logger.info("Loaded existing ACME account key")
            return JWKRSA(key=private_key)
        except secrets_client.exceptions.ResourceNotFoundException:
            logger.info("Creating new ACME account key")
        except (ValueError, TypeError, UnicodeDecodeError) as e:
            logger.warning(f"Invalid account key, generating new one: {e}")

        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

        secrets_client.put_secret_value(
            SecretId=account_secret_name,
            SecretString=key_pem,
        )
        return JWKRSA(key=private_key)

    def _register_account(self) -> client.ClientV2:
        """Register or retrieve ACME account."""
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
        except Exception as e:
            logger.error(f"Unexpected error in account registration: {e}")
            raise

        return acme_client

    def _generate_csr(self, domains: list[str]) -> tuple[bytes, bytes]:
        """Generate a private key and CSR for the domains."""
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
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

    @retry_with_backoff(max_attempts=3, base_delay=10, exceptions=(Exception,))
    def _create_dns_record(self, domain: str, validation: str) -> str:
        """Create DNS TXT record for ACME challenge."""
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

        response = route53_client.change_resource_record_sets(
            HostedZoneId=HOSTED_ZONE_ID, ChangeBatch=change_batch
        )

        change_id = response["ChangeInfo"]["Id"]
        logger.info(f"Created DNS record {record_name}, change ID: {change_id}")

        # Wait for DNS propagation
        waiter = route53_client.get_waiter("resource_record_sets_changed")
        waiter.wait(Id=change_id, WaiterConfig={"Delay": 10, "MaxAttempts": 30})
        logger.info(f"DNS record {record_name} propagated")

        return record_name

    def _cleanup_dns_record(self, domain: str, validation: str) -> None:
        """Remove DNS TXT record after challenge."""
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

            route53_client.change_resource_record_sets(
                HostedZoneId=HOSTED_ZONE_ID, ChangeBatch=change_batch
            )
            logger.info(f"Cleaned up DNS record {record_name}")
        except Exception as e:
            logger.warning(f"Failed to cleanup DNS record {record_name}: {e}")

    def _perform_dns_challenge(
        self, order: messages.OrderResource, authz: messages.AuthorizationResource
    ) -> str:
        """Perform DNS-01 challenge for a single authorization."""
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
        time.sleep(30)

        # Answer the challenge
        self.acme_client.answer_challenge(
            dns_challenge, dns_challenge.response(self.account_key)
        )
        logger.info(f"Answered challenge for {domain}")

        return validation

    def obtain_certificate(self, domains: list[str]) -> dict:
        """Obtain a new certificate for the given domains."""
        self.acme_client = self._register_account()

        # Generate key and CSR
        private_key_pem, csr_pem = self._generate_csr(domains)

        # Create order
        order = self.acme_client.new_order(csr_pem)
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
                order = self.acme_client.poll_authorizations(order, deadline)

                # Check if all authorizations are valid
                all_valid = all(
                    authz.body.status.name == "valid" for authz in order.authorizations
                )
                if all_valid:
                    break

                time.sleep(5)

            # Finalize order
            order = self.acme_client.finalize_order(
                order, deadline=datetime.now() + timedelta(minutes=2)
            )

            # Get certificate
            fullchain_pem = order.fullchain_pem
            logger.info("Certificate obtained successfully")

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
            for domain, validation in validations.items():
                self._cleanup_dns_record(domain, validation)

        return {
            "private_key": private_key_pem.decode(),
            "certificate": certificate,
            "chain": chain,
            "fullchain": fullchain_pem,
            "expiry": expiry,
            "domains": domains,
            "obtained_at": datetime.now(timezone.utc).isoformat(),
        }

    @retry_with_backoff(max_attempts=2, base_delay=3, exceptions=(Exception,))
    def store_certificate(self, cert_data: dict) -> None:
        """Store certificate in Secrets Manager."""
        secret_name = f"{SECRET_NAME_PREFIX}-certificate"
        secret_value = json.dumps(cert_data)
        secrets_client.put_secret_value(SecretId=secret_name, SecretString=secret_value)
        logger.info(f"Stored certificate in {secret_name}")

    def get_current_certificate(self) -> Optional[dict]:
        """Get current certificate from Secrets Manager."""
        secret_name = f"{SECRET_NAME_PREFIX}-certificate"
        try:
            response = secrets_client.get_secret_value(SecretId=secret_name)
            return json.loads(response["SecretString"])
        except secrets_client.exceptions.ResourceNotFoundException:
            return None

    def needs_renewal(self, cert_data: Optional[dict]) -> bool:
        """Check if certificate needs renewal."""
        if not cert_data:
            return True

        # Try to use stored expiry first
        if "expiry" in cert_data:
            try:
                expiry = datetime.fromisoformat(
                    cert_data["expiry"].replace("Z", "+00:00")
                )
                days_until_expiry = (expiry - datetime.now(timezone.utc)).days
                logger.info(f"Certificate expires in {days_until_expiry} days")
                return days_until_expiry <= RENEWAL_DAYS_BEFORE_EXPIRY
            except (ValueError, KeyError):
                pass

        # Fallback to parsing certificate
        cert_pem = cert_data.get("certificate") or cert_data.get("fullchain")
        if not cert_pem:
            return True

        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            expiry = cert.not_valid_after_utc
            days_until_expiry = (expiry - datetime.now(timezone.utc)).days

            logger.info(f"Certificate expires in {days_until_expiry} days")

            return days_until_expiry <= RENEWAL_DAYS_BEFORE_EXPIRY
        except Exception as e:
            logger.error(f"Error checking certificate expiry: {e}")
            return True


def send_notification(subject: str, message: str) -> None:
    """Send SNS notification if configured."""
    if sns_client and SNS_TOPIC_ARN:
        try:
            sns_client.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject, Message=message)
            logger.info(f"Sent notification: {subject}")
        except Exception as e:
            logger.error(f"Failed to send notification: {e}")


@logger.inject_lambda_context(log_event=True)
def lambda_handler(event: dict, context: LambdaContext) -> dict:
    """Lambda entry point."""
    logger.info(f"Starting certificate check/renewal for domains: {DOMAINS}")

    force_renewal = event.get("force_renewal", False)

    try:
        manager = CertificateManager()

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

        # Obtain new certificate
        logger.info("Obtaining new certificate...")
        cert_data = manager.obtain_certificate(DOMAINS)

        # Store certificate
        manager.store_certificate(cert_data)

        # Send success notification
        send_notification(
            subject=f"Certificate renewed for {DOMAINS[0]}",
            message=f"Successfully renewed certificate for domains: {', '.join(DOMAINS)}",
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

    except Exception as e:
        logger.error(f"Certificate renewal failed: {e}", exc_info=True)

        # Send failure notification
        send_notification(
            subject=f"Certificate renewal FAILED for {DOMAINS[0]}",
            message=f"Failed to renew certificate for {', '.join(DOMAINS)}.\nError: {str(e)}",
        )

        return {
            "statusCode": 500,
            "body": json.dumps(
                {"message": "Certificate renewal failed", "error": str(e)}
            ),
        }
