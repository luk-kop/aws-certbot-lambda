import json
import logging
import os
import time
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any, Optional, TypedDict, TypeVar

import boto3
from botocore.exceptions import ClientError
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

# Type definitions
F = TypeVar("F", bound=Callable[..., Any])


class CertificateData(TypedDict, total=False):
    """Certificate data structure stored in Secrets Manager."""

    private_key: str
    certificate: str
    chain: str
    fullchain: str
    expiry: str
    domains: list[str]
    issued_at: str


class LambdaResponse(TypedDict):
    """Lambda function response structure."""

    statusCode: int
    body: str


def retry_with_backoff(
    max_attempts: int = 3,
    base_delay: int = 5,
    exceptions: tuple[type[Exception], ...] = (ClientError, IOError, ValueError),
) -> Callable[[F], F]:
    """Decorator that retries function calls with exponential backoff.

    Wraps a function to automatically retry on specified exceptions with
    exponentially increasing delays between attempts.

    Args:
        max_attempts: Maximum number of retry attempts (default: 3).
        base_delay: Base delay in seconds between retries (default: 5).
            Actual delay doubles with each attempt: base_delay * 2^(attempt-1).
        exceptions: Tuple of exception types to catch and retry (default:
            ClientError, IOError, ValueError).

    Returns:
        Callable[[F], F]: Decorated function with retry behavior.

    Example:
        @retry_with_backoff(max_attempts=3, base_delay=5)
        def flaky_operation():
            # This will be retried up to 3 times with delays of 5s, 10s
            pass
    """

    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
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
            return None  # unreachable, satisfies type checker

        return wrapper  # type: ignore[return-value]

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
DNS_TXT_TTL = int(os.environ.get("DNS_TXT_TTL", "60"))
ACME_PERSIST_ACCOUNT_KEY = (
    os.environ.get("ACME_PERSIST_ACCOUNT_KEY", "true").lower() == "true"
)


def _validate_config() -> None:
    """Validate required environment variables for Lambda execution.

    Checks that all required environment variables are set and have valid
    values before proceeding with certificate operations.

    Raises:
        ValueError: If DOMAINS is empty or not set.
        ValueError: If HOSTED_ZONE_ID is not set or has invalid format.
        ValueError: If SECRET_NAME_PREFIX is not set.
        ValueError: If RENEWAL_DAYS_BEFORE_EXPIRY is not positive.
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
    """Handles Let's Encrypt certificate lifecycle operations via ACME protocol.

    Manages certificate issuance, renewal, and storage using Route53 DNS-01 challenges
    and AWS Secrets Manager for certificate persistence.

    Attributes:
        certificate_secret_name: Name of the Secrets Manager secret for certificate storage.
        acme_account_key_secret_name: Name of the secret for ACME account key (if persistent).
        account_key: JWKRSA key for ACME account authentication.
        cleanup_errors: List of errors encountered during DNS record cleanup.
    """

    def __init__(
        self,
        certificate_secret_name: str,
        acme_account_key_secret_name: Optional[str] = None,
    ) -> None:
        """Initialize CertificateManager with AWS clients and ACME account key.

        Args:
            certificate_secret_name: AWS Secrets Manager secret name for storing
                the certificate data (must already exist).
            acme_account_key_secret_name: Optional secret name for persisting the
                ACME account key. If None, an ephemeral key is generated for each
                invocation (not recommended for production due to rate limits).
        """
        self._secrets_client = boto3.client("secretsmanager")
        self._route53_client = boto3.client("route53")
        self._acme_client: Optional[client.ClientV2] = None
        self.acme_account_key_secret_name = acme_account_key_secret_name
        self.certificate_secret_name = certificate_secret_name
        self.cleanup_errors: list[str] = []
        self.account_key: JWKRSA = (
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

    @retry_with_backoff(
        max_attempts=3, base_delay=10, exceptions=(ClientError, IOError, ValueError)
    )
    def _create_dns_record(self, domain: str, validation: str) -> str:
        """Create DNS TXT record for ACME DNS-01 challenge validation.

        Creates a TXT record at _acme-challenge.{domain} with the validation
        token and waits for Route53 to propagate the change.

        Args:
            domain: Domain name for the challenge (e.g., "example.com").
            validation: ACME challenge validation token string.

        Returns:
            str: Full DNS record name that was created (e.g., "_acme-challenge.example.com").

        Raises:
            ClientError: If Route53 API calls fail after retries.
        """
        record_name = f"_acme-challenge.{domain}"

        change_batch = {
            "Changes": [
                {
                    "Action": "UPSERT",
                    "ResourceRecordSet": {
                        "Name": record_name,
                        "Type": "TXT",
                        "TTL": DNS_TXT_TTL,
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
        """Remove DNS TXT record after ACME challenge completion.

        Attempts to delete the challenge record. Failures are logged as warnings
        and added to cleanup_errors rather than raising exceptions, to ensure
        all cleanup attempts are made even if some fail.

        Args:
            domain: Domain name for the challenge (e.g., "example.com").
            validation: ACME challenge validation token that was used.
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
                            "TTL": DNS_TXT_TTL,
                            "ResourceRecords": [{"Value": f'"{validation}"'}],
                        },
                    }
                ]
            }

            self._route53_client.change_resource_record_sets(
                HostedZoneId=HOSTED_ZONE_ID, ChangeBatch=change_batch
            )
            logger.info(f"Cleaned up DNS record {record_name}")
        except (ClientError, IOError, ValueError) as e:
            error_msg = f"Failed to cleanup DNS record {record_name}: {e}"
            logger.warning(error_msg)
            self.cleanup_errors.append(error_msg)

    def _perform_dns_challenge(
        self, order: messages.OrderResource, authz: messages.AuthorizationResource
    ) -> str:
        """Execute DNS-01 challenge for domain authorization.

        Creates the DNS record, waits for propagation, and responds to the
        ACME challenge.

        Args:
            order: ACME order resource containing the certificate request.
            authz: Authorization resource for the specific domain to validate.

        Returns:
            str: Challenge validation token for later cleanup.

        Raises:
            ValueError: If no DNS-01 challenge is available for the domain.
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

    def issue_certificate(self, domains: list[str]) -> CertificateData:
        """Issue new TLS certificate from Let's Encrypt.

        Performs the full ACME certificate issuance flow:
        1. Registers/retrieves ACME account
        2. Generates CSR with the specified domains
        3. Creates DNS-01 challenge records in Route53
        4. Completes ACME validation and obtains certificate
        5. Cleans up DNS records

        Args:
            domains: List of domain names for the certificate. The first domain
                becomes the Common Name (CN), all domains are added as SANs.

        Returns:
            CertificateData: Certificate data including private key, certificate,
                chain, fullchain, expiry date, domains, and issuance timestamp.

        Raises:
            ValueError: If DNS-01 challenge is not available for a domain.
            acme.errors.Error: If ACME protocol errors occur.
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

    @retry_with_backoff(
        max_attempts=2, base_delay=3, exceptions=(ClientError, IOError, ValueError)
    )
    def store_certificate(self, cert_data: CertificateData) -> None:
        """Store certificate data in AWS Secrets Manager with metadata tags.

        Saves the certificate data as JSON and updates the secret's tags with
        metadata for monitoring (expiration date, issuance date, domains).

        Args:
            cert_data: Certificate data containing private key, certificate chain,
                expiry date, and domain list.

        Raises:
            ClientError: If Secrets Manager operations fail after retries.
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
        except (ClientError, IOError, ValueError) as e:
            logger.warning(f"Failed to update secret tags: {e}")

    def get_current_certificate(self) -> Optional[CertificateData]:
        """Retrieve current certificate data from AWS Secrets Manager.

        Fetches and validates the stored certificate data, ensuring all
        required fields are present.

        Returns:
            Optional[CertificateData]: Certificate data if valid, None if the
                secret doesn't exist, has no value, or contains invalid data.
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
            # Secret doesn't exist or has no value (first run)
            logger.info(
                f"No existing certificate found in '{self.certificate_secret_name}'"
            )
            return None
        except (json.JSONDecodeError, ValueError, TypeError) as e:
            logger.error(f"Error parsing certificate data: {e}")
            return None

    def needs_renewal(self, cert_data: Optional[CertificateData]) -> bool:
        """Determine if certificate requires renewal based on expiry date.

        Parses the actual certificate PEM to get the authoritative expiry date,
        rather than trusting the stored 'expiry' field which could be out of sync.
        Logs a warning if there's a mismatch between stored and actual expiry.

        Args:
            cert_data: Certificate data dictionary or None. If None, returns True
                (no certificate means renewal is needed).

        Returns:
            bool: True if certificate needs renewal (expires within
                RENEWAL_DAYS_BEFORE_EXPIRY days or is missing/invalid),
                False otherwise.
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
    except (ClientError, IOError, ValueError) as e:
        logger.error(f"Failed to send notification: {e}")


def publish_event(
    bus_name: str, source: str, detail_type: str, detail: dict[str, Any]
) -> None:
    """Publish event to EventBridge for downstream processing.

    Args:
        bus_name: EventBridge bus name to publish to.
        source: Event source identifier (typically the Lambda function name).
        detail_type: Event detail type (e.g., "Certificate Renewed").
        detail: Event detail payload as a dictionary (will be JSON-serialized).
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
    except (ClientError, IOError, ValueError) as e:
        logger.error(f"Failed to publish event: {e}")


@logger.inject_lambda_context(log_event=True)
def lambda_handler(event: dict[str, Any], context: LambdaContext) -> LambdaResponse:
    """AWS Lambda function entry point for certificate management.

    Checks if the current certificate needs renewal and issues a new one if
    necessary. Can be triggered by EventBridge schedule or manual invocation.

    Args:
        event: Lambda event data. Supports the following parameters:
            - force_renewal (bool): If True, renews certificate regardless of
              expiry date. Useful for testing or emergency re-issuance.
        context: Lambda runtime context providing function metadata.

    Returns:
        LambdaResponse: Response with statusCode (200 for success, 500 for
            failure) and JSON body containing operation result.

    Environment Variables Required:
        - DOMAINS: JSON array of domain names
        - HOSTED_ZONE_ID: Route53 hosted zone ID
        - SECRET_NAME_PREFIX: Prefix for Secrets Manager secret names
        - RENEWAL_DAYS_BEFORE_EXPIRY: Days before expiry to trigger renewal

    Optional Environment Variables:
        - ACME_EMAIL: Email for Let's Encrypt account
        - SNS_TOPIC_ARN: SNS topic for notifications
        - EB_BUS_NAME: EventBridge bus for events
        - ACME_PERSIST_ACCOUNT_KEY: Whether to persist ACME account key
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
        cert_data: CertificateData = manager.issue_certificate(DOMAINS)

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

    except (errors.Error, ClientError, IOError, ValueError) as e:
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
