import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import boto3
from acme import challenges, client, messages
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from josepy import JWKRSA

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ACME_DIRECTORY_URL = os.environ.get(
    "ACME_DIRECTORY_URL", "https://acme-v02.api.letsencrypt.org/directory"
)
ACME_EMAIL = os.environ["ACME_EMAIL"]
DOMAINS = os.environ["DOMAINS"].split(",")
HOSTED_ZONE_ID = os.environ["HOSTED_ZONE_ID"]
SECRET_NAME = os.environ["SECRET_NAME"]
RENEWAL_DAYS_BEFORE_EXPIRY = int(os.environ.get("RENEWAL_DAYS_BEFORE_EXPIRY", "30"))
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")

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
        account_secret_name = f"{SECRET_NAME}-account-key"

        try:
            response = secrets_client.get_secret_value(SecretId=account_secret_name)
            key_pem = response["SecretString"]
            private_key = serialization.load_pem_private_key(
                key_pem.encode(), password=None, backend=default_backend()
            )
            logger.info("Loaded existing ACME account key")
        except secrets_client.exceptions.ResourceNotFoundException:
            logger.info("Creating new ACME account key")
            private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=default_backend()
            )
            key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode()

            secrets_client.create_secret(
                Name=account_secret_name,
                SecretString=key_pem,
                Description="ACME account private key for Let's Encrypt",
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
            registration = messages.NewRegistration.from_data(
                email=ACME_EMAIL, terms_of_service_agreed=True
            )
            acme_client.new_account(registration)
            logger.info("Registered new ACME account")
        except messages.Error as e:
            if "already exists" in str(e).lower() or e.code == "accountDoesNotExist":
                # Account exists, retrieve it
                registration = messages.NewRegistration.from_data(
                    email=ACME_EMAIL,
                    terms_of_service_agreed=True,
                    only_return_existing=True,
                )
                acme_client.new_account(registration)
                logger.info("Retrieved existing ACME account")
            else:
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

        csr = builder.sign(private_key, None, default_backend())

        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        return private_key_pem, csr.public_bytes(serialization.Encoding.DER)

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
        private_key_pem, csr_der = self._generate_csr(domains)

        # Create order
        order = self.acme_client.new_order(csr_der)
        logger.info(f"Created order for domains: {domains}")

        # Process each authorization
        validations = {}
        try:
            for authz in order.authorizations:
                domain = authz.body.identifier.value
                validation = self._perform_dns_challenge(order, authz)
                validations[domain] = validation

            # Poll for order completion
            deadline = datetime.now(timezone.utc) + timedelta(minutes=5)
            while datetime.now(timezone.utc) < deadline:
                order = self.acme_client.poll_authorizations(order)

                # Check if all authorizations are valid
                all_valid = all(
                    authz.body.status.name == "valid" for authz in order.authorizations
                )
                if all_valid:
                    break

                time.sleep(5)

            # Finalize order
            order = self.acme_client.finalize_order(
                order, deadline=datetime.now(timezone.utc) + timedelta(minutes=2)
            )

            # Get certificate
            certificate_pem = order.fullchain_pem
            logger.info("Certificate obtained successfully")

        finally:
            # Cleanup DNS records
            for domain, validation in validations.items():
                self._cleanup_dns_record(domain, validation)

        return {
            "private_key": private_key_pem.decode(),
            "certificate": certificate_pem,
            "domains": domains,
            "obtained_at": datetime.now(timezone.utc).isoformat(),
        }

    def store_certificate(self, cert_data: dict) -> None:
        """Store certificate in Secrets Manager."""
        secret_value = json.dumps(cert_data)

        try:
            secrets_client.update_secret(
                SecretId=SECRET_NAME, SecretString=secret_value
            )
            logger.info(f"Updated certificate in {SECRET_NAME}")
        except secrets_client.exceptions.ResourceNotFoundException:
            secrets_client.create_secret(
                Name=SECRET_NAME,
                SecretString=secret_value,
                Description=f"TLS certificate for {', '.join(cert_data['domains'])}",
            )
            logger.info(f"Created certificate secret {SECRET_NAME}")

    def get_current_certificate(self) -> Optional[dict]:
        """Get current certificate from Secrets Manager."""
        try:
            response = secrets_client.get_secret_value(SecretId=SECRET_NAME)
            return json.loads(response["SecretString"])
        except secrets_client.exceptions.ResourceNotFoundException:
            return None

    def needs_renewal(self, cert_data: Optional[dict]) -> bool:
        """Check if certificate needs renewal."""
        if not cert_data:
            return True

        cert_pem = cert_data.get("certificate")
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


def lambda_handler(event: dict, context) -> dict:
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
