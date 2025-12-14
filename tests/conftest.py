"""Pytest fixtures for CertificateManager tests."""

import json
import os
from datetime import datetime, timedelta, timezone
import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from moto import mock_aws


@pytest.fixture(scope="function")
def aws_credentials():
    """Mock AWS credentials for moto."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


@pytest.fixture(scope="function")
def env_vars():
    """Set required environment variables and reload module to apply them."""
    import importlib

    os.environ["ACME_DIRECTORY_URL"] = (
        "https://acme-staging-v02.api.letsencrypt.org/directory"
    )
    os.environ["ACME_EMAIL"] = "test@example.com"
    os.environ["DOMAINS"] = json.dumps(["example.com", "*.example.com"])
    os.environ["HOSTED_ZONE_ID"] = "Z1234567890"
    os.environ["SECRET_NAME_PREFIX"] = "test-certbot"
    os.environ["RENEWAL_DAYS_BEFORE_EXPIRY"] = "30"
    os.environ["SNS_TOPIC_ARN"] = ""
    os.environ["EB_BUS_NAME"] = ""
    os.environ["POWERTOOLS_SERVICE_NAME"] = "test-certbot"
    os.environ["RSA_KEY_SIZE"] = "2048"
    os.environ["DNS_PROPAGATION_WAIT_SECONDS"] = "1"
    os.environ["ACME_PERSIST_ACCOUNT_KEY"] = "true"

    # Reload lambda_function module to pick up new env vars
    import lambda_function

    importlib.reload(lambda_function)


@pytest.fixture
def sample_private_key():
    """Generate a sample RSA private key."""
    key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    return key


@pytest.fixture
def sample_private_key_pem(sample_private_key):
    """Generate sample private key PEM."""
    return sample_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


@pytest.fixture
def sample_certificate_pem(sample_private_key):
    """Generate a sample certificate PEM."""
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "example.com"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(sample_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=90))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("example.com"),
                    x509.DNSName("*.example.com"),
                ]
            ),
            critical=False,
        )
        .sign(sample_private_key, hashes.SHA256(), default_backend())
    )

    return cert.public_bytes(serialization.Encoding.PEM).decode()


@pytest.fixture
def sample_cert_data(sample_certificate_pem, sample_private_key_pem):
    """Generate sample certificate data dict."""
    expiry = (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()
    issued_at = datetime.now(timezone.utc).isoformat()

    return {
        "certificate": sample_certificate_pem,
        "private_key": sample_private_key_pem,
        "chain": sample_certificate_pem,
        "fullchain": sample_certificate_pem + sample_certificate_pem,
        "expiry": expiry,
        "domains": ["example.com", "*.example.com"],
        "issued_at": issued_at,
    }


@pytest.fixture
def secrets_manager():
    """Create mocked Secrets Manager."""
    with mock_aws():
        import boto3

        client = boto3.client("secretsmanager", region_name="us-east-1")

        # Create certificate secret
        client.create_secret(
            Name="test-certbot-certificate", SecretString=json.dumps({"test": "data"})
        )

        yield client
