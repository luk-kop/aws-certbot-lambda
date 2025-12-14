"""Unit tests for CertificateManager class."""

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

import pytest
from acme import challenges, errors
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from josepy import JWKRSA

from lambda_function import CertificateManager

pytestmark = pytest.mark.usefixtures("aws_credentials", "env_vars")


class TestCertificateManagerInit:
    """Test CertificateManager initialization."""

    @patch("lambda_function.boto3.client")
    def test_init_with_persistent_account_key(self, mock_boto_client, secrets_manager):
        """Test initialization with persistent account key."""
        mock_boto_client.return_value = secrets_manager

        with patch.object(CertificateManager, "_get_or_create_account_key") as mock_get:
            mock_get.return_value = Mock(spec=JWKRSA)

            manager = CertificateManager(
                certificate_secret_name="test-cert",
                acme_account_key_secret_name="test-account-key",
            )

            assert manager.certificate_secret_name == "test-cert"
            assert manager.acme_account_key_secret_name == "test-account-key"
            assert manager._secrets_client is not None
            assert manager._route53_client is not None
            assert manager._acme_client is None
            mock_get.assert_called_once()

    @patch("lambda_function.boto3.client")
    def test_init_with_ephemeral_account_key(self, mock_boto_client, secrets_manager):
        """Test initialization with ephemeral account key."""
        mock_boto_client.return_value = secrets_manager

        with patch.object(
            CertificateManager, "_create_ephemeral_account_key"
        ) as mock_create:
            mock_create.return_value = Mock(spec=JWKRSA)

            manager = CertificateManager(
                certificate_secret_name="test-cert", acme_account_key_secret_name=None
            )

            assert manager.acme_account_key_secret_name is None
            mock_create.assert_called_once()

    @patch("lambda_function.boto3.client")
    def test_init_cleanup_errors_empty(self, mock_boto_client, secrets_manager):
        """Test cleanup_errors list is initialized as empty."""
        mock_boto_client.return_value = secrets_manager

        with patch.object(CertificateManager, "_get_or_create_account_key") as mock_get:
            mock_get.return_value = Mock(spec=JWKRSA)

            manager = CertificateManager(
                certificate_secret_name="test-cert",
                acme_account_key_secret_name="test-account-key",
            )

            assert manager.cleanup_errors == []
            assert isinstance(manager.cleanup_errors, list)


class TestEphemeralAccountKey:
    """Test ephemeral account key generation."""

    @patch("lambda_function.boto3.client")
    def test_create_ephemeral_account_key_success(
        self, mock_boto_client, secrets_manager
    ):
        """Test successful ephemeral key creation."""
        mock_boto_client.return_value = secrets_manager

        with patch.object(CertificateManager, "_get_or_create_account_key"):
            manager = CertificateManager(
                certificate_secret_name="test-cert",
                acme_account_key_secret_name="test-key",
            )

            key = manager._create_ephemeral_account_key()

            assert isinstance(key, JWKRSA)
            assert key.key.key_size == 2048


class TestPersistentAccountKey:
    """Test persistent account key management."""

    @patch("lambda_function.boto3.client")
    def test_get_or_create_account_key_existing(
        self, mock_boto_client, secrets_manager, sample_private_key_pem
    ):
        """Test loading existing account key."""
        # Store account key in Secrets Manager
        secrets_manager.create_secret(
            Name="test-account-key", SecretString=sample_private_key_pem
        )

        mock_boto_client.return_value = secrets_manager

        manager = CertificateManager(
            certificate_secret_name="test-cert",
            acme_account_key_secret_name="test-account-key",
        )

        assert isinstance(manager.account_key, JWKRSA)

    @patch("lambda_function.boto3.client")
    def test_get_or_create_account_key_not_found(
        self, mock_boto_client, secrets_manager
    ):
        """Test creating new account key when not found."""
        # Pre-create the secret with placeholder so put_secret_value can update it
        secrets_manager.create_secret(Name="test-new-key", SecretString="placeholder")

        mock_boto_client.return_value = secrets_manager

        manager = CertificateManager(
            certificate_secret_name="test-cert",
            acme_account_key_secret_name="test-new-key",
        )

        assert isinstance(manager.account_key, JWKRSA)

        # Verify key was stored
        response = secrets_manager.get_secret_value(SecretId="test-new-key")
        assert "BEGIN PRIVATE KEY" in response["SecretString"]

    @patch("lambda_function.boto3.client")
    def test_get_or_create_account_key_empty_secret(
        self, mock_boto_client, secrets_manager
    ):
        """Test creating new account key when secret value is empty."""
        # Create secret with empty-like value (whitespace only)
        secrets_manager.create_secret(Name="test-empty-key", SecretString="   ")

        mock_boto_client.return_value = secrets_manager

        manager = CertificateManager(
            certificate_secret_name="test-cert",
            acme_account_key_secret_name="test-empty-key",
        )

        assert isinstance(manager.account_key, JWKRSA)

        # Verify new key was stored
        response = secrets_manager.get_secret_value(SecretId="test-empty-key")
        assert "BEGIN PRIVATE KEY" in response["SecretString"]

    @patch("lambda_function.boto3.client")
    def test_get_or_create_account_key_invalid_pem(
        self, mock_boto_client, secrets_manager
    ):
        """Test creating new account key when stored PEM is invalid."""
        # Create secret with invalid PEM data
        secrets_manager.create_secret(
            Name="test-invalid-key", SecretString="not-a-valid-pem-key"
        )

        mock_boto_client.return_value = secrets_manager

        manager = CertificateManager(
            certificate_secret_name="test-cert",
            acme_account_key_secret_name="test-invalid-key",
        )

        assert isinstance(manager.account_key, JWKRSA)

        # Verify new key was stored
        response = secrets_manager.get_secret_value(SecretId="test-invalid-key")
        assert "BEGIN PRIVATE KEY" in response["SecretString"]


class TestCSRGeneration:
    """Test CSR generation."""

    @patch("lambda_function.boto3.client")
    def test_generate_csr_single_domain(self, mock_boto_client, secrets_manager):
        """Test CSR generation for single domain."""
        mock_boto_client.return_value = secrets_manager

        with patch.object(CertificateManager, "_get_or_create_account_key"):
            manager = CertificateManager(
                certificate_secret_name="test-cert",
                acme_account_key_secret_name="test-key",
            )

            private_key_pem, csr_pem = manager._generate_csr(["example.com"])

            assert b"BEGIN PRIVATE KEY" in private_key_pem
            assert b"BEGIN CERTIFICATE REQUEST" in csr_pem

            # Verify CSR content
            csr = x509.load_pem_x509_csr(csr_pem, default_backend())
            cn = csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[
                0
            ].value
            assert cn == "example.com"

    @patch("lambda_function.boto3.client")
    def test_generate_csr_multiple_domains(self, mock_boto_client, secrets_manager):
        """Test CSR generation for multiple domains."""
        mock_boto_client.return_value = secrets_manager

        with patch.object(CertificateManager, "_get_or_create_account_key"):
            manager = CertificateManager(
                certificate_secret_name="test-cert",
                acme_account_key_secret_name="test-key",
            )

            domains = ["example.com", "*.example.com", "www.example.com"]
            private_key_pem, csr_pem = manager._generate_csr(domains)

            csr = x509.load_pem_x509_csr(csr_pem, default_backend())

            # Verify SAN extension
            san_ext = csr.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            san_domains = [name.value for name in san_ext.value]
            assert set(san_domains) == set(domains)

    @patch("lambda_function.boto3.client")
    def test_generate_csr_wildcard_domain(self, mock_boto_client, secrets_manager):
        """Test CSR generation with wildcard domain."""
        mock_boto_client.return_value = secrets_manager

        with patch.object(CertificateManager, "_get_or_create_account_key"):
            manager = CertificateManager(
                certificate_secret_name="test-cert",
                acme_account_key_secret_name="test-key",
            )

            domains = ["example.com", "*.example.com"]
            private_key_pem, csr_pem = manager._generate_csr(domains)

            csr = x509.load_pem_x509_csr(csr_pem, default_backend())

            # Verify CN is set to first domain
            cn = csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[
                0
            ].value
            assert cn == "example.com"

            # Verify SAN includes wildcard
            san_ext = csr.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            san_domains = [name.value for name in san_ext.value]
            assert "*.example.com" in san_domains


class TestCertificateStorage:
    """Test certificate storage."""

    @patch("lambda_function.boto3.client")
    def test_store_certificate_success(
        self, mock_boto_client, secrets_manager, sample_cert_data
    ):
        """Test successful certificate storage."""
        mock_boto_client.return_value = secrets_manager

        with patch.object(CertificateManager, "_get_or_create_account_key"):
            manager = CertificateManager(
                certificate_secret_name="test-certbot-certificate",
                acme_account_key_secret_name="test-key",
            )

            manager.store_certificate(sample_cert_data)

            # Verify certificate was stored
            response = secrets_manager.get_secret_value(
                SecretId="test-certbot-certificate"
            )
            stored_data = json.loads(response["SecretString"])

            assert stored_data["domains"] == sample_cert_data["domains"]
            assert stored_data["expiry"] == sample_cert_data["expiry"]

            # Verify tags
            tags_response = secrets_manager.describe_secret(
                SecretId="test-certbot-certificate"
            )
            tags = {tag["Key"]: tag["Value"] for tag in tags_response.get("Tags", [])}

            assert "ExpirationDate" in tags
            assert "IssuedAt" in tags
            assert "Domains" in tags

    @patch("lambda_function.boto3.client")
    def test_store_certificate_domains_truncated(
        self, mock_boto_client, secrets_manager, sample_cert_data
    ):
        """Test domains tag truncation."""
        mock_boto_client.return_value = secrets_manager

        # Create cert data with many domains
        long_domains = [f"subdomain{i}.example.com" for i in range(20)]
        sample_cert_data["domains"] = long_domains

        with patch.object(CertificateManager, "_get_or_create_account_key"):
            manager = CertificateManager(
                certificate_secret_name="test-certbot-certificate",
                acme_account_key_secret_name="test-key",
            )

            manager.store_certificate(sample_cert_data)

            tags_response = secrets_manager.describe_secret(
                SecretId="test-certbot-certificate"
            )
            tags = {tag["Key"]: tag["Value"] for tag in tags_response.get("Tags", [])}

            assert len(tags["Domains"]) <= 256

    @patch("lambda_function.boto3.client")
    def test_store_certificate_tagging_failure(
        self, mock_boto_client, sample_cert_data
    ):
        """Test certificate storage succeeds even when tagging fails."""
        mock_secrets = Mock()
        mock_secrets.put_secret_value = Mock()
        mock_secrets.tag_resource = Mock(side_effect=IOError("Tagging failed"))

        mock_boto_client.return_value = mock_secrets

        with patch.object(CertificateManager, "_get_or_create_account_key"):
            manager = CertificateManager(
                certificate_secret_name="test-certbot-certificate",
                acme_account_key_secret_name="test-key",
            )

            # Should not raise exception
            manager.store_certificate(sample_cert_data)

            # Verify put_secret_value was called
            mock_secrets.put_secret_value.assert_called_once()


class TestCertificateRetrieval:
    """Test certificate retrieval."""

    @patch("lambda_function.boto3.client")
    def test_get_current_certificate_exists(
        self, mock_boto_client, secrets_manager, sample_cert_data
    ):
        """Test retrieving existing certificate."""
        # Store certificate
        secrets_manager.put_secret_value(
            SecretId="test-certbot-certificate",
            SecretString=json.dumps(sample_cert_data),
        )

        mock_boto_client.return_value = secrets_manager

        with patch.object(CertificateManager, "_get_or_create_account_key"):
            manager = CertificateManager(
                certificate_secret_name="test-certbot-certificate",
                acme_account_key_secret_name="test-key",
            )

            cert_data = manager.get_current_certificate()

            assert cert_data is not None
            assert cert_data["domains"] == sample_cert_data["domains"]

    @patch("lambda_function.boto3.client")
    def test_get_current_certificate_not_found(self, mock_boto_client, secrets_manager):
        """Test retrieving non-existent certificate raises ValueError."""
        mock_boto_client.return_value = secrets_manager

        with patch.object(CertificateManager, "_get_or_create_account_key"):
            manager = CertificateManager(
                certificate_secret_name="non-existent-cert",
                acme_account_key_secret_name="test-key",
            )

            with pytest.raises(ValueError, match="does not exist"):
                manager.get_current_certificate()

    @patch("lambda_function.boto3.client")
    def test_get_current_certificate_invalid_json(
        self, mock_boto_client, secrets_manager
    ):
        """Test retrieving certificate with invalid JSON returns None."""
        # Store invalid JSON
        secrets_manager.put_secret_value(
            SecretId="test-certbot-certificate", SecretString="not-valid-json{"
        )

        mock_boto_client.return_value = secrets_manager

        with patch.object(CertificateManager, "_get_or_create_account_key"):
            manager = CertificateManager(
                certificate_secret_name="test-certbot-certificate",
                acme_account_key_secret_name="test-key",
            )

            cert_data = manager.get_current_certificate()

            assert cert_data is None

    @patch("lambda_function.boto3.client")
    def test_get_current_certificate_missing_keys(
        self, mock_boto_client, secrets_manager
    ):
        """Test retrieving certificate with missing required keys returns None."""
        # Store JSON with missing keys (missing 'private_key' and 'expiry')
        incomplete_data = {
            "certificate": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            "domains": ["example.com"],
        }
        secrets_manager.put_secret_value(
            SecretId="test-certbot-certificate",
            SecretString=json.dumps(incomplete_data),
        )

        mock_boto_client.return_value = secrets_manager

        with patch.object(CertificateManager, "_get_or_create_account_key"):
            manager = CertificateManager(
                certificate_secret_name="test-certbot-certificate",
                acme_account_key_secret_name="test-key",
            )

            cert_data = manager.get_current_certificate()

            assert cert_data is None

    @patch("lambda_function.boto3.client")
    def test_get_current_certificate_all_keys_present(
        self, mock_boto_client, secrets_manager, sample_cert_data
    ):
        """Test retrieving certificate with all required keys succeeds."""
        secrets_manager.put_secret_value(
            SecretId="test-certbot-certificate",
            SecretString=json.dumps(sample_cert_data),
        )

        mock_boto_client.return_value = secrets_manager

        with patch.object(CertificateManager, "_get_or_create_account_key"):
            manager = CertificateManager(
                certificate_secret_name="test-certbot-certificate",
                acme_account_key_secret_name="test-key",
            )

            cert_data = manager.get_current_certificate()

            assert cert_data is not None
            assert "private_key" in cert_data
            assert "certificate" in cert_data
            assert "expiry" in cert_data
            assert "domains" in cert_data


class TestCertificateRenewal:
    """Test certificate renewal checks."""

    @patch("lambda_function.boto3.client")
    def test_needs_renewal_no_certificate(self, mock_boto_client, secrets_manager):
        """Test renewal needed when no certificate exists."""
        mock_boto_client.return_value = secrets_manager

        with patch.object(CertificateManager, "_get_or_create_account_key"):
            manager = CertificateManager(
                certificate_secret_name="test-cert",
                acme_account_key_secret_name="test-key",
            )

            assert manager.needs_renewal(None) is True

    @patch("lambda_function.boto3.client")
    def test_needs_renewal_expiring_soon(
        self, mock_boto_client, secrets_manager, sample_cert_data
    ):
        """Test renewal needed when certificate expires soon."""
        mock_boto_client.return_value = secrets_manager

        # Test with missing certificate field to trigger renewal
        cert_data_no_cert = {
            "expiry": (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
        }

        with patch.object(CertificateManager, "_get_or_create_account_key"):
            manager = CertificateManager(
                certificate_secret_name="test-cert",
                acme_account_key_secret_name="test-key",
            )

            # Without certificate field, needs renewal returns True
            assert manager.needs_renewal(cert_data_no_cert) is True

    @patch("lambda_function.boto3.client")
    def test_needs_renewal_not_expiring(
        self, mock_boto_client, secrets_manager, sample_cert_data
    ):
        """Test renewal not needed when certificate is valid."""
        mock_boto_client.return_value = secrets_manager

        # sample_cert_data has a certificate with 90 days validity (> 30 days threshold)
        with patch.object(CertificateManager, "_get_or_create_account_key"):
            manager = CertificateManager(
                certificate_secret_name="test-cert",
                acme_account_key_secret_name="test-key",
            )

            assert manager.needs_renewal(sample_cert_data) is False

    @patch("lambda_function.boto3.client")
    def test_needs_renewal_expiry_field_invalid_logs_warning(
        self, mock_boto_client, secrets_manager, sample_cert_data
    ):
        """Test renewal check logs warning when expiry field is invalid but still parses certificate."""
        mock_boto_client.return_value = secrets_manager

        # Cert data with invalid expiry but valid certificate
        cert_data = {
            "expiry": "not-a-valid-date",
            "certificate": sample_cert_data["certificate"],
        }

        with patch.object(CertificateManager, "_get_or_create_account_key"):
            manager = CertificateManager(
                certificate_secret_name="test-cert",
                acme_account_key_secret_name="test-key",
            )

            # Should not raise, parses certificate and logs warning about invalid expiry
            result = manager.needs_renewal(cert_data)
            assert isinstance(result, bool)

    @patch("lambda_function.boto3.client")
    def test_needs_renewal_parse_certificate(
        self, mock_boto_client, secrets_manager, sample_cert_data
    ):
        """Test renewal check parses certificate when expiry field is missing."""
        mock_boto_client.return_value = secrets_manager

        # Cert data without expiry field
        cert_data = {"certificate": sample_cert_data["certificate"]}

        with patch.object(CertificateManager, "_get_or_create_account_key"):
            manager = CertificateManager(
                certificate_secret_name="test-cert",
                acme_account_key_secret_name="test-key",
            )

            # Certificate in fixture has 90 days validity, should not need renewal
            result = manager.needs_renewal(cert_data)
            assert result is False

    @patch("lambda_function.boto3.client")
    def test_needs_renewal_no_certificate_field(
        self, mock_boto_client, secrets_manager
    ):
        """Test renewal returns True when cert_data has no certificate field."""
        mock_boto_client.return_value = secrets_manager

        cert_data = {"domains": ["example.com"]}

        with patch.object(CertificateManager, "_get_or_create_account_key"):
            manager = CertificateManager(
                certificate_secret_name="test-cert",
                acme_account_key_secret_name="test-key",
            )

            assert manager.needs_renewal(cert_data) is True

    @patch("lambda_function.boto3.client")
    def test_needs_renewal_expiry_mismatch_logs_warning(
        self, mock_boto_client, secrets_manager, sample_cert_data, caplog
    ):
        """Test renewal check logs warning when stored expiry doesn't match certificate."""
        import logging

        mock_boto_client.return_value = secrets_manager

        # Use valid certificate but with wrong expiry date
        cert_data = {
            "certificate": sample_cert_data["certificate"],
            "expiry": "2020-01-01T00:00:00+00:00",  # Wrong date
        }

        with patch.object(CertificateManager, "_get_or_create_account_key"):
            manager = CertificateManager(
                certificate_secret_name="test-cert",
                acme_account_key_secret_name="test-key",
            )

            with caplog.at_level(logging.WARNING):
                manager.needs_renewal(cert_data)

            assert "doesn't match" in caplog.text

    @patch("lambda_function.boto3.client")
    def test_needs_renewal_invalid_certificate_pem(
        self, mock_boto_client, secrets_manager
    ):
        """Test renewal returns True when certificate PEM is invalid."""
        mock_boto_client.return_value = secrets_manager

        cert_data = {"certificate": "not-a-valid-certificate-pem"}

        with patch.object(CertificateManager, "_get_or_create_account_key"):
            manager = CertificateManager(
                certificate_secret_name="test-cert",
                acme_account_key_secret_name="test-key",
            )

            assert manager.needs_renewal(cert_data) is True


class TestAcmeAccountRegistration:
    """Test ACME account registration."""

    @patch("lambda_function.boto3.client")
    @patch("lambda_function.client.ClientNetwork")
    @patch("lambda_function.messages.Directory.from_json")
    @patch("lambda_function.client.ClientV2")
    def test_register_account_new_account(
        self,
        mock_client_v2,
        mock_directory,
        mock_network,
        mock_boto_client,
        secrets_manager,
    ):
        """Test registering a new ACME account."""
        mock_boto_client.return_value = secrets_manager

        mock_net_instance = Mock()
        mock_net_instance.get.return_value.json.return_value = {}
        mock_network.return_value = mock_net_instance

        mock_acme_client = Mock()
        mock_acme_client.new_account.return_value = Mock()
        mock_client_v2.return_value = mock_acme_client

        with patch.object(CertificateManager, "_get_or_create_account_key"):
            manager = CertificateManager(
                certificate_secret_name="test-cert",
                acme_account_key_secret_name="test-key",
            )
            manager.account_key = Mock(spec=JWKRSA)

            result = manager._register_account()

            assert result == mock_acme_client
            mock_acme_client.new_account.assert_called_once()

    @patch("lambda_function.boto3.client")
    @patch("lambda_function.client.ClientNetwork")
    @patch("lambda_function.messages.Directory.from_json")
    @patch("lambda_function.client.ClientV2")
    def test_register_account_existing_account(
        self,
        mock_client_v2,
        mock_directory,
        mock_network,
        mock_boto_client,
        secrets_manager,
    ):
        """Test using existing ACME account via ConflictError."""
        mock_boto_client.return_value = secrets_manager

        mock_net_instance = Mock()
        mock_net_instance.get.return_value.json.return_value = {}
        mock_network.return_value = mock_net_instance

        mock_acme_client = Mock()
        conflict_error = errors.ConflictError("Account exists")
        conflict_error.location = "https://acme.example.com/acct/123"
        mock_acme_client.new_account.side_effect = conflict_error
        mock_client_v2.return_value = mock_acme_client

        with patch.object(CertificateManager, "_get_or_create_account_key"):
            manager = CertificateManager(
                certificate_secret_name="test-cert",
                acme_account_key_secret_name="test-key",
            )
            manager.account_key = Mock(spec=JWKRSA)

            result = manager._register_account()

            assert result == mock_acme_client

    @patch("lambda_function.boto3.client")
    @patch("lambda_function.client.ClientNetwork")
    @patch("lambda_function.messages.Directory.from_json")
    @patch("lambda_function.client.ClientV2")
    def test_register_account_conflict_empty_location(
        self,
        mock_client_v2,
        mock_directory,
        mock_network,
        mock_boto_client,
        secrets_manager,
    ):
        """Test ConflictError with empty location raises exception."""
        mock_boto_client.return_value = secrets_manager

        mock_net_instance = Mock()
        mock_net_instance.get.return_value.json.return_value = {}
        mock_network.return_value = mock_net_instance

        mock_acme_client = Mock()
        # Create ConflictError with empty string location (falsy value)
        conflict_error = errors.ConflictError("")
        mock_acme_client.new_account.side_effect = conflict_error
        mock_client_v2.return_value = mock_acme_client

        with patch.object(CertificateManager, "_get_or_create_account_key"):
            manager = CertificateManager(
                certificate_secret_name="test-cert",
                acme_account_key_secret_name="test-key",
            )
            manager.account_key = Mock(spec=JWKRSA)

            with pytest.raises(errors.ConflictError):
                manager._register_account()


class TestDnsRecordCreation:
    """Test DNS record creation."""

    @patch("lambda_function.boto3.client")
    def test_create_dns_record_success(self, mock_boto_client, secrets_manager):
        """Test successful DNS record creation."""
        mock_route53 = Mock()
        mock_route53.change_resource_record_sets.return_value = {
            "ChangeInfo": {"Id": "/change/ABC123"}
        }
        mock_waiter = Mock()
        mock_route53.get_waiter.return_value = mock_waiter

        def client_factory(service_name, **kwargs):
            if service_name == "route53":
                return mock_route53
            return secrets_manager

        mock_boto_client.side_effect = client_factory

        with patch.object(CertificateManager, "_get_or_create_account_key"):
            manager = CertificateManager(
                certificate_secret_name="test-cert",
                acme_account_key_secret_name="test-key",
            )

            record_name = manager._create_dns_record("example.com", "test-validation")

            assert record_name == "_acme-challenge.example.com"
            mock_route53.change_resource_record_sets.assert_called_once()
            mock_waiter.wait.assert_called_once()

    @patch("lambda_function.boto3.client")
    @patch("lambda_function.time.sleep")
    def test_create_dns_record_retry_on_failure(
        self, mock_sleep, mock_boto_client, secrets_manager
    ):
        """Test DNS record creation retries on failure."""
        mock_route53 = Mock()
        # Fail twice, then succeed
        mock_route53.change_resource_record_sets.side_effect = [
            IOError("Network error"),
            IOError("Network error"),
            {"ChangeInfo": {"Id": "/change/ABC123"}},
        ]
        mock_waiter = Mock()
        mock_route53.get_waiter.return_value = mock_waiter

        def client_factory(service_name, **kwargs):
            if service_name == "route53":
                return mock_route53
            return secrets_manager

        mock_boto_client.side_effect = client_factory

        with patch.object(CertificateManager, "_get_or_create_account_key"):
            manager = CertificateManager(
                certificate_secret_name="test-cert",
                acme_account_key_secret_name="test-key",
            )

            record_name = manager._create_dns_record("example.com", "test-validation")

            assert record_name == "_acme-challenge.example.com"
            assert mock_route53.change_resource_record_sets.call_count == 3

    @patch("lambda_function.boto3.client")
    @patch("lambda_function.time.sleep")
    def test_create_dns_record_max_retries_exceeded(
        self, mock_sleep, mock_boto_client, secrets_manager
    ):
        """Test DNS record creation fails after max retries."""
        mock_route53 = Mock()
        mock_route53.change_resource_record_sets.side_effect = IOError("Network error")

        def client_factory(service_name, **kwargs):
            if service_name == "route53":
                return mock_route53
            return secrets_manager

        mock_boto_client.side_effect = client_factory

        with patch.object(CertificateManager, "_get_or_create_account_key"):
            manager = CertificateManager(
                certificate_secret_name="test-cert",
                acme_account_key_secret_name="test-key",
            )

            with pytest.raises(IOError):
                manager._create_dns_record("example.com", "test-validation")


class TestDnsRecordCleanup:
    """Test DNS record cleanup."""

    @patch("lambda_function.boto3.client")
    def test_cleanup_dns_record_success(self, mock_boto_client, secrets_manager):
        """Test successful DNS record cleanup."""
        mock_route53 = Mock()
        mock_route53.change_resource_record_sets.return_value = {
            "ChangeInfo": {"Id": "/change/ABC123"}
        }

        def client_factory(service_name, **kwargs):
            if service_name == "route53":
                return mock_route53
            return secrets_manager

        mock_boto_client.side_effect = client_factory

        with patch.object(CertificateManager, "_get_or_create_account_key"):
            manager = CertificateManager(
                certificate_secret_name="test-cert",
                acme_account_key_secret_name="test-key",
            )

            manager._cleanup_dns_record("example.com", "test-validation")

            mock_route53.change_resource_record_sets.assert_called_once()
            call_args = mock_route53.change_resource_record_sets.call_args
            assert call_args[1]["ChangeBatch"]["Changes"][0]["Action"] == "DELETE"

    @patch("lambda_function.boto3.client")
    def test_cleanup_dns_record_failure(self, mock_boto_client, secrets_manager):
        """Test DNS cleanup failure adds error to cleanup_errors."""
        mock_route53 = Mock()
        mock_route53.change_resource_record_sets.side_effect = IOError("Network error")

        def client_factory(service_name, **kwargs):
            if service_name == "route53":
                return mock_route53
            return secrets_manager

        mock_boto_client.side_effect = client_factory

        with patch.object(CertificateManager, "_get_or_create_account_key"):
            manager = CertificateManager(
                certificate_secret_name="test-cert",
                acme_account_key_secret_name="test-key",
            )

            # Should not raise exception
            manager._cleanup_dns_record("example.com", "test-validation")

            assert len(manager.cleanup_errors) == 1
            assert "example.com" in manager.cleanup_errors[0]


class TestDnsChallenge:
    """Test DNS challenge handling."""

    @patch("lambda_function.boto3.client")
    @patch("lambda_function.time.sleep")
    def test_perform_dns_challenge_success(
        self, mock_sleep, mock_boto_client, secrets_manager
    ):
        """Test successful DNS challenge."""
        mock_route53 = Mock()
        mock_route53.change_resource_record_sets.return_value = {
            "ChangeInfo": {"Id": "/change/ABC123"}
        }
        mock_waiter = Mock()
        mock_route53.get_waiter.return_value = mock_waiter

        def client_factory(service_name, **kwargs):
            if service_name == "route53":
                return mock_route53
            return secrets_manager

        mock_boto_client.side_effect = client_factory

        # Create mock authorization with DNS-01 challenge
        mock_authz = Mock()
        mock_authz.body.identifier.value = "example.com"

        mock_challenge = Mock()
        mock_challenge.chall = Mock(spec=challenges.DNS01)
        mock_challenge.chall.validation.return_value = "test-validation-token"
        mock_challenge.response.return_value = Mock()

        mock_authz.body.challenges = [mock_challenge]

        mock_order = Mock()

        with patch.object(CertificateManager, "_get_or_create_account_key"):
            manager = CertificateManager(
                certificate_secret_name="test-cert",
                acme_account_key_secret_name="test-key",
            )
            manager.account_key = Mock(spec=JWKRSA)
            manager._acme_client = Mock()

            validation = manager._perform_dns_challenge(mock_order, mock_authz)

            assert validation == "test-validation-token"
            manager._acme_client.answer_challenge.assert_called_once()

    @patch("lambda_function.boto3.client")
    def test_perform_dns_challenge_no_dns01(self, mock_boto_client, secrets_manager):
        """Test DNS challenge fails when no DNS-01 challenge available."""
        mock_boto_client.return_value = secrets_manager

        # Create mock authorization without DNS-01 challenge
        mock_authz = Mock()
        mock_authz.body.identifier.value = "example.com"

        # HTTP-01 challenge only
        mock_challenge = Mock()
        mock_challenge.chall = Mock()  # Not DNS01
        mock_authz.body.challenges = [mock_challenge]

        mock_order = Mock()

        with patch.object(CertificateManager, "_get_or_create_account_key"):
            manager = CertificateManager(
                certificate_secret_name="test-cert",
                acme_account_key_secret_name="test-key",
            )

            with pytest.raises(ValueError, match="No DNS-01 challenge found"):
                manager._perform_dns_challenge(mock_order, mock_authz)


class TestCertificateIssuance:
    """Test certificate issuance."""

    @patch("lambda_function.boto3.client")
    @patch("lambda_function.time.sleep")
    def test_issue_certificate_success(
        self, mock_sleep, mock_boto_client, secrets_manager, sample_certificate_pem
    ):
        """Test successful certificate issuance."""
        mock_route53 = Mock()
        mock_route53.change_resource_record_sets.return_value = {
            "ChangeInfo": {"Id": "/change/ABC123"}
        }
        mock_waiter = Mock()
        mock_route53.get_waiter.return_value = mock_waiter

        def client_factory(service_name, **kwargs):
            if service_name == "route53":
                return mock_route53
            return secrets_manager

        mock_boto_client.side_effect = client_factory

        with patch.object(CertificateManager, "_get_or_create_account_key"):
            with patch.object(CertificateManager, "_register_account") as mock_register:
                with patch.object(
                    CertificateManager, "_perform_dns_challenge"
                ) as mock_challenge:
                    mock_acme_client = Mock()

                    # Create mock order with authorization
                    mock_authz = Mock()
                    mock_authz.body.identifier.value = "example.com"
                    mock_authz.body.status.name = "valid"

                    mock_order = Mock()
                    mock_order.authorizations = [mock_authz]
                    mock_order.fullchain_pem = sample_certificate_pem

                    mock_acme_client.new_order.return_value = mock_order
                    mock_acme_client.poll_authorizations.return_value = mock_order
                    mock_acme_client.finalize_order.return_value = mock_order
                    mock_register.return_value = mock_acme_client

                    mock_challenge.return_value = "test-validation"

                    manager = CertificateManager(
                        certificate_secret_name="test-cert",
                        acme_account_key_secret_name="test-key",
                    )

                    result = manager.issue_certificate(["example.com"])

                    assert "private_key" in result
                    assert "certificate" in result
                    assert "domains" in result
                    assert result["domains"] == ["example.com"]

    @patch("lambda_function.boto3.client")
    @patch("lambda_function.time.sleep")
    def test_issue_certificate_cleanup_on_failure(
        self, mock_sleep, mock_boto_client, secrets_manager
    ):
        """Test DNS cleanup happens even when certificate issuance fails."""
        mock_route53 = Mock()
        mock_route53.change_resource_record_sets.return_value = {
            "ChangeInfo": {"Id": "/change/ABC123"}
        }
        mock_waiter = Mock()
        mock_route53.get_waiter.return_value = mock_waiter

        def client_factory(service_name, **kwargs):
            if service_name == "route53":
                return mock_route53
            return secrets_manager

        mock_boto_client.side_effect = client_factory

        with patch.object(CertificateManager, "_get_or_create_account_key"):
            with patch.object(CertificateManager, "_register_account") as mock_register:
                with patch.object(
                    CertificateManager, "_perform_dns_challenge"
                ) as mock_challenge:
                    mock_acme_client = Mock()

                    mock_authz = Mock()
                    mock_authz.body.identifier.value = "example.com"
                    mock_authz.body.status.name = "pending"

                    mock_order = Mock()
                    mock_order.authorizations = [mock_authz]

                    mock_acme_client.new_order.return_value = mock_order
                    mock_acme_client.poll_authorizations.side_effect = Exception(
                        "Authorization failed"
                    )
                    mock_register.return_value = mock_acme_client

                    mock_challenge.return_value = "test-validation"

                    manager = CertificateManager(
                        certificate_secret_name="test-cert",
                        acme_account_key_secret_name="test-key",
                    )

                    with pytest.raises(Exception, match="Authorization failed"):
                        manager.issue_certificate(["example.com"])

                    # Verify cleanup was attempted (DELETE action)
                    delete_calls = [
                        call
                        for call in mock_route53.change_resource_record_sets.call_args_list
                        if call[1]["ChangeBatch"]["Changes"][0]["Action"] == "DELETE"
                    ]
                    assert len(delete_calls) >= 1
