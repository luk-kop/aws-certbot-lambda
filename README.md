# aws-certbot-lambda

[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/release/python-3110/)
[![Terraform](https://img.shields.io/badge/terraform-~>%201.12.1-purple.svg)](https://www.terraform.io/)
[![MIT license](https://img.shields.io/badge/License-MIT-blue.svg)](https://lbesson.mit-license.org/)

Serverless TLS certificate renewal using Let's Encrypt ACME protocol. Runs as an AWS Lambda function with Route53 DNS-01 challenges and stores certificates in Secrets Manager. Deployed with Terraform.

## Features

- Automatic certificate renewal (checks every 12 hours by default)
- DNS-01 challenge validation via Route53
- Certificate storage in AWS Secrets Manager (JSON format)
- Certificate metadata tags (ExpirationDate, IssuedAt, Domains) for monitoring without decryption
- Support for wildcard certificates
- Optional SNS notifications for renewal events
- Optional EventBridge event publishing for integration with other AWS services
- Configurable ACME account key persistence (persistent or ephemeral)
- Configurable renewal threshold (default: 30 days before expiry)
- Retry with exponential backoff for reliability
- AWS Lambda Powertools for structured logging

## Prerequisites

- AWS account with appropriate permissions
- Route53 hosted zone for your domain
- Terraform ~> 1.12.1
- Python 3.11 and pip (for local Lambda layer building)

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  EventBridge    │────▶│  Lambda         │────▶│  Let's Encrypt  │
│  (Schedule)     │     │  (Python 3.11)  │     │  ACME Server    │
└─────────────────┘     └────────┬────────┘     └─────────────────┘
                                 │
                    ┌────────────┼────────────┬────────────┬────────────┐
                    ▼            ▼            ▼            ▼            ▼
             ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────┐
             │ Route53  │ │ Secrets  │ │CloudWatch│ │   SNS    │ │EventBridge│
             │ (DNS-01) │ │ Manager  │ │ (Logs)   │ │(Optional)│ │(Optional) │
             └──────────┘ └──────────┘ └──────────┘ └──────────┘ └───────────┘
```

## Lambda Function Logic

```
START
  │
  ▼
┌─────────────────────────────┐
│ Load certificate from       │
│ Secrets Manager             │
└──────────────┬──────────────┘
               │
               ▼
        ┌─────────────┐  Yes (valid > 30 days)
        │ Certificate ├──────────────────────────┐
        │ needs       │                          │
        │ renewal?    │                          ▼
        └──────┬──────┘                    ┌───────────┐
               │ Yes (missing/expired/     │ Exit      │
               │ expiring soon)            │ (skip)    │
               ▼                           └───────────┘
┌───────────────────────────────┐
│ persist_account_key = true?   │
└──────┬──────────────┬─────────┘
       │ Yes          │ No
       ▼              ▼
┌──────────┐   ┌──────────────┐
│ Load or  │   │ Create       │
│ create   │   │ ephemeral    │
│ from     │   │ account key  │
│ Secrets  │   │              │
└─────┬────┘   └──────┬───────┘
      │               │
      └───────┬───────┘
              ▼
┌─────────────────────────────┐
│ Register with Let's Encrypt │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│ For each domain:            │
│ - Create _acme-challenge    │
│   TXT record in Route53     │
│ - Complete DNS-01 challenge │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│ Download certificate        │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│ Store in Secrets Manager    │
│ + Update metadata tags      │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│ Cleanup DNS records         │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│ Send SNS notification       │
│ (if enabled)                │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│ Publish EventBridge event   │
│ (if enabled)                │
└──────────────┬──────────────┘
               │
               ▼
              END
```

**Certificate renewal triggers:**
- Secret is empty (first run)
- Certificate field is missing or invalid
- Certificate expires within 30 days (configurable via `RENEWAL_DAYS_BEFORE_EXPIRY`)
- `force_renewal: true` in event payload

**Note:** Expiry is always determined by parsing the actual certificate PEM, not the stored `expiry` field. This ensures the certificate itself is the source of truth. If the stored `expiry` field doesn't match the actual certificate expiry, a warning is logged.

## Secrets Manager

**Important:** Secrets must be created by Terraform before the Lambda function runs. The Lambda function will fail with a clear error if the certificate secret does not exist. This is by design - the infrastructure (Terraform) manages secret lifecycle, while the Lambda only reads/updates the secret value.

Secrets created by Terraform:

| Secret | Content | Purpose | Created When |
|--------|---------|---------|-------------|
| `{project}-{env}-certificate` | Certificate JSON (see format below) | Stores the TLS certificate, private key, and chain | Always |
| `{project}-{env}-account-key` | PEM-encoded RSA private key | ACME account key for Let's Encrypt registration | Only if `acme_persist_account_key = true` (default) |

**Certificate Secret Tags**

The certificate secret is automatically tagged with metadata on each renewal:

| Tag | Description | Example |
|-----|-------------|----------|
| `ExpirationDate` | Certificate expiration date (ISO 8601) | `2025-03-10T00:00:00+00:00` |
| `IssuedAt` | When the certificate was issued (ISO 8601) | `2024-12-10T00:00:00+00:00` |
| `Domains` | Comma-separated list of domains (max 256 chars) | `example.com,*.example.com` |

These tags enable monitoring and alerting without decrypting the secret value.

**ACME Account Key Persistence**

You can control whether the ACME account key is persisted using the `acme_persist_account_key` Terraform variable:

- **`acme_persist_account_key = true` (default, recommended for production)**
  - Account key is stored in Secrets Manager and reused across renewals
  - Maintains your account registration with Let's Encrypt
  - Avoids hitting rate limits for new registrations (10 per IP per 3 hours)
  - Required for certificate revocation if needed
  - Enables account history tracking

- **`acme_persist_account_key = false` (ephemeral mode)**
  - New account key is generated on every renewal
  - Simpler architecture - one less secret to manage
  - Useful for testing or specific use cases
  - **Warning**: May hit Let's Encrypt rate limits with frequent renewals

**Certificate JSON format:**

```json
{
  "certificate": "-----BEGIN FAKE CERTIFICATE-----...",
  "private_key": "-----BEGIN FAKE PRIVATE KEY-----...",
  "chain": "-----BEGIN FAKE CERTIFICATE-----...",
  "fullchain": "-----BEGIN FAKE CERTIFICATE-----...",
  "expiry": "2025-03-10T00:00:00+00:00",
  "domains": ["example.com", "*.example.com"],
  "issued_at": "2024-12-10T00:00:00+00:00"
}
```

| Field | Description |
|-------|-------------|
| `certificate` | Leaf certificate only |
| `private_key` | RSA private key |
| `chain` | Intermediate CA certificates |
| `fullchain` | Leaf + intermediate certificates |
| `expiry` | Certificate expiration date (ISO 8601) |
| `domains` | List of domains in the certificate |
| `issued_at` | When the certificate was issued (ISO 8601) |

## Lambda Layer Building

The Lambda function requires Python dependencies (`acme`, `cryptography`, `josepy`, `boto3`) packaged as a Lambda layer. Terraform builds this layer locally during `terraform apply` using `pip install` with the `--platform manylinux2014_x86_64` flag to ensure compatibility with the Lambda runtime.

**Why local building?**
- Simple setup - no Docker or CI/CD pipeline required
- Automatic rebuild when `requirements.txt` changes
- Suitable for single-function deployments

**Requirements:**
- Python 3.11 and pip installed locally
- Internet access to download packages from PyPI

For production environments with stricter reproducibility needs, consider building the layer in CI/CD and storing it in S3.

## Deployment

See [terraform/README.md](terraform/README.md) for detailed configuration, variables, and outputs.

```bash
cd terraform
terraform init
terraform plan
terraform apply
```

**Important:** Always test with Let's Encrypt staging environment first (`acme_use_staging = true`). Production Let's Encrypt has strict [rate limits](https://letsencrypt.org/docs/rate-limits/) - you can only request 5 duplicate certificates per week.

## Usage

### Invoke Lambda without force certificate renewal

```bash
aws lambda invoke --function-name aws-certbot-lambda-prod \
  --cli-binary-format raw-in-base64-out \
  --payload '{"force_renewal": false}' response.json
```

### Force certificate renewal

```bash
aws lambda invoke --function-name aws-certbot-lambda-prod \
  --cli-binary-format raw-in-base64-out \
  --payload '{"force_renewal": true}' response.json
```

### Retrieve certificate

```bash
# Full JSON
aws secretsmanager get-secret-value \
  --secret-id aws-certbot-lambda-prod-certificate \
  --query SecretString --output text | jq .

# Certificate only
aws secretsmanager get-secret-value \
  --secret-id aws-certbot-lambda-prod-certificate \
  --query SecretString --output text | jq -r .certificate > cert.pem

# Private key only
aws secretsmanager get-secret-value \
  --secret-id aws-certbot-lambda-prod-certificate \
  --query SecretString --output text | jq -r .private_key > key.pem
```

### Check certificate expiration (using tags)

```bash
# Get expiration date from secret tags (no decryption needed)
aws secretsmanager describe-secret \
  --secret-id aws-certbot-lambda-prod-certificate \
  --query 'Tags[?Key==`ExpirationDate`].Value' --output text

# Get certificate issue date
aws secretsmanager describe-secret \
  --secret-id aws-certbot-lambda-prod-certificate \
  --query 'Tags[?Key==`IssuedAt`].Value' --output text
```

## Configuration Options

### ACME Account Key Persistence

Set `acme_persist_account_key = false` in your `terraform.tfvars` to use ephemeral account keys:

```hcl
acme_persist_account_key = false
```

This will:
- Skip creating the account key secret in Secrets Manager
- Generate a new account key on every certificate renewal
- Reduce AWS costs slightly (one less secret)

**When to use ephemeral mode:**
- Testing and development environments
- One-time certificate generation
- When you don't need certificate revocation capabilities

**When to use persistent mode (default):**
- Production environments
- Frequent certificate renewals
- When you need to revoke certificates
- To avoid Let's Encrypt rate limits

### SNS Notifications

Enable SNS notifications for certificate renewal events:

```hcl
enable_notifications = true
notification_email   = "admin@example.com"
```

Notifications are sent for:
- Successful certificate renewals
- Failed certificate renewals

### EventBridge Integration

Publish certificate events to EventBridge for integration with other AWS services:

```hcl
eb_bus_name = "default"  # or your custom event bus name
```

**Event Details:**

Success event (`Certificate Renewed`):
```json
{
  "status": "success",
  "domains": ["example.com", "*.example.com"],
  "expiry": "2025-03-10T00:00:00+00:00",
  "issued_at": "2024-12-10T00:00:00+00:00",
  "secret_name": "aws-certbot-lambda-prod-certificate"
}
```

Failure event (`Certificate Renewal Failed`):
```json
{
  "status": "failed",
  "domains": ["example.com", "*.example.com"],
  "error": "Error message",
  "secret_name": "aws-certbot-lambda-prod-certificate"
}
```

Event source is the Lambda function name (e.g., `aws-certbot-lambda-prod`).

## Environment Variables

The Lambda function uses the following environment variables (automatically configured by Terraform):

| Variable | Description | Default |
|----------|-------------|----------|
| `ACME_DIRECTORY_URL` | Let's Encrypt ACME directory URL | Production or staging based on `acme_use_staging` |
| `ACME_EMAIL` | Email for ACME account registration | From `acme_email` variable |
| `DOMAINS` | JSON array of domains | From `domains` variable |
| `HOSTED_ZONE_ID` | Route53 hosted zone ID | From `hosted_zone_id` variable |
| `SECRET_NAME_PREFIX` | Prefix for Secrets Manager secret names | `{project_name}-{environment}` |
| `RENEWAL_DAYS_BEFORE_EXPIRY` | Days before expiry to trigger renewal | `30` |
| `SNS_TOPIC_ARN` | SNS topic ARN for notifications | Empty if disabled |
| `EB_BUS_NAME` | EventBridge bus name for events | Empty if disabled |
| `POWERTOOLS_SERVICE_NAME` | Service name for AWS Lambda Powertools | From `project_name` variable |
| `ACME_PERSIST_ACCOUNT_KEY` | Whether to persist ACME account key | `true` |
| `RSA_KEY_SIZE` | RSA key size for certificates | `2048` |
| `DNS_PROPAGATION_WAIT_SECONDS` | Additional DNS propagation wait time | `30` |

## Testing

Unit tests are written using pytest. Run tests in a virtual environment:

```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install test dependencies
pip install -e ".[test]"

# Run tests with coverage
PYTHONPATH=./lambda pytest tests/ -v

# Run tests with coverage report
PYTHONPATH=./lambda pytest tests/ -v --cov=lambda --cov-report=term-missing
```

Test coverage includes:
- `CertificateManager` class (initialization, account keys, CSR generation, DNS challenges, certificate issuance/storage/retrieval)
- `retry_with_backoff` decorator
- `_validate_config` function
- `send_notification` and `publish_event` functions

## TODO
- Add a feature that enables the storage of certificate-generating data in AWS ACM
- Add support for multiple Hosted Zones
