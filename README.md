# aws-certbot-lambda

[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/release/python-3110/)
[![Terraform](https://img.shields.io/badge/terraform-%3E%3D1.0-purple.svg)](https://www.terraform.io/)
[![MIT license](https://img.shields.io/badge/License-MIT-blue.svg)](https://lbesson.mit-license.org/)

Serverless TLS certificate renewal using Let's Encrypt ACME protocol. Runs as an AWS Lambda function with Route53 DNS-01 challenges and stores certificates in Secrets Manager. Deployed with Terraform.

## Features

- Automatic certificate renewal (checks every 12 hours by default)
- DNS-01 challenge validation via Route53
- Certificate storage in AWS Secrets Manager (JSON format)
- Support for wildcard certificates
- Optional SNS notifications for renewal events
- Configurable renewal threshold (default: 30 days before expiry)
- Retry with exponential backoff for reliability

## Prerequisites

- AWS account with appropriate permissions
- Route53 hosted zone for your domain
- Terraform >= 1.0
- Python 3.11 and pip (for local Lambda layer building)

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  EventBridge    │────▶│  Lambda         │────▶│  Let's Encrypt  │
│  (Schedule)     │     │  (Python 3.11)  │     │  ACME Server    │
└─────────────────┘     └────────┬────────┘     └─────────────────┘
                                 │
                    ┌────────────┼────────────┐
                    ▼            ▼            ▼
             ┌──────────┐ ┌──────────┐ ┌──────────┐
             │ Route53  │ │ Secrets  │ │CloudWatch│
             │ (DNS-01) │ │ Manager  │ │ (Logs)   │
             └──────────┘ └──────────┘ └──────────┘
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
┌─────────────────────────────┐
│ Load or create ACME         │
│ account key                 │
└──────────────┬──────────────┘
               │
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
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│ Cleanup DNS records         │
└──────────────┬──────────────┘
               │
               ▼
              END
```

**Certificate renewal triggers:**
- Secret is empty (first run)
- Certificate field is missing
- Certificate expires within 30 days (configurable)
- `force_renewal: true` in event payload

## Secrets Manager

Two secrets are created by Terraform:

| Secret | Content | Purpose |
|--------|---------|---------|
| `{project}-{env}-certificate` | Certificate JSON (see format below) | Stores the TLS certificate, private key, and chain |
| `{project}-{env}-certificate-account-key` | PEM-encoded RSA private key | ACME account key for Let's Encrypt registration |

**Why account key is stored separately?**

The **ACME account key** identifies your account with Let's Encrypt. Reusing the same key across renewals:
- Maintains your account registration
- Avoids hitting rate limits for new registrations
- Required for certificate revocation if needed

**Certificate JSON format:**

```json
{
  "certificate": "-----BEGIN FAKE CERTIFICATE-----...",
  "private_key": "-----BEGIN FAKE PRIVATE KEY-----...",
  "chain": "-----BEGIN FAKE CERTIFICATE-----...",
  "fullchain": "-----BEGIN FAKE CERTIFICATE-----...",
  "expiry": "2025-03-10T00:00:00+00:00",
  "domains": ["example.com", "*.example.com"],
  "obtained_at": "2024-12-10T00:00:00+00:00"
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
| `obtained_at` | When the certificate was obtained |

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

**Important:** Always test with Let's Encrypt staging environment first (`use_staging = true`). Production Let's Encrypt has strict [rate limits](https://letsencrypt.org/docs/rate-limits/) - you can only request 5 duplicate certificates per week.

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



# TODO
- Store generating certificate data in AWS ACM
