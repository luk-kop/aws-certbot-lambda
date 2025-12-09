# aws-certbot-lambda


[![Python 3.10.12](https://img.shields.io/badge/python-3.10.12-blue.svg)](https://www.python.org/downloads/release/python-377/)
[![Boto3](https://img.shields.io/badge/Boto3-1.42.3-blue.svg)](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
[![MIT license](https://img.shields.io/badge/License-MIT-blue.svg)](https://lbesson.mit-license.org/)

Serverless TLS certificate renewal using Let's Encrypt ACME protocol. Runs as an AWS Lambda function with Route53 DNS-01 challenges and stores certificates in Secrets Manager. Deployed with Terraform.

## Features

## Prerequisites

## Deployment

AWS resources can be deployed using Terraform code in the `terraform/` directory:

```bash
cd terraform
terraform init
terraform plan
terraform apply
```

- Key Configuration (`terraform.tfvars`)

```hcl
acme_email     = "admin@example.com"
domains        = ["example.com", "*.example.com"]
hosted_zone_id = "Z1234567890ABC"
use_staging    = true  # Set false for production
```

## Useful commands

```bash
# Force renewal
aws lambda invoke --function-name certbot-lambda-prod \
--payload '{"force_renewal": true}' response.json

# Get certificate
aws secretsmanager get-secret-value \
--secret-id certbot-lambda-prod-certificate \
--query SecretString --output text
```
