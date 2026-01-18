# ============================================================================
# Lambda Layer for Dependencies
# ============================================================================
#
# IMPORTANT: Known limitation with local-exec provisioner
#
# This approach uses local-exec to build the Lambda layer during `terraform apply`.
# While convenient (no external build step needed), it has a significant drawback:
#
# - Terraform reads files during PLAN phase to compute hashes
# - local-exec runs during APPLY phase (after plan)
# - If layer.zip doesn't exist, `terraform plan` fails before apply runs
#
# When this happens (e.g., fresh clone or path changes), use terraform taint or build manually first:
#   # Try to taint terraform_data and redeploy
#   terraform taint terraform_data.lambda_layer && terraform apply
#
#   # From project root:
#   uv lock  # if uv.lock doesn't exist
#   uv export --package certbot-lambda --no-hashes --no-dev --frozen --no-emit-project -o lambdas/certbot/requirements.txt
#   cd lambdas/certbot
#   rm -rf python layer.zip
#   mkdir -p python
#   uv pip install -r requirements.txt --target python/ --python-platform x86_64-manylinux2014 --only-binary :all: --python-version 3.11
#   rm requirements.txt
#   zip -r layer.zip python
#
# Why use this approach anyway?
# - Simple single-command deployment after initial setup
# - No external build tools (Make, Docker, CI/CD) required
# - Automatic rebuild when pyproject.toml changes (after layer.zip exists)
# - Acceptable trade-off for infrequent layer rebuilds
#
# ============================================================================

resource "terraform_data" "lambda_layer" {
  triggers_replace = {
    dependencies = filemd5("${path.module}/../lambdas/certbot/pyproject.toml")
    architecture = var.lambda_architecture
  }

  provisioner "local-exec" {
    command = <<-EOT
      cd ${path.module}/..
      uv export --package certbot-lambda --no-hashes --no-dev --frozen --no-emit-project -o lambdas/certbot/requirements.txt
      cd lambdas/certbot
      rm -rf python layer.zip
      mkdir -p python
      uv pip install -r requirements.txt --target python/ --python-platform ${local.uv_platform} --only-binary :all: --python-version ${local.python_version}
      rm requirements.txt
      zip -r layer.zip python
      rm -rf python
    EOT
  }
}

resource "aws_lambda_layer_version" "this" {
  filename                 = "${path.module}/../lambdas/certbot/layer.zip"
  layer_name               = "${local.function_name}-dependencies"
  compatible_runtimes      = [var.python_runtime]
  compatible_architectures = [var.lambda_architecture]

  depends_on = [terraform_data.lambda_layer]
}

# ============================================================================
# Lambda Function
# ============================================================================

data "archive_file" "lambda" {
  type        = "zip"
  source_file = "${path.module}/../lambdas/certbot/lambda_function.py"
  output_path = "${path.module}/../lambdas/certbot/function.zip"
}

resource "aws_lambda_function" "this" {
  filename         = data.archive_file.lambda.output_path
  function_name    = local.function_name
  architectures    = [var.lambda_architecture]
  role             = aws_iam_role.this.arn
  handler          = "lambda_function.lambda_handler"
  source_code_hash = data.archive_file.lambda.output_base64sha256
  runtime          = var.python_runtime
  timeout          = 300
  memory_size      = 256

  layers = [
    aws_lambda_layer_version.this.arn,
    "arn:aws:lambda:${var.region}:017000801446:layer:AWSLambdaPowertoolsPythonV3-${replace(var.python_runtime, ".", "")}-${var.lambda_architecture}:${var.lambda_layer_powertools_version}"
  ]

  environment {
    variables = {
      ACME_DIRECTORY_URL         = local.acme_directory_url
      ACME_EMAIL                 = var.acme_email
      DOMAINS                    = jsonencode(var.domains)
      HOSTED_ZONE_ID             = var.hosted_zone_id
      SECRET_NAME_PREFIX         = local.secret_name_prefix
      RENEWAL_DAYS_BEFORE_EXPIRY = tostring(var.renewal_days_before_expiry)
      SNS_TOPIC_ARN              = var.enable_notifications ? aws_sns_topic.notifications[0].arn : ""
      EB_BUS_NAME                = var.eb_bus_name
      POWERTOOLS_SERVICE_NAME    = var.project_name
      ACME_PERSIST_ACCOUNT_KEY   = tostring(var.acme_persist_account_key)
      DNS_TXT_TTL                = tostring(var.dns_txt_ttl)
    }
  }

  depends_on = [
    aws_secretsmanager_secret.certificate
  ]
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = 30
}
