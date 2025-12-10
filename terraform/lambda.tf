# ============================================================================
# Lambda Layer for Dependencies
# ============================================================================

resource "terraform_data" "lambda_layer" {
  triggers_replace = {
    requirements = filemd5("${path.module}/../lambda/requirements.txt")
  }

  provisioner "local-exec" {
    command = <<-EOT
      cd ${path.module}/../lambda
      rm -rf layer python
      mkdir -p python
      pip install -r requirements.txt -t python/ --platform manylinux2014_x86_64 --only-binary=:all: --python-version ${local.python_version}
      zip -r layer.zip python
    EOT
  }
}

resource "aws_lambda_layer_version" "this" {
  filename                 = "${path.module}/../lambda/layer.zip"
  layer_name               = "${local.function_name}-dependencies"
  compatible_runtimes      = [var.python_runtime]
  compatible_architectures = ["x86_64", "arm64"]

  depends_on = [terraform_data.lambda_layer]
}

# ============================================================================
# Lambda Function
# ============================================================================

data "archive_file" "lambda" {
  type        = "zip"
  source_file = "${path.module}/../lambda/lambda_function.py"
  output_path = "${path.module}/../lambda/function.zip"
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
      DOMAINS                    = join(",", var.domains)
      HOSTED_ZONE_ID             = var.hosted_zone_id
      SECRET_NAME_PREFIX         = local.secret_name_prefix
      RENEWAL_DAYS_BEFORE_EXPIRY = tostring(var.renewal_days_before_expiry)
      SNS_TOPIC_ARN              = var.enable_notifications ? aws_sns_topic.notifications[0].arn : ""
      POWERTOOLS_SERVICE_NAME    = var.project_name
    }
  }

  depends_on = [
    aws_secretsmanager_secret.certificate,
    aws_secretsmanager_secret.account_key
  ]
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = 30
}
