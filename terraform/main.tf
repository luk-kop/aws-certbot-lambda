
# ============================================================================
# SNS Topic for Notifications
# ============================================================================

# trivy:ignore:avd-aws-0095
resource "aws_sns_topic" "notifications" {
  count = var.enable_notifications ? 1 : 0
  name  = "${local.function_name}-notifications"
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.enable_notifications && var.notification_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.notifications[0].arn
  protocol  = "email"
  endpoint  = var.notification_email
}

# ============================================================================
# Lambda Layer for Dependencies
# ============================================================================

resource "null_resource" "lambda_layer" {
  triggers = {
    requirements = filemd5("${path.module}/../lambda/requirements.txt")
  }

  provisioner "local-exec" {
    command = <<-EOT
      cd ${path.module}/../lambda
      rm -rf layer python
      mkdir -p python
      pip install -r requirements.txt -t python/ --platform manylinux2014_x86_64 --only-binary=:all: --python-version 3.11
      zip -r layer.zip python
    EOT
  }
}

resource "aws_lambda_layer_version" "dependencies" {
  filename            = "${path.module}/../lambda/layer.zip"
  layer_name          = "${local.function_name}-dependencies"
  compatible_runtimes = ["python3.11"]

  depends_on = [null_resource.lambda_layer]
}

# ============================================================================
# Lambda Function
# ============================================================================

data "archive_file" "lambda" {
  type        = "zip"
  source_file = "${path.module}/../lambda/certbot_handler.py"
  output_path = "${path.module}/../lambda/function.zip"
}

resource "aws_lambda_function" "certbot" {
  filename         = data.archive_file.lambda.output_path
  function_name    = local.function_name
  role             = aws_iam_role.lambda.arn
  handler          = "certbot_handler.lambda_handler"
  source_code_hash = data.archive_file.lambda.output_base64sha256
  runtime          = "python3.11"
  timeout          = 300
  memory_size      = 256

  layers = [aws_lambda_layer_version.dependencies.arn]

  environment {
    variables = {
      ACME_DIRECTORY_URL         = local.acme_directory_url
      ACME_EMAIL                 = var.acme_email
      DOMAINS                    = join(",", var.domains)
      HOSTED_ZONE_ID             = var.hosted_zone_id
      SECRET_NAME                = local.secret_name
      RENEWAL_DAYS_BEFORE_EXPIRY = tostring(var.renewal_days_before_expiry)
      SNS_TOPIC_ARN              = var.enable_notifications ? aws_sns_topic.notifications[0].arn : ""
    }
  }
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = 30
}

# ============================================================================
# EventBridge Schedule
# ============================================================================

resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "${local.function_name}-schedule"
  description         = "Trigger certificate renewal check"
  schedule_expression = var.schedule_expression
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.schedule.name
  target_id = "certbot-lambda"
  arn       = aws_lambda_function.certbot.arn
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.certbot.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule.arn
}
