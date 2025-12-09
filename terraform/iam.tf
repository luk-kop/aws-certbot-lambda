data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "lambda" {
  name               = "${local.function_name}-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

data "aws_iam_policy_document" "lambda_permissions" {
  # CloudWatch Logs
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = ["arn:aws:logs:*:*:*"]
  }

  # Secrets Manager
  statement {
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:CreateSecret",
      "secretsmanager:UpdateSecret",
      "secretsmanager:PutSecretValue"
    ]
    resources = [
      "arn:aws:secretsmanager:${var.region}:*:secret:${local.secret_name}*"
    ]
  }

  # Route53 for DNS challenges
  statement {
    effect = "Allow"
    actions = [
      "route53:ChangeResourceRecordSets"
    ]
    resources = [
      "arn:aws:route53:::hostedzone/${var.hosted_zone_id}"
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "route53:GetChange"
    ]
    resources = ["arn:aws:route53:::change/*"]
  }

  # SNS for notifications (conditional)
  dynamic "statement" {
    for_each = var.enable_notifications ? [1] : []
    content {
      effect = "Allow"
      actions = [
        "sns:Publish"
      ]
      resources = [aws_sns_topic.notifications[0].arn]
    }
  }
}

resource "aws_iam_role_policy" "lambda" {
  name   = "${local.function_name}-policy"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda_permissions.json
}
