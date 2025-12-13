# ============================================================================
# Secrets Manager Secrets
# ============================================================================

resource "aws_secretsmanager_secret" "certificate" {
  name        = "${local.secret_name_prefix}-certificate"
  description = "TLS certificate for ${join(", ", var.domains)}"
}

resource "aws_secretsmanager_secret" "account_key" {
  count       = var.acme_persist_account_key ? 1 : 0
  name        = "${local.secret_name_prefix}-account-key"
  description = "ACME account private key for Let's Encrypt"
}

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
