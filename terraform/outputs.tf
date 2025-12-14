output "lambda_function_name" {
  description = "Name of the Lambda function"
  value       = aws_lambda_function.this.function_name
}

output "lambda_function_arn" {
  description = "ARN of the Lambda function"
  value       = aws_lambda_function.this.arn
}

output "lambda_role_arn" {
  description = "ARN of the Lambda IAM role"
  value       = aws_iam_role.this.arn
}

output "certificate_secret_name" {
  description = "Name of the Secrets Manager secret storing the certificate"
  value       = aws_secretsmanager_secret.certificate.name
}

output "certificate_secret_arn" {
  description = "ARN of the Secrets Manager secret storing the certificate"
  value       = aws_secretsmanager_secret.certificate.arn
}

output "acme_account_key_secret_arn" {
  description = "ARN of the Secrets Manager secret storing the ACME account key (null if acme_persist_account_key is false)"
  value       = var.acme_persist_account_key ? aws_secretsmanager_secret.account_key[0].arn : null
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for notifications"
  value       = var.enable_notifications ? aws_sns_topic.notifications[0].arn : null
}

output "eventbridge_rule_arn" {
  description = "ARN of the EventBridge rule"
  value       = aws_cloudwatch_event_rule.this.arn
}
