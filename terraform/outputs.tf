output "lambda_function_name" {
  description = "Name of the Lambda function"
  value       = aws_lambda_function.certbot.function_name
}

output "lambda_function_arn" {
  description = "ARN of the Lambda function"
  value       = aws_lambda_function.certbot.arn
}

output "lambda_role_arn" {
  description = "ARN of the Lambda IAM role"
  value       = aws_iam_role.lambda.arn
}

output "certificate_secret_name" {
  description = "Name of the Secrets Manager secret storing the certificate"
  value       = local.secret_name
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for notifications"
  value       = var.enable_notifications ? aws_sns_topic.notifications[0].arn : null
}

output "eventbridge_rule_arn" {
  description = "ARN of the EventBridge rule"
  value       = aws_cloudwatch_event_rule.schedule.arn
}

output "invoke_command" {
  description = "AWS CLI command to manually invoke the Lambda function"
  value       = "aws lambda invoke --function-name ${aws_lambda_function.certbot.function_name} --payload '{\"force_renewal\": false}' response.json"
}

output "force_renewal_command" {
  description = "AWS CLI command to force certificate renewal"
  value       = "aws lambda invoke --function-name ${aws_lambda_function.certbot.function_name} --payload '{\"force_renewal\": true}' response.json"
}

output "get_certificate_command" {
  description = "AWS CLI command to retrieve the certificate"
  value       = "aws secretsmanager get-secret-value --secret-id ${local.secret_name} --query SecretString --output text | jq ."
}
