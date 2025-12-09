# terraform

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | ~> 1.12.1 |
| <a name="requirement_archive"></a> [archive](#requirement\_archive) | >= 2.0 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | ~> 6.0 |
| <a name="requirement_null"></a> [null](#requirement\_null) | >= 3.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_archive"></a> [archive](#provider\_archive) | >= 2.0 |
| <a name="provider_aws"></a> [aws](#provider\_aws) | ~> 6.0 |
| <a name="provider_terraform"></a> [terraform](#provider\_terraform) | n/a |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [aws_cloudwatch_event_rule.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_target.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_log_group.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_iam_role.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role_policy.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_lambda_function.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_layer_version.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_layer_version) | resource |
| [aws_lambda_permission.eventbridge](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_secretsmanager_secret.account_key](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret) | resource |
| [aws_secretsmanager_secret.certificate](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret) | resource |
| [aws_sns_topic.notifications](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic) | resource |
| [aws_sns_topic_subscription.email](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic_subscription) | resource |
| [terraform_data.lambda_layer](https://registry.terraform.io/providers/hashicorp/terraform/latest/docs/resources/data) | resource |
| [archive_file.lambda](https://registry.terraform.io/providers/hashicorp/archive/latest/docs/data-sources/file) | data source |
| [aws_iam_policy_document.assume_role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_acme_email"></a> [acme\_email](#input\_acme\_email) | Email address for Let's Encrypt account registration (optional but recommended) | `string` | `""` | no |
| <a name="input_additional_tags"></a> [additional\_tags](#input\_additional\_tags) | Additional tags to set for all resources | `map(string)` | `{}` | no |
| <a name="input_domains"></a> [domains](#input\_domains) | List of domains to obtain certificates for | `list(string)` | n/a | yes |
| <a name="input_enable_notifications"></a> [enable\_notifications](#input\_enable\_notifications) | Enable SNS notifications for certificate events | `bool` | `false` | no |
| <a name="input_environment"></a> [environment](#input\_environment) | Environment name (e.g., prod, staging) | `string` | `"dev"` | no |
| <a name="input_hosted_zone_id"></a> [hosted\_zone\_id](#input\_hosted\_zone\_id) | Route53 Hosted Zone ID for DNS challenges | `string` | n/a | yes |
| <a name="input_notification_email"></a> [notification\_email](#input\_notification\_email) | Email address for certificate notifications | `string` | `""` | no |
| <a name="input_project_name"></a> [project\_name](#input\_project\_name) | Project name used for resource naming | `string` | `"aws-certbot-lambda"` | no |
| <a name="input_python_runtime"></a> [python\_runtime](#input\_python\_runtime) | Python runtime version for Lambda | `string` | `"python3.11"` | no |
| <a name="input_region"></a> [region](#input\_region) | AWS region for deployment | `string` | `"eu-west-1"` | no |
| <a name="input_renewal_days_before_expiry"></a> [renewal\_days\_before\_expiry](#input\_renewal\_days\_before\_expiry) | Days before expiry to trigger renewal | `number` | `30` | no |
| <a name="input_schedule_expression"></a> [schedule\_expression](#input\_schedule\_expression) | EventBridge schedule expression for certificate checks | `string` | `"rate(12 hours)"` | no |
| <a name="input_use_staging"></a> [use\_staging](#input\_use\_staging) | Use Let's Encrypt staging environment (for testing) | `bool` | `false` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_account_key_secret_arn"></a> [account\_key\_secret\_arn](#output\_account\_key\_secret\_arn) | ARN of the Secrets Manager secret storing the ACME account key |
| <a name="output_certificate_secret_arn"></a> [certificate\_secret\_arn](#output\_certificate\_secret\_arn) | ARN of the Secrets Manager secret storing the certificate |
| <a name="output_certificate_secret_name"></a> [certificate\_secret\_name](#output\_certificate\_secret\_name) | Name of the Secrets Manager secret storing the certificate |
| <a name="output_eventbridge_rule_arn"></a> [eventbridge\_rule\_arn](#output\_eventbridge\_rule\_arn) | ARN of the EventBridge rule |
| <a name="output_force_renewal_command"></a> [force\_renewal\_command](#output\_force\_renewal\_command) | AWS CLI command to force certificate renewal |
| <a name="output_get_certificate_command"></a> [get\_certificate\_command](#output\_get\_certificate\_command) | AWS CLI command to retrieve the certificate |
| <a name="output_invoke_command"></a> [invoke\_command](#output\_invoke\_command) | AWS CLI command to manually invoke the Lambda function |
| <a name="output_lambda_function_arn"></a> [lambda\_function\_arn](#output\_lambda\_function\_arn) | ARN of the Lambda function |
| <a name="output_lambda_function_name"></a> [lambda\_function\_name](#output\_lambda\_function\_name) | Name of the Lambda function |
| <a name="output_lambda_role_arn"></a> [lambda\_role\_arn](#output\_lambda\_role\_arn) | ARN of the Lambda IAM role |
| <a name="output_sns_topic_arn"></a> [sns\_topic\_arn](#output\_sns\_topic\_arn) | ARN of the SNS topic for notifications |
<!-- END_TF_DOCS -->
