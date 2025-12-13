variable "region" {
  description = "AWS region for deployment"
  type        = string
  default     = "eu-west-1"
}

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "aws-certbot-lambda"
}

variable "environment" {
  description = "Environment name (e.g., prod, staging)"
  type        = string
  default     = "dev"
}

variable "acme_email" {
  description = "Email address for Let's Encrypt account registration (optional but recommended)"
  type        = string
  default     = ""
}

variable "domains" {
  description = "List of domains to obtain certificates for"
  type        = list(string)
}

variable "hosted_zone_id" {
  description = "Route53 Hosted Zone ID for DNS challenges"
  type        = string
}

variable "acme_use_staging" {
  description = "Use Let's Encrypt staging environment (for testing)"
  type        = bool
  default     = false
}

variable "renewal_days_before_expiry" {
  description = "Days before expiry to trigger renewal"
  type        = number
  default     = 30
}

variable "schedule_expression" {
  description = "EventBridge schedule expression for certificate checks"
  type        = string
  default     = "rate(12 hours)"
}

variable "enable_notifications" {
  description = "Enable SNS notifications for certificate events"
  type        = bool
  default     = false
}

variable "notification_email" {
  description = "Email address for certificate notifications"
  type        = string
  default     = ""
}

variable "additional_tags" {
  description = "Additional tags to set for all resources"
  type        = map(string)
  default     = {}
}

variable "python_runtime" {
  description = "Python runtime version for Lambda"
  type        = string
  default     = "python3.11"
}

variable "lambda_architecture" {
  description = "Lambda function architecture"
  type        = string
  default     = "x86_64"
  validation {
    condition     = contains(["x86_64", "arm64"], var.lambda_architecture)
    error_message = "Lambda architecture must be either x86_64 or arm64."
  }
}

variable "lambda_layer_powertools_version" {
  description = "AWS Lambda Powertools layer version"
  type        = number
  default     = 18
}

variable "acme_persist_account_key" {
  description = "Persist ACME account key in Secrets Manager (recommended for production to avoid rate limits)"
  type        = bool
  default     = true
}
