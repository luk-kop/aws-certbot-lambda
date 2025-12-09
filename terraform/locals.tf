locals {
  function_name = "${var.project_name}-${var.environment}"
  secret_name   = "${var.project_name}-${var.environment}-certificate"

  acme_directory_url = var.use_staging ? "https://acme-staging-v02.api.letsencrypt.org/directory" : "https://acme-v02.api.letsencrypt.org/directory"

  tags = merge(
    var.additional_tags,
    {
      Project     = var.project_name
      Environment = var.environment,
      Terraform   = "true"
    }
  )
}
