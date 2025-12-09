locals {
  function_name      = "${var.project_name}-${var.environment}"
  secret_name_prefix = "${var.project_name}-${var.environment}"

  acme_directory_url = var.use_staging ? "https://acme-staging-v02.api.letsencrypt.org/directory" : "https://acme-v02.api.letsencrypt.org/directory"

  # Extract version number from runtime (e.g., "python3.11" -> "3.11")
  python_version = replace(var.python_runtime, "python", "")

  tags = merge(
    var.additional_tags,
    {
      Project     = var.project_name
      Environment = var.environment,
      Terraform   = "true"
    }
  )
}
