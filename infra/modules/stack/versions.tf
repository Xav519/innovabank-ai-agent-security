# =============================================================================
# WHAT THIS FILE IS
# =============================================================================
#
# Pins the Terraform and provider versions this module needs.
#
# Why it matters:
#   - Same versions everywhere means same behavior locally and in CI.
#   - Stops a future breaking release from silently changing the stack.
#
# =============================================================================

terraform {
  # Oldest Terraform that supports the syntax used here.
  required_version = ">= 1.6.0"

  required_providers {
    # Creates the AWS resources. "~> 5.80" allows 5.x fixes, blocks 6.0 breaks.
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
    # Zips app/ into the Lambda package.
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.6.0"
    }
  }
}
