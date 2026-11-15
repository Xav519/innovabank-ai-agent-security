# =============================================================================
# WHAT THIS FILE IS
# -----------------------------------------------------------------------------
# This is the "front door" for deploying the HARDENED version of InnovaBank,
# the copy of the banking agent with all 12 security controls switched on.
#
# It contains almost no real infrastructure itself. All the actual resources
# (Lambdas, DynamoDB tables, S3 bucket, KMS key, Guardrail, alarms) live in one
# shared module: infra/modules/stack. This file just says "build that module
# in hardened mode" and passes along a few optional settings.
#
# Why it is built this way: the vulnerable and hardened deployments must be
# identical except for their security controls. If each had its own copy of
# the infrastructure, they could drift apart and the comparison between them
# would no longer be fair. Keeping both thin and pointing at the same module
# guarantees the only difference is the "mode" value below.
#
# How to use it:
#   make deploy-hardened   runs terraform apply here, saves the outputs below
#                          to outputs.json, then seeds the demo data.
#   make destroy           tears it down again (live AWS costs money).
#
# Sibling file: infra/envs/vulnerable/main.tf is the same file with
# mode = "vulnerable". Keep the two in sync.
# =============================================================================

# InnovaBank, hardened posture. Deploy with: make deploy-hardened

# Pin Terraform and provider versions so every deploy (yours, CI, a reviewer's)
# behaves the same and a surprise provider upgrade cannot change the lab.
terraform {
  required_version = ">= 1.6.0"

  required_providers {
    # Creates all the AWS resources.
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
    # Needed because the module zips the app/ folder into the Lambda package.
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.6.0"
    }
  }
}

# Inputs you can set at deploy time (with -var or a .tfvars file).
# All have safe defaults, so a plain "make deploy-hardened" just works.

# The region matters because not every region offers the pinned Bedrock
# models; deploying elsewhere would fail when the agent first calls the model.
variable "region" {
  description = "AWS Region. Must offer the Bedrock models in supplychain/model-lock.yaml."
  type        = string
  default     = "us-east-1"
}

# Left empty, no email subscription is created (the alarms still exist).
# Set it if you want to actually be notified when a security alarm fires.
variable "alarm_email" {
  description = "Optional address for security alarm notifications."
  type        = string
  default     = ""
}

# Lets you switch off (or on) individual controls without editing code, for
# example "-taint_lock" to deploy hardened minus one control. This is how you
# measure live how much each control contributes. Empty means "all controls".
variable "controls_override" {
  description = "Optional control ablation, for example \"-taint_lock\"."
  type        = string
  default     = ""
}

provider "aws" {
  region = var.region

  # Every resource gets these tags automatically. They make it easy to find,
  # cost-track, and clean up lab resources, and to tell the two postures apart
  # when both are deployed in the same account.
  default_tags {
    tags = {
      Project = "innovabank"
      Posture = "hardened"
      Purpose = "ai-security-lab"
    }
  }
}

# The whole stack. "mode" is the single switch that makes this deployment
# hardened instead of vulnerable; everything else is shared code.
module "stack" {
  source = "../../modules/stack"

  mode              = "hardened"
  alarm_email       = var.alarm_email
  controls_override = var.controls_override
}

# Outputs: the names and IDs of what was just created.
# The Makefile saves these to infra/envs/hardened/outputs.json, and the test
# harness reads that file to find and attack the live stack (call the agent
# Lambda, check the transfers and outbox tables, sign KB documents, and so on).
# Removing or renaming one here will break the harness, so keep them aligned
# with infra/modules/stack/outputs.tf and the vulnerable env.
output "region" { value = module.stack.region }
output "mode" { value = module.stack.mode }
output "controls_override" { value = module.stack.controls_override }
output "model_id" { value = module.stack.model_id }
output "agent_function" { value = module.stack.agent_function }
output "ingest_function" { value = module.stack.ingest_function }
output "customers_table" { value = module.stack.customers_table }
output "transfers_table" { value = module.stack.transfers_table }
output "outbox_table" { value = module.stack.outbox_table }
output "kb_table" { value = module.stack.kb_table }
output "bucket" { value = module.stack.bucket }
output "signing_key_id" { value = module.stack.signing_key_id }
output "guardrail_id" { value = module.stack.guardrail_id }
output "alarm_topic_arn" { value = module.stack.alarm_topic_arn }
