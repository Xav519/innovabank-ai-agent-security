# =============================================================================
# WHAT THIS FILE IS
# =============================================================================
#
# This file turns on Bedrock "model invocation logging" for the whole AWS
# account in one Region. Once it is on, every call any app makes to a Bedrock
# model (the prompt sent and the answer that came back) is copied into a
# CloudWatch log group, so you can look back and see exactly what the model
# was asked and what it said.
#
# Why it matters for this lab: the agent's own security events show what our
# code decided. This log shows the raw conversation with the model, which is
# the ground truth when you want to check what an attack actually injected or
# what a leaked secret looked like on the wire.
#
# What it creates:
#   1. A log group that holds the prompts and answers.
#   2. An IAM role that Bedrock itself uses to write into that log group.
#   3. The account setting that switches logging on and points it at 1 and 2.
#   4. A saved CloudWatch Logs Insights query that shows who called which
#      model and how many tokens they used.
#
# Things to know:
#   - It is optional. The vulnerable and hardened stacks work without it.
#   - It is account-wide, so apply it once per Region, not once per stack.
#     Running it twice would just fight over the same single setting.
#   - Deploy with: make deploy-account
#   - Full prompts and answers are stored. Here that is fake data. In a real
#     account it would be customer data, so lock down who can read the logs.
#
# =============================================================================

# Pin Terraform and the AWS provider so every run uses the same behaviour.
# The Bedrock logging resource needs a fairly recent 5.x provider.
terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
  }
}

# The Region to turn logging on in. Bedrock logging is set per Region, so it
# must match the Region where the lab stacks call the model.
variable "region" {
  type    = string
  default = "us-east-1"
}

provider "aws" {
  region = var.region

  # Tag everything this file creates so it is easy to find, cost-track and
  # clean up alongside the rest of the lab.
  default_tags {
    tags = {
      Project = "innovabank"
      Purpose = "ai-security-lab"
    }
  }
}

# Look up the current account ID so the IAM trust policy below can be scoped to
# this account only, without hardcoding a number in the code.
data "aws_caller_identity" "current" {}

# Where the prompts and answers end up. Kept short (14 days) on purpose: the
# logs contain full conversations, so the less time they stick around, the
# smaller the exposure if someone gets read access.
resource "aws_cloudwatch_log_group" "invocations" {
  #checkov:skip=CKV_AWS_338:Optional lab logging, 14 days is enough to inspect a run; it holds prompts, so shorter is better
  #checkov:skip=CKV_AWS_158:Service-managed encryption; the log is removed with terraform destroy after the lab
  name              = "/innovabank/bedrock/model-invocations"
  retention_in_days = 14
}

# The role Bedrock takes on when it writes logs. Bedrock is a separate AWS
# service, so it needs its own identity with permission to write to our log
# group; it cannot borrow ours.
resource "aws_iam_role" "bedrock_logging" {
  name = "innovabank-bedrock-invocation-logging"

  # Trust policy: who is allowed to use this role. Only the Bedrock service,
  # and only when acting for this account in this Region. The two conditions
  # stop the "confused deputy" problem, where another account could trick
  # Bedrock into using our role to write into our logs.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "bedrock.amazonaws.com" }
      Condition = {
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        ArnLike      = { "aws:SourceArn" = "arn:aws:bedrock:${var.region}:${data.aws_caller_identity.current.account_id}:*" }
      }
    }]
  })
}

# What the role is allowed to do once Bedrock has it: create a log stream and
# write log lines, and nothing else. It is limited to the single stream name
# Bedrock uses, so even this role cannot touch other logs in the account.
resource "aws_iam_role_policy" "bedrock_logging" {
  name = "write-invocation-logs"
  role = aws_iam_role.bedrock_logging.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = ["${aws_cloudwatch_log_group.invocations.arn}:log-stream:aws/bedrock/modelinvocations"]
    }]
  })
}

# The actual on switch. There is only one of these per account per Region,
# which is why this lives here and not in the per-stack module.
resource "aws_bedrock_model_invocation_logging_configuration" "this" {
  logging_config {
    # Text is what we care about: prompts, tool calls and answers. Images and
    # embeddings are off because the agent does not use images, and embedding
    # vectors are large and tell a human reader nothing useful.
    text_data_delivery_enabled      = true
    image_data_delivery_enabled     = false
    embedding_data_delivery_enabled = false

    cloudwatch_config {
      log_group_name = aws_cloudwatch_log_group.invocations.name
      role_arn       = aws_iam_role.bedrock_logging.arn
    }
  }

  # Bedrock checks that it can write to the log group when logging is turned
  # on. Wait until the role has its permissions, otherwise that check can fail
  # on the first apply.
  depends_on = [aws_iam_role_policy.bedrock_logging]
}

# A ready-made query in the CloudWatch console, so nobody has to write one to
# answer the basic questions: who is calling the model, which model, how often,
# and how many tokens. A sudden spike for one caller is a quick sign of abuse
# or a runaway agent loop.
resource "aws_cloudwatch_query_definition" "invocations_by_identity" {
  name            = "InnovaBank/bedrock invocations by caller and model"
  log_group_names = [aws_cloudwatch_log_group.invocations.name]

  query_string = <<-EOT
    fields @timestamp, identity.arn, modelId, operation, input.inputTokenCount, output.outputTokenCount
    | stats count() as calls, sum(input.inputTokenCount) as input_tokens, sum(output.outputTokenCount) as output_tokens by identity.arn, modelId
    | sort calls desc
  EOT
}
