# =============================================================================
# WHAT THIS FILE IS
# =============================================================================
#
# The stack's "address book". After a deploy, these values tell other tools
# where everything lives (function names, table names, keys, and so on).
#
# Why it matters:
#   - Each env (vulnerable, hardened) passes these through and writes them
#     to infra/envs/<mode>/outputs.json.
#   - The seed script, `make ask` and the live attack harness read that file,
#     so they never need hard-coded resource names.
#
# =============================================================================

# Where the stack runs, so clients call the right AWS region.
output "region" {
  value = local.region
}

# Which posture was deployed, so reports label results correctly.
output "mode" {
  value = var.mode
}

# Any custom control set, so a run can be traced back to its exact config.
output "controls_override" {
  value = var.controls_override
}

# The pinned Bedrock model, recorded alongside the results.
output "model_id" {
  value = var.model_id
}

# The chat entry point the harness invokes.
output "agent_function" {
  value = aws_lambda_function.fn["agent"].function_name
}

# The function that checks and indexes knowledge base documents.
output "ingest_function" {
  value = aws_lambda_function.fn["ingest"].function_name
}

# Tables below are seeded with fake data and read to judge attack success.
output "customers_table" {
  value = aws_dynamodb_table.this["customers"].name
}

# Checked for unwanted transfers.
output "transfers_table" {
  value = aws_dynamodb_table.this["transfers"].name
}

# Checked for leaked outgoing messages.
output "outbox_table" {
  value = aws_dynamodb_table.this["outbox"].name
}

# Knowledge base index.
output "kb_table" {
  value = aws_dynamodb_table.this["kb"].name
}

# Holds documents uploaded for ingest.
output "bucket" {
  value = aws_s3_bucket.data.id
}

# Used to sign KB documents so ingest can verify them.
output "signing_key_id" {
  value = aws_kms_key.signing.key_id
}

# Empty in vulnerable mode, since only hardened creates a Guardrail.
output "guardrail_id" {
  value = local.hardened ? aws_bedrock_guardrail.this[0].guardrail_id : ""
}

# Where security alarms are sent, so you can subscribe to them.
output "alarm_topic_arn" {
  value = aws_sns_topic.security.arn
}
