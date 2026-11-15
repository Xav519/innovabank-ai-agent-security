# =============================================================================
# WHAT THIS FILE IS
# =============================================================================
#
# This is the heart of the stack: it builds the actual things the banking
# agent runs on. The other files in this folder add to it (iam.tf gives
# permissions, guardrail.tf adds the Bedrock Guardrail, detections.tf adds
# alarms), but the data stores and the Lambda functions themselves live here.
#
# The same file builds BOTH postures (vulnerable and hardened). The only input
# that changes is `var.mode`. That is the point of the lab: one codebase, two
# security settings, so any difference in attack results comes from the
# controls and not from different infrastructure.
#
# What gets built, in plain steps:
#   1. Shared names and settings (the `locals` block), computed once so every
#      resource below uses the same names and the same tool list.
#   2. Storage:
#        - one S3 bucket for knowledge base documents,
#        - four DynamoDB tables (customers, transfers, outbox, kb),
#        - one KMS key used to sign and verify knowledge base documents.
#   3. Functions: seven Lambdas built from the same Python zip of `app/`:
#        - `agent`  runs the conversation with the model,
#        - `ingest` checks and indexes new knowledge base documents,
#        - one Lambda per tool (5 tools), so each tool can get its own
#          narrow IAM role in iam.tf.
#   4. Wiring: dropping a file into `kb/public/` in the bucket automatically
#      triggers the ingest function.
#
# Things to know:
#   - Everything holds fictional data and is destroyed after each demo, so
#     some production habits (backups, replication, VPC, X-Ray) are skipped on
#     purpose. Each skip is written next to the resource as a
#     `#checkov:skip=ID:reason` line, so the security scanner in CI still
#     fails on any NEW finding.
#   - The Python code reads its settings from the `IB_*` environment variables
#     defined below (see Config.from_env() in app/innovabank/config.py).
#
# =============================================================================

# Look up facts about the AWS account we are deploying into, so nothing
# (account id, region, partition) has to be hard coded.
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  # Prefix every resource with the posture name, so the vulnerable and the
  # hardened stack can live side by side in one account without clashing.
  name     = "${var.name_prefix}-${var.mode}"
  hardened = var.mode == "hardened"
  account  = data.aws_caller_identity.current.account_id
  region   = data.aws_region.current.name
  # "aws" in most regions, but different in GovCloud or China, so we read it.
  arn_base = "arn:${data.aws_partition.current.partition}"

  # The five tools the agent can call. Each becomes its own Lambda below.
  # Keeping them separate is what lets iam.tf give each tool only the
  # permissions it needs (for example only transfer_funds can write transfers).
  tools = [
    "search_knowledge_base",
    "read_document",
    "get_account_summary",
    "transfer_funds",
    "send_secure_message",
  ]

  # tool name -> function key, for example transfer_funds -> tool-transfer-funds
  # (Lambda names cannot contain underscores in a readable way, so we use dashes.)
  tool_keys = { for t in local.tools : t => "tool-${replace(t, "_", "-")}" }

  # Every Lambda to create, with its Python entry point and its size.
  # The agent gets the longest timeout and most memory because it waits on
  # several model calls in one turn. Tools are short, single actions.
  functions = merge(
    {
      agent  = { handler = "innovabank.handlers.agent_handler", timeout = 300, memory = 512 }
      ingest = { handler = "innovabank.handlers.ingest_handler", timeout = 60, memory = 256 }
    },
    { for t, k in local.tool_keys : k => { handler = "innovabank.handlers.tool_handler", timeout = 30, memory = 256 } }
  )

  # Names and ARNs are computed up front (instead of read from the Lambda
  # resources) so IAM policies can reference them without creating a
  # dependency loop between roles and functions.
  function_names = { for k, _ in local.functions : k => "${local.name}-${k}" }
  function_arns  = { for k, n in local.function_names : k => "${local.arn_base}:lambda:${local.region}:${local.account}:function:${n}" }

  # DynamoDB tables and their primary key. One simple key per table is
  # enough: the app only ever looks items up by id.
  tables = {
    customers = "customer_id"
    transfers = "transfer_id"
    outbox    = "message_id"
    kb        = "chunk_id"
  }

  # Settings handed to every Lambda as environment variables. This is how
  # the same Python code knows which posture it runs in and where its data
  # lives. Only names and ids go here, never secrets.
  # The Guardrail only exists in the hardened posture, so the vulnerable stack
  # passes empty strings and the app skips it. IB_TOOL_FUNCTIONS maps each
  # tool name to its Lambda name, so the agent knows which function to invoke
  # for each tool call the model makes.
  environment = {
    IB_MODE              = var.mode
    IB_CONTROLS          = var.controls_override
    IB_MODEL_ID          = var.model_id
    IB_EMBED_MODEL_ID    = var.embed_model_id
    IB_GUARDRAIL_ID      = local.hardened ? aws_bedrock_guardrail.this[0].guardrail_id : ""
    IB_GUARDRAIL_VERSION = local.hardened ? aws_bedrock_guardrail_version.this[0].version : ""
    IB_CUSTOMERS_TABLE   = aws_dynamodb_table.this["customers"].name
    IB_TRANSFERS_TABLE   = aws_dynamodb_table.this["transfers"].name
    IB_OUTBOX_TABLE      = aws_dynamodb_table.this["outbox"].name
    IB_KB_TABLE          = aws_dynamodb_table.this["kb"].name
    IB_BUCKET            = aws_s3_bucket.data.id
    IB_SIGNING_KEY_ID    = aws_kms_key.signing.key_id
    IB_TOOL_FUNCTIONS    = jsonencode({ for t, k in local.tool_keys : t => local.function_names[k] })
  }
}

# ----------------------------------------------------------------------------- storage

# The bucket that holds knowledge base documents, plus a quarantine area for
# documents that fail the ingest checks. It is the entry point for the
# "poisoned document" attacks, so it matters who can write here.
resource "aws_s3_bucket" "data" {
  # Lab trade-offs, both postures. The bucket holds synthetic data and is destroyed after each demo.
  #checkov:skip=CKV_AWS_18:Access logging needs a second bucket kept beyond teardown; CloudTrail data events cover audit if needed
  #checkov:skip=CKV_AWS_144:Cross-region replication doubles cost for synthetic, disposable data
  #checkov:skip=CKV2_AWS_61:No lifecycle rule; the stack is destroyed between demos (force_destroy)
  #checkov:skip=CKV_AWS_145:SSE-S3 (AES256) on purpose; integrity of the knowledge base comes from KMS signatures, not bucket encryption
  # bucket_prefix lets AWS add a random suffix, because bucket names must be
  # unique across all AWS accounts worldwide.
  bucket_prefix = "${local.name}-"
  force_destroy = true # lab stack, torn down between demos
}

# Never let the bucket become public, even by accident (a stray ACL or
# policy). Applied in both postures: the lab is about the AI agent, not
# about leaking data from a misconfigured bucket.
resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Encrypt every object at rest with the free S3 managed key. Trust in the
# documents comes from KMS signatures (below), not from this encryption.
resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Keep old versions of objects, so an overwritten (for example poisoned)
# document can still be inspected after an attack.
resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Refuse any request that is not over HTTPS, so data never travels in clear
# text.
resource "aws_s3_bucket_policy" "tls_only" {
  bucket = aws_s3_bucket.data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.data.arn, "${aws_s3_bucket.data.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })

  # Apply the public access block first, otherwise AWS can reject a bucket
  # policy while the public settings are still being changed.
  depends_on = [aws_s3_bucket_public_access_block.data]
}

# One table per entry in local.tables (customers, transfers, outbox, kb).
# The harness reads transfers and outbox after each attack to decide if
# money moved or a message leaked.
resource "aws_dynamodb_table" "this" {
  for_each = local.tables

  # Encrypted at rest with the AWS owned key. A customer managed key per table adds monthly cost
  # and key policy work with no gain for synthetic data. Point in time recovery is pointless for a
  # lab that seed.reset() restores to a known state before every attack.
  #checkov:skip=CKV_AWS_119:AWS owned key is enough for synthetic lab data; CMK adds cost and policy surface
  #checkov:skip=CKV_AWS_28:Tables are re-seeded before every case and destroyed after the demo; no backup value

  name = "${local.name}-${each.key}"
  # Pay per request: no cost when idle, which suits a lab used in bursts.
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = each.value

  attribute {
    name = each.value
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }
}

# Asymmetric key for knowledge base documents. Publishers hold kms:Sign.
# The ingestion function holds kms:Verify and nothing else on this key.
# Why: if an attacker can drop a file in the bucket but cannot sign it, the
# hardened ingest refuses to index it, so poisoned documents never reach the
# model. Splitting Sign and Verify means the ingest function, even if
# compromised, cannot sign its own fake documents.
resource "aws_kms_key" "signing" {
  # Default key policy (account root) on purpose: who may sign and verify is granted through IAM,
  # the ingestion role gets kms:Verify only (iam.tf), publishers get kms:Sign.
  #checkov:skip=CKV2_AWS_64:Default key policy delegates to IAM; Sign/Verify separation is enforced in iam.tf
  description              = "${local.name} knowledge base document signing"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"
  # Shortest allowed wait before deletion, so a destroyed lab cleans up fast.
  deletion_window_in_days = 7
}

# A readable name for the key, easier to find in the console than a raw id.
resource "aws_kms_alias" "signing" {
  name          = "alias/${local.name}-kb-signing"
  target_key_id = aws_kms_key.signing.key_id
}

# ----------------------------------------------------------------------------- functions

# Zip the whole app/ folder once. Every Lambda uses this same zip and only
# the handler differs, so the agent and the tools always run the same code
# version. The zip name includes the mode so the two postures do not
# overwrite each other's build.
data "archive_file" "app" {
  type        = "zip"
  source_dir  = "${path.module}/../../../app"
  output_path = "${path.module}/.build/app-${var.mode}.zip"
  excludes    = ["**/__pycache__/**"]
}

# Create each function's log group ourselves (instead of letting Lambda do
# it) so we control retention, and so detections.tf can attach security
# alarms to a log group that already exists.
resource "aws_cloudwatch_log_group" "fn" {
  for_each = local.functions

  #checkov:skip=CKV_AWS_338:Retention is var.log_retention_days; a one-year lab log adds cost with no benefit
  #checkov:skip=CKV_AWS_158:Logs hold security events and synthetic data only; service-managed encryption is used

  name              = "/aws/lambda/${local.function_names[each.key]}"
  retention_in_days = var.log_retention_days
}

# The seven Lambda functions (agent, ingest, five tools), one per entry in
# local.functions. Each one runs under its own IAM role from iam.tf.
resource "aws_lambda_function" "fn" {
  for_each = local.functions

  # Production items this lab does not need. No VPC: the functions only call AWS APIs and have no
  # private resources to reach. No DLQ: invocations are synchronous and tool calls are never retried
  # (a retried transfer would move money twice). No reserved concurrency: the tool call budget caps
  # fan-out per turn. Env vars hold resource names and model ids, never secrets.
  #checkov:skip=CKV_AWS_117:No private resources to reach; a VPC would add NAT cost for AWS API calls only
  #checkov:skip=CKV_AWS_116:Synchronous invocations, never retried; a DLQ would never receive anything
  #checkov:skip=CKV_AWS_115:Fan-out is capped by the per-turn tool call budget in the orchestrator
  #checkov:skip=CKV_AWS_173:Environment holds names and ids only, no secrets; default Lambda encryption applies
  #checkov:skip=CKV_AWS_50:X-Ray off to keep the lab cheap; every decision is logged as a structured security event
  #checkov:skip=CKV_AWS_272:Code signing needs a signing profile; the zip is built from this repository by Terraform

  function_name = local.function_names[each.key]
  role          = aws_iam_role.fn[each.key].arn
  runtime       = "python3.13"
  # arm64 (Graviton) is cheaper than x86 for the same work.
  architectures = ["arm64"]
  handler       = each.value.handler
  timeout       = each.value.timeout
  memory_size   = each.value.memory
  filename      = data.archive_file.app.output_path
  # Changes whenever the code changes, which tells Terraform to redeploy.
  source_code_hash = data.archive_file.app.output_base64sha256

  environment {
    variables = local.environment
  }

  # Log group first, so early logs are not lost to an auto-created group.
  # Role policy first, so the function never starts without its permissions.
  depends_on = [aws_cloudwatch_log_group.fn, aws_iam_role_policy.fn]
}

# New public documents are ingested as they land.
# This permission lets S3 (and only S3, from this bucket in this account)
# invoke the ingest function. The account check stops another account that
# owns a bucket with a similar name from triggering it.
resource "aws_lambda_permission" "s3_ingest" {
  statement_id   = "AllowS3Invoke"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.fn["ingest"].function_name
  principal      = "s3.amazonaws.com"
  source_arn     = aws_s3_bucket.data.arn
  source_account = local.account
}

# Call the ingest function every time a file is created under kb/public/.
# Only that folder is watched, so other files in the bucket (like
# quarantined documents) never trigger ingest again.
resource "aws_s3_bucket_notification" "ingest" {
  bucket = aws_s3_bucket.data.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.fn["ingest"].arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "kb/public/"
  }

  # S3 checks it may invoke the function when the notification is saved, so
  # the permission above must exist first.
  depends_on = [aws_lambda_permission.s3_ingest]
}
