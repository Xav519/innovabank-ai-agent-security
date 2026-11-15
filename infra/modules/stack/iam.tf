# =============================================================================
# WHAT THIS FILE IS
# =============================================================================
#
# This file decides what each Lambda function is ALLOWED to do in AWS.
#
# In AWS, code can do nothing by default. Every Lambda runs as an "IAM role",
# and the role carries a list of permissions (a "policy") such as "may read
# this DynamoDB table" or "may call this Bedrock model". If an action is not
# on the list, AWS refuses it, no matter what the code or the AI model asks.
#
# Why this matters for an AI agent: the model can be tricked by a prompt
# injection into asking for things it should not. Our Python checks try to
# stop that, but IAM is the last wall. Even if every check in the app failed,
# a function can only touch what its role allows.
#
# What gets built, in plain steps:
#   1. One role per function (the agent, ingest, and each of the 5 tools).
#      Every function gets its own role in both postures, so one role being
#      misused never hands out another function's powers.
#   2. A small "logs" policy on every role, so each function can write to
#      its own CloudWatch log group (where security events end up).
#   3. The main policy, which is the part that differs between postures:
#        - hardened:   "least-privilege". Each function gets only the exact
#                      actions and resources its job needs (the `scoped` map).
#        - vulnerable: "broad-shared". Every function gets the same wide
#                      policy (the `broad` list), the common "one role for
#                      the whole app" shortcut that real teams take.
#
# Things to know:
#   - The broad policy is intentionally bad, so attacks can show what it
#     costs. Do not "fix" it here: it is part of the lab.
#   - Even the broad policy stays inside this lab's own tables, bucket, key
#     and functions. It is never account-wide, so a mistake here cannot reach
#     anything else in your AWS account.
#   - The function list comes from main.tf (`local.functions`), and the
#     guardrail referenced below is created in guardrail.tf.
#
# =============================================================================

# Short names for the ARNs (AWS resource addresses) used in the policies below,
# plus the two policy documents themselves: `scoped` and `broad`.
locals {
  # Table name -> table ARN, for example "customers" -> arn:aws:dynamodb:...
  table_arn = { for k, t in aws_dynamodb_table.this : k => t.arn }
  bucket    = aws_s3_bucket.data.arn

  # The chat model is called through an inference profile, which can route
  # the request to the underlying foundation model in another region. AWS
  # checks permission on both, so both are listed. The region is `*` on the
  # foundation model because the profile picks the region, not us.
  llm_arns = [
    "${local.arn_base}:bedrock:${local.region}:${local.account}:inference-profile/${var.model_id}",
    "${local.arn_base}:bedrock:*::foundation-model/${var.foundation_model_id}",
  ]
  # The embedding model (turns text into vectors for knowledge base search).
  embed_arn = "${local.arn_base}:bedrock:${local.region}::foundation-model/${var.embed_model_id}"

  # Listing the public prefix lets S3 answer "no such key" instead of "access denied"
  # for a missing public document. It grants no read on any other prefix.
  # Defined once here because two roles (ingest and read-document) need it.
  list_public = {
    Effect    = "Allow"
    Action    = ["s3:ListBucket"]
    Resource  = [local.bucket]
    Condition = { StringLike = { "s3:prefix" = ["kb/public/*"] } }
  }

  # ---------------------------------------------------------------------------
  # HARDENED: one tailored permission list per function.
  # Each key matches a function name from main.tf. Read each block as
  # "this function may do exactly this, and nothing else".
  # ---------------------------------------------------------------------------
  scoped = {
    # The agent is the orchestrator: it talks to the chat model, calls the
    # tool Lambdas, and reads the customer record to know who it is serving.
    # It has NO direct access to money, messages or documents. To move money
    # it must go through the transfer tool, which is where the policy checks
    # in the app run.
    agent = concat(
      [
        { Effect = "Allow", Action = ["bedrock:InvokeModel"], Resource = local.llm_arns },
        # Only the 5 tool functions, not ingest and not itself.
        { Effect = "Allow", Action = ["lambda:InvokeFunction"], Resource = [for t, k in local.tool_keys : local.function_arns[k]] },
        { Effect = "Allow", Action = ["dynamodb:GetItem"], Resource = [local.table_arn["customers"]] },
      ],
      # The guardrail only exists in the hardened stack, so permission to call
      # it is only added there. Pointing at a missing resource would fail.
      local.hardened ? [
        { Effect = "Allow", Action = ["bedrock:ApplyGuardrail"], Resource = [aws_bedrock_guardrail.this[0].guardrail_arn] },
      ] : []
    )

    # Ingest checks new knowledge base documents. A clean, signed document
    # is embedded and indexed; anything else is moved to quarantine/ (copied
    # there, then deleted from kb/public/). It may only VERIFY signatures,
    # never create them, so a hijacked ingest cannot sign a poisoned document.
    ingest = [
      { Effect = "Allow", Action = ["s3:GetObject", "s3:DeleteObject"], Resource = ["${local.bucket}/kb/public/*"] },
      { Effect = "Allow", Action = ["s3:PutObject"], Resource = ["${local.bucket}/quarantine/*"] },
      local.list_public,
      { Effect = "Allow", Action = ["kms:Verify"], Resource = [aws_kms_key.signing.arn] },
      { Effect = "Allow", Action = ["dynamodb:Scan", "dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:BatchWriteItem"], Resource = [local.table_arn["kb"]] },
      { Effect = "Allow", Action = ["bedrock:InvokeModel"], Resource = [local.embed_arn] },
    ]

    # Search reads the knowledge base index and embeds the query. Read only:
    # it cannot add or change entries in the index.
    "tool-search-knowledge-base" = [
      { Effect = "Allow", Action = ["dynamodb:Scan"], Resource = [local.table_arn["kb"]] },
      { Effect = "Allow", Action = ["bedrock:InvokeModel"], Resource = [local.embed_arn] },
    ]

    # The internal/ prefix lives in the same bucket. This role cannot read it,
    # whatever key the model asks for.
    "tool-read-document" = [
      { Effect = "Allow", Action = ["s3:GetObject"], Resource = ["${local.bucket}/kb/public/*"] },
      local.list_public,
    ]

    # Read one customer record. Which customer is allowed is enforced in the
    # app (ownership binding); IAM limits it to reading, never writing.
    "tool-get-account-summary" = [
      { Effect = "Allow", Action = ["dynamodb:GetItem"], Resource = [local.table_arn["customers"]] },
    ]

    # The debit and the transfer record are one DynamoDB transaction
    # (TransactWriteItems). It has no IAM action of its own: each item is
    # authorised as UpdateItem on customers and PutItem on transfers.
    # PutItem (add a new record) rather than UpdateItem on transfers means it
    # can record new transfers but cannot rewrite past ones.
    "tool-transfer-funds" = [
      { Effect = "Allow", Action = ["dynamodb:GetItem", "dynamodb:UpdateItem"], Resource = [local.table_arn["customers"]] },
      { Effect = "Allow", Action = ["dynamodb:PutItem"], Resource = [local.table_arn["transfers"]] },
    ]

    # Sending a message only drops it in the outbox table. It cannot read
    # customer data, so a hijacked call has nothing extra to leak.
    "tool-send-secure-message" = [
      { Effect = "Allow", Action = ["dynamodb:PutItem"], Resource = [local.table_arn["outbox"]] },
    ]
  }

  # ---------------------------------------------------------------------------
  # VULNERABLE: one wide permission list shared by every function.
  # This is the "just make it work" policy. Any function, including a tool
  # the model was tricked into calling, can read or change every table, read
  # internal/ documents, SIGN documents with the KMS key (so it could make a
  # poisoned document look trusted), call any of the lab's Lambdas, and call
  # any Bedrock model. Still limited to this lab's own resources.
  # ---------------------------------------------------------------------------
  broad = [
    { Effect = "Allow", Action = ["dynamodb:*"], Resource = values(local.table_arn) },
    { Effect = "Allow", Action = ["s3:*"], Resource = [local.bucket, "${local.bucket}/*"] },
    { Effect = "Allow", Action = ["kms:Sign", "kms:Verify", "kms:GetPublicKey"], Resource = [aws_kms_key.signing.arn] },
    # Every function whose name starts with this stack's prefix.
    { Effect = "Allow", Action = ["lambda:InvokeFunction"], Resource = ["${local.arn_base}:lambda:${local.region}:${local.account}:function:${local.name}-*"] },
    { Effect = "Allow", Action = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"], Resource = ["*"] },
  ]
}

# One role per function. The "trust policy" (assume_role_policy) says who may
# wear this role: only the Lambda service. No user or other service can step
# into it and borrow its permissions.
resource "aws_iam_role" "fn" {
  for_each = local.functions

  name = "${local.function_names[each.key]}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

# Logging permission, the same in both postures. Kept as a separate policy so
# security events always reach CloudWatch (and its alarms) whatever the main
# policy is. Each function can only write to its own log group, so one
# function cannot fake or flood another function's logs.
resource "aws_iam_role_policy" "logs" {
  for_each = local.functions

  name = "logs"
  role = aws_iam_role.fn[each.key].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = ["${aws_cloudwatch_log_group.fn[each.key].arn}:*"]
    }]
  })
}

# The main policy: this is where the two postures differ. Hardened attaches
# the function's own entry from `scoped`; vulnerable attaches the shared
# `broad` list to everyone. The policy name says which one you are looking at
# in the AWS console.
resource "aws_iam_role_policy" "fn" {
  for_each = local.functions

  name = local.hardened ? "least-privilege" : "broad-shared"
  role = aws_iam_role.fn[each.key].id

  policy = local.hardened ? jsonencode({
    Version   = "2012-10-17"
    Statement = local.scoped[each.key]
    }) : jsonencode({
    Version   = "2012-10-17"
    Statement = local.broad
  })
}
