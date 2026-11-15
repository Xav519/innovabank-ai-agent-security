# =============================================================================
# WHAT THIS FILE IS
# =============================================================================
#
# This file is the "alarm system" of the stack. It watches the agent's logs
# for security events and raises an alarm (and optionally sends an email)
# when it sees them.
#
# How it works, in plain steps:
#   1. Every time the app's security code makes a decision (for example "this
#      looks like a prompt injection" or "this transfer is not allowed"), it
#      writes one JSON log line with a field called `ib_event` naming what
#      happened.
#   2. For each event name, a CloudWatch "metric filter" counts how many of
#      those log lines appear.
#   3. For each count, a CloudWatch "alarm" fires when it goes over a limit
#      within 5 minutes.
#   4. The alarm sends a message to an SNS topic, which can email a person.
#   5. Two saved Logs Insights queries help that person dig into what
#      happened afterwards.
#
# Why it matters: blocking an attack is only half the job. Someone also needs
# to know it happened. Each alarm's description already says which MITRE
# ATLAS technique and OWASP LLM category it matches, so whoever gets paged
# does not have to look that up.
#
# Things to know:
#   - The checks run in both postures. In the vulnerable stack they log
#     action="observed" (nothing is stopped). In the hardened stack they log
#     action="blocked". The alarms fire either way, so you can see attacks
#     even on the stack that lets them through.
#   - The `detections` table below must match EVENTS in
#     app/innovabank/seclog.py. The test
#     test_terraform_detections_match_application_events reads this file and
#     fails if they drift apart. Adding a new event means updating both
#     places, plus docs/controls.md.
#   - That test parses each table row with a regex, so keep every row on one
#     line in the same `name = { atlas = ..., technique = ..., owasp = ... }`
#     shape.
#
# =============================================================================

locals {
  # One entry per security event the app can emit. Each field means:
  #   atlas     : MITRE ATLAS technique ID, so responders can look up the attack.
  #   technique : human readable name of that technique.
  #   owasp     : OWASP Top 10 for LLM Applications category.
  #   source    : which Lambda writes the event ("agent" handles chats,
  #               "ingest" handles knowledge base uploads). This picks the
  #               log group to watch.
  #   threshold : how many events in 5 minutes before the alarm fires.
  #
  # Why thresholds differ: events that a real customer could trigger by
  # accident (an odd phrase that looks like injection, a denied tool call, a
  # long conversation) get a higher threshold so one honest mistake does not
  # page anyone. Events that should basically never happen to an honest user
  # (a leaked system prompt, an exfiltration attempt, a poisoned document)
  # fire on the first one.
  detections = {
    prompt_injection           = { atlas = "AML.T0051.000", technique = "LLM Prompt Injection: Direct", owasp = "LLM01", source = "agent", threshold = 3 }
    prompt_obfuscation         = { atlas = "AML.T0068", technique = "LLM Prompt Obfuscation", owasp = "LLM01", source = "agent", threshold = 1 }
    indirect_injection         = { atlas = "AML.T0051.001", technique = "LLM Prompt Injection: Indirect", owasp = "LLM01", source = "agent", threshold = 1 }
    rag_document_rejected      = { atlas = "AML.T0070", technique = "RAG Poisoning", owasp = "LLM04", source = "ingest", threshold = 1 }
    tool_call_denied           = { atlas = "AML.T0053", technique = "AI Agent Tool Invocation", owasp = "LLM06", source = "agent", threshold = 3 }
    exfiltration_attempt       = { atlas = "AML.T0086", technique = "Exfiltration via AI Agent Tool Invocation", owasp = "LLM06", source = "agent", threshold = 1 }
    system_prompt_leak         = { atlas = "AML.T0056", technique = "Extract LLM System Prompt", owasp = "LLM07", source = "agent", threshold = 1 }
    sensitive_data_in_output   = { atlas = "AML.T0057", technique = "LLM Data Leakage", owasp = "LLM02", source = "agent", threshold = 1 }
    unsafe_output_rendering    = { atlas = "AML.T0077", technique = "LLM Response Rendering", owasp = "LLM05", source = "agent", threshold = 1 }
    poisoned_content_in_output = { atlas = "AML.T0070", technique = "RAG Poisoning", owasp = "LLM04", source = "agent", threshold = 1 }
    resource_budget_exceeded   = { atlas = "AML.T0029", technique = "Denial of AI Service", owasp = "LLM10", source = "agent", threshold = 5 }
    guardrail_intervened       = { atlas = "AML.T0054", technique = "LLM Jailbreak", owasp = "LLM01", source = "agent", threshold = 3 }
    tool_access_denied         = { atlas = "AML.T0053", technique = "AI Agent Tool Invocation", owasp = "LLM06", source = "agent", threshold = 1 }
  }

  # Separate namespace per posture so the vulnerable and hardened stacks can
  # live in the same account without their metrics mixing together.
  metric_namespace = "InnovaBank/${var.mode}"
}

# Step 2: turn matching log lines into numbers.
# One filter per event. It watches the right Lambda's log group and adds 1 to
# a metric every time a log line has that exact `ib_event` value. Alarms can
# only watch metrics, not raw logs, which is why this step exists.
resource "aws_cloudwatch_log_metric_filter" "detection" {
  for_each = local.detections

  name           = "${local.name}-${each.key}"
  log_group_name = aws_cloudwatch_log_group.fn[each.value.source].name
  # JSON match on the structured field, not a text search, so a customer
  # typing the word "prompt_injection" in a chat cannot trigger it.
  pattern = "{ $.ib_event = \"${each.key}\" }"

  metric_transformation {
    name      = each.key
    namespace = local.metric_namespace
    value     = "1"
    # Report 0 when nothing matched, so graphs show a flat line instead of
    # gaps and it is obvious the metric is alive.
    default_value = "0"
  }
}

# Step 4: where alarms send their notifications.
resource "aws_sns_topic" "security" {
  #checkov:skip=CKV_AWS_26:CloudWatch alarms cannot publish to a topic encrypted with the AWS managed key (see below)
  # Not encrypted with alias/aws/sns on purpose: CloudWatch alarms cannot publish
  # to a topic that uses the AWS managed key. Alarm text holds no customer data.
  name = "${local.name}-security-alarms"
}

# Optional email subscription. Only created when alarm_email is set, so the
# stack still deploys cleanly for people who just want to look at the
# alarms in the console. AWS sends a confirmation email that must be clicked
# before messages start arriving.
resource "aws_sns_topic_subscription" "email" {
  count = var.alarm_email == "" ? 0 : 1

  topic_arn = aws_sns_topic.security.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

# Step 3: one alarm per event.
resource "aws_cloudwatch_metric_alarm" "detection" {
  for_each = local.detections

  alarm_name = "${local.name}-${each.key}"
  # The description travels with the alarm email, so it carries the full
  # threat mapping and the posture. The responder knows right away what kind
  # of attack it is and whether it hit the vulnerable or hardened stack.
  alarm_description = "MITRE ATLAS ${each.value.atlas} ${each.value.technique} | OWASP ${each.value.owasp} | posture ${var.mode} | event ${each.key}"
  namespace         = local.metric_namespace
  metric_name       = each.key
  # Add up all events in each 5 minute window and compare to the threshold.
  # A single window is enough to fire, so attacks are reported fast.
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = each.value.threshold
  comparison_operator = "GreaterThanOrEqualToThreshold"
  # No data means no attacks, so treat it as "OK" rather than as an unknown
  # state that would leave alarms stuck in INSUFFICIENT_DATA.
  treat_missing_data = "notBreaching"
  alarm_actions      = [aws_sns_topic.security.arn]

  # Tags let you filter alarms by technique or category in the console or
  # with the CLI, for example "show me every LLM01 alarm".
  tags = {
    "mitre-atlas" = each.value.atlas
    "owasp-llm"   = each.value.owasp
  }

  # The metric only exists once its filter does. Waiting avoids creating an
  # alarm that points at a metric that is not wired up yet.
  depends_on = [aws_cloudwatch_log_metric_filter.detection]
}

# Step 5a: saved query for the big picture.
# Counts every security event across the agent and ingest logs, grouped by
# technique, control and action. Useful to answer "what is being thrown at
# us, and is it being blocked or just observed?"
resource "aws_cloudwatch_query_definition" "by_technique" {
  name = "InnovaBank/${var.mode}/security events by ATLAS technique"

  log_group_names = [
    aws_cloudwatch_log_group.fn["agent"].name,
    aws_cloudwatch_log_group.fn["ingest"].name,
  ]

  query_string = <<-EOT
    fields @timestamp, ib_event, atlas_technique, owasp, control, action, customer_id, detail
    | filter ispresent(ib_event)
    | stats count() as events by atlas_technique, atlas_name, owasp, control, action
    | sort events desc
  EOT
}

# Step 5b: saved query for the close-up view.
# Lists security events in time order with their request_id, so after an
# alarm you can follow one attack step by step (input flagged, tool denied,
# output filtered, and so on). Capped at 200 rows to keep it readable.
resource "aws_cloudwatch_query_definition" "timeline" {
  name = "InnovaBank/${var.mode}/attack timeline for one request"

  log_group_names = [aws_cloudwatch_log_group.fn["agent"].name]

  query_string = <<-EOT
    fields @timestamp, request_id, ib_event, atlas_technique, control, action, detail
    | filter ispresent(ib_event)
    | sort @timestamp asc
    | limit 200
  EOT
}
