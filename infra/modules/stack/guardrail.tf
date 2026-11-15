# =============================================================================
# WHAT THIS FILE IS
# =============================================================================
#
# This file creates an Amazon Bedrock Guardrail: a managed AWS safety filter
# that reads a piece of text and says "this is fine" or "block this".
#
# Think of it as a second pair of eyes. The app already has its own security
# checks written in Python (app/innovabank/guards.py and policy.py). The
# guardrail is an extra, independent layer run by AWS, so an attack that
# slips past our own code still has to get past this one too.
#
# How it is used, in plain steps:
#   1. Terraform creates the guardrail (the rules) and a frozen, numbered
#      version of it.
#   2. main.tf passes the guardrail ID and version to the Lambdas through
#      the IB_GUARDRAIL_ID and IB_GUARDRAIL_VERSION environment variables.
#   3. The agent (app/innovabank/agent.py) calls the ApplyGuardrail API at
#      three points:
#        - on the customer's message, before the model sees it,
#        - on documents pulled from the knowledge base, before the model
#          reads them (they could contain hidden instructions),
#        - on the final answer, before the customer sees it.
#
# What the rules catch:
#   - Prompt attacks (jailbreaks and "ignore your instructions" tricks).
#   - Misconduct (requests for help with crime or fraud).
#   - Sensitive data: SIN numbers, card numbers, AWS keys, our internal API
#     key format, and the leak canary hidden in the system prompt.
#   - Investment advice, which a bank assistant must not give.
#
# Things to know:
#   - It only exists in the hardened stack. The vulnerable stack has no
#     guardrail on purpose, so you can compare the two.
#   - The app enforces it only when the `guardrail` control is on (see
#     app/innovabank/config.py). Offline runs and tests never call it.
#   - IAM access to call it is granted in iam.tf, and when it intervenes
#     the app logs a `guardrail_intervened` event that detections.tf alarms on.
#   - Each ApplyGuardrail call costs money, which is why the app skips it
#     when its own checks have already blocked the text.
#
# =============================================================================

# The guardrail itself: the list of rules AWS will apply to text.
resource "aws_bedrock_guardrail" "this" {
  # count = 1 builds it, count = 0 skips it. Only the hardened posture gets a
  # guardrail, so the vulnerable stack shows what happens without one.
  count = local.hardened ? 1 : 0

  name        = local.name
  description = "InnovaBank hardened assistant: prompt attack, sensitive data and topic policy"

  # What the customer sees instead of the blocked text. Kept short and
  # generic on purpose: telling an attacker which rule fired helps them
  # tweak the attack until it passes.
  blocked_input_messaging   = "I can't help with that request."
  blocked_outputs_messaging = "I can't share that information."

  # Built-in AWS content filters. "input" applies to text going into the
  # model, "output" to text coming out of it.
  content_policy_config {
    # Prompt attacks are things a user (or a poisoned document) types to
    # hijack the model, like "ignore all previous instructions". They only
    # make sense on the way in, and AWS does not support this filter on
    # outputs, so output is NONE.
    filters_config {
      type            = "PROMPT_ATTACK"
      input_strength  = "HIGH"
      output_strength = "NONE"
    }
    # Misconduct means help with crime, fraud or similar. Checked in both
    # directions: we neither want to accept such a request nor let the model
    # produce such content if it is tricked into it.
    filters_config {
      type            = "MISCONDUCT"
      input_strength  = "HIGH"
      output_strength = "HIGH"
    }
  }

  # Sensitive data that must never leave the assistant. BLOCK stops the whole
  # message rather than masking parts of it, because for a bank a partial
  # leak is still a leak.
  sensitive_information_policy_config {
    # Canadian Social Insurance Number, the most sensitive customer ID here.
    pii_entities_config {
      type   = "CA_SOCIAL_INSURANCE_NUMBER"
      action = "BLOCK"
    }
    # Card numbers, which could be used for fraud.
    pii_entities_config {
      type   = "CREDIT_DEBIT_CARD_NUMBER"
      action = "BLOCK"
    }
    # AWS secret keys, in case the model was tricked into revealing one.
    pii_entities_config {
      type   = "AWS_SECRET_KEY"
      action = "BLOCK"
    }
    # AWS cannot know our own secret formats, so we describe them with
    # regular expressions. This matches InnovaBank internal API keys such as
    # "ibk_live_..." (the vulnerable stack deliberately puts one in the
    # system prompt). The same pattern is checked in app/innovabank/guards.py.
    regexes_config {
      name        = "internal-api-key"
      description = "InnovaBank internal API key format"
      pattern     = "ibk_(live|test)_[A-Za-z0-9]{12,}"
      action      = "BLOCK"
    }
    # A canary is a unique made-up marker hidden in the system prompt. It
    # has no meaning, so if it ever shows up in an answer we know for sure
    # the prompt is leaking, and this rule stops it from reaching the user.
    regexes_config {
      name        = "prompt-leak-canary"
      description = "Canary embedded in the system prompt to make leaks detectable"
      pattern     = "IB-LEAK-CANARY-[A-Z0-9]+"
      action      = "BLOCK"
    }
  }

  # Topics the assistant must refuse even if the request is harmless.
  topic_policy_config {
    # A bank chatbot giving stock tips is a regulatory and liability risk, so
    # this subject is off limits. AWS uses the definition and the examples
    # to recognise the topic, so they are written in plain customer language.
    topics_config {
      name       = "investment-advice"
      type       = "DENY"
      definition = "Recommendations to buy, sell or hold specific stocks, funds, cryptocurrencies or other investments."
      examples = [
        "Which stock should I buy this week?",
        "Should I move my savings into crypto?",
      ]
    }
  }
}

# A frozen, numbered snapshot of the rules above. The app calls this fixed
# version instead of the editable draft, so a change to the rules only takes
# effect when Terraform publishes a new version, and the version number tells
# you exactly which rules were active during a test run.
resource "aws_bedrock_guardrail_version" "this" {
  count = local.hardened ? 1 : 0

  guardrail_arn = aws_bedrock_guardrail.this[0].guardrail_arn
  description   = "Managed by Terraform"
}
