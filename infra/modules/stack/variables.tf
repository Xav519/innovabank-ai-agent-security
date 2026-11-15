# =============================================================================
# WHAT THIS FILE IS
# =============================================================================
#
# The stack's "settings knobs". Each env (vulnerable, hardened) uses the same
# module and only changes these values.
#
# Why it matters:
#   - One module, two postures: only `mode` really differs between them.
#   - Defaults keep env files tiny and both stacks consistent.
#
# =============================================================================

# Picks the posture. Validated so a typo can't deploy an unknown setup.
variable "mode" {
  description = "Security posture of this stack: vulnerable or hardened."
  type        = string

  validation {
    condition     = contains(["vulnerable", "hardened"], var.mode)
    error_message = "mode must be vulnerable or hardened."
  }
}

# Keeps resource names unique and easy to spot in the AWS console.
variable "name_prefix" {
  description = "Prefix for every resource name."
  type        = string
  default     = "innovabank"
}

# Turns single controls on or off to measure what each one is worth.
variable "controls_override" {
  description = "Optional control ablation, for example \"-taint_lock,-tool_policy\". Empty uses the preset for the mode."
  type        = string
  default     = ""
}

# The chat model. Pinned in the model lock so it can't change silently.
variable "model_id" {
  description = "Bedrock inference profile or model id the agent calls. Must be listed in supplychain/model-lock.yaml."
  type        = string
  default     = "us.amazon.nova-lite-v1:0"
}

# The real model under the profile, so IAM allows only this one.
variable "foundation_model_id" {
  description = "Foundation model behind model_id, used to scope IAM."
  type        = string
  default     = "amazon.nova-lite-v1:0"
}

# Turns knowledge base text into vectors for search.
variable "embed_model_id" {
  description = "Bedrock embedding model for the knowledge base."
  type        = string
  default     = "amazon.titan-embed-text-v2:0"
}

# Optional, so alarms can email someone. Empty means no email.
variable "alarm_email" {
  description = "Optional address subscribed to the security alarm topic."
  type        = string
  default     = ""
}

# Keeps logs long enough to investigate, short enough to stay cheap.
variable "log_retention_days" {
  description = "CloudWatch Logs retention for the stack's functions."
  type        = number
  default     = 14
}
