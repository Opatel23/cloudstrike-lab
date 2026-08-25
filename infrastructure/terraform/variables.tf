variable "aws_region" {
  description = "AWS region for the isolated lab. Use a dedicated sandbox account."
  type        = string
  default     = "us-east-1"
}

variable "lab_owner" {
  description = "Owner tag used by every safety check and cleanup query."
  type        = string
  validation {
    condition     = length(trimspace(var.lab_owner)) > 2
    error_message = "lab_owner must identify the operator."
  }
}

variable "enable_vulnerable_policy" {
  description = "Explicitly enables the PassRole chain. false represents remediated state."
  type        = bool
  default     = false
}

variable "acknowledge_isolated_sandbox" {
  description = "Must be true: never deploy this lab into a production/shared AWS account."
  type        = bool
  default     = false
  validation {
    condition     = var.acknowledge_isolated_sandbox
    error_message = "Set acknowledge_isolated_sandbox=true only in a dedicated AWS sandbox account."
  }
}

