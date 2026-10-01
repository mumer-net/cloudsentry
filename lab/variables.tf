variable "region" {
  type    = string
  default = "us-east-1"
}

variable "az" {
  description = "Availability zone for every subnet. Pick one that offers t4g.micro."
  type        = string
  default     = "us-east-1a"
}

variable "faults" {
  description = "false builds a CIS-clean lab; true adds the seeded misconfigurations"
  type        = bool
  default     = false
}

variable "ami_id" {
  description = "Leave null to use the latest Amazon Linux 2023 arm64 AMI"
  type        = string
  default     = null
}

variable "offline" {
  description = "Plan without AWS credentials, the way CI does"
  type        = bool
  default     = false
}
