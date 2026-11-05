# Read-only drift check of Prego grants in tenant `acme`, with the OpenTofu `http` provider.
#
# It reads the grants with an admin token (scope admin:read) and warns in `tofu plan` when a wanted grant is
# missing. It changes nothing. To create or delete grants from CI, use examples/admin/ansible/grants.yml.
#
# In CI (protected ref only):
#   PREGO_ADMIN_SCOPE="admin:read" PREGO_TENANT=acme
#   TF_VAR_admin_token="$(sh examples/admin/prego-admin-token.sh)"
#   export TF_VAR_admin_token
#   tofu plan
#
# The token is a sensitive variable, so OpenTofu does not print it. It is valid for 15 minutes.

terraform {
  required_version = ">= 1.6"
  required_providers {
    http = {
      source  = "hashicorp/http"
      version = "~> 3.4"
    }
  }
}

variable "tenant" {
  description = "Prego tenant slug."
  type        = string
  default     = "acme"
}

variable "admin_token" {
  description = "Prego admin token with scope admin:read. Set it with TF_VAR_admin_token."
  type        = string
  sensitive   = true
}

variable "wanted_grants" {
  description = "Grants that must exist. Each key is namespace|package_glob|actions (sorted, comma-separated)."
  type        = set(string)
  default = [
    "default|core-*|read",
    "releases|*|read",
  ]
}

data "http" "grants" {
  url = "https://sts.prego.k8skill.com/v1/admin/tenants/${var.tenant}/grants"
  request_headers = {
    Accept        = "application/json"
    Authorization = "Bearer ${var.admin_token}"
  }

  lifecycle {
    postcondition {
      condition     = self.status_code == 200
      error_message = "The Prego admin API returned HTTP ${self.status_code}. Check the admin token and its scope."
    }
  }
}

locals {
  grants = jsondecode(data.http.grants.response_body).items
  current_keys = toset([
    for g in local.grants : "${g.namespace}|${g.package_glob}|${join(",", sort(g.actions))}"
  ])
  missing = setsubtract(var.wanted_grants, local.current_keys)
}

check "wanted_grants_exist" {
  assert {
    condition     = length(local.missing) == 0
    error_message = "Missing Prego grants: ${join(", ", sort(local.missing))}"
  }
}

output "grants" {
  description = "Current grants (no secrets)."
  value = [
    for g in local.grants : {
      id           = g.id
      namespace    = g.namespace
      package_glob = g.package_glob
      actions      = g.actions
      grantee      = g.grantee
      expires_at   = g.expires_at
    }
  ]
}
