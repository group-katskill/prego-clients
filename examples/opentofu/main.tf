# Consumer side only: install cargo-credential-prego on this machine and write the Cargo registry config.
# Use it when you build a CI runner image or a developer VM with OpenTofu.
#
# This example changes nothing in your Prego tenant. To manage trust configs, principals and grants as code,
# see examples/admin/.

terraform {
  required_version = ">= 1.6"
  required_providers {
    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
    }
  }
}

variable "tenant" {
  description = "Prego tenant slug."
  type        = string
  default     = "acme"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,38}[a-z0-9]$", var.tenant))
    error_message = "The tenant slug must match ^[a-z][a-z0-9-]{1,38}[a-z0-9]$."
  }
}

variable "namespace" {
  description = "Prego namespace slug."
  type        = string
  default     = "default"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,38}[a-z0-9]$", var.namespace))
    error_message = "The namespace slug must match ^[a-z][a-z0-9-]{1,38}[a-z0-9]$."
  }
}

variable "edge_code" {
  description = "Edge code of the tenant (4 characters, not a secret). The Prego console shows it. Needed from 0.6.0."
  type        = string
  default     = "k7mq"
  validation {
    condition     = can(regex("^[a-hjkmnop-z2-9]{4}$", var.edge_code))
    error_message = "The edge code has 4 characters from a-z and 2-9, without i, l, 0 and 1."
  }
}

variable "provider_version" {
  description = "cargo-credential-prego release to install."
  type        = string
  default     = "0.6.0"
}

variable "target" {
  description = "Release target triple."
  type        = string
  default     = "x86_64-unknown-linux-musl"
  validation {
    condition = contains([
      "x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl", "aarch64-apple-darwin",
    ], var.target)
    error_message = "Use one of the three release targets."
  }
}

variable "cargo_home" {
  description = "Cargo home directory. The binary goes in <cargo_home>/bin, the config in <cargo_home>/config.toml."
  type        = string
  default     = "~/.cargo"
}

locals {
  cargo_home = pathexpand(var.cargo_home)
  base_url   = "https://github.com/group-katskill/prego-clients/releases/download/prego-clients-v${var.provider_version}"
  archive    = "cargo-credential-prego-${var.target}.tar.gz"
}

# Download, check the SHA-256 sum, and install. Runs again when the version or target changes.
resource "terraform_data" "install_provider" {
  triggers_replace = [var.provider_version, var.target, local.cargo_home]

  provisioner "local-exec" {
    interpreter = ["/bin/sh", "-c"]
    environment = {
      BASE_URL   = local.base_url
      ARCHIVE    = local.archive
      CARGO_HOME = local.cargo_home
    }
    command = <<-EOT
      set -eu
      work="$(mktemp -d)"
      trap 'rm -rf "$work"' EXIT
      cd "$work"
      curl -fsSLO "$BASE_URL/$ARCHIVE"
      curl -fsSLO "$BASE_URL/$ARCHIVE.sha256"
      if command -v sha256sum >/dev/null; then sha256sum -c "$ARCHIVE.sha256"; else shasum -a 256 -c "$ARCHIVE.sha256"; fi
      tar -xzf "$ARCHIVE" cargo-credential-prego
      mkdir -p "$CARGO_HOME/bin"
      install -m 0755 cargo-credential-prego "$CARGO_HOME/bin/cargo-credential-prego"
    EOT
  }
}

# The registry config. It holds no secret. The identity comes from the environment at build time
# (CI OIDC token, SPIFFE, token file, or PREGO_API_KEY on a laptop).
#
# Note: this file replaces <cargo_home>/config.toml. If you keep other settings there, merge them into
# the content below, or point cargo_home at a dedicated directory.
resource "local_file" "cargo_config" {
  filename        = "${local.cargo_home}/config.toml"
  file_permission = "0644"
  content         = <<-EOT
    [registries.${var.tenant}]
    index = "sparse+https://cargo.prego.k8skill.com/t/${var.tenant}/${var.namespace}/index/"
    credential-provider = ["cargo-credential-prego", "--tenant", "${var.tenant}", "--edge-code", "${var.edge_code}"]
  EOT
}

output "registry_name" {
  description = "Use this name in Cargo.toml: registry = \"<name>\"."
  value       = var.tenant
}
