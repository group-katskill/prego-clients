# Changelog

All notable changes to `docker-credential-prego` are listed here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the crate uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.5.1] - 2026-11-05

### Changed

- Rebuild of 0.5.0 in the new public repository `group-katskill/prego-clients` (fresh history, signed commits).
  No code change.

## [0.5.0] - 2026-11-04

### Changed

- No change in behavior: the helper gives Docker the subject token, and Docker gets the realm token and a
  new one after a `401` by itself.
- Version 0.5.0. All crates in this workspace have the same version.

## [0.4.0] - 2026-11-04

### Changed

- README: Podman, crane, ORAS and Helm use the same `credHelpers` entry; the 95 MiB rule and a link to the
  OCI quickstart.
- Version 0.4.0. All crates in this workspace have the same version.

## [0.3.0] - 2026-11-04

### Changed

- Version 0.3.0. All crates in this workspace have the same version.

## [0.2.0] - 2026-11-03

### Added

- First version, 0.2.0. A Docker credential helper for the Prego OCI registry:
  - `get` gives the tenant as `Username` and the subject token as `Secret` for `oci.prego.k8skill.com` and the
    hosts in `oci_hosts` or `PREGO_OCI_HOSTS`. For other hosts it answers
    "credentials not found in native keychain" and reads no identity source.
  - `store` and `erase` do nothing. `list` shows the Prego OCI hosts with the tenant.
  - The same identity sources and `auto` order as `cargo-credential-prego`, from `prego-auth` 0.2.0.
  - Tenant from `--tenant`, `PREGO_TENANT` or `~/.config/prego/config.toml`.
  - The host list comes from `prego_auth::oci`, the same list that `prego setup docker` uses.
- Prebuilt binaries in the `prego-clients-v0.2.0` GitHub release for `x86_64-unknown-linux-musl`,
  `aarch64-unknown-linux-musl` and `aarch64-apple-darwin`, with SHA-256 sums and `install.sh`.

