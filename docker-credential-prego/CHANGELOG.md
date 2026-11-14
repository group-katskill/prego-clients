# Changelog

All notable changes to `docker-credential-prego` are listed here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the crate uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.10.0] - 2026-11-14

### Changed

- Release 0.10.0: version only, no code change.

## [0.9.0] - 2026-11-08

### Changed

- Release 0.9.0: version only, no code change.

## [0.8.0] - 2026-11-08

### Changed

- Release 0.8.0: version only, no code change.

## [0.7.0] - 2026-11-07

### Changed

- Release 0.7.0: the Docker helper with a `prego login` session.

### Added

- `--help` lists the `device` source.
- With a `prego login` session, `get` returns Username = the tenant and Secret = a registry token from the
  session. The session refresh token never goes to Docker.
- With a session, `get` gives a registry token with at least half of its lifetime left, so a long push does
  not outlive the realm token.

## [0.6.0] - 2026-11-06

### Changed

- Release 0.6.0 (GitHub Latest) for the registry 1.4.0 production cut-over: the code of 0.6.0-rc.1. The
  prego-auth realm refusal has a new hint.

## [0.6.0-rc.1] - 2026-11-05

### Changed

- Pre-release 0.6.0-rc.1 (GitHub pre-release, not Latest; not on crates.io) with the edge code token URLs:
  registry tokens at `/v1/sts/token/e/<edge code>` and the OCI realm at `/v1/oci/token/e/<edge code>`.
- No code change. Docker takes the token realm, now `/v1/oci/token/e/<edge code>`, from the registry's `401`
  answer. The helper still sends the tenant and the subject token only for Prego hosts.

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

