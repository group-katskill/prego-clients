# Changelog

All notable changes to `cargo-credential-prego` are listed here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the crate uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `--help` lists the `device` source.
- Uses the `prego login` session when no workload identity and no `PREGO_API_KEY` is set.

## [0.6.0] - 2026-11-06

### Changed

- Release 0.6.0 (GitHub Latest) for the registry 1.4.0 production cut-over: the code of 0.6.0-rc.1. The
  prego-auth realm refusal has a new hint.

## [0.6.0-rc.1] - 2026-11-05

### Changed

- Pre-release 0.6.0-rc.1 (GitHub pre-release, not Latest; not on crates.io) with the edge code token URLs:
  registry tokens at `/v1/sts/token/e/<edge code>` and the OCI realm at `/v1/oci/token/e/<edge code>`.
- The tenant's edge code is required: `--edge-code`, `PREGO_EDGE_CODE` or `edge_code` in the settings file.
  Tokens come from `https://sts.prego.k8skill.com/v1/sts/token/e/<edge code>`.

## [0.5.1] - 2026-11-05

### Changed

- Rebuild of 0.5.0 in the new public repository `group-katskill/prego-clients` (fresh history, signed commits).
  No code change.

## [0.5.0] - 2026-11-04

### Changed

- Sends the registry base URL from the index URL as `resource` (for example
  `https://cargo.prego.k8skill.com/t/acme/default/`), so the token gets the lifetime of the grants for that
  namespace.
- Cargo may cache the token until its expiry minus `min(60 s, lifetime / 4)`, from `expires_in` and the
  local clock (was the `exp` claim minus 60 s, which never cached a 1-minute token). A 1-minute token is
  cached for 45 s. Tests with 1-minute tokens.
- Version 0.5.0. All crates in this workspace have the same version.

## [0.4.0] - 2026-11-04

### Changed

- Version 0.4.0. All crates in this workspace have the same version.

## [0.3.0] - 2026-11-04

### Changed

- Version 0.3.0. All crates in this workspace have the same version.

## [0.2.0] - 2026-11-03

### Changed

- The tenant, STS URL, audience and source can also come from `~/.config/prego/config.toml`, after the
  arguments and the `PREGO_*` variables. A bad settings file is an error.
- Version 0.2.0, with `prego-auth` 0.2.0.
- Prebuilt binaries in the `prego-clients-v0.2.0` GitHub release for `x86_64-unknown-linux-musl`,
  `aarch64-unknown-linux-musl` and `aarch64-apple-darwin`, with SHA-256 sums and `install.sh`.

### Removed

- The prebuilt `x86_64-apple-darwin` (Intel Mac) binary. Use `cargo install` on an Intel Mac.

## [0.1.2] - 2026-11-02

### Changed

- Product name: Prego by Katskill. The crate description and the help text use the new name. Domains,
  crate names and the protocol URNs do not change.

## [0.1.1] - 2026-11-02

### Changed

- License is Apache-2.0 only (license change). Version 0.1.0 stays available under `MIT OR Apache-2.0`.
  The package holds `LICENSE` (the Apache-2.0 text, was `LICENSE-APACHE`) and a new `NOTICE` file;
  `LICENSE-MIT` is removed.

## [0.1.0] - 2026-11-02

### Changed

- Package metadata: `repository` (GitHub) and `homepage` (clients.prego.k8skill.com).

### Added

- Cargo credential provider over `prego-auth`, using the `cargo-credential` crate (protocol v1).
- `get` returns the registry token with `cache = expires` at the token `exp` minus 60 s and
  `operation_independent = true`.
- `login` and `logout` return `operation-not-supported` with a hint to the Prego console.
- Arguments `--tenant`, `--sts-url`, `--audience`, `--source` from the `credential-provider` config, with
  environment fallbacks. `PREGO_CA_FILE` adds a PEM CA bundle.

### Removed

- `--no-cache` and `PREGO_NO_CACHE`. Cargo caches the token with the `expires` hint.
- `--version` prints the version and the git commit. `--help` prints usage.
- Protocol tests that start the binary and speak the Cargo credential protocol to a mock STS.

### Fixed

- The crate package now holds `LICENSE-MIT` and `LICENSE-APACHE`.
- `build.rs` watches `.git/HEAD` only when it exists, so builds from crates.io do not rerun it each time.
