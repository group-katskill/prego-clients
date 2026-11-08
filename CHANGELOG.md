# Changelog

Repository-level changes (docs, licenses, CI). Each crate has its own `CHANGELOG.md`.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.8.0] - 2026-11-08

### Added

- `docs/release-variables.md`: the Release Variables guide for `prego env` (0.8.0). README, the website and
  PROTOCOL.md 1.10.0 section 12 (routes, RFC 8785 hashes, env output) and the `vars:write` admin scope.
- `docs/openapi.yaml` 1.5.0: the Release Variables routes (`/v1/vars/*` and `/v1/admin/tenants/{tenant}/vars/*`),
  their schemas, the `vars:write` scope and the new error codes and fields.

### Changed

- Release 0.8.0: `prego env` for Release Variables (registry 1.8.0), with the guide
  `docs/release-variables.md`, the website section, PROTOCOL.md 1.10.0 and `docs/openapi.yaml` 1.5.0.
- Go `.netrc` with an API key (registry 1.6.0): the Go quickstart has a "Last resort" section with the grant
  switch "Allow this API key in .netrc" and the new `401` text; PROTOCOL.md 1.9.0 section 9.2 and the website
  say the same. `prego go-auth` stays first.
- Go `.netrc` docs: the deploy step also opened the Go read grants that other tenants gave to those keys'
  tenants, it ran within an hour of the deploy, and an `ecosystem = any` grant cannot have the switch.
- `examples/` and `docs/frontline-ci-publish.md` pin prego-clients 0.7.0; the guide's install step has the
  SHA-256 of the 0.7.0 archive.

## [0.7.0] - 2026-11-07

### Changed

- Release 0.7.0: `prego login` for registry 1.5.2 and console 0.14.2 in production. The website and the README
  show the console page `app.prego.k8skill.com/device`, the quick start downloads `install.sh` from the release
  (the site does not serve it), npm is no longer "coming soon", and the verify examples use 0.7.0.

### Added

- `prego login`, `prego logout` and `prego status`: a device login for people on a laptop. No action is
  needed: API keys and workload identity keep working and come first.
- Docs for `prego login`: README "Quick start on a laptop", the four quickstarts start with `prego login` on a
  laptop, the CI guide says CI never uses it, PROTOCOL.md 1.8.0 section 11 (device login, refresh, revoke,
  storage) and the Docker helper with a session, SECURITY.md (storage per OS, no plain file, the marker file,
  a lost laptop), OpenAPI 1.4.0 (the device routes and the refresh at the edge code token URL), and the website
  ("Log in on a laptop", "Lost laptop?", the login session source).
- The release workflow builds the macOS binaries on a macOS 15 runner (the keychain code needs the macOS SDK),
  and CI has a macOS build and test job.
- PROTOCOL.md section 11: the Docker helper takes its secret from the session refresh with at least half of its
  lifetime left (registry 1.5.0 refuses a realm token as a password), and a `401 invalid_grant` (ended trial)
  on a refresh keeps the session.
- PROTOCOL.md section 11.3: a stop of the tenant (usage limit) during the login or a refresh is shown with "try
  again after the reset or ask the owner".
- `docs/frontline-ci-publish.md`: publish crates, images, npm packages and Go modules to Prego from GitHub
  Actions or GitLab CI next to a registry of record, with the 0.6.0 install lines and the edge code. README links
  to it.
- `examples/`: pin prego-clients 0.6.0, and add the tenant's edge code where a tool requests a token (Cargo
  config, OpenTofu, Ansible, the GitHub Actions image job). The `docker login` jobs need no edge code.

## [0.6.0] - 2026-11-06

### Changed

- Release 0.6.0, for the registry 1.4.0 production cut-over: npm packages and the edge code token URLs.
  Website: the "Coming soon" marks and their CSS are removed, and the Cargo section and the options table
  show the edge code. The site shows 0.6.0 as the newest version.
- Merge of `main` with the 0.6.0-rc.1 changes (release workflow pre-release flags, Pages version stamp).

## [0.6.0-rc.1] - 2026-11-05

### Changed

- Release 0.6.0-rc.1, a GitHub pre-release for tests on staging: npm packages and the edge code token URLs.
  The release workflow makes a tag with `-` a pre-release that is not Latest, so `releases/latest` and the
  install script without `--version` still give the newest X.Y.Z release. `install.sh --version` also
  takes `X.Y.Z-rc.N`.
- The Pages workflow shows the newest X.Y.Z release tag on the site when `prego/Cargo.toml` has a
  pre-release version, so the site never shows an rc. It fails if it finds no such tag.
- PROTOCOL.md 1.7.0: the edge code. Registry tokens at `POST /v1/sts/token/e/<edge code>`, the OCI realm at
  `/v1/oci/token/e/<edge code>`, the refusals for the URL without the code, and the settings key `edge_code`.
  README, quickstarts and CI examples set `PREGO_EDGE_CODE`.
- The Unreleased items in every CHANGELOG move under `## [0.5.0] - 2026-11-04`.
- PROTOCOL.md 1.6.0: section 10, npm packages (client files, tokens, trusted publishing), and the settings
  key `npm_host`.
- CI installs pnpm 10.28.0 and runs the live npm and pnpm tests (`PREGO_TEST_NPM=1`).
- The Go quickstart and PROTOCOL.md section 9.3 name 0.5.0, not 0.4.1, for the 300 MiB check before the
  upload. There was no 0.4.1 release.
- Website footer: the version and the commit of the deploy, on the right of the copyright line. The Pages
  workflow fills them in from `prego/Cargo.toml` and the commit, and also the hero version. The site deploys
  on every push to `main`.
- npm quickstart: `npm whoami` and `npm ping` with `--registry`; Prego's message on a `401` is an
  `npm notice` line next to npm's "Unable to authenticate"; npm 11 refuses a republish before any request,
  npm 10 shows the `403`.
- Website: a "Go modules" section and a "Go" nav item; an "npm packages" section and nav item marked
  "Coming soon" until the npm host is live; the Go and npm quickstarts in the footer links; the hero names
  Go modules and version 0.5.0. The README top section names crates, images, Go modules and npm packages.

### Added

- `docs/npm-quickstart.md`: install, publish, CI, trusted publishing from GitLab CI and GitHub Actions, and
  dependency confusion. Links from the README and the website.

## [0.5.1] - 2026-11-05

### Changed

- Release 0.5.1: the 0.5.0 code, released again from the new public repository (fresh history, signed commits).
  0.5.0 stays in the archived repository; it is not tagged again here.

## [0.5.0] - 2026-11-04

### Changed

- Token lifetime per grant (registry 1.2.0): PROTOCOL.md 1.5.0 (the `resource` field, section 2.1 Token
  lifetime with the plan ranges, section 2.2 Rate limits, the client rules for expiry, cache margin, `429`
  and `invalid_target`), README section "Token lifetime", and the lifetime text in the Go, OCI, consumer and
  CI guides, the crate READMEs and the site.
- `docs/openapi.yaml` 1.3.0: STS `resource`, `expires_in` 60 to 1800, `429` with `Retry-After` and the
  per-tenant budget; grant fields `ecosystem`, `token_ttl_minutes`, `effective_token_ttl_minutes`,
  `ineffective_actions`, `broad` and `created_by_principal`; action `delete`; the `effective` route;
  tenant `PATCH` with `separate_publish_delete`; principal `admin_namespace_id`; error codes
  `token_ttl_out_of_range`, `action_not_supported`, `broad_grant_needs_confirm`, `grant_ceiling`,
  `separation_of_duties`, `admin_namespace` and `admin_namespace_required`. New fields are marked
  "registry 1.2.0".
- Go zip cap 300 MiB in `docs/go-quickstart.md` (limits and a new error row), README, the site and
  PROTOCOL.md 1.4.1 (section 9.3, limits).
- Install and verify examples use the 0.4.0 release (README, site, `docs/consumer-quickstart.md`). The
  crates.io lines stay at 0.3.0.

## [0.4.0] - 2026-11-04

### Added

- `docs/go-quickstart.md` (from 0.4.0): connect Go with `prego setup go`, the GOAUTH helper, publish with
  `prego go publish`, CI, old Go with `prego exec`, the privacy note on module paths, and the errors. README
  section "Go modules", site card, and settings keys `go_hosts` and `go_prefixes`.

### Changed

- PROTOCOL.md 1.4.0: section 9 (Go modules: the GOAUTH helper, `.netrc`, and publish) and the Go keys in
  section 8.
- Docs for OCI and 0.3.0: new `docs/oci-quickstart.md` (Docker, Podman, crane, ORAS, Helm, cosign,
  multi-platform images, big layers, Kubernetes `imagePullSecret`, errors); image jobs in `docs/ci.md`; README
  sections "Push and pull images" and "Not in 1.0.0", crates.io and the 0.3.0 install line; examples pinned to
  0.3.0, with new GitLab and GitHub Actions image jobs and a Kubernetes pull secret; the site shows 0.3.0, all
  three tools, OCI and the cosign check.
- Changelogs: the 0.3.0 items of each crate and of this file are under `[0.3.0] - 2026-11-04`. The older
  items of this file are under "Up to 0.2.0".

## [0.3.0] - 2026-11-04

### Added

- Signed releases: the release workflow signs `SHA256SUMS` with cosign (keyless, with the GitHub OIDC identity of
  `release.yml` at the tag) and attaches the bundle `SHA256SUMS.sigstore.json`. The README section "Verify a
  release" and the notes in `install.sh` give the `cosign verify-blob` command.

### Changed

- PROTOCOL.md 1.3.0: OCI clients keep one registry token per scope set and send at most 60 realm requests
  per minute.
- PROTOCOL.md section 7: chunked uploads. README: `prego oci push` replaces the 0.3.0 note in the layer limit
  paragraph.

## Up to 0.2.0

Repository changes up to release 0.2.0 (this file had no version headings before 0.3.0).

### Changed

- Product name: Prego by Katskill (README, crate READMEs, API spec, site). Release 0.1.2 of both crates.
- License is Apache-2.0 only from 0.1.1 (license change): `LICENSE-APACHE` renamed to `LICENSE`, `LICENSE-MIT`
  removed, `NOTICE` added. README, site and release archives updated. Version 0.1.0 stays available under
  `MIT OR Apache-2.0`.
- Changelogs and code comments no longer cite internal design record numbers.
- Release 0.1.1 of `prego-auth` and `cargo-credential-prego`.

### Added

- Release 0.2.0 of all crates with one tag, `prego-clients-vX.Y.Z` (was `cargo-credential-prego-vX.Y.Z`).
  `release.yml` builds `cargo-credential-prego`, `docker-credential-prego` and `prego` for Linux x86_64 and
  aarch64 (musl) and macOS arm64. Each release has one archive with all three binaries per target, one archive
  per binary, a `.sha256` file for each archive, `SHA256SUMS` and `install.sh`. The Intel Mac build is
  removed. No crates.io publish step.
- `install.sh`: downloads the archive for the machine, checks its SHA-256 sum, and copies the three binaries
  to `~/.local/bin` (or `--dir`). No `sudo`.
- CI runs `shellcheck` on `install.sh`.
- `README.md`: install with `install.sh`, the new tag and archive names, and the 95 MiB layer limit of
  `docker push` until `prego oci push` in 0.3.0. Quickstart, examples and site use release 0.2.0 and the new
  tag.
- `prego` 0.2.0: CLI with `token`, `whoami`, `setup cargo` and `setup docker`. README section "The prego CLI".
  `NOTICE` names `prego`.
- `docker-credential-prego` 0.2.0: Docker credential helper for the Prego OCI registry.
- `PROTOCOL.md` 1.2.0: section 7 (the OCI token realm and the Docker credential helper) and section 8 (the
  settings file `prego/config.toml`).
- `README.md`: "Configure Docker" and "Settings file" sections. `NOTICE` names `docker-credential-prego`.
- Site: the guide and example cards mention managing Prego from CI with an admin token.
- `examples/admin/`: `prego-admin-token.sh` (admin token exchange with curl, token on stdin), a GitLab plan and
  apply job, an Ansible playbook that creates missing grants, and an OpenTofu read-only grant drift check.
- Admin token docs: `PROTOCOL.md` 1.1.0 section 4 (the `prego-admin` audience, admin scopes, errors `invalid_target`
  and `invalid_scope`), `docs/openapi.yaml` 1.2.0 (admin token security scheme, scope per admin operation,
  human-only operations, `admin_scopes` on principals, audit `actor_kind`), and a "Manage Prego from CI" section
  in `docs/ci.md`. Removed the statement that admin access is not supported from CI.
- `README.md`: a pre-release notice and badges (crates.io, docs.rs, CI, license, MSRV).
- User docs: `docs/openapi.yaml` (OpenAPI 3.1 of the public API), `docs/consumer-quickstart.md`, `docs/ci.md`,
  and `examples/` for GitHub Actions, GitLab CI, Cargo config, OpenTofu and Ansible (consumer side only).
  Linked from the README and the site.
- Site: a Guides section and footer links to the quickstart, the CI guide, the examples and the API reference.
- `README.md`, `PROTOCOL.md` (public STS contract and identity sources), `SECURITY.md`.
- Dual license files `LICENSE-MIT` and `LICENSE-APACHE` (Katskill LLC).
- Cargo workspace with the crates `prego-auth` and `cargo-credential-prego`. Resolver 3 keeps dependencies
  on Rust 1.91.
- `SECURITY.md`: the contact address `security@k8skill.com` is final.
- `README.md` and `PROTOCOL.md`: client safety rules (no cache, https and no redirects, TLS
  checks always on, `PREGO_CA_FILE`, auto mode fails closed).
- `.gitlab-ci.yml`: lint, test (with and without feature `spiffe`), release builds for four targets with
  cargo-zigbuild, and on tag `cargo-credential-prego-vX.Y.Z`: tag check, release with SHA-256 sums, and
  crates.io publish (needs `CARGO_REGISTRY_TOKEN`).
- GitHub Actions: `ci.yml` (fmt, clippy and tests with and without default features), `release.yml` (tag
  check, four release binaries with cargo-zigbuild, GitHub release with SHA-256 sums; no crates.io publish yet)
  and `pages.yml`. All actions are pinned to full commit SHAs.
- `site/`: the website for clients.prego.k8skill.com (GitHub Pages) in the Prego look, light and dark
  themes, self-hosted OFL fonts with their licenses, a strict self-only CSP, no external requests.
- `README.md`: links to the website and the GitHub release page; the release and CI steps for GitHub.

### Removed

- `.gitlab-ci.yml`. The public repository is on GitHub.
