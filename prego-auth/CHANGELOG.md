# Changelog

All notable changes to `prego-auth` are listed here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the crate uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.6.0] - 2026-11-06

### Changed

- Release 0.6.0 (GitHub Latest) for the registry 1.4.0 production cut-over: the code of 0.6.0-rc.1 and one
  message change.
- The refusal of a challenge realm without the edge code also says "Check the repository name, or try again
  later" (the registry sends that realm for an unknown tenant or a rate limit).

## [0.6.0-rc.1] - 2026-11-05

### Changed

- Pre-release 0.6.0-rc.1 (GitHub pre-release, not Latest; not on crates.io) with the edge code token URLs:
  registry tokens at `/v1/sts/token/e/<edge code>` and the OCI realm at `/v1/oci/token/e/<edge code>`.
- Registry tokens come from the edge code URL `<sts_url>/e/<edge code>` (`Config::token_url`), and the OCI
  realm is `/v1/oci/token/e/<edge code>`. The STS refuses registry tokens on the URL without the code from
  registry 1.4.0. Admin tokens stay on `sts_url`.
- `oci::check_challenge_realm`: the realm from a repository's `401` challenge must be on the STS host with the
  path `/v1/oci/token/e/<edge code>` and a valid code. The code can be another tenant's (a grant from that
  tenant), so it is not compared with the configured one. `RealmTokens::new` takes the
  realm URL, and `realm_token_at` gets a token at a given realm.

### Added

- `Config::edge_code` from `--edge-code`, `PREGO_EDGE_CODE` or the settings key `edge_code`, checked with
  `check_edge_code` (`^[a-hjkmnop-z2-9]{4}$`). `sts_url` can also be the console's token URL
  (`.../v1/sts/token/e/<code>`); two different codes are an error.
- `npm` module: `npm_host` (`PREGO_NPM_HOST`, then `npm_host` in the settings file, then
  `npm.prego.k8skill.com`), `registry_url` and `TOKEN_VAR`.
- Settings file key `npm_host`.

## [0.5.1] - 2026-11-05

### Changed

- Rebuild of 0.5.0 in the new public repository `group-katskill/prego-clients` (fresh history, signed commits).
  No code change.

## [0.5.0] - 2026-11-04

### Added

- `RegistryToken::lifetime`, `RegistryToken::new`, `margin`, `fresh_until` and `is_fresh`, and
  `sts::cache_margin`: the cache margin is `min(60 s, lifetime / 4)`.
- `sts::exchange` and `TokenClient::registry_token_for` take an optional `resource` (the registry base URL).
  If the STS answers `400 invalid_target`, the exchange asks once more without it.
- `sts::resource_base`: the base URL `<scheme>://<host>/t/<tenant>/<namespace>` of a registry URL.
- `sts::send_rate_limited`: after a `429` from the STS, wait for `Retry-After` (at most 60 s, plus up to
  500 ms of jitter) and try again, at most two times. Then `Error::RateLimited`, which names the tenant's
  budget.
- `http::Response::retry_after`. `testing::MockResponse::with_header`.

### Changed

- **Breaking:** the token expiry is the local time of the request plus `expires_in` (the token lifetime),
  never the `exp` claim, so a wrong local clock does not matter. Without `expires_in`: `exp - iat` from the
  token. With both: the shorter one. `sts::exchange` has a new `resource` argument.
- OCI realm tokens: no `expires_in` means 60 s, and less than 60 s counts as 60 s (the distribution token
  spec). `oci::RealmTokens` uses a token again until its expiry minus the margin (was 30 s before `exp`).
  `oci::REUSE_MARGIN_SECONDS` is replaced by `oci::MIN_REALM_LIFETIME_SECONDS`.
- Version 0.5.0. All crates in this workspace have the same version.

## [0.4.0] - 2026-11-04

### Added

- `go::go_hosts` and `go::DEFAULT_GO_HOST`: the Go hosts from `PREGO_GO_HOSTS`, `go_hosts` and the default.
- Settings file keys `go_hosts` and `go_prefixes`.

### Changed

- Version 0.4.0. All crates in this workspace have the same version.

## [0.3.0] - 2026-11-04

### Added

- `http::Http::send`: one request with headers and a body (`http::Body`: empty, bytes, or a reader that is
  streamed with `Content-Length`). It returns the status, headers and body (`http::FullResponse`).
- `http::Http::for_transfers`: a client for large uploads, with no total time limit and a 120 s limit for each
  socket read or write.
- `oci::RealmTokens`: gets registry tokens from the OCI realm and keeps one token for each set of scopes. It
  uses the token again until 30 seconds before it expires. It sends at most 60 realm requests per minute
  (`oci::MAX_REALM_REQUESTS_PER_MINUTE`, the realm limit for each IP address), and waits when it must.
- `oci::Pacer`: the sliding one-minute window that `RealmTokens` uses.

### Changed

- Version 0.3.0. All crates in this workspace have the same version.

## [0.2.0] - 2026-11-03

### Added

- Settings file `prego/config.toml` (`FileConfig`), shared by all Prego client tools. Location:
  `$XDG_CONFIG_HOME/prego/config.toml`, else `$HOME/.config/prego/config.toml`. Keys: `tenant`, `sts_url`,
  `audience`, `source`, `oci_hosts`. A missing file is not an error. A bad file, an unknown key, or a key that
  looks like a secret (`api_key`, `token`, ...) is an error.
- `Config::from_parts`, for a settings file that is already loaded.
- Module `oci`: the Prego OCI hosts (`oci_hosts`, `normalize_host`) and the Docker token realm
  (`realm_url`, `realm_token`) with HTTP Basic auth.
- `Http::get_with_basic` and `jwt::unverified_claims`.

### Changed

- `Config::from_args` uses the settings file as the last fallback, after arguments and `PREGO_*` variables.
- Version 0.2.0. New dependency: `toml`.

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

- Six identity sources in `auto` order: `spiffe` (Workload API, feature `spiffe`), `svid-file`, `gitlab`,
  `github`, `token-file`, `api-key`.
- `Config::from_args` with environment fallbacks (`PREGO_TENANT`, `PREGO_STS_URL`, `PREGO_AUDIENCE`,
  `PREGO_SOURCE`).
- STS token exchange: form POST, 10 s timeout, 2 retries on network errors and `5xx` (250 ms, 1 s), no redirects.
- `invalid_grant` maps to a clear message that names the tenant.
- `TokenClient`: finds the subject token and does the exchange. It keeps no token cache.
- Optional `PREGO_CA_FILE`: a PEM CA bundle that is trusted in addition to the Mozilla roots, for on-prem
  TLS proxies.
- A source error names the source and suggests `--source <name>` (auto mode fails closed).
- The crate package holds `LICENSE-MIT` and `LICENSE-APACHE`.

### Security

- Token values are held in `Secret`, which hides the value in `Debug`. No error holds a token value.
- The STS URL must use `https`; plain `http` is accepted only for loopback hosts.
- TLS certificate checks are always on. There is no switch to turn them off.

### Removed

- The in-memory token cache and its switch `--no-cache` / `PREGO_NO_CACHE`.
