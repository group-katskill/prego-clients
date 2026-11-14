# Changelog

All notable changes to `prego` are listed here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the crate uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `prego adapter push <folder> <repo>:<version>` and `prego adapter get <repo>:<version> <folder>` (ADR-0052,
  registry 1.11.1, Publisher plan and Trial): AI model adapters as one OCI artifact. The push checks the folder
  with the rules of the registry first (peft config, one safetensors file with a valid header, at most 8 text
  files, 2 GiB, a license) and sends a manifest that is the same for the same files. The get checks the
  SHA-256 of each file, follows the storage link without the registry token, and writes nothing if a check
  fails. Clear messages for `403 plan_limit`, `409 tag_exists` and `400 adapter_invalid`.
- The crate `prego-cli` on crates.io, an alias of `prego`: the same source and version, the same binary `prego`.
  `tools/publish-prego-cli.sh` publishes it from the release tag. No code change in `prego`.

## [0.9.0] - 2026-11-08

### Added

- Python packages (registry 1.9.0): `prego setup python [--project NAME]... [--tool uv|poetry|pip] [--print]`
  writes the prego index (`explicit = true`) and `[tool.uv.sources]` to `pyproject.toml` (never a token; without
  `--project`, the projects from the JSON root index), or a Poetry source, or prints the pip line with the
  dependency confusion warning. `prego exec` has a Python mode (`--python`, `--pip`, or automatic for uv, pip,
  python, twine, poetry, pdm and hatch): one Python token in the uv, twine and Poetry variables, and
  `PIP_EXTRA_INDEX_URL` with `--pip`; nothing on stderr. `prego token --python [--url URL]` prints a Python
  token, cached (mode 0600) until 1 minute before it ends, and refuses a URL on another host.
  `prego python publish <file>...` streams wheels and sdists to the upload API and refuses files over 90 MiB
  before the upload. `pypi_host` in the settings file and `PREGO_PYPI_HOST`.
- `prego token --python --url` refuses a plain `http://` URL, except for a loopback host: a token is sent
  only over https.

### Changed

- Release 0.9.0: Python packages (registry 1.9.0).

## [0.8.0] - 2026-11-08

### Added

- `prego env` for Release Variables (registry 1.8.0): `pull`, `push`, `history`, `rollback`, `diff` and `hash`.
  References with 2, 3 and 4 or more segments. `pull --format env|json|flat --out FILE`; the env format
  shell-quotes every value, and `--expect <hash>` exits with 3 and writes nothing if the resolved hash is
  different. `pull` computes the resolved hash again and refuses an answer that does not match it. `push`
  replaces the whole set from `--file`, `--env-file` (strings only), `--set` and `--set-json`, with
  `--if-current`, `--message` and `--level tenant|namespace`. `hash` gives the RFC 8785 hash offline, the
  same as the registry. The help says that Release Variables are not secrets.

### Changed

- Release 0.8.0: `prego env` for Release Variables (registry 1.8.0).
- `serde_json` parses numbers exactly (`float_roundtrip`), so the canonical form of a number is the same as in
  the registry.

## [0.7.0] - 2026-11-07

### Changed

- Release 0.7.0: `prego login`, `prego logout` and `prego status`. A session is named
  `prego-cli/0.7.0 on <address>`.

### Added

- `prego login [--publish] [--no-browser]`: log in with the console sign-in (open the page, confirm the
  code). Read access, or read and publish with `--publish`. It opens a browser on a desktop, not over SSH.
- `prego logout`: ends the session at the STS and deletes it from this computer, also when the STS call
  fails (then it says so). `prego status`: tenant, session, access, end times and the storage; never a token.
- The login session is the last identity source, after workload identity and `PREGO_API_KEY`. `prego exec`
  writes no NETRC file for a login session, and `prego go-auth` keeps no file cache for it: a registry token
  from a session is never written to a file.

## [0.6.0] - 2026-11-06

### Changed

- Release 0.6.0 (GitHub Latest) for the registry 1.4.0 production cut-over: the code of 0.6.0-rc.1. The
  prego-auth realm refusal has a new hint.

## [0.6.0-rc.1] - 2026-11-05

### Added

- `prego setup npm [--scope @acme] [--namespace ns] [--client npm|pnpm|yarn|bun] [--user] [--print]`: writes
  the scope line and a `${PREGO_NPM_TOKEN}` reference, never a token, to `.npmrc` (npm, pnpm; `--user` for
  `~/.npmrc`), `.yarnrc.yml` (Yarn 4) or `bunfig.toml` (Bun). It keeps all other lines, replaces a pasted
  token, and warns on a `registry=` line that points to Prego. It never rewrites YAML or TOML: when a
  scopes section is already there, it prints the lines. The scope defaults to the tenant's only npm scope
  (admin API, `admin:read`).
- `prego setup npm` also prints `prego exec -- npm whoami --registry <URL>` for npm and pnpm: `npm whoami`
  and `npm ping` do not use the scope line.
- `prego npm-env`: prints `export PREGO_NPM_TOKEN='<token>'` for `eval`, and the lifetime on stderr.
- `prego whoami` shows the npm registry URL of the namespace.
- `PREGO_NPM_HOST` for another npm host.
- Tests: live `npm` and `pnpm` install through `prego exec` and `prego token`, and `npm publish` through
  `prego exec`, against a mock registry. CI runs them with pnpm 10.28.0.

### Changed

- Pre-release 0.6.0-rc.1 (GitHub pre-release, not Latest; not on crates.io) with the edge code token URLs:
  registry tokens at `/v1/sts/token/e/<edge code>` and the OCI realm at `/v1/oci/token/e/<edge code>`.
- The tenant's edge code is required for registry tokens: `--edge-code`, `PREGO_EDGE_CODE` or `edge_code` in
  the settings file (or the console's token URL as `--sts-url`). `prego push` takes the realm from the
  `401` challenge of the repository (`GET /v2/<name>/tags/list`), because the `/v2/` challenge names no
  repository and has no edge code. `prego token --scope` uses your own tenant's realm. `prego whoami` shows the token URL.
- `prego exec` also sets `PREGO_NPM_TOKEN` and `PREGO_TOKEN` for the command. The short-lifetime warning
  now says "long Go builds need GOAUTH, see prego setup go. npm, pnpm: run the command again with prego
  exec."

## [0.5.1] - 2026-11-05

### Changed

- Rebuild of 0.5.0 in the new public repository `group-katskill/prego-clients` (fresh history, signed commits).
  No code change.

## [0.5.0] - 2026-11-04

### Added

- `prego token --resource <url>` and `prego whoami --resource <url>`: the token for one registry
  namespace. `prego whoami` shows the token lifetime.

### Changed

- `prego go publish`: a module zip can be at most 300 MiB, compressed and uncompressed (was 500 MiB, Go's own
  limit). The registry has the same cap. A bigger module is refused before any token exchange or upload,
  with the size and the cap in the message. Tests at 300 MiB + 1 byte.
- Token lifetime from the STS (`expires_in`), never assumed to be 15 minutes:
  - `prego go-auth` sends the `GOPROXY` Prego entry as `resource` when there is one namespace, and caches a
    token until its expiry minus `min(60 s, lifetime / 4)` (was 60 s). The cache file holds the lifetime.
  - `prego go publish` sends the namespace as `resource` and gets a new token before a request when the
    current one is no longer fresh, so short tokens do not expire between parts.
  - `prego exec` sends `resource`, prints the token lifetime on stderr, and warns under 10 minutes ("token
    valid for N min; long builds need GOAUTH, see prego setup go"). The netrc file cannot be renewed.
  - `prego oci push` uses the same margin for realm tokens.
  - After a `429` from the STS, the tools wait for `Retry-After` (at most 60 s) and try again at most two
    times.
- Tests with 1-minute tokens, and with 2-second tokens that the mock registry refuses when they are older.
- Version 0.5.0. All crates in this workspace have the same version.

## [0.4.0] - 2026-11-04

### Added

- `prego go publish [<module dir>] [<tag>]`: builds a Go module zip from the git tree of the tag (`git ls-tree`
  and `git cat-file`, never the working directory), with the file rules of `golang.org/x/mod/zip` (vendored
  packages, nested modules, symlinks, file path and case rules, 500 MiB, go.mod 1 MiB) and the root `LICENSE`
  rule of the go command. It checks the module path, the version (tags only, no pseudo-versions) and the major
  version rule, computes the zip h1 and the go.mod h1, and sends `X-Prego-Go-H1` and `X-Prego-Go-Origin`. Up
  to 95 MiB in one `PUT`, else in a chunked session. It fails if the registry's h1 differs. Options
  `--namespace`, `--dir`, `--tag`, `--dry-run` (file list and h1, nothing sent) and `--json`.
- `prego go-auth`: the GOAUTH helper for Go 1.24 and later (`GOAUTH='prego go-auth'`). It gives one registry
  token for the Prego entries of `GOPROXY`, gets a new one after a `401`, and makes no STS call after other
  statuses. The token cache is a 0600 file in a checked 0700 directory under `$XDG_RUNTIME_DIR` or `$TMPDIR`.
- `prego setup go [--prefix <path>]... [--namespace <ns>] [--write]`: the `go env -w` lines for `GOPROXY`,
  `GONOSUMDB` (from `--prefix`, `go_prefixes`, or the admin API with `admin:read`) and `GOAUTH` (added to an
  existing value).
- `prego exec -- <command>`: runs the command with `NETRC` set to a temporary 0600 file with a registry token,
  deleted at the end. For Go before 1.24.
- Tests: h1 and go.mod h1 of fixture modules (root, subdirectory, `/v2`) equal the `Sum` and `GoModSum` of
  Go 1.26.8; a mock Go host checks the uploaded zips; `PREGO_TEST_GO` runs the same check against real Go.

### Changed

- `docs/go-quickstart.md`: a note that after a `SIGKILL` of `prego exec`, the 0600 netrc file can stay in the
  private 0700 cache directory until it is deleted; its token expires after 15 minutes.
- README: the 95 MiB rule for `docker push`, with a `prego oci push` example.
- Version 0.4.0. All crates in this workspace have the same version.

## [0.3.0] - 2026-11-04

### Added

- `prego oci push <input> <image>`: pushes an image from an OCI image layout directory or a `docker save` tar
  file (the old format and the OCI format). Each blob that the repository does not have is sent in parts with
  `Content-Range` (default 64 MiB, `--chunk-size <MiB>`, at least `OCI-Chunk-Min-Length`, at most 95 MiB), so
  layers above the 95 MiB limit of `docker push` work. It resumes from the upload status after a network
  error, a `5xx` or a `416`. It pushes child manifests by digest, then the top manifest by tag. `--from <repo>`
  mounts blobs from another repository of the tenant. Blob digests are checked before any upload. One registry
  token is used for the whole push, and the identity goes only to the Prego token realm.

### Changed

- Version 0.3.0. All crates in this workspace have the same version.

## [0.2.0] - 2026-11-03

### Added

- First version, 0.2.0, with these commands:
  - `prego token`: prints a registry token from the STS. With `--scope` (one or more), gets it from the OCI
    token realm.
  - `prego whoami`: shows the tenant, the identity source, the principal (`sub`, `tid`, read from the token
    without a signature check and marked "not verified"), the time the token is valid, and the Cargo and OCI
    URLs. It never shows a token.
  - `prego setup cargo [--namespace <ns>] [--registry <name>]`: prints the Cargo snippet.
  - `prego setup docker [--write]`: prints the `credHelpers` snippet. With `--write`, changes
    `$DOCKER_CONFIG/config.json` or `~/.docker/config.json`: backup copy first, other keys and their order
    kept, atomic replace, no change if the file is not a JSON object.
- Options `--tenant`, `--sts-url`, `--audience`, `--source`, with the `PREGO_*` and settings-file fallbacks.
- Prebuilt binaries in the `prego-clients-v0.2.0` GitHub release for `x86_64-unknown-linux-musl`,
  `aarch64-unknown-linux-musl` and `aarch64-apple-darwin`, with SHA-256 sums and `install.sh`.

