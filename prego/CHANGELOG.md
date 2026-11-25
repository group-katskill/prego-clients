# Changelog

All notable changes to `prego` are listed here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the crate uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

Version 1.3.0 (minor). Not released yet.

### Added

- `prego keys` (ADR-0061, Keys and Certificates; needs the registry with ADR-0061): `push <file>... <ref>
  [--type ssh|openpgp|jwk|pem-public-key|x509]`, `get [--entry <index>] [--expect <hash>]`, `ls`, `log`, `tag`,
  `rollback`, `revoke --reason`, `fingerprint <file>` (offline) and `new --alg ed25519|es256 <ref>` (the private
  key goes to a local file with mode 0600, never replaced and never sent; the public JWK is added to the current
  entries of the item). Before any upload, every file is checked for private key material (PEM private key
  labels, OpenSSH and OpenPGP private keys and secret-key packets, JWK private members, PKCS #12), also outside
  the declared entry, and the push stops with the ADR-0061 item 2.4 message ("Keys and Certificates holds public
  keys and certificates only. Entry <index> holds a private key (<kind>). <hint>"). Each entry is checked as its
  type with the registry rules (RSA at least 3072 bits for ssh, 2048 for jwk and pem-public-key; no DSA; OpenPGP
  v4 only; at most 100 certificates in an x509 entry). The version hash (ADR-0061 section 4a) is computed
  offline. Fingerprints: `SHA256:<base64>` (ssh; the certified key for a certificate), the v4 hex fingerprint
  (openpgp), `sha256:<hex>` of the DER (x509), the RFC 7638 thumbprint (jwk, pem-public-key).
- `prego a2a` (ADR-0062, A2A Agent Cards; needs the registry with ADR-0062): `check <folder|file> [--key-file
  <file>] [--key <ref>]` (offline A2A 1.0 check, then the signatures), `push <folder|file> <ref> --sign <key file>
  --key <key ref> [--no-source]`, `get <ref>[@<v>] [<folder>] [--card <file>] [--expect <hash>] [--verify]`, `ls`,
  `log`, `diff`, `tag`, `rollback`, and `upgrade <file> [-o <file>] [--force]`. A2A 1.0 only: the card rule of the
  pinned A2A v1.0.1 proto (only known fields, REQUIRED fields set and not empty, oneof of security schemes and
  OAuth flows); a 0.3 card gets "A2A 1.0 only. Card <file> looks like A2A 0.3 (<reason>). Run `prego a2a upgrade
  <file>` ...". `push --sign` adds the source extension (`https://prego.k8skill.com/ext/a2a-source/v1`, tenant,
  namespace, set) to each card, signs each card with an A2A 1.0 signature (JWS over the RFC 8785 form of the card
  without `signatures` and without default values, A2A 1.0 section 8.4; protected header `alg`, `typ` JOSE, `kid`
  = RFC 7638 thumbprint, `prego_key`) and the set (ADR-0061 section 3, `.prego/set.jws.json`), on this computer,
  and checks before the push that the key is in Keys and Certificates and not revoked. `get --verify` checks the
  set signature and a signature on every card with the keys from Keys and Certificates and the reader's own
  grants; a revoked key fails with the date and reason; no read on the key item gives "verify needs read on key
  <ref> (type Keys and Certificates); ask an admin of <tenant> for a grant". `upgrade` converts an A2A 0.3 card to
  1.0 offline (no account needed), prints each change, stops at a field it cannot map with certainty (JSON
  pointer), and writes `agent-card.json` next to the input by default; the output is unsigned.
- Signing on this computer with ring (already in the tree through rustls): EdDSA (Ed25519), ES256, ES384, PS256 and
  RS256 verify; Ed25519, ES256, ES384 and PS256 signing from PKCS #8 key files.
- A missing grant names the grant and the item: "read on a2a set <ref> (type A2A Agent Cards) is missing ...",
  "read on key <ref> (type Keys and Certificates) is missing ...".
- Tests: every case of the shared ADR-0061/0062 vectors (`tests/vectors/{signing,keys,a2a}/`: JCS, RFC 7638, set
  payloads, JWS verify rules, key entries, private material, version hashes, the A2A card rule, 0.3 detection,
  card and set signatures, upgrade), and `keys new` -> `a2a push --sign` -> `a2a get --verify` against a mock
  registry.

- `prego login --namespace <ns>` (minor): the login session asks for that namespace, not only `default`. Give it
  up to 10 times (one access item each; the same namespace two times is one item). `prego login` checks each slug
  with the rule of the server (`^[a-z][a-z0-9-]{1,38}[a-z0-9]$`) and the count before the request; a bad one
  makes no request. No `--namespace` sends the same body as before (namespace `default`). `prego status` shows
  the namespaces. Fixes: a login session could reach only namespace `default`.

## [1.2.0] - 2026-11-20

### Added

- `prego sqlite` (ADR-0059): SQLite snapshots. `save <file.db> <ref> [--compact] [--check quick|full|none]
  [--label k=v]... [--message M] [--tag T]`, `restore <ref>[@<snapshot>] <file.db> [--expect H] [--force]`,
  `ls <tenant>[/<namespace>]`, `log <ref>`, `tag <ref>@<snapshot> <tag>`, `rm <ref>[@<snapshot>] [--yes]`,
  `prune <ref> [--keep N] [--older-than <n>h|<n>d|<n>w] [--yes]`, `set <ref> [--keep-count N] [--keep-days D]` and
  `hash <file.db> [--compact]` (offline). The save makes the copy with SQLite (the online backup API, or
  `VACUUM INTO` with `--compact`), never by copying the file, runs `PRAGMA quick_check` (or `integrity_check`) on
  the copy, and sends it in 64 MiB gzip frames: one `PUT`, or an upload session for more frames. The snapshot
  hash is the `sha256` of the frame hash lines (PROTOCOL.md 16.2). The restore writes `<target>.prego-tmp`,
  checks the snapshot hash, the file `sha256` and `quick_check`, and then renames it; a database with a `-wal` or
  `-journal` file is not replaced unless `--force`. Exit codes: 2 an unknown encryption mode, 3 an `--expect`
  mismatch, 4 a refused save, 5 a failed check. Needs registry 1.26.0.
  Written to the registry route shapes: the restore also checks the frame list, `X-Prego-Sqlite-Hash` and
  `X-Prego-File-Sha256`; a save prints the snapshots that `keep_count` removed (`rotated`); a commit refused with
  `429` is sent again; a file of 0 bytes is refused before the copy; a save of a WAL database that no program
  has open (no `-wal` and no `-shm` file) leaves no `-wal` or `-shm` file next to it: it is opened read-write,
  with no write, and SQLite checkpoints and removes the files at close; if that open fails, read-only, and in a
  folder that the user cannot write, as immutable; a hint is printed when SQLite leaves the files. A save reads
  `GET <d>` first: when the latest snapshot has the same hash, nothing is sent and the exit code is 0 (also within
  the one-save-per-minute limit, which gave `429` and exit code 4 in the staging test); `--tag` then tags the
  latest snapshot. Tested against the shared vectors of
  Prego-registry (`tests/vectors/sqlite/`: the hash rule, the frame, snapshot and file hashes, the header
  values, a restore of each accepted file, and no upload for the refused files).
- SQLite 3.54.1 is compiled in, through `rusqlite` 0.41.1 with the `bundled` feature. The release binary is
  about 2.1 MiB larger.

## [1.1.1] - 2026-11-20

### Fixed

- `prego go publish` refuses a `go.mod` larger than 64 KiB before the upload, the registry limit. It took up to
  1 MiB, and the registry then refused a `go.mod` between 64 KiB and 1 MiB with `400`.

## [1.1.0] - 2026-11-20

### Added

- `prego context` (ADR-0058): agent context. Checkpoints of text files (memory, notes, plans, transcripts)
  that agents save and restore with their own identity. `save <folder> <ref> [--session S] [--parent H]
  [--trigger compact|stop|manual|schedule] [--label k=v]... [--message M] [--tag T] [--no-redact]`,
  `restore <ref>[@<checkpoint>] <folder> [--session S] [--expect H]`, `ls <tenant>[/<namespace>]`,
  `log <ref> [--session S]`, `tag <ref>@<checkpoint> <tag>`, `rm <ref>@<checkpoint>` or
  `rm <ref> --session S`, `set <ref> [--keep-days N] [--on-full refuse|drop_oldest]`, and `hash <folder>`
  (offline). The checkpoint hash and the tar form are the Snippets ones, checked against the shared vectors.
- Client redaction, on by default: strings shaped like a Prego API key, a PEM private key, an AWS access key
  ID, a GitHub, GitLab or Slack token, a Stripe live key or a JWT are replaced with `[REDACTED:<kind>]` before
  the upload. `prego` prints how many strings it replaced, never the strings. `--no-redact` turns it off. The
  kinds (`prego_api_key`, `private_key`, `aws_access_key_id`, `github_token`, `github_pat`, `gitlab_token`,
  `slack_token`, `stripe_live_key`, `jwt`) and the test cases are the registry's shared secret-shape vectors
  (`tests/vectors/secrets/`, data only).
- A refused save (any error from the registry or the token exchange, or an upload that is too large) keeps the
  checkpoint in `./.prego-context/<context>-<utc time>.tar.gz` (mode `0600`), prints the path and the error,
  and exits with 4.
- A save that removed the oldest checkpoint without a tag (`on_full = drop_oldest`) says which one. A
  `422 looks_like_secret` lists every match (file and line, never the value).
- `restore` checks the hash of the file list, reads the content by that hash, checks it against the file list,
  and writes only to a new or empty folder: no path leaves the folder, mode `0644` or `0755` only. `--expect`
  exits with 3 on a mismatch, and an encryption mode other than `none` exits with 2; nothing is written in
  both cases.

### Changed

- The Snippets file rules take their size limits from one place, so Snippets (100 files, 1 MiB, 8 MiB) and
  Context (1,000 files, 32 MiB, 128 MiB, upload 32 MiB) share the same path and entry rules. No change for
  `prego snippet`, except that the NUL byte message no longer says "snippet".

## [1.0.0] - 2026-11-20

This release replaces 0.12.0, which was never tagged, and is the first stable release, for paying users. From 1.0.0 the commands, flags, exit codes, config file locations, the credential-provider protocols and PROTOCOL.md keep working within 1.x (README section "Stability").

### Added

- `prego snippet` (ADR-0057, registry 1.24.0): Snippets, named sets of text files with immutable versions.
  `push <folder|file> <ref> [--tag] [--message] [--if-current] [--tar]`, `get <ref>[@<version>] [<folder>]
  [--file P] [--tar] [--expect H]`, `ls <tenant>[/<namespace>]`, `log`, `diff <ref> <v1> <v2>`,
  `tag <ref>@<v> <tag>`, `rollback <ref> --to <v> --reason R`, and `hash <folder|file> [--tar]` (offline).
  The version hash (RFC 8785 canonical file list) and the fixed tar form are written from the ADR text and
  checked against the registry's shared test vectors (`tests/vectors/snippets/`, data only).
- `get` checks the version hash of the file list, reads every file from that exact version by its hash, checks
  each file's size and SHA-256, and writes only to a new or empty folder: no path leaves the folder, mode
  `0644` or `0755` only, and nothing is left behind on an error. `--expect` exits with 3 on a mismatch (local
  or `412`) and writes nothing.
- `push` checks the files first (100 files, 1 MiB each, 8 MiB together, UTF-8 without NUL, path rules
  including no C0, C1 or bidi controls, no two paths equal after Unicode NFC and lowercase, no path that is also a
  folder of another path (also after folding), no symlinks), refuses tags that end in `.tar.gz`, skips a `.git` folder, maps the mode by the owner execute bit, and sends one `.tar.gz` in the
  fixed form.

- An encryption mode other than `none` (header `X-Prego-Encryption` on any snippet read, or
  `encryption.mode` in version metadata) stops with exit code 2 and writes nothing. A missing header or field
  is `none`. `get` makes its folder only after every file is read and checked.

### Changed

- New direct dependency `icu_normalizer` 2.4 (Unicode NFC of snippet paths). It was in the tree already
  through `url` and `idna`; `Cargo.lock` gets no new crate.
- `prego env` and `prego snippet` share the code that gets the control host and the registry token. No change
  in behavior.

## [0.11.0] - 2026-11-17

### Changed

- The default STS URL is `https://api.prego.k8skill.com/v1/sts/token` (ADR-0054, through `prego-auth` 0.11.0).
  sts.prego.k8skill.com is an alias and keeps working. A `prego login` session from an older version stays
  valid. `prego oci push` and `prego adapter` accept the token realm of the registry on the sts name.

## [0.10.0] - 2026-11-14

### Added

- `prego adapter push <folder> <repo>:<version>` and `prego adapter get <repo>:<version> <folder>` (ADR-0052,
  registry 1.11.1, Publisher plan and Trial): AI model adapters as one OCI artifact. The push checks the folder
  with the rules of the registry first (peft config, one safetensors file with a valid header, at most 8 text
  files, 2 GiB, a license) and sends a manifest that is the same for the same files. The get checks the
  SHA-256 of each file, follows the storage link without the registry token, and writes nothing if a check
  fails. Clear messages for `403 plan_limit`, `409 tag_exists` and `400 adapter_invalid`.
- The crate `prego-cli` on crates.io, an alias of `prego`: the same source and version, the same binary `prego`.
  `tools/publish-prego-cli.sh` publishes it from the release tag. No code change in `prego`.

### Changed

- Release 0.10.0: `prego adapter push` and `prego adapter get`.

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

