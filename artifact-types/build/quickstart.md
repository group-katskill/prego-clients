# Build artifacts with `prego build`

**From prego 1.5.0 and the registry with ADR-0066.**

A build stream is a name in a namespace, for example `api-cli` or `api-test-reports`. The first build makes it. A
build is one upload of 1 to 32 files. This guide uses tenant `acme`, namespace `ci` and the stream `api-cli`.
Replace them with your own.

## Plans and access

- Trial, Indie, Org and Publisher can upload. Consumer reads through grants.
- Grants use the type "Build artifacts" (`ecosystem = build`) with the actions `read`, `publish` and `delete`. An
  `any` grant also matches. With no grant, Prego answers as if the stream does not exist (`404`).
- CI identities (GitHub Actions, GitLab CI) and SPIFFE workloads can upload. People (`prego login`) and API keys can
  upload only when a tenant admin turns on "Allow uploads by people and API keys" for the namespace.

## Push a build

```sh
prego build push acme/ci/api-cli dist/api-cli-linux-amd64.tar.gz dist/SHA256SUMS
prego build push acme/ci/api-cli dist/* --promote "$TAG" --release-url "$RELEASE_URL"
prego build push acme/ci/api-test-reports reports/junit.xml --expires-in 7
```

- `prego` computes the sha256 of each file first and sends the files in parts of at most 95 MiB. Prego computes the
  sha256 again. When a file changed during the upload, Prego refuses it and `prego` cancels the upload; nothing is
  stored.
- File names: 1 to 128 characters from `A-Z`, `a-z`, `0-9`, `.`, `_`, `+` and `-`, not starting with `.`. Two files
  with the same name are refused. Put a folder in an archive first.
- The build expires after the namespace window. `--expires-in <days>` asks for fewer days (at least 3), never more.
- `--promote <label>` keeps the build with that label at once (a release). `--release-url` adds a link to the forge
  release (`https://`, at most 2,048 characters). Prego does not fetch it.
- `prego build push` prints the build ID on stdout.

## Get a build

```sh
prego build get acme/ci/api-cli bld_01J...                     # by ID
prego build get acme/ci/api-cli --commit "$GITHUB_SHA" --out dist
prego build get acme/ci/api-cli --run 456
prego build get acme/ci/api-cli --label v1.4.0
prego build get acme/ci/api-cli --latest --ref refs/heads/main
```

- `get` writes the files to a folder (`--out`, default `.`) and checks the sha256 of each file against the build's
  file list. It does not replace a file that exists. `--no-verify` turns the check off.
- Prego gives each file through a storage link that lasts 60 seconds. `prego` follows it without the token.

## List and promote

```sh
prego build list acme/ci/api-cli --promoted
prego build list acme/ci/api-cli --commit 9f2c1ab --json
prego build promote acme/ci/api-cli bld_01J... v1.4.0
prego build promote acme/ci/api-cli v1.4.0 --commit "$GITHUB_SHA"
```

A promote is one-way. A label is unique in the stream and does not move. In the console, "Keep" is the same as
promote.

## Errors

| Message | What to do |
| --- | --- |
| `403 forbidden: uploads by people and API keys are off` | Upload from CI, or ask a tenant admin to allow uploads by people and API keys for the namespace. |
| `413 file_too_large` | The file is larger than the plan allows. |
| `403 plan_limit` | The tenant's storage is full, or it has 20 open uploads. Add a storage pack, or delete builds. |
| `409 conflict` (label) | The label exists in the stream, or the build already has another label. |
| `422 digest_mismatch` | The file changed during the upload. Upload it again. |
| `not found, or you have no grant for it` | Ask an admin of the tenant for a grant on type Build artifacts. |
