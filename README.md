> **Pre-release:** Prego is in early access. APIs and versions may change before 1.0.

# prego-clients

[![crates.io: cargo-credential-prego](https://img.shields.io/crates/v/cargo-credential-prego?label=cargo-credential-prego)](https://crates.io/crates/cargo-credential-prego)
[![crates.io: prego-auth](https://img.shields.io/crates/v/prego-auth?label=prego-auth)](https://crates.io/crates/prego-auth)
[![docs.rs: cargo-credential-prego](https://img.shields.io/docsrs/cargo-credential-prego?label=docs%3A%20cargo-credential-prego)](https://docs.rs/cargo-credential-prego)
[![docs.rs: prego-auth](https://img.shields.io/docsrs/prego-auth?label=docs%3A%20prego-auth)](https://docs.rs/prego-auth)
[![CI](https://github.com/group-katskill/prego-clients/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/group-katskill/prego-clients/actions/workflows/ci.yml?query=branch%3Amain)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![MSRV: 1.91](https://img.shields.io/badge/MSRV-1.91-orange)](Cargo.toml)

Open source client tools for **Prego by KatSkill**, a private package registry with federated machine identity.
They serve every Prego type: see [Supported artifact types](#supported-artifact-types).

| Crate | Kind | What it does |
| --- | --- | --- |
| [`cargo-credential-prego`](cargo-credential-prego/) | binary | Cargo credential provider. Cargo runs it to get a registry token for a Prego registry. |
| [`docker-credential-prego`](docker-credential-prego/) | binary | Docker credential helper. Docker, Podman, BuildKit, crane and ORAS run it to sign in to the Prego OCI registry. |
| [`prego`](prego/) | binary | CLI: `prego token`, `prego whoami`, `prego setup cargo\|docker\|go`, `prego oci push`, and from 0.4.0 `prego go publish`, `prego go-auth` (GOAUTH) and `prego exec`, from 0.6.0 `prego setup npm` and `prego npm-env`, and from 0.7.0 `prego login`, `prego logout` and `prego status`. |
| [`prego-auth`](prego-auth/) | library | Identity sources, the settings file and the STS exchange. All binaries use it. |

Website: <https://clients.prego.k8skill.com>. Releases: <https://github.com/group-katskill/prego-clients/releases>.

Guides: [consumer quickstart](docs/consumer-quickstart.md) (crates on a laptop, API key), a quickstart for each
type in [`artifact-types/`](artifact-types/) (for example [OCI](artifact-types/oci/quickstart.md),
[Go](artifact-types/go/quickstart.md), [npm](artifact-types/npm/quickstart.md),
[Keys and Certificates](artifact-types/keys/quickstart.md) and [A2A Agent Cards](artifact-types/a2a/quickstart.md)), [CI guide](docs/ci.md)
(GitLab, GitHub Actions, SPIFFE, cloud workloads), [frontline guide](docs/frontline-ci-publish.md) (publish
from your own CI to Prego next to JFrog or Cloudsmith, and serve the fleet from Prego), [examples](examples/),
and the public API as [OpenAPI](docs/openapi.yaml).

License: `Apache-2.0`. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Version 0.1.0 was released under
`MIT OR Apache-2.0`; from 0.1.1 on, the license is Apache-2.0 only.
The code is open. The "Prego" name and logo are not licensed for reuse.

## Supported artifact types

Prego hosts these types. The `prego` tools work with all of them. Each type has a folder in
[`artifact-types/`](artifact-types/) with what it is, the plans, the quickstart and the examples.

| Type | Command or tool | Plans that can publish |
| --- | --- | --- |
| [Crates (Cargo)](artifact-types/crates/) | `cargo`, with `cargo-credential-prego` | Trial, Indie, Org, Publisher |
| [Containers and OCI artifacts](artifact-types/oci/) | Docker, Podman, crane, ORAS, Helm and cosign, with `docker-credential-prego`; `prego oci push` | Trial, Org, Publisher |
| [Go modules](artifact-types/go/) | `go`, with `prego go-auth` and `prego go publish` | Trial, Indie, Org, Publisher |
| [npm](artifact-types/npm/) | npm, pnpm, Yarn and Bun, with `prego setup npm` | Trial, Indie, Org, Publisher |
| [Python](artifact-types/python/) | uv, pip and Poetry, with `prego setup python` and `prego python publish` | Trial, Indie, Org, Publisher |
| [Release Variables](artifact-types/release-variables/) | `prego env` | Trial, Indie, Org, Publisher |
| [Snippets](artifact-types/snippets/) | `prego snippet` | Trial, Indie, Org, Publisher |
| [Adapters](artifact-types/adapters/) | `prego adapter` (preview) | Trial, Publisher |
| [Context](artifact-types/context/) | `prego context` | Trial, Org, Publisher |
| [SQLite snapshots](artifact-types/sqlite-snapshots/) | `prego sqlite` | Trial, Org, Publisher |
| [Keys and Certificates](artifact-types/keys/) | `prego keys` | Trial, Indie, Org, Publisher |
| [A2A Agent Cards](artifact-types/a2a/) | `prego a2a` | Trial, Indie, Org, Publisher |
| [API specs (OpenAPI, GraphQL)](artifact-types/apispec/) | `prego apispec` | Trial, Indie, Org, Publisher |

The Consumer plan publishes no type. A Consumer tenant reads every type through grants from other tenants.

The full list of limits is on the [plan limits page](https://docs.prego.k8skill.com/limits). The docs site needs a
sign-in with your Prego account.

## Full documentation

Full docs for each package type, with examples, are at https://docs.prego.k8skill.com (sign in with your Prego
account; open from the console's Docs link).

## Quick start on a laptop

From prego 0.7.0. Log in with your own console account. No key is stored in a file.

```sh
curl -fsSLO https://github.com/group-katskill/prego-clients/releases/latest/download/install.sh
sh install.sh                                                  # or see Install below
export PREGO_TENANT=acme PREGO_EDGE_CODE=k7mq                  # your tenant and its edge code (console)
prego login                  # open https://app.prego.k8skill.com/device, confirm the code; --publish to publish too
prego setup cargo            # then: prego setup docker --write, prego setup go, prego setup npm
prego status                 # tenant, access and end time of the session (never a token)
```

- The session is kept in your OS keychain (on Linux without a desktop, in the kernel keyring, which is lost at
  reboot), never in a plain file. It ends after 7 days without use, after 30 days in all, or with
  `prego logout`. See [SECURITY.md](SECURITY.md).
- Cargo, Docker, Go, npm and the `prego` commands use the session when no workload identity and no
  `PREGO_API_KEY` is set.
- **CI never uses `prego login`.** CI uses its job identity or an API key: see the [CI guide](docs/ci.md).
- Lost laptop? Revoke its session in the console: Settings, Your sessions.

## How the token exchange works

Prego registries accept only a short-lived **registry token** (15 minutes by default; see
[Token lifetime](#token-lifetime)). The credential provider gets one for each Cargo session:

1. It finds a **subject token** on the machine: a SPIFFE JWT-SVID, a CI OIDC ID token, a token file, or an
   API key (`prk_...`). With none of them, it uses the `prego login` session, which gets the registry token
   directly with a session refresh. SPIFFE needs the Org or Publisher plan (or a Trial); OIDC works on every plan.
2. It sends the subject token to the Prego **STS** (`POST /v1/sts/token/e/<edge code>`, RFC 8693 token exchange).
3. The STS checks the subject token against the trust config and principals of your tenant. It returns a
   registry token.
4. The provider gives the registry token to Cargo, with an expiry time so Cargo can cache it.

### Token lifetime

From registry 1.16.0, a tenant owner sets the token lifetime per grant: 15 to 30 minutes on Indie, Org and
Publisher, fixed at 15 minutes on Trial and Consumer. The default is 15 minutes. A token gets
the shortest lifetime of the grants it can be used with. Revoking a machine takes effect within seconds,
whatever the lifetime.

From 0.5.0, the clients handle any lifetime:

- They send the registry URL as `resource`, so the STS gives the lifetime of the grants for that namespace.
- They compute the expiry from `expires_in` and the local time, never from the token's `exp` claim, so a
  wrong local clock does not matter.
- They cache a token until its expiry minus `min(60 s, lifetime / 4)`. The rule also works for a
  token shorter than a grant can set: Cargo caches a 1-minute token for 45 s.
- They get a new token before the old one expires (also between the parts of a big upload), and after a
  `401`. Go and Docker also get a new token after a `401` by themselves.
- On `429` from the STS, they wait for `Retry-After` (at most 60 s) and try again at most two times. A
  successful exchange counts against your tenant's budget per minute, not against your IP address.

Very short lifetimes mean many more token exchanges. `prego exec` (a `.netrc` for old Go) cannot get a new
token during the command, and warns when the lifetime is under 10 minutes. `prego whoami --resource <url>`
shows the lifetime for one namespace.

The provider never prints a token and never writes a token to disk. [PROTOCOL.md](PROTOCOL.md) has the full
contract, so you can write your own client.

## Install

The install script puts all three tools on your `PATH` (`~/.local/bin`, or `--dir DIR`). It checks the
SHA-256 sum of the download and never uses `sudo`:

```sh
curl -fsSLO https://github.com/group-katskill/prego-clients/releases/latest/download/install.sh
sh install.sh                    # or: sh install.sh --version 0.4.0 --dir /usr/local/bin
```

Or from [crates.io](https://crates.io/crates/prego) with Cargo (all five crates are there at 1.3.0, with the alias
`prego-cli`; versions 0.4.0 to 0.7.0 are only on the GitHub releases):

```sh
cargo install cargo-credential-prego docker-credential-prego prego
```

`cargo install prego-cli` is the same: the crate `prego-cli` is an alias of `prego`, with the same source and
version, and it installs the same `prego` binary. Install one of the two, not both.

Each [GitHub release](https://github.com/group-katskill/prego-clients/releases) (tag `prego-clients-vX.Y.Z`) has
prebuilt binaries with SHA-256 sums for:

- `x86_64-unknown-linux-musl` (static)

Prebuilt binaries are Linux x86_64 only for now. Linux arm64 and macOS binaries come after the 2.0 release. On
those systems, use `cargo install` (Cargo 1.74 or later). Earlier releases keep their arm64 and macOS binaries.

`prego-clients-<target>.tar.gz` holds all three binaries. `<binary>-<target>.tar.gz` holds one binary, for CI
jobs that need only one. `SHA256SUMS` lists all files. Check a download:

```sh
sha256sum -c cargo-credential-prego-x86_64-unknown-linux-musl.tar.gz.sha256
```

### Verify a release

A SHA-256 sum shows that a download is complete. It does not show who made it, because the sums come from the
same release. From 0.3.0, the release workflow signs `SHA256SUMS` with [cosign](https://docs.sigstore.dev/)
(keyless): the signing certificate is issued to the GitHub Actions identity of `release.yml` at the release tag,
and the signature is in the public Sigstore transparency log. `SHA256SUMS.sigstore.json` holds the bundle.

Check the signature, then the sums (cosign 3.0 or later):

```sh
V=0.7.0
base=https://github.com/group-katskill/prego-clients/releases/download/prego-clients-v$V
curl -fsSLO "$base/SHA256SUMS" -O "$base/SHA256SUMS.sigstore.json" \
  -O "$base/prego-clients-x86_64-unknown-linux-musl.tar.gz"
cosign verify-blob SHA256SUMS \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/group-katskill/prego-clients/.github/workflows/release.yml@refs/tags/prego-clients-v$V" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --ignore-missing -c SHA256SUMS
```

`cosign verify-blob` must print `Verified OK`. A signature from any other workflow, repository or tag fails.
Releases before 0.3.0 are not signed.

Releases up to 0.1.2 have the tag `cargo-credential-prego-vX.Y.Z` and hold only `cargo-credential-prego`.

Cargo 1.74 or later is necessary.

## Configure Cargo

```toml
# .cargo/config.toml
[registries.acme]
index = "sparse+https://cargo.prego.k8skill.com/t/acme/default/index/"
credential-provider = ["cargo-credential-prego", "--tenant", "acme"]
```

Replace `acme` with your tenant slug. Replace `default` with your namespace if you use another one.

### Arguments and environment

Put arguments after the binary name in `credential-provider`. Each argument has an environment fallback, and
then a fallback in the [settings file](#settings-file).

| Argument | Environment | Default | Meaning |
| --- | --- | --- | --- |
| `--tenant <slug>` | `PREGO_TENANT` | required | Tenant slug sent to the STS. Can also come from the [settings file](#settings-file). |
| `--sts-url <url>` | `PREGO_STS_URL` | `https://api.prego.k8skill.com/v1/sts/token` | STS endpoint. The console's token URL (`.../v1/sts/token/e/<edge code>`) also works. |
| `--edge-code <code>` | `PREGO_EDGE_CODE` | required | Your tenant's edge code, 4 characters, for example `k7mq`. The console shows it. See [Edge code](#edge-code). |
| `--audience <aud>` | `PREGO_AUDIENCE` | `prego.k8skill.com` | Audience to request for SVIDs and CI tokens. |
| `--source <name>` | `PREGO_SOURCE` | `auto` | Use only one source: `spiffe`, `svid-file`, `gitlab`, `github`, `token-file`, `api-key`. |
| | `PREGO_CA_FILE` | none | PEM CA bundle to trust in addition to the built-in roots. For on-prem TLS proxies. |

Safety rules:

- The STS URL must use `https`. Plain `http` is accepted only for `localhost`, `127.0.0.1` and `[::1]`
  (local tests).
- The provider never follows an HTTP redirect, so a subject token cannot go to another host.
- TLS certificate checks are always on. There is no option to turn them off. If an on-prem TLS proxy
  re-signs traffic, put its CA certificates in a PEM file and set `PREGO_CA_FILE` to its path.
- The provider keeps no token cache. Cargo caches the registry token until its expiry time.

`cargo-credential-prego --version` prints the version and the git commit of the build.

## Configure Docker

`docker-credential-prego` gives Docker your machine identity for the Prego OCI registry
(`oci.prego.k8skill.com`). No password is written to `~/.docker/config.json`.

```json
{ "credHelpers": { "oci.prego.k8skill.com": "prego" } }
```

Set the tenant in the [settings file](#settings-file) or in `PREGO_TENANT`. Docker cannot give arguments to a
credential helper. Then:

```sh
docker pull oci.prego.k8skill.com/acme/default/api:1.0.0
```

For a Prego host, the helper gives Docker the tenant as the username and the subject token (from the
[identity sources](#identity-sources)) as the password. Docker sends them only to the Prego token realm
(`https://api.prego.k8skill.com/v1/oci/token/e/<edge code>`, from the registry's challenge;
sts.prego.k8skill.com is an alias and keeps working). For all other hosts the helper answers "not found", so Docker
uses its other credentials. `docker login` and `docker logout` do not change anything in the helper. Podman
uses the same `credHelpers` key in `auth.json`.

**Layer limit:** `docker push` (and Podman and BuildKit) sends each layer in one request, and Prego accepts at
most 95 MiB in one request. So `docker push` of an image with a layer larger than 95 MiB fails. Use
`prego oci push` for such an image. It sends each layer in parts of at most 95 MiB:

```sh
docker save acme-api:1.4.0 -o api.tar          # or an OCI image layout directory (buildah, skopeo, crane)
prego oci push api.tar acme/default/api:1.4.0
```

In CI you can also sign in with no helper: `echo "$PREGO_ID_TOKEN" | docker login oci.prego.k8skill.com -u acme
--password-stdin`. The CI token expires after the job.

With the `prego` CLI, `prego setup docker --write` adds the `credHelpers` entry for you. It makes a backup
copy of `config.json` first and keeps all other keys.

## Push and pull images

Prego has an OCI registry at `oci.prego.k8skill.com`. Image names are
`oci.prego.k8skill.com/<tenant>/<namespace>/<repo>:<tag>`. Docker, Podman, BuildKit, crane, ORAS, Helm and cosign
work with it through `docker-credential-prego` ([Configure Docker](#configure-docker)). Grants for images use
`ecosystem = oci` with the actions `read`, `publish` and `delete`. One `any` grant covers images and crates.

The [OCI quickstart](artifact-types/oci/quickstart.md) has the steps for each tool, multi-platform images, cosign
signatures, big layers with `prego oci push`, a Kubernetes `imagePullSecret`, and the errors. CI jobs:
[CI guide](docs/ci.md#build-and-push-images).

## Go modules

From prego 0.4.0. Prego serves private Go modules on `go.prego.k8skill.com` through the GOPROXY protocol.
Public modules still come from `proxy.golang.org`.

```sh
prego setup go --prefix go.acme.com --write   # GOPROXY, GONOSUMDB, GOAUTH='prego go-auth'
go get go.acme.com/core@v1.4.0
git tag v1.4.0 && prego go publish --dry-run && prego go publish
```

- `prego go-auth` is the GOAUTH helper (Go 1.24 or later). It gives a registry token to Go for the Prego URL
  only, and caches it in a private file until it expires. Write `GOAUTH='prego go-auth'`, with no word
  `command` in front.
- `prego go publish` builds the zip from the git tree of the tag, never from the working directory, with
  Go's own file rules and hashes. A zip can be at most 300 MiB. Zips above 95 MiB go up in parts.
- `prego exec -- go build ./...` is for Go before 1.24: a temporary `.netrc` with a registry token.

The [Go quickstart](artifact-types/go/quickstart.md) has the console setup, publishing, CI, the privacy note on module
paths, and the errors. [PROTOCOL.md](PROTOCOL.md) section 9 has the helper contract.

## npm packages

From prego 0.6.0. Prego serves private **scoped** npm packages (`@acme/core`) on `npm.prego.k8skill.com`. All
other packages still come from registry.npmjs.org.

```sh
prego setup npm --scope @acme        # .npmrc: the scope line and ${PREGO_NPM_TOKEN}, never a token
prego exec -- npm install            # or: eval "$(prego npm-env)"
prego exec -- npm publish
```

- `prego setup npm` writes `.npmrc` (npm, pnpm), `.yarnrc.yml` (`--client yarn`) or `bunfig.toml`
  (`--client bun`). Commit the file: it holds the variable name only.
- `prego exec` sets `PREGO_NPM_TOKEN` for one command. `prego npm-env` exports it in the shell. In CI:
  `export PREGO_NPM_TOKEN="$(prego token)"`.
- Create the free organization `@acme` on npmjs.com too, against dependency confusion.

The [npm quickstart](artifact-types/npm/quickstart.md) has the console setup, publishing, CI, trusted publishing, the
dependency-confusion note and the errors. [PROTOCOL.md](PROTOCOL.md) section 10 has the client contract.

## Python packages

From prego 0.9.0 and registry 1.9.0 (Trial, Indie, Org and Publisher plans). Prego serves private Python packages on
`pypi.prego.k8skill.com`, one index for each namespace. Public packages still come from pypi.org.

```sh
prego setup python                 # pyproject.toml: the prego index (explicit) and [tool.uv.sources]
prego exec -- uv sync              # a 30-minute Python token for uv, pip, twine and Poetry
prego python publish dist/*        # upload wheels and sdists (at most 90 MiB each)
```

- `prego exec` uses the Python mode for `uv`, `pip`, `python`, `twine`, `poetry`, `pdm` and `hatch`, or with
  `--python`. `--pip` also sets `PIP_EXTRA_INDEX_URL`.
- `prego token --python` prints a Python token for tools and for the keyring helper `keyrings.prego`
  (`keyrings-prego/`, not on pypi.org yet).
- Use uv or Poetry with the explicit index, against dependency confusion.

The [Python guide](artifact-types/python/quickstart.md) has pip, Poetry, publishing, CI and the errors.
[PROTOCOL.md](PROTOCOL.md) section 13 has the client contract.

## Adapters

**Preview.** The `prego adapter` commands and flags can still change in a 1.x minor release (see [Stability](#stability)).

From prego 0.10.0 and registry 1.11.1 (Publisher plan and Trial). AI model adapters are the fine-tuned
layers (LoRA and the other peft methods) of your AI models. Prego keeps them as one checked OCI artifact:
`adapter_config.json`, one `.safetensors` weights file and at most 8 text files, at most 2 GiB.

```sh
prego adapter push ./out/support-bot acme/ml/support-bot:2026-11-14 --license LicenseRef-llama3.1
prego adapter get acme/ml/support-bot:2026-11-14 ./adapters/support-bot
```

- `prego adapter push` checks the folder with the rules of the registry before it sends anything. Pickle files
  (`.bin`, `.pt`, `.ckpt`) are refused. A license is required (`--license`, or `license:` in the README.md
  front matter). `--base-revision` records the commit of the base model.
- A version is written one time only. A second push of other content to the same version gets `409`.
- `prego adapter get` writes the files to a new or empty folder and checks the SHA-256 of each file. Load it with
  `PeftModel.from_pretrained(base, "./adapters/support-bot")` or vLLM `--lora-modules`.

The [Adapters quickstart](artifact-types/adapters/quickstart.md) has the console setup, the rules, loading, CI and the
errors.

## Release Variables

From prego 0.8.0 and registry 1.8.0. Release Variables are plain settings that go with a release (an API base
URL, feature flags), on the tenant, a namespace or a package version. A machine that can pull the release can
read them with the same identity.

**Release Variables are plain text, readable by everyone who can pull the release. Do not store passwords,
tokens or keys here.**

```sh
prego env pull acme/releases/payments@1.4.0 --out release.env --expect sha256:...   # exit 3 if it changed
prego env push acme/releases/payments@1.4.0 --file release-vars.json               # replaces the whole set
prego env history acme/releases/payments@1.4.0
prego env rollback acme/releases/payments@1.4.0 --to 2 --reason "..."
prego env hash release-vars.json                                                   # offline, RFC 8785
```

The [Release Variables guide](artifact-types/release-variables/quickstart.md) has the levels, the merge, references, access, CI and
the errors. [PROTOCOL.md](PROTOCOL.md) section 12 has the client contract.

## Snippets

From prego 1.0.0 and registry 1.24.0. A snippet is a named set of text files (scripts, prompts, agent skills,
templates) with versions that do not change, read by machines and agents with the identity they already have.
Like a gist, but private and versioned.

**An agent follows the text in a snippet. Pin the hash with `--expect`, and grant `read` only on snippets you
trust.**

```sh
prego snippet push ./deploy-scripts acme/ops/deploy-scripts --tag stable     # a new version, if the files changed
prego snippet get acme/ops/deploy-scripts@stable ./scripts --expect sha256:...  # exit 3 if it changed
prego snippet log acme/ops/deploy-scripts
prego snippet diff acme/ops/deploy-scripts 6 stable
prego snippet rollback acme/ops/deploy-scripts --to 6 --reason "..."
prego snippet hash ./deploy-scripts                                            # offline
```

The [Snippets guide](artifact-types/snippets/quickstart.md) has references, the file rules, the hash, CI and the errors.
[PROTOCOL.md](PROTOCOL.md) section 14 has the client contract.

## Context

From prego 1.1.0 and registry 1.25.0. Context is agent context that you save in Prego: memory files, notes,
plans, task lists and transcripts. An agent saves a checkpoint before it compacts or stops; later the same agent
or another agent restores it. Agents use the identity they already have; they do not keep a key.

```sh
prego context save ./.agent-memory acme/agents/billing-agent --session 2026-11-20-a --trigger compact
prego context restore acme/agents/billing-agent ./.agent-memory --session 2026-11-20-a
prego context restore acme/agents/billing-agent@handoff ./.agent-memory --expect sha256:...   # exit 3 if it changed
prego context log acme/agents/billing-agent --session 2026-11-20-a
prego context tag acme/agents/billing-agent@42 handoff
prego context set acme/agents/billing-agent --keep-days 30 --on-full drop_oldest
```

Before the upload, `prego` replaces strings that look like keys or tokens with `[REDACTED:<kind>]` and prints how
many it replaced (`--no-redact` turns this off). If the registry refuses a save, `prego` keeps the checkpoint in
`./.prego-context/`, prints the path and exits with 4: the context is not lost.

**An agent follows the text in the context that it restores. Pin the hash with `--expect`, and grant `read` only
to agents you trust.**

### Save context before compaction

Run `prego context save` from the hook that your agent tool runs before it compacts its context. For example, a
pre-compaction hook command:

```sh
prego context save "$HOME/.agent-memory" acme/agents/billing-agent \
  --session "${AGENT_SESSION_ID:-$(date -u +%Y-%m-%d)}" --trigger compact --message "before compaction"
```

The same files as the latest checkpoint of the session make no new checkpoint, so the hook can run often. A
refused save exits with 4 and keeps the checkpoint in `./.prego-context/`; make the hook report that exit code
instead of failing the agent.

The [Context guide](artifact-types/context/quickstart.md) has references, restore, tags, retention, the file rules and the errors.
[PROTOCOL.md](PROTOCOL.md) section 15 has the client contract.

## Share a SQLite database

From prego 1.2.0 and registry 1.26.0. SQLite snapshots share a SQLite database with your machines,
your agents and other developers: save a snapshot from one machine, restore it on many. They use the identity
they already have; they do not keep a key.

**We are not your backup. We are for sharing.** Prego does not give point-in-time recovery. Keep your own backups
of data that you must not lose.

`prego sqlite save` makes the snapshot with SQLite, never by copying the file, so the application can keep using
the database. It runs `PRAGMA quick_check` on the snapshot first; if the check fails, nothing is sent and the exit
code is 5. A restore writes a new file, checks the hashes and `quick_check`, and only then replaces the target.

Save after a build in CI (GitLab CI here; the job uses its OIDC identity, see [GitLab CI](#gitlab-ci)):

```yaml
build-lookup:
  id_tokens:
    PREGO_ID_TOKEN:
      aud: prego.k8skill.com
  script:
    - ./build-lookup-db.sh lookup.db
    - prego sqlite save lookup.db acme/fleet/lookup --message "build $CI_COMMIT_SHORT_SHA" --label commit=$CI_COMMIT_SHA
```

Restore at start-up on each machine of a fleet, pinned by hash, before the application opens the database:

```sh
prego sqlite restore acme/fleet/lookup@2026-11-20 /var/lib/app/lookup.db \
  --expect sha256:<hash from prego sqlite log>
exec /usr/local/bin/app --db /var/lib/app/lookup.db
```

A different hash exits with 3 and writes nothing. A database with a `-wal` or `-journal` file next to it is not
replaced unless `--force`: stop the application first.

```sh
prego sqlite log acme/fleet/lookup                     # snapshots, newest first
prego sqlite tag acme/fleet/lookup@42 2026-11-20       # keep a snapshot
prego sqlite prune acme/fleet/lookup --older-than 7d   # remove old snapshots (asks first; --yes in scripts)
prego sqlite set acme/fleet/lookup --keep-count 10 --keep-days 14
```

The [SQLite snapshots guide](artifact-types/sqlite-snapshots/quickstart.md) has references, restore, rotation, the exit codes and the errors.
[PROTOCOL.md](PROTOCOL.md) section 16 has the client contract.

## Keys and Certificates

From prego 1.3.0. Keys and Certificates holds the public keys and certificates of your team: SSH public keys and
SSH certificates, OpenPGP public keys, public JWKs and JWK Sets, PEM `PUBLIC KEY` files, and X.509 certificates and
bundles. Prego checks each entry by its type and records its fingerprint and validity. Versions do not change.

**Keys and Certificates holds public keys and certificates only; Prego never stores a private key.** `prego keys`
checks every file before the upload. A private key stops the push, and nothing is sent.

```sh
prego keys new --alg ed25519 acme/release-keys/signer --out ./signer.private.pem   # private key stays here (0600)
prego keys push ~/.ssh/deploy_ed25519.pub acme/release-keys/deploy                 # the type comes from the content
prego keys push ca-bundle.pem acme/release-keys/internal-ca --type x509
prego keys get acme/release-keys/deploy                  # type, algorithm, fingerprint, validity, revoke state
prego keys fingerprint ~/.ssh/deploy_ed25519.pub         # offline
prego keys revoke acme/release-keys/signer --reason "laptop lost"   # one-way; signatures then fail --verify
```

The [Keys and Certificates quickstart](artifact-types/keys/quickstart.md) has the entry types, the private-key
check, tags, rollback, revoke and the errors.

## A2A Agent Cards

From prego 1.3.0. A2A (Agent2Agent) Agent Cards describe an agent: its name, endpoints, skills and security schemes.
Prego keeps a set of A2A 1.0 cards as one signed version that does not change. Every card and every set is signed
with a key from Keys and Certificates. Prego does not serve cards in public.

```sh
prego a2a check ./cards                                         # offline: the A2A 1.0 schema
prego a2a push ./cards acme/agents/support --sign ./signer.private.pem --key acme/release-keys/signer
prego a2a get acme/agents/support@stable ./support-cards --verify
prego a2a upgrade ./agent.json                                  # A2A 0.3 to 1.0, offline, no account needed
```

- `--sign` signs each card (an A2A 1.0 signature) and the set on your computer. Prego never gets the private key.
  It also adds the Prego source extension (`https://prego.k8skill.com/ext/a2a-source/v1`: tenant, namespace, set)
  to each card before it signs; `--no-source` leaves it out.
- `--verify` needs `read` on the card set and `read` on the signing key item. A missing grant is named:
  "verify needs read on key acme/release-keys/signer (type Keys and Certificates); ask an admin of acme for a grant".
- `prego a2a upgrade` needs no Prego account. It prints each change, stops and names the field when it cannot map
  one, and writes an unsigned card.

The [A2A Agent Cards quickstart](artifact-types/a2a/quickstart.md) has the rules, CI and the errors.
[`artifact-types/a2a/examples/`](artifact-types/a2a/examples/) has a sample card set, a script and CI jobs.

## Verify where a version came from

From prego 1.4.0 and the registry with ADR-0065. At each publish, Prego writes a signed publish attestation from
the identity that it checked at the front door: the CI issuer, the repository or project, the ref, the commit, the
workflow and the run. `prego verify` checks it.

```sh
prego verify cargo:acme/default/payments@1.4.0
prego verify npm:acme/default/@acme/hello --repository acme/hello --ref v1.2.0 --level ci_source --hosted-runner
prego verify oci:acme/default/api@v1 --sha "$GITHUB_SHA" --json
```

- It checks the Prego signature with the public keys at
  `https://api.prego.k8skill.com/.well-known/prego-attestation-keys.json` (or a local copy, `--keys <file>`), that
  the attestation names this version, and the content digest, which it computes from a download of the content.
- `--repository`, `--ref`, `--sha`, `--level` and `--hosted-runner` are a policy: each one must match.
- Python: each file of a release has its own attestation (the wheels and the sdist can come from different jobs).
  `prego verify` checks each file and prints its facts.
- Exit codes: 0 verified; 1 a signature, version, digest or policy mismatch; 3 the version has no attestation
  (published before attestations started); 2 a usage or network error.
- The attestation says who published the bytes and from which pipeline. It does not say that the bytes were built
  from that source: a CI job that is compromised can still publish bad bytes with a correct attestation.

## API specs (OpenAPI, GraphQL)

From prego 1.4.0 and the registry with ADR-0067. Versioned OpenAPI 3.0 and 3.1 documents and GraphQL schemas (SDL):
one document per version, a SemVer label, a body that does not change, a stable URL, and an informational diff. A
spec keeps the format of its first version.

```sh
prego apispec push ./openapi.yaml acme/payments-api@1.4.0 --tag stable
prego apispec push ./schema acme/payments-graph@2.0.0          # a folder of .graphql files, joined in path order
prego apispec get acme/payments-api@1.4.0 --out openapi.yaml
prego apispec diff acme/payments-api@1.3.0 acme/payments-api@1.4.0
```

- Swagger 2.0 is refused before the upload. Bundle external `$ref`s first; Prego does not follow them.
- GraphQL: the schema only. A query, mutation, subscription or fragment is refused before the upload.
- The diff comes from the registry, the same as in the console. It says "added", "removed" or "changed", never
  "breaking". OpenAPI: it does not look inside `components.schemas` ("schema `<name>` changed"). GraphQL: types,
  fields, arguments, enum values, union members and directives, by schema coordinate (`Query.user(id:)`).

The [API specs quickstart](artifact-types/apispec/quickstart.md) has the checks, CI and the errors.

## Not in 1.0.0

Prego registry 1.0.0 does not have these:

- Layers above 95 MiB with stock `docker push`, Podman or BuildKit. Use `prego oci push`.
- Public or anonymous images. Every pull needs an identity.
- `/v2/_catalog`.
- A pull-through cache of Docker Hub, GHCR or other registries.
- Vulnerability scanning, or a signature policy. cosign signatures are stored, not checked.
- Webhooks and replication.
- A kubelet credential provider. Kubernetes pulls use an `imagePullSecret` with a read-only API key.
- `cargo login` and `cargo logout` ([Login and logout](#login-and-logout)).

## The prego CLI

```sh
prego login [--publish] [--namespace <ns>]...  # log in on a laptop with your console account (0.7.0)
prego status                     # the login session: tenant, access, end time (0.7.0)
prego logout                     # end the session and delete it from this computer (0.7.0)
prego whoami                     # tenant, identity source, principal, token lifetime, registry URLs (no token)
prego token                      # a registry token on stdout (15 minutes by default)
prego setup cargo                # the .cargo/config.toml snippet
prego setup docker --write       # add credHelpers to ~/.docker/config.json
prego oci push api.tar acme/default/api:1.4.0   # push an image, big layers in parts
prego setup go --prefix go.acme.com             # the go env -w lines (0.4.0)
prego go publish --dry-run                      # a Go module zip from the tag (0.4.0)
prego setup npm --scope @acme                   # .npmrc lines with ${PREGO_NPM_TOKEN} (0.6.0)
prego exec -- npm install                       # a fresh token in PREGO_NPM_TOKEN (0.6.0)
prego env pull acme/payments@1.4.0 --out release.env   # Release Variables of a release (0.8.0)
prego env push acme/payments@1.4.0 --file vars.json    # push a new version of the set (0.8.0)
prego setup python                              # the uv index in pyproject.toml (0.9.0)
prego exec -- uv sync                           # a Python token for uv, pip, twine, Poetry (0.9.0)
prego python publish dist/*                     # upload wheels and sdists (0.9.0)
prego adapter push ./out/bot acme/ml/bot:v1     # push an AI model adapter (0.10.0, Publisher)
prego adapter get acme/ml/bot:v1 ./adapters/bot # write an adapter to a folder (0.10.0)
prego snippet push ./skill acme/agent-skill     # push a new version of a snippet (1.0.0)
prego snippet get acme/agent-skill@stable --expect sha256:...   # get a pinned snippet (1.0.0)
prego context save ./.agent-memory acme/agents/a1 --trigger compact   # save agent context (1.1.0)
prego context restore acme/agents/a1 ./.agent-memory --expect sha256:...   # restore a pinned checkpoint (1.1.0)
prego sqlite save ./app.db acme/fleet/lookup        # save a SQLite snapshot (1.2.0)
prego sqlite restore acme/fleet/lookup ./lookup.db --expect sha256:...   # restore a pinned snapshot (1.2.0)
prego keys new --alg ed25519 acme/release-keys/signer   # a key pair: private key local (0600), public JWK pushed (1.3.0)
prego keys push deploy.pub acme/release-keys/deploy      # push public keys and certificates (1.3.0)
prego keys get acme/release-keys/deploy                  # entries, fingerprints, validity, revoke state (1.3.0)
prego keys fingerprint deploy.pub                        # fingerprints, offline (1.3.0)
prego a2a check ./cards                                  # check A2A 1.0 Agent Cards, offline (1.3.0)
prego a2a push ./cards acme/agents/support --sign ./signer.private.pem --key acme/release-keys/signer   # sign and push (1.3.0)
prego a2a get acme/agents/support ./cards --verify       # get a card set and check the signatures (1.3.0)
prego a2a upgrade ./agent.json                           # A2A 0.3 card to 1.0, offline, no account (1.3.0)
prego verify npm:acme/default/@acme/hello@1.2.0          # check the publish attestation and the content (1.4.0)
```

`prego oci push <input> <image>`:

- `<input>` is an OCI image layout directory, or a tar file from `docker save` (the old format and the OCI
  format of Docker 25 and later). Decompress a `.tar.gz` first. A multi-platform image index is pushed with all
  its platforms; each platform must be in the input.
- `<image>` is `[oci.prego.k8skill.com/]<tenant>/<namespace>/<repo>[:tag]`. The tag is `latest` if not given.
- Each blob that the repository does not have is sent in parts with `Content-Range`. The part size is
  64 MiB by default (`--chunk-size <MiB>`), at least the size the registry asks for, at most 95 MiB. After a
  network error or a `416`, the push asks the registry how much it has and goes on from there.
- `--from <tenant>/<namespace>/<repo>` mounts blobs that are already in that repository, with no upload.
- It checks the digest of each blob before the upload, and stops before any upload if one does not match.
- It gets one registry token for the push and uses it again until 30 s before it expires (at most 60 token
  requests per minute). The identity goes only to the Prego token realm.
- It prints `<host>/<name>:<tag>@<digest>` on stdout, and the progress on stderr.

`prego` takes the same options (`--tenant`, `--sts-url`, `--audience`, `--source`) and the same identity
sources as the other tools. `prego token` prints a secret: put it in a variable, not in a log.

## Settings file

All Prego client tools read `~/.config/prego/config.toml` (or `$XDG_CONFIG_HOME/prego/config.toml`):

```toml
tenant = "acme"
edge_code = "k7mq"   # from the console (0.6.0)
# Optional: sts_url, audience, source, oci_hosts = ["..."] for more OCI hosts,
# go_hosts = ["..."] and go_prefixes = ["go.acme.com"] (0.4.0), npm_host = "..." (0.6.0),
# pypi_host = "..." (0.9.0).
```

### Edge code

From 0.6.0 the tools get registry tokens at `https://api.prego.k8skill.com/v1/sts/token/e/<edge code>` (from
0.11.0 the default host is `api.`; sts.prego.k8skill.com is an alias and keeps working). The
edge code is 4 characters, fixed for your tenant, for example `k7mq`. It is not a secret. The Prego console
shows it, and the answer that creates a principal (API key or trust) has it as `edge_code` and as the full
`token_url`. Set it one time: `edge_code` in the settings file, `PREGO_EDGE_CODE`, or `--edge-code`. You can
also set `sts_url` to the `token_url`. Without it, the tools stop with "the edge code of your tenant is not
set". Tools before 0.6.0 get "this client uses an old token URL" from the STS: upgrade them.

Docker and `prego push` take the token realm from the registry's `401` answer for the repository. It has the
edge code of the repository's tenant, which can be another tenant that gives you a grant. `prego token
--scope` uses your own tenant's realm. The
admin API exchange (`prego setup` defaults) does not need it.

An argument or a `PREGO_*` variable wins over the file. The file must not hold a secret: a key such as
`api_key` or `token` is an error. [PROTOCOL.md](PROTOCOL.md) section 8 has the format.

## Identity sources

In `auto` mode the provider uses the first source that is present, in this order:

| Order | Source | Present when | Subject token type |
| --- | --- | --- | --- |
| 1 | `spiffe` | `SPIFFE_ENDPOINT_SOCKET` is set | JWT-SVID from the SPIFFE Workload API |
| 2 | `svid-file` | `PREGO_SVID_FILE` is set | JWT-SVID read from that file |
| 3 | `gitlab` | `PREGO_ID_TOKEN` is set | GitLab CI `id_tokens` value |
| 4 | `github` | `ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN` are set | GitHub Actions OIDC token |
| 5 | `token-file` | `PREGO_TOKEN_FILE` is set | OIDC JWT read from that file |
| 6 | `api-key` | `PREGO_API_KEY` is set | Prego API key `prk_...` |
| 7 | `device` | none of the above, and you ran `prego login` (0.7.0) | none: a session refresh gives the registry token |

The SPIFFE sources (`spiffe` and `svid-file`) need the Org or Publisher plan (or a Trial). Indie and
Consumer do not have SPIFFE machine identity: use OIDC, a token file or an API key there.

If no source is present, the error lists the sources that the provider checked.

Auto mode fails closed. If the first present source fails (for example, a bad token file), the provider
stops with an error that names that source. It never falls through to the next source, so it never uses an
identity that you did not expect. Fix the source, or use `--source <name>` to choose another one.

### GitLab CI

```yaml
build:
  id_tokens:
    PREGO_ID_TOKEN:
      aud: prego.k8skill.com
  script:
    - cargo build --locked
```

### GitHub Actions

```yaml
permissions:
  id-token: write
  contents: read
```

The provider requests the token with audience `prego.k8skill.com`.

### Kubernetes and cloud workload identity

Mount a projected service account token (or an AWS/GCP web identity token file) and set
`PREGO_TOKEN_FILE` to its path. Set the token audience to `prego.k8skill.com`.

### API key

```sh
export PREGO_API_KEY=prk_...   # from the Prego console
cargo build
```

The STS takes the tenant from the API key. Registry endpoints never accept an API key directly.

## Login and logout

On a laptop, use `prego login` and `prego logout` ([Quick start](#quick-start-on-a-laptop)). `prego login`
prints a code; confirm it at <https://app.prego.k8skill.com/device> while you are signed in to the console. A
login with `--publish` asks for your passkey there.

The session is for namespace `default`. To use another namespace, give `--namespace <ns>` (up to 10 times):
`prego login --publish --namespace releases --namespace team-a`. `prego status` shows the namespaces of the
session. A namespace is 3 to 40 lower case letters, digits and `-`; `prego login` checks it before the request. `cargo login`,
`cargo logout`, `docker login` and `npm login` are not supported. Manage trust configs, principals and API keys in the
Prego console at <https://app.prego.k8skill.com>, or from CI with an admin token
(see [Manage Prego from CI](docs/ci.md#manage-prego-from-ci) and [`examples/admin/`](examples/admin/)).

## Build from source

```sh
cargo build --release -p cargo-credential-prego -p docker-credential-prego -p prego
```

Feature `spiffe` of `prego-auth` (on by default) adds the SPIFFE Workload API source. It pulls in `tokio`
and `tonic`. Build without it if you do not use SPIFFE:

```sh
cargo build --release -p cargo-credential-prego --no-default-features
```

TLS uses `rustls` with the Mozilla root set (`webpki-roots`). No OpenSSL is necessary.

## Test

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Release

Releases come from GitHub Actions (`.github/workflows/release.yml`). The maintainer:

1. Moves the `Unreleased` items in each crate `CHANGELOG.md` under the new version.
2. Sets the same version in all four crates (`prego-auth`, `cargo-credential-prego`,
   `docker-credential-prego`, `prego`).
3. Commits `release: X.Y.Z` and pushes tag `prego-clients-vX.Y.Z`.

The workflow checks that the tag matches every crate version, builds the three binaries for the three targets
with cargo-zigbuild, signs `SHA256SUMS` with cosign (keyless, GitHub OIDC), and attaches everything to a GitHub
release: the archives with SHA-256 sums, `SHA256SUMS`, `SHA256SUMS.sigstore.json` and `install.sh`.
Publishing to crates.io is a separate manual step: `cargo publish --workspace --locked` from a clean checkout of
the tag. Cargo publishes `prego-auth` first. Then publish the alias `prego-cli` with
`tools/publish-prego-cli.sh prego-clients-vX.Y.Z` (a dry run) and the same command with `--publish`.

CI (`.github/workflows/ci.yml`) runs fmt, clippy and tests on every push to `main` and on every pull request.
The website in `site/` is deployed to GitHub Pages by `.github/workflows/pages.yml`.

## Stability

From 1.0.0, the Prego client tools follow [Semantic Versioning](https://semver.org/). Within 1.x, these do not
break:

- The command names and subcommands of `prego`, `cargo-credential-prego` and `docker-credential-prego`.
- The flags and options, their environment variables (`PREGO_*`) and their meaning.
- The exit codes: `0` success, `1` error, `2` an encryption mode that this version cannot read, `3` an
  `--expect` hash that does not match, `4` a refused `prego context save` (from 1.1.0; the checkpoint is kept) or
  `prego sqlite save` (from 1.2.0), `5` a failed `PRAGMA quick_check` or `integrity_check` in `prego sqlite`
  (from 1.2.0).
  `prego exec` exits with the code of the command it runs.
- The config file locations and their keys: `~/.config/prego/config.toml` (or
  `$XDG_CONFIG_HOME/prego/config.toml`), the login session in the OS keychain, and the files that `prego setup`
  writes.
- The credential-provider protocols: the Cargo credential provider protocol of `cargo-credential-prego`, the
  Docker credential helper protocol of `docker-credential-prego`, and `prego go-auth` as a GOAUTH command.
- [PROTOCOL.md](PROTOCOL.md), the contract between a client and the registry. A break is a new major version.

A 1.x release can add commands, flags, environment variables, config keys, JSON fields and exit codes for new
cases. A change to a default host name keeps the old name working.

Not covered:

- The text that commands print for people. Scripts use the exit codes, `--json`, `env pull --format`, and the
  hash that the `hash` commands print.
- The Rust API of the `prego-auth` crate. It serves the Prego tools.
- Preview features, marked "preview" in this README, the guides and `prego --help`. They can change in a 1.x
  minor release, with a CHANGELOG note. Preview now: `prego adapter push` and `prego adapter get`.

## Security

See [SECURITY.md](SECURITY.md).
