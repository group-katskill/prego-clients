# Quickstart: Go modules with Prego

**From prego 0.4.0.** Go modules need `prego` 0.4.0 or later and a Prego registry with the Go host
(`go.prego.k8skill.com`).

Prego serves private Go modules through the GOPROXY protocol. Public modules still come from
`proxy.golang.org` and are checked against `sum.golang.org`. This guide uses tenant `acme`, namespace
`default` and the module path prefix `go.acme.com`. Replace them with your own.

## What you need

- Go 1.24 or later for the GOAUTH helper. For older Go, see [Old Go and other build tools](#old-go-and-other-build-tools).
- `prego` 0.4.0 or later: the [install script](../README.md#install), or `cargo install prego` when crates.io
  has 0.4.0 or later. Use 0.5.0 or later for the 300 MiB check before the upload.
- In the Prego console (<https://app.prego.k8skill.com>), a tenant admin:
  - registers the **module path prefixes** of the tenant under **Settings**, for example `go.acme.com` or
    `github.com/acme`. On a shared code host the prefix has at least two parts (`github.com/acme`, not
    `github.com`).
  - gives a **grant** with `ecosystem = go` (or `any`) and the actions `read`, `publish` or `delete`. The glob
    is on the full module path: `go.acme.com/*`. Note: `go.acme.com/core` does not match
    `go.acme.com/core/v2`; use `go.acme.com/core*` or two grants.

## 1. Connect Go

```sh
prego setup go --prefix go.acme.com
```

It prints three lines. Run them, or use `prego setup go --write` to run them for you:

```sh
go env -w GOPROXY='https://go.prego.k8skill.com/t/acme/default,https://proxy.golang.org,direct'
go env -w GONOSUMDB='go.acme.com'
go env -w GOAUTH='prego go-auth'
```

- `GOPROXY`: Go asks Prego first. For a module that is not in Prego, Prego answers `404` and Go asks
  `proxy.golang.org`.
- `GONOSUMDB`: only your prefixes skip the public checksum database. All other modules are still checked.
  Do not use `GOPRIVATE` for this.
- `GOAUTH='prego go-auth'`: Go runs `prego go-auth` to get a token. Write it with no word `command` in front.
  If `GOAUTH` already has a value, `prego setup go` adds the helper at the end: `netrc;prego go-auth`.
  If `prego` is not on `PATH`, use its full path: `GOAUTH='/opt/prego/bin/prego go-auth'`.

The prefixes come from `--prefix` (one or more times), from `go_prefixes = ["go.acme.com"]` in
`~/.config/prego/config.toml`, or from the admin API when your identity can read it. The console Settings
page shows the line for your tenant.

Set your identity as for the other Prego tools. On a laptop, from prego 0.7.0, run `prego login` (add
`--publish` to publish modules) and approve the code in the console; or set `PREGO_API_KEY`. CI never uses
`prego login`. See the [identity sources](../README.md#identity-sources). With a login session,
`prego go-auth` keeps no token file cache and `prego exec` writes no `.netrc` file: use GOAUTH (Go 1.24).

## 2. Use a module

```sh
go get go.acme.com/core@v1.4.0
go build ./...
```

`prego go-auth` gets a registry token (15 minutes by default; the grant sets it, from 1 to 30 minutes) and
gives it to Go for the Prego URL only. Go never
sends it to `proxy.golang.org`. A long build gets a new token when Prego answers `401`. When Prego answers
`404` for a public module, the helper gives the same token again and makes no new STS call. The token cache
is a file with mode 0600 in `$XDG_RUNTIME_DIR/prego/` (or `$TMPDIR/prego-<uid>/`). It is deleted when the
token expires.

## 3. Publish a module

Tag the commit, then publish. `prego go publish` builds the zip from the **git tree of the tag**, never from
your working directory, so untracked files such as `.env` or build output can never go into the zip. Check
the file list one time with `--dry-run`:

```sh
git tag v1.4.0
prego go publish --dry-run          # the files, the size and the h1; nothing is sent
prego go publish                    # prints: go get go.acme.com/core@v1.4.0
```

- The tag defaults to the tag on `HEAD`. Give it as a word to choose: `prego go publish . v1.4.0`.
- A module in a subdirectory uses tags such as `tools/v1.0.0`: `prego go publish tools tools/v1.0.0`.
- `v2` and later need a module path that ends in `/v2` (Go's major version rule). The module can be at the
  root, or in a `v2/` directory with tags `v2.x.y`.
- Only tagged releases: no pseudo-versions, no `+incompatible`, no build metadata.
- `--namespace rel` publishes to another namespace. `--json` prints `{"module", "version", "h1", "mod_h1"}`.
- Versions are immutable. A second publish of the same version gets `409`, also after a delete. To withdraw a
  version, add a `retract` line to `go.mod` and publish a new version.
- A zip can be up to 300 MiB, compressed and uncompressed (Go itself allows 500 MiB). `go.mod` can be up to
  1 MiB. A zip above 95 MiB is sent in parts. From 0.5.0, `prego go publish` refuses a bigger module before it
  sends anything. Move large files out of the module, for example into an OCI artifact.
- The file rules are Go's own: no vendored packages, no files of nested modules, no symlinks. If a module in
  a subdirectory has no `LICENSE`, the root `LICENSE` is added, as the go command does.

The registry computes the h1 again. `prego go publish` fails if it differs from the local one, so the
`go.sum` lines of your users always match.

## CI

**GitLab CI:** the job's ID token is the identity. Nothing is stored.

```yaml
build:
  image: golang:1.26
  id_tokens:
    PREGO_ID_TOKEN:
      aud: prego.k8skill.com
  variables:
    PREGO_TENANT: acme
    PREGO_EDGE_CODE: k7mq
  script:
    - prego setup go --write --prefix go.acme.com   # install prego first (see the README)
    - go build ./...

publish:
  image: golang:1.26
  id_tokens:
    PREGO_ID_TOKEN:
      aud: prego.k8skill.com
  variables:
    PREGO_TENANT: acme
    PREGO_EDGE_CODE: k7mq
  rules:
    - if: $CI_COMMIT_TAG
  script:
    - prego go publish . "$CI_COMMIT_TAG"
```

The publish principal needs a `publish` grant and should pin a protected ref (see [ci.md](ci.md)).

**GitHub Actions:** give the job `permissions: id-token: write` and run the same commands. `prego` requests
the OIDC token with audience `prego.k8skill.com`.

## Old Go and other build tools

For Go before 1.24, or a tool with no GOAUTH, run the command through `prego exec`:

```sh
prego exec -- go build ./...
```

It writes a temporary `.netrc` (mode 0600, deleted when the command ends) with a registry token for the Go
host, and sets `NETRC` for the command. Go reads the file once, so the token cannot be renewed during the
command. `prego exec` prints the token lifetime, and warns when it is under 10 minutes ("token valid for 5
min; long builds need GOAUTH, see prego setup go").
If `prego` itself is killed (for example with `SIGKILL`), the netrc file (mode 0600) can stay in the
private cache directory (mode 0700, or the temporary directory if no private one is safe to use) until you
delete it. The token in it expires after its lifetime (at most 30 minutes).

## Last resort: an API key in `.netrc`

Use `prego go-auth` (GOAUTH) first, then `prego exec`. Use a static `.netrc` with an API key only when neither
works, for example a Docker build secret for an old tool. The key is a long-lived secret in a file.

```
machine go.prego.k8skill.com login acme password prk_...
```

From registry 1.6.0, the Go host accepts the key only when all of these are true:

- The key's principal has a Go grant (`ecosystem = go`) with the actions `read` only. A grant with
  `ecosystem = any` cannot have the switch.
- An admin turned on **Allow this API key in .netrc (older Go tools)** for that grant: in the console, Grants,
  the Go grant. In the admin API it is `allow_netrc_api_key: true` on the grant. Prego refuses it on any grant
  that is not Go with `read` only. It is off by default.
- The module is one that such a grant matches.

Otherwise the Go host answers `401` with `prego: use a read-only API key or "prego go-auth"`. A key that can
publish or delete is never accepted. When registry 1.6.0 was deployed, Prego turned the switch on for the Go
read grants of keys that used `.netrc` in the 30 days before, and for the Go read grants that other tenants gave
to those keys' tenants. Until that step ran (within an hour of the deploy), the old rule applied. Any other key
needs an admin to turn it on.

This changes nothing for `prego go-auth`, for `prego exec`, or for a registry token in `.netrc`.

## Privacy of module paths

When Prego answers `404` (a path inside your prefix that is not a module, or a module you have no grant
for), Go asks the next `GOPROXY` entry, and that path name goes to `proxy.golang.org`. The contents of your
modules never go there. For builds that use only private modules, or for sensitive tenants, end `GOPROXY`
with `off`:

```sh
go env -w GOPROXY='https://go.prego.k8skill.com/t/acme/default,off'
```

Do not put `proxy.golang.org` first: then every private path name goes to it first.

## Errors

| Message | Cause and fix |
| --- | --- |
| `401` with `prego: run "prego setup go"` | No token, or the wrong kind of token. Check `GOAUTH='prego go-auth'` (no word `command`), your identity, and `PREGO_TENANT`. Run `go env GOAUTH` and `prego whoami`. |
| `401` with `prego: use a read-only API key or "prego go-auth"` | An API key in `.netrc` that Prego does not accept for this module: the grant is not Go `read` only, its switch "Allow this API key in .netrc" is off, or no such grant matches the module. Use GOAUTH, or ask an admin to turn on the switch ([Last resort](#last-resort-an-api-key-in-netrc)). |
| `404` for your own module | No `read` grant on it in this namespace, or the version does not exist. Prego shows a missing grant as "not found". |
| `400 module path ... is not under a registered Go module path prefix` | Register the prefix in the console Settings. |
| `400 go.mod declares module X, not Y` | The `module` line must equal the published path, with the `/vN` suffix for v2 and later. |
| `403` on publish | You can read but not publish, or a plan or quota limit applies. |
| `409` on publish | The version was used before. Go versions are immutable: tag a new version. |
| `Prego takes a module zip of at most 300 MiB` | The module files, or the zip, are larger than 300 MiB. Nothing was sent. Remove large files from the module and tag a new version. |
| `verifying ...: reading https://sum.golang.org/lookup/...: 404 Not Found` | `GONOSUMDB` does not hold your prefix, so Go asks the public checksum database about a private module. Run `prego setup go` again with your prefixes. |

## Not in this release

- Public modules: Prego does not proxy or cache `proxy.golang.org`.
- A checksum database for private modules (`GOSUMDB`).
- Pseudo-versions, `+incompatible` versions, modules without `go.mod`.
- Vanity import pages (`?go-get=1`).
