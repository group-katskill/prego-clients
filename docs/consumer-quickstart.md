# Quickstart: use Prego crates on your laptop

This guide connects Cargo on your laptop to the Prego registry of tenant `acme`. From prego 0.7.0 you log in
with your own console account (`prego login`), and no key is stored in a file. An API key also works. It takes
about five minutes. For CI, use [ci.md](ci.md): CI jobs use their own identity or an API key, never
`prego login`.

Replace `acme` with your tenant slug. Replace `default` with your namespace if you use another one.

## What you need

- Cargo 1.74 or later.
- For `prego login` (from 0.7.0): membership of the tenant in the Prego console, with a role that can read
  the crates. To publish, a passkey in the console (Settings, Passkeys).
- Or a Prego API key (`prk_...`). An admin of your tenant makes one in the Prego console
  (<https://app.prego.k8skill.com>, **Principals**, kind **API key**). The key needs a grant with `read` on the
  crates you use. The console shows the key one time only. An API key lives for at most 90 days.

## 1. Install the credential provider

```sh
cargo install cargo-credential-prego
cargo-credential-prego --version
```

All Prego client crates are on [crates.io](https://crates.io/crates/cargo-credential-prego), version 0.3.0.

Or install all Prego tools (`cargo-credential-prego`, `docker-credential-prego`, `prego`) with the install
script. It checks the SHA-256 sum and copies the binaries to `~/.local/bin`:

```sh
curl -fsSLO https://github.com/group-katskill/prego-clients/releases/latest/download/install.sh
sh install.sh
```

Or download a prebuilt binary from the
[release page](https://github.com/group-katskill/prego-clients/releases), check it, and put it on your `PATH`:

```sh
TARGET=aarch64-apple-darwin   # or x86_64-unknown-linux-musl, aarch64-unknown-linux-musl
VERSION=0.4.0
BASE=https://github.com/group-katskill/prego-clients/releases/download/prego-clients-v$VERSION
curl -fsSLO "$BASE/cargo-credential-prego-$TARGET.tar.gz"
curl -fsSLO "$BASE/cargo-credential-prego-$TARGET.tar.gz.sha256"
shasum -a 256 -c "cargo-credential-prego-$TARGET.tar.gz.sha256"   # Linux: sha256sum -c
tar -xzf "cargo-credential-prego-$TARGET.tar.gz" cargo-credential-prego
install -m 0755 cargo-credential-prego ~/.local/bin/
```

## 2. Tell Cargo about the registry

Add this to `~/.cargo/config.toml` (all projects) or to `.cargo/config.toml` in one project:

```toml
[registries.acme]
index = "sparse+https://cargo.prego.k8skill.com/t/acme/default/index/"
credential-provider = ["cargo-credential-prego", "--tenant", "acme"]
```

From 0.6.0 the provider also needs your tenant's [edge code](../README.md#edge-code). The Prego console shows
it. Set it one time for all Prego tools: `edge_code = "k7mq"` in `~/.config/prego/config.toml`, or
`PREGO_EDGE_CODE=k7mq`. Replace `k7mq` with your code.

## 3. Log in

**On a laptop (from 0.7.0):** install the `prego` tool too (the install script above has it), then:

```sh
prego login             # read access. prego login --publish: read and publish
```

`prego login` shows a page and a code. Open the page, sign in, check the code, and approve. The session is
kept in your OS keychain (on Linux without a desktop, in the kernel keyring, lost at reboot), never in a file.
`prego status` shows it; `prego logout` ends it. The provider uses the session when no workload identity and
no `PREGO_API_KEY` is set. Lost laptop? Revoke the session in the console: Settings, Your sessions.

**Or with an API key.** Put the key in your shell environment. Do not write it into `config.toml` or a file in your project.

```sh
export PREGO_API_KEY=prk_...
```

Tip: load it from your password manager or keychain, for example on macOS:

```sh
export PREGO_API_KEY="$(security find-generic-password -s prego-api-key -w)"
```

## 4. Use a crate

In `Cargo.toml`:

```toml
[dependencies]
acme-core = { version = "1", registry = "acme" }
```

Then:

```sh
cargo build
```

Cargo starts `cargo-credential-prego`. With a login session, the provider trades the session for a registry
token. With an API key, the provider sends the key to the Prego STS
(`https://sts.prego.k8skill.com/v1/sts/token/e/k7mq`) and gets a registry token (15 minutes by default; the grant of
the tenant that shares the crates can set a shorter or longer one). Cargo uses that token for the registry
and asks for a new one shortly before it expires. The API key itself never goes to the
registry.

## Troubleshooting

| Message | What to do |
| --- | --- |
| `no identity source found. Checked: ...` | Run `prego login`, or set `PREGO_API_KEY` in this shell. |
| `the login session ended; run prego login again` | The session expired (7 days without use, 30 days in all) or was revoked. Run `prego login`. |
| `this computer has no secure storage for a login session` | No keychain and no kernel keyring (some containers). Use an API key here. |
| `PREGO_API_KEY must start with prk_` | The value is not a Prego API key. Copy it again from the console. |
| `Prego refused this identity for tenant acme` | The key is wrong, expired, disabled or revoked, or it belongs to another tenant. Make a new key in the console. |
| `no matching package named ... found` | The key has no `read` grant on that crate or namespace. Ask a tenant admin. Prego shows a missing grant as "not found". |
| `tenant is not set` | Add `"--tenant", "acme"` to `credential-provider`, or set `PREGO_TENANT`. |
| TLS errors behind a company proxy | Set `PREGO_CA_FILE` to a PEM file with the proxy's CA certificate. |

`cargo login` and `cargo logout` are not supported. Use `prego login` and `prego logout`, or manage keys in
the console.

## Next steps

- [oci-quickstart.md](oci-quickstart.md): push and pull images, Helm charts and signatures with the same identity.
- [ci.md](ci.md): connect GitLab CI, GitHub Actions, SPIFFE or cloud workloads without an API key.
- [../PROTOCOL.md](../PROTOCOL.md): the STS contract, if you want to write your own client.
- [openapi.yaml](openapi.yaml): the public API.
