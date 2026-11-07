# Security policy

The tools in this repository handle identity tokens on build machines and in CI. We take reports about them
seriously.

## Supported versions

| Crate | Supported |
| --- | --- |
| `cargo-credential-prego` | the latest minor release |
| `prego-auth` | the latest minor release |
| `prego`, `docker-credential-prego` | the latest minor release |

## Report a vulnerability

Do not open a public issue for a vulnerability.

Send the report by email to **security@k8skill.com**. Include:

- the affected crate and version,
- the steps to reproduce the problem,
- the effect (for example: a token is written to a log),
- your name or handle if you want credit.

Do not include a real token, API key or private key in the report. Remove it or replace it with a fake value.

We confirm that we received the report in 3 working days. We tell you our plan in 10 working days. We
publish a fix and an advisory, and we credit you if you agree.

## `prego login` sessions

From prego 0.7.0, `prego login` keeps a device session on the computer. It holds a refresh token that gets
registry tokens. Where it is kept:

| OS | Storage |
| --- | --- |
| macOS | the login Keychain. The binaries are not code-signed yet, so the Keychain asks you to allow access the first time. |
| Windows | the Windows Credential Manager. |
| Linux with a desktop | the Secret Service (GNOME Keyring, KWallet). |
| Linux without a desktop (SSH hosts, servers, containers, WSL) | the kernel keyring of your user session. It is lost at logout or reboot; then run `prego login` again. |

- There is no plain file fallback. Without secure storage, `prego login` stops. Use an API key or a workload
  identity on such a host.
- On Linux, if the Secret Service refuses a write (for example, a locked keyring), the session goes to the
  kernel keyring. The file `~/.config/prego/session-stores.json` (mode 0600) records which store holds each
  entry. It holds only store names and hashes of the entry names (tenant and STS URL), never a token or a
  value made from a token.
- The refresh token changes on every use. A second use of an old refresh token, after 10 seconds, ends the
  whole session.
- Registry tokens from a session are kept in memory or in the same secure storage, never in a plain file.

**Lost or stolen laptop:** in the console, open Settings, Your sessions, and revoke the session of that laptop.
A tenant owner or admin can revoke any session of the tenant. A member who leaves the tenant loses all their
sessions at once.

## What the tools must never do

These are security bugs. Report them:

- Print, log or write to disk a subject token, an API key or a registry token.
- Keep a `prego login` refresh token anywhere but in secure storage, or show it in any output.
- Send a subject token to a host other than the configured STS, or over plain `http` to a host that is not
  a loopback host.
- Follow an HTTP redirect with a subject token.
- Use a registry token or a subject token from a source that the user did not configure.

## Scope

This policy covers the code in this repository. For problems with the hosted Prego service, use the same
address.
