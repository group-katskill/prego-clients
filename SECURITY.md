# Security policy

The tools in this repository handle identity tokens on build machines and in CI. We take reports about them
seriously.

## Supported versions

| Crate | Supported |
| --- | --- |
| `cargo-credential-prego` | the latest minor release |
| `prego-auth` | the latest minor release |

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

## What the tools must never do

These are security bugs. Report them:

- Print, log or write to disk a subject token, an API key or a registry token.
- Send a subject token to a host other than the configured STS, or over plain `http` to a host that is not
  a loopback host.
- Follow an HTTP redirect with a subject token.
- Use a registry token or a subject token from a source that the user did not configure.

## Scope

This policy covers the code in this repository. For problems with the hosted Prego service, use the same
address.
