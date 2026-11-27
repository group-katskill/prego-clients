# Supported artifact types

Prego by KatSkill hosts these types. Each folder tells you what the type is, which plans include it, how to start,
and where the examples are.

| Type | Command or tool | Plans that can publish |
| --- | --- | --- |
| [Crates (Cargo)](crates/) | `cargo`, with `cargo-credential-prego` | Trial, Indie, Org, Publisher |
| [Containers and OCI artifacts](oci/) | Docker, Podman, crane, ORAS, Helm and cosign, with `docker-credential-prego`; `prego oci push` | Trial, Org, Publisher |
| [Go modules](go/) | `go`, with `prego go-auth` and `prego go publish` | Trial, Indie, Org, Publisher |
| [npm](npm/) | npm, pnpm, Yarn and Bun, with `prego setup npm` | Trial, Indie, Org, Publisher |
| [Python](python/) | uv, pip and Poetry, with `prego setup python` and `prego python publish` | Trial, Indie, Org, Publisher |
| [Release Variables](release-variables/) | `prego env` | Trial, Indie, Org, Publisher |
| [Snippets](snippets/) | `prego snippet` | Trial, Indie, Org, Publisher |
| [Adapters](adapters/) | `prego adapter` (preview) | Trial, Publisher |
| [Context](context/) | `prego context` | Trial, Org, Publisher |
| [SQLite snapshots](sqlite-snapshots/) | `prego sqlite` | Trial, Org, Publisher |
| [Keys and Certificates](keys/) | `prego keys` | Trial, Indie, Org, Publisher |
| [A2A Agent Cards](a2a/) | `prego a2a` | Trial, Indie, Org, Publisher |
| [API specs (OpenAPI)](apispec/) | `prego apispec` | Trial, Indie, Org, Publisher |

The Consumer plan publishes no type. A Consumer tenant reads every type through grants from other tenants.

Plan rules that apply to all types:

- The plan of the tenant that owns the item decides if a push is allowed.
- Grants to other tenants follow the plan. Indie and Consumer cannot make them. Org can grant only to tenants with
  the same verified domain. Publisher can grant to any tenant. Trial can grant to a small number of tenants.
- A grant to another tenant gives `read` only.

The full list of limits is on the [plan limits page](https://docs.prego.k8skill.com/limits). The docs site needs a
sign-in with your Prego account.

Cross-cutting guides stay in [`docs/`](../docs/): the [consumer quickstart](../docs/consumer-quickstart.md), the
[CI guide](../docs/ci.md), the [frontline guide](../docs/frontline-ci-publish.md) and the
[OpenAPI file](../docs/openapi.yaml). [PROTOCOL.md](../PROTOCOL.md) has the client contract.
