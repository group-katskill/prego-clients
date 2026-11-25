# Crates (Cargo)

Prego hosts private Rust crates for Cargo. Cargo reads them from a sparse index at `cargo.prego.k8skill.com`.
The credential provider `cargo-credential-prego` gives Cargo a short-lived registry token. No token goes into your
config files.

**Plans:** Trial, Indie, Org and Publisher can publish. Consumer reads through grants.

## Start

- [Configure Cargo](../../README.md#configure-cargo) in the root README.
- [Consumer quickstart](../../docs/consumer-quickstart.md): crates on a laptop, in about five minutes.
- [CI guide](../../docs/ci.md): GitLab CI, GitHub Actions, SPIFFE and cloud workloads.
- Full docs: <https://docs.prego.k8skill.com/crates> (sign in with your Prego account).

## Examples

The examples are in the shared [`examples/`](../../examples/) folder:

- [`examples/cargo/config.toml`](../../examples/cargo/config.toml): the `.cargo/config.toml` registry block.
- [`examples/github-actions/build.yml`](../../examples/github-actions/build.yml): a GitHub Actions build with the
  job's OIDC token.
- [`examples/gitlab/.gitlab-ci.yml`](../../examples/gitlab/.gitlab-ci.yml): a GitLab CI build with `id_tokens`.
- [`examples/opentofu/main.tf`](../../examples/opentofu/main.tf) and
  [`examples/ansible/playbook.yml`](../../examples/ansible/playbook.yml): set up a build machine.
