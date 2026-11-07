# Examples

Copy-and-paste examples for tenant `acme`, namespace `default`. Replace both with your own slugs.

| Folder | What it shows |
| --- | --- |
| [`cargo/`](cargo/config.toml) | The `.cargo/config.toml` registry block. |
| [`github-actions/build.yml`](github-actions/build.yml) | A GitHub Actions workflow that builds with Prego crates, with the job's OIDC token. No stored secret. |
| [`github-actions/docker-build.yml`](github-actions/docker-build.yml) | A GitHub Actions workflow that builds an image and pushes it to Prego through `docker-credential-prego`. No stored secret. |
| [`gitlab/.gitlab-ci.yml`](gitlab/.gitlab-ci.yml) | A GitLab CI job that builds with Prego crates, with `id_tokens`. No stored secret. |
| [`gitlab/docker-build.gitlab-ci.yml`](gitlab/docker-build.gitlab-ci.yml) | A GitLab CI job that builds an image and pushes it with `docker login` and the ID token. A template for layers above 95 MiB with `prego oci push`. No stored secret. |
| [`kubernetes/`](kubernetes/image-pull-secret.yaml) | An `imagePullSecret` with a read-only API key, a pod and a service account that use it. Placeholder key only. |
| [`opentofu/`](opentofu/main.tf) | OpenTofu: install `cargo-credential-prego` and write the Cargo config on a machine. |
| [`ansible/`](ansible/playbook.yml) | Ansible: the same for a CI runner or developer machine. |
| [`admin/`](admin/) | Manage grants and other tenant objects from CI with an admin token. No stored secret. |

The examples pin prego-clients 0.7.0. From 0.6.0 the tools that request a token need the edge code of your
tenant (`k7mq` in the examples; the console shows yours). The CI examples download the release binary and check
its SHA-256 sum. `cargo install --locked cargo-credential-prego` also works.

## Build machines and tenant objects

The OpenTofu and Ansible examples at the top level set up the **machine that builds**. They change nothing in
your Prego tenant.

To manage tenant objects (trust configs, principals, grants, namespaces) as code, use the examples in
[`admin/`](admin/). They run in CI with an admin token. A human admin first gives the CI principal its admin
scopes in the Prego console (<https://app.prego.k8skill.com>). Members, owners and admin scopes stay in the
console.

No example stores a secret. CI jobs use their own OIDC token. The Kubernetes example has a placeholder
(`prk_REPLACE_ME`): keep the real key in your secret store. On a laptop, set `PREGO_API_KEY` in your shell
(see [`docs/consumer-quickstart.md`](../docs/consumer-quickstart.md)).

See [`docs/ci.md`](../docs/ci.md) and [`docs/oci-quickstart.md`](../docs/oci-quickstart.md) for the console setup that each CI example needs.
