# Manage Prego from CI (admin examples)

These examples manage objects in tenant `acme` from a CI pipeline. They use an **admin token** from the Prego
STS, so they need no stored secret. See [`PROTOCOL.md`](../../PROTOCOL.md) section 4 and
[`docs/ci.md`](../../docs/ci.md#manage-prego-from-ci).

| File | What it does | Scopes |
| --- | --- | --- |
| [`prego-admin-token.sh`](prego-admin-token.sh) | Exchanges the CI ID token for an admin token and prints it. Needs `curl` and `jq`. | any |
| [`gitlab-manage-prego.yml`](gitlab-manage-prego.yml) | GitLab jobs: a read-only plan on protected refs, and a manual apply on the default branch. | `admin:read`, `grants:write` |
| [`ansible/grants.yml`](ansible/grants.yml) | Creates the listed grants that are missing (`uri` module). `--check` only reads. | `admin:read`, `grants:write` |
| [`opentofu/main.tf`](opentofu/main.tf) | Read-only drift check of grants with the `http` provider. Warns in `tofu plan`. | `admin:read` |

## One-time setup (a human admin, in the Prego console)

1. Trust config: kind `oidc`, issuer `https://gitlab.com` (or your GitLab URL).
2. Principal: kind `oidc` with `claims_match` that pins the project **and a protected ref**, for example
   `{"project_path": "acme/prego-config", "ref_protected": "true"}`. Prego refuses a write scope on a GitLab or
   GitHub principal without that pin.
3. Admin scopes on that principal: only what the pipeline needs, for example `admin:read grants:write`.

Only a human admin or owner can give admin scopes. A pipeline can never change members, owners or admin scopes,
and it cannot change the principal or trust config that it uses itself.

## Safety notes

- Run admin jobs on protected refs only, and keep each job's scope small. `grants:write` lets a job grant
  itself `publish`.
- The admin token is valid for 15 minutes. Do not cache it, print it or save it as an artifact.
- Every admin call is in the tenant's audit log, with the principal and the CI claims it pinned.
