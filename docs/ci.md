# CI guide: Prego crates and images, no stored secret

A CI job can prove who it is with a short-lived OIDC token from the CI system. Prego exchanges that token for a
registry token. You store no API key in CI variables.

This guide uses tenant `acme`. Full example files are in [`examples/`](../examples/).

Each setup has two parts:

1. **Once, in the Prego console** (a tenant admin, <https://app.prego.k8skill.com>): add a **trust config** for
   the issuer, a **principal** that matches your job, and a **grant** for that principal.
2. **In the job:** install `cargo-credential-prego`, write `.cargo/config.toml`, and make the CI token available.

## Cargo config (all CI systems)

```toml
# .cargo/config.toml in the repository
[registries.acme]
index = "sparse+https://cargo.prego.k8skill.com/t/acme/default/index/"
credential-provider = ["cargo-credential-prego", "--tenant", "acme"]
```

## GitLab CI (`id_tokens`)

**Console:**

- Trust config: kind `oidc`, issuer `https://gitlab.com` (or the URL of your self-managed GitLab).
- Principal: kind `oidc`, with `claims_match` that pins your project, for example
  `{"project_path": "acme/core", "ref_protected": "true"}`. Prego refuses a principal on a shared issuer that
  does not pin `project_path`, `namespace_path` or `project_id`.
- Grant: `read` on the crates the job needs.

**Job** (full file: [`examples/gitlab/.gitlab-ci.yml`](../examples/gitlab/.gitlab-ci.yml)):

```yaml
build:
  image: rust:1
  id_tokens:
    PREGO_ID_TOKEN:
      aud: prego.k8skill.com
  script:
    - cargo install --locked cargo-credential-prego
    - cargo build --locked
```

The provider finds `PREGO_ID_TOKEN` and uses it. If you run a self-managed GitLab that Prego cannot reach over
the internet, give the trust config your GitLab JWKS as `jwks_inline`, and update it when GitLab rotates its
keys.

## GitHub Actions (OIDC)

**Console:**

- Trust config: kind `oidc`, issuer `https://token.actions.githubusercontent.com`.
- Principal: kind `oidc`, with `claims_match` that pins your repository, for example
  `{"repository": "acme/core", "ref": "refs/heads/main"}`. A principal must pin `repository`,
  `repository_owner` or `repository_id`.
- Grant: `read` on the crates the job needs.

**Workflow** (full file: [`examples/github-actions/build.yml`](../examples/github-actions/build.yml)):

```yaml
permissions:
  id-token: write   # lets the job request an OIDC token
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<full commit SHA>
      - run: cargo install --locked cargo-credential-prego
      - run: cargo build --locked
```

The provider sees `ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN`, and requests a token with
audience `prego.k8skill.com`.

## SPIFFE

If the job runs next to a SPIRE agent (or another SPIFFE Workload API), set `SPIFFE_ENDPOINT_SOCKET`. The
provider fetches a JWT-SVID with audience `prego.k8skill.com`. With spiffe-helper, write the JWT-SVID to a file
and set `PREGO_SVID_FILE` instead.

Console: a trust config of kind `spiffe` with your trust domain (for example `prod.acme.io`) and its JWKS, and a
principal with a SPIFFE ID, `exact` or `prefix` match (for example prefix `spiffe://prod.acme.io/ci/`).

## Kubernetes, Google Cloud and other OIDC token files

Write an OIDC ID token with audience `prego.k8skill.com` to a file and set `PREGO_TOKEN_FILE` to its path:

- **Kubernetes:** a projected service account token with `audience: prego.k8skill.com`. Trust config issuer is
  your cluster's service account issuer.
- **Google Cloud:** ask the metadata server for an ID token with `audience=prego.k8skill.com&format=full`. Trust
  config issuer `https://accounts.google.com`. The principal must pin `sub` (the service account's numeric ID) or
  `email`.

## Microsoft Entra ID: audience note

Entra ID issues tokens for an app registration, so the audience cannot be `prego.k8skill.com`.

1. In your Entra tenant, create an app registration (for example "Prego") with Application ID URI `api://prego`,
   and set `"accessTokenAcceptedVersion": 2` in its manifest.
2. In the Prego console, add an OIDC trust config with issuer
   `https://login.microsoftonline.com/<tenant-guid>/v2.0` and **audience** `api://prego`. Use one trust config
   per Entra tenant. Do not use the `common` or `organizations` endpoints.
3. The principal must pin `tid` and `oid` (or `sub`).
4. In the workload, get a token for `api://prego/.default` (for example with a managed identity), write it to a
   file, and set `PREGO_TOKEN_FILE`.

## Build and push images

The same CI identity can push images to `oci.prego.k8skill.com`. Console setup is the same as for crates, with a
grant of `publish` on the repository (`ecosystem = oci`, or `any` to cover crates and images with one grant).
The [OCI quickstart](oci-quickstart.md) has the image names, tools and errors.

**GitLab CI:** `docker login` with the ID token on stdin. The token expires after the job (full file:
[`examples/gitlab/docker-build.gitlab-ci.yml`](../examples/gitlab/docker-build.gitlab-ci.yml)):

```yaml
build-image:
  image: docker:27
  services:
    - docker:27-dind
  id_tokens:
    PREGO_ID_TOKEN:
      aud: prego.k8skill.com
  script:
    - printf '%s' "$PREGO_ID_TOKEN" | docker login oci.prego.k8skill.com -u acme --password-stdin
    - docker build -t "oci.prego.k8skill.com/acme/default/api:$CI_COMMIT_SHORT_SHA" .
    - docker push "oci.prego.k8skill.com/acme/default/api:$CI_COMMIT_SHORT_SHA"
```

**GitHub Actions:** install the Prego clients and run `prego setup docker --write`. `docker-credential-prego`
then requests the OIDC token for each push (full file:
[`examples/github-actions/docker-build.yml`](../examples/github-actions/docker-build.yml)):

```yaml
permissions:
  id-token: write
  contents: read

jobs:
  image:
    runs-on: ubuntu-24.04
    env:
      PREGO_TENANT: acme
      PREGO_EDGE_CODE: k7mq
    steps:
      - uses: actions/checkout@<full commit SHA>
      # install cargo-credential-prego, docker-credential-prego and prego (see the full file)
      - run: prego setup docker --write
      - run: |
          docker build -t "oci.prego.k8skill.com/acme/default/api:${GITHUB_SHA}" .
          docker push "oci.prego.k8skill.com/acme/default/api:${GITHUB_SHA}"
```

**Layers above 95 MiB:** `docker push` fails with `413`. Save the image and push it with `prego oci push`, which
sends each layer in parts. `prego` finds the CI identity by itself:

```sh
docker save api:build -o api.tar
prego oci push api.tar "acme/default/api:$CI_COMMIT_SHORT_SHA"
```

The token realm takes at most 60 requests per minute from one IP address. From registry 1.2.0, only refused
requests count against the IP address. A successful token request counts against your tenant's budget per
minute, so many parallel jobs behind one NAT address are limited only by that budget. `prego oci push` keeps one token per
repository and gets a new one only shortly before it expires. Very short grant lifetimes (1 or 2 minutes)
mean many more token requests.

## npm packages

Commit the `.npmrc` from `prego setup npm`: it holds `${PREGO_NPM_TOKEN}`, never a token. In the job, with the
same `id_tokens` (GitLab) or `id-token: write` (GitHub) as above:

```sh
export PREGO_NPM_TOKEN="$(prego token)"
npm ci
```

To publish with no Prego tool and no stored secret, use npm trusted publishing (npm 11.5.1 and later, ID token
audience `npm:npm.prego.k8skill.com`). The [npm quickstart](npm-quickstart.md) has the jobs.

## Manage Prego from CI

A pipeline can also manage objects in its own tenant: namespaces, trust configs, principals and grants. It uses
an **admin token** from the STS, with the same CI identity. It stores no secret. Full examples:
[`examples/admin/`](../examples/admin/). The protocol: [`PROTOCOL.md`](../PROTOCOL.md) section 4.

**Once, in the console (a human admin or owner):**

- A principal for the pipeline that pins the project **and a protected ref**, for example
  `{"project_path": "acme/prego-config", "ref_protected": "true"}` (GitLab) or
  `{"repository": "acme/prego-config", "ref": "refs/heads/main"}` (GitHub). Prego refuses a write scope on a
  GitLab or GitHub principal without that pin.
- **Admin scopes** on that principal. Give only what the job needs:

| Scope | Allows |
| --- | --- |
| `admin:read` | Read everything in the tenant, including the audit log. |
| `namespaces:write` | Create namespaces. |
| `trust_configs:write` | Create, delete and test trust configs. |
| `principals:write` | Create, change, revoke and delete principals. |
| `grants:write` | Create and delete grants. A job with it can grant itself `publish`. |

`api_key` principals can hold `admin:read` only. A pipeline can never manage members, owners or plans, set admin
scopes, or change the principal or trust config that it uses itself. Those stay with humans in the console.

**GitLab job:**

```yaml
manage-prego:
  image: alpine:3.22
  id_tokens:
    PREGO_ID_TOKEN:
      aud: prego.k8skill.com
  rules:
    - if: $CI_COMMIT_REF_PROTECTED == "true"
  variables:
    PREGO_TENANT: acme
    PREGO_ADMIN_SCOPE: "admin:read grants:write"
  script:
    - apk add --no-cache curl jq ansible-core
    - PREGO_ADMIN_TOKEN="$(sh examples/admin/prego-admin-token.sh)"
    - export PREGO_ADMIN_TOKEN
    - ansible-playbook -i localhost, -c local examples/admin/ansible/grants.yml
```

[`prego-admin-token.sh`](../examples/admin/prego-admin-token.sh) does the exchange with `curl`. It sends the
ID token on stdin, so the token does not show in the process list:

```sh
printf '%s' "$PREGO_ID_TOKEN" | curl -sS --proto '=https' https://sts.prego.k8skill.com/v1/sts/token \
  --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
  --data-urlencode 'subject_token@-' \
  --data-urlencode 'subject_token_type=urn:ietf:params:oauth:token-type:jwt' \
  --data-urlencode 'tenant=acme' \
  --data-urlencode 'audience=prego-admin' \
  --data-urlencode 'scope=admin:read grants:write' | jq -r .access_token
```

Then call the admin API with `Authorization: Bearer $PREGO_ADMIN_TOKEN`, for example
`GET https://sts.prego.k8skill.com/v1/admin/tenants/acme/grants`. The token is valid for 15 minutes. The
operations and their scopes are in [`openapi.yaml`](openapi.yaml).

| Error | What to do |
| --- | --- |
| `invalid_scope` (STS) | The principal holds none of the requested scopes. Ask a human admin to add them in the console. |
| `403` (admin API) | The route needs a scope the token does not have, or it is a human-only action. |
| `404` (admin API) | The `{tenant}` in the URL is not the principal's own tenant. |

## Choose a source

In `auto` mode the provider uses the first source that is present, in this order: `spiffe`, `svid-file`,
`gitlab`, `github`, `token-file`, `api-key`. If that source fails, the provider stops with an error. It does
not try the next source. To force one source, add `"--source", "<name>"` to `credential-provider` or set
`PREGO_SOURCE`.

## Troubleshooting

| Message | What to do |
| --- | --- |
| `Prego refused this identity for tenant acme` | The token did not match a trust config and principal. In the console, use **Test** on the trust config with a sample token to see why. |
| `identity source github failed: ... id-token: write` | Add `permissions: id-token: write` to the workflow or job. |
| `no matching package named ... found` | The principal has no `read` grant on that crate or namespace. Prego shows a missing grant as "not found". |
| `no identity source found` | The CI token is not in the job environment. Check `id_tokens` (GitLab) or `permissions` (GitHub). |
| `404 NAME_UNKNOWN` on `docker push` | The principal has no `publish` grant (or no grant at all) on that repository. |
| `413` on `docker push` | A layer is larger than 95 MiB. Use `prego oci push`. |
