# Prego as your frontline registry: publish from CI, serve the fleet

This guide is for prego-clients 0.6.0 and later. Replace the values in angle brackets: `<tenant>` is your tenant
slug, `<namespace>` is your namespace (for example `default` or `releases`), and `<edge-code>` is the 4-character
edge code of your tenant (the console shows it; it is not a secret, see the
[README](../README.md#edge-code)).

## What this is

Your registry of record can stay where it is: JFrog, Cloudsmith, GitHub Packages, or your own. Prego sits in front
of it for the traffic that costs money and needs machine identity: CI runners, Kubernetes nodes, autoscaling
fleets, AI agents, and your customers' machines.

The pattern has three parts:

1. **Publish to Prego from the pipeline you already have.** A job in GitHub Actions or GitLab CI publishes each
   release to Prego as well as to your registry of record. The job signs in with the CI job's own OIDC identity.
   There is no Prego secret in the repository.
2. **Point the heavy readers at Prego.** Fleets, runners and customers pull from Prego with the identity they
   already have (OIDC, SPIFFE, or a read-only API key where nothing else exists). Pulls are not charged by the
   byte; each plan has a monthly usage limit and a hard stop, never an overage bill.
3. **You stay in control.** Prego never reaches into your registry. If you stop the publish job, Prego stops
   changing. Nothing you publish to Prego is required to be anywhere else.

Prego hosts private Rust crates, container images, Go modules and scoped npm packages. It does not proxy public
registries.

## Before the first job: one-time setup in the Prego console

On the Connect page of your tenant:

1. **Trust config** for your CI issuer. GitHub Actions: issuer `https://token.actions.githubusercontent.com`.
   GitLab.com: `https://gitlab.com`; self-managed GitLab: your GitLab URL. The audience stays the default
   `prego.k8skill.com`.
2. **Principal** for the publishing job, pinned to the repository and a protected ref or environment. For example,
   GitHub `{"repository": "acme/core", "ref": "refs/heads/main"}` (or `"environment": "release"`), GitLab
   `{"project_path": "acme/core", "ref_protected": "true"}`. A principal must pin at least a repository or project;
   Prego refuses "anyone from github.com".
3. **Grant** on that principal: `publish` on the namespace and package type you ship (`ecosystem` `cargo`, `oci`,
   `go`, `npm`, or `any`). Publish never includes delete.
4. Readers get their own principals and `read` grants, in your tenant (Org) or in their own tenant (Publisher,
   cross-domain grants).

## GitHub Actions

Every job that talks to Prego needs the ID token permission, the tenant, the edge code and the client tools:

```yaml
permissions:
  contents: read
  id-token: write          # lets the job request its OIDC identity token

env:
  PREGO_TENANT: <tenant>
  PREGO_EDGE_CODE: <edge-code>
```

```yaml
      - name: Install prego-clients 0.7.0
        run: |
          base=https://github.com/group-katskill/prego-clients/releases/download/prego-clients-v0.7.0
          file=prego-clients-x86_64-unknown-linux-musl.tar.gz
          curl -fsSLO "$base/$file"
          echo "4526657f6a4164cfd1f08c17ee62a700bdd62499cb82db954f0acec6f77b0557  $file" | sha256sum -c -
          mkdir -p "$HOME/.local/bin"
          tar -xzf "$file" -C "$HOME/.local/bin" cargo-credential-prego docker-credential-prego prego
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"
```

The step pins the SHA-256 sum of the 0.7.0 archive, so a changed download fails the job. For a runner on ARM, use
`prego-clients-aarch64-unknown-linux-musl.tar.gz` and its line in the release's `SHA256SUMS`. To check who made the
release, see [Verify a release](../README.md#verify-a-release).

`cargo-credential-prego`, `docker-credential-prego` and `prego` find GitHub Actions by themselves
(`ACTIONS_ID_TOKEN_REQUEST_URL` is set). They request a token with audience `prego.k8skill.com` and exchange it at
the Prego STS for a registry token that is valid for some minutes. They write no token to disk.

### Rust crates

Commit this file. It holds no secret:

```toml
# .cargo/config.toml
[registries.prego]
index = "sparse+https://cargo.prego.k8skill.com/t/<tenant>/<namespace>/index/"
credential-provider = ["cargo-credential-prego", "--tenant", "<tenant>", "--edge-code", "<edge-code>"]
```

```yaml
      - name: Publish crate to Prego
        run: cargo publish --registry prego
```

The index URL has the tenant slug. Only the token request uses the edge code; the provider sends it there.
Publish to crates.io or your registry of record in its own step, as today. Readers add the same
`[registries.prego]` block and depend on the crate with `registry = "prego"`.

### Container images

`docker login` works with the job's OIDC token. You need no Prego tool and no edge code for this step: the
registry's challenge gives Docker the token address.

```yaml
      - name: Log in to Prego and push
        run: |
          id_token="$(curl -fsS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=prego.k8skill.com" | jq -r .value)"
          printf '%s' "$id_token" | docker login oci.prego.k8skill.com -u <tenant> --password-stdin
          docker tag "app:${GITHUB_SHA}" "oci.prego.k8skill.com/<tenant>/<namespace>/app:${GITHUB_REF_NAME}"
          docker push "oci.prego.k8skill.com/<tenant>/<namespace>/app:${GITHUB_REF_NAME}"
```

The identity token is valid for at most an hour, and the login stops working after the job. Keep the token in
one step: do not write it to `$GITHUB_ENV`. For a multi-arch build, `docker buildx build --push` with the same
tag works the same way after the login.

You can also use the credential helper: run `prego setup docker --write` after the install step, and do not run
`docker login`. `docker-credential-prego` then gets a fresh identity token for each push.

A layer larger than 95 MiB fails with `413` on `docker push`. Use `prego oci push` for such an image (see the
[OCI quickstart](oci-quickstart.md)).

**Fan-out from a registry of record (the "frontline" step).** If the image is built elsewhere and lands in JFrog
or Cloudsmith first, add a small job that your release starts (`repository_dispatch` from a webhook, or
`workflow_dispatch` by hand) and that copies the image one time:

```yaml
      # First log in to your registry of record, and to Prego as above.
      - name: Copy the release image to Prego
        env:
          TAG: ${{ github.event.client_payload.tag }}
        run: |
          docker pull "<your-registry>/app:$TAG"
          docker tag "<your-registry>/app:$TAG" "oci.prego.k8skill.com/<tenant>/<namespace>/app:$TAG"
          docker push "oci.prego.k8skill.com/<tenant>/<namespace>/app:$TAG"
```

Give the tag to the step in `env`, not as `${{ ... }}` in `run`, so that a tag value cannot change the script.
The job pulls one time from your registry of record per release, not one time per node per deploy. The same job
can run as a cloud function if you prefer. It needs only Docker (or `crane` or `skopeo`) and an identity that
Prego trusts.

### npm (scoped packages)

npm 11.5.1 or later publishes with the job's identity and no token ("trusted publishing"). Commit the `.npmrc`
from `prego setup npm --scope @acme`. It has the scope line and a `${PREGO_NPM_TOKEN}` line, never a token:

```ini
@acme:registry=https://npm.prego.k8skill.com/t/<tenant>/<namespace>/
//npm.prego.k8skill.com/t/<tenant>/<namespace>/:_authToken=${PREGO_NPM_TOKEN}
```

```yaml
      - uses: actions/setup-node@v5
        with:
          node-version: 24
      - run: npm install --global npm@^11.5.1
      - run: npm publish            # no --provenance: Prego does not accept provenance yet
```

The package scope (`@acme`) must be registered to your tenant in the console. Readers commit the same `.npmrc`
and run installs through `prego exec -- npm install`, which sets `PREGO_NPM_TOKEN` for that one command. The
[npm quickstart](npm-quickstart.md) has the details.

### Go modules

Go has no publish command. `prego go publish` builds the module zip from the git tree of the tag, the way
`go mod` does, and publishes it. Run it on a tag push:

```yaml
      - name: Publish Go module to Prego
        if: github.ref_type == 'tag'
        run: prego go publish --namespace <namespace> --tag "$GITHUB_REF_NAME"
```

The module path in `go.mod` must be under a module path prefix that your tenant registered (for example
`go.acme.com` or `github.com/acme`). Readers run `prego setup go --namespace <namespace> --prefix go.acme.com
--write`. It sets `GOPROXY='https://go.prego.k8skill.com/t/<tenant>/<namespace>,https://proxy.golang.org,direct'`,
`GONOSUMDB` to your prefixes, and `GOAUTH='prego go-auth'` (Go 1.24 or later).

## GitLab CI

GitLab issues the ID token through `id_tokens`. The tools read `PREGO_ID_TOKEN`. Install the tools as in the
GitHub step above (without the `$GITHUB_PATH` line; put `$HOME/.local/bin` on `PATH`), and set the tenant and the
edge code:

```yaml
variables:
  PREGO_TENANT: <tenant>
  PREGO_EDGE_CODE: <edge-code>

publish-crate:
  stage: release
  id_tokens:
    PREGO_ID_TOKEN:
      aud: prego.k8skill.com
  script:
    - cargo publish --registry prego      # same .cargo/config.toml as above
  rules:
    - if: $CI_COMMIT_TAG
```

```yaml
publish-image:
  stage: release
  image: docker:27
  services:
    - docker:27-dind
  id_tokens:
    PREGO_ID_TOKEN:
      aud: prego.k8skill.com
  script:
    - printf '%s' "$PREGO_ID_TOKEN" | docker login oci.prego.k8skill.com -u <tenant> --password-stdin
    - docker build -t "oci.prego.k8skill.com/<tenant>/<namespace>/app:$CI_COMMIT_TAG" .
    - docker push "oci.prego.k8skill.com/<tenant>/<namespace>/app:$CI_COMMIT_TAG"
  rules:
    - if: $CI_COMMIT_TAG
```

```yaml
publish-npm:
  stage: release
  image: node:24
  id_tokens:
    NPM_ID_TOKEN:
      aud: npm:npm.prego.k8skill.com    # npm trusted publishing uses this exact audience
  script:
    - npm install --global npm@^11.5.1
    - npm publish
  rules:
    - if: $CI_COMMIT_TAG
```

```yaml
publish-go:
  stage: release
  id_tokens:
    PREGO_ID_TOKEN:
      aud: prego.k8skill.com
  script:
    - prego go publish --namespace <namespace> --tag "$CI_COMMIT_TAG"
  rules:
    - if: $CI_COMMIT_TAG
```

The `docker login` and `npm publish` jobs do not need the edge code. The `cargo` and `prego` jobs need it.
Pin the principal in the Prego console to `project_path` and `ref_protected = "true"`, so that only protected
tags and branches of that project can publish.

## Readers: the fleet, the runners, the customers

- **CI runners** use the same tools in read mode: `cargo build` with the `[registries.prego]` block,
  `prego exec -- npm install`, `go build` with `GOAUTH`. The job's identity needs a `read` grant, and the job
  needs `PREGO_TENANT` and `PREGO_EDGE_CODE` as above.
- **Kubernetes nodes** pull images with an `imagePullSecret` that holds a read-only API key (username = tenant,
  password = `prk_...`). The [OCI quickstart](oci-quickstart.md) has the commands.
- **Your customers** (Publisher plan) pull from their own Prego tenant through a cross-domain grant. Their machines
  sign in as themselves; you give out no tokens and rotate nothing.
- **Usage.** Every plan has a monthly usage limit, shown in the console by package type. At 100%, pulls and
  publishes stop until the 1st of the month or until you add a $25 pack. Nothing is deleted. One customer can use
  at most half of a Publisher's usage limit.

## Why this is better than a mirror

- You decide what goes to Prego and when. A mirror decides for you and needs credentials for your registry of
  record.
- One copy per release, not one pull per node, and no transfer bill on either side for the fleet traffic.
- A rollback is a publish, not a cache flush.

## Troubleshooting

| Message | What to do |
| --- | --- |
| `the edge code of your tenant is not set` | Set `PREGO_EDGE_CODE` (or `--edge-code` in `credential-provider`). The console shows the code. |
| `this client uses an old token URL` | The tools are older than 0.6.0. Install 0.6.0 or later. |
| `identity source github failed: ... id-token: write` | Add `permissions: id-token: write` to the workflow or job. |
| `subject token not accepted` on `docker login` | Check the `-u <tenant>` value, the token audience `prego.k8skill.com`, and the principal pins. |
| `404 NAME_UNKNOWN` on `docker push` | The principal has no `publish` grant on that repository. |

The [CI guide](ci.md) has more errors and the other identity sources.
