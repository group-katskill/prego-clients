# Quickstart: push and pull images with Prego

Prego has an OCI registry at `oci.prego.k8skill.com`. It works with Docker, Podman, BuildKit, crane, ORAS, Helm
and cosign. This guide uses tenant `acme` and namespace `default`. Replace them with your own slugs.

For crates, see [consumer-quickstart.md](consumer-quickstart.md). For CI jobs, see [ci.md](ci.md).

## Image names

```text
oci.prego.k8skill.com/<tenant>/<namespace>/<repo>:<tag>
oci.prego.k8skill.com/acme/default/api:1.4.0
oci.prego.k8skill.com/acme/default/tools/build-x:latest
```

- The namespace is always in the name.
- The repo has 1 to 4 parts. Each part has lowercase letters and digits, with `.`, `_`, `__` or `-` between
  them.
- The full name (without the host) has at most 255 characters.

## What you need

- A Prego identity: an API key (`prk_...`) on a laptop, or the CI identity in a job ([ci.md](ci.md)).
- A grant on the repository, with `ecosystem = oci` (or `any`, which also covers crates):

| Action | Allows |
| --- | --- |
| `read` | Pull: manifests, blobs, tags list, referrers. |
| `publish` | Push: blobs, manifests and tags. |
| `delete` | Delete tags and manifests through `/v2/`. It implies `read`. `publish` does not imply it. |

A tenant admin makes keys and grants in the Prego console (<https://app.prego.k8skill.com>). An API key lives for
at most 90 days.

## 1. Install the credential helper

```sh
cargo install docker-credential-prego prego
```

Or install all Prego tools with the install script. See the [README](../README.md#install).

## 2. Connect Docker

```sh
prego setup docker --write
```

This adds the helper to `~/.docker/config.json`. It makes a backup copy first and keeps all other keys. The
result is:

```json
{ "credHelpers": { "oci.prego.k8skill.com": "prego" } }
```

Set the tenant and your identity:

```toml
# ~/.config/prego/config.toml
tenant = "acme"
```

```sh
export PREGO_API_KEY=prk_...   # from the Prego console; do not write it to a file in your project
```

The helper gives the tenant as the username and the identity as the password. Docker sends them only to the
Prego token realm (`https://sts.prego.k8skill.com/v1/oci/token/e/<edge code>`, from the registry's `401`
answer). The realm gives Docker a registry token (15
minutes by default, or the lifetime of your grant), and Docker gets a new one when the registry answers `401`. No password goes into `config.json`.

## 3. Push and pull

```sh
docker build -t oci.prego.k8skill.com/acme/default/api:1.4.0 .
docker push oci.prego.k8skill.com/acme/default/api:1.4.0
docker pull oci.prego.k8skill.com/acme/default/api:1.4.0
```

Each layer must be 95 MiB or less for `docker push`. For bigger layers, see [Big layers](#big-layers).

## Podman

Podman reads `credHelpers` from its auth file. Use the Docker file, or add the same key to
`${XDG_RUNTIME_DIR}/containers/auth.json`:

```sh
export REGISTRY_AUTH_FILE="$HOME/.docker/config.json"
podman push oci.prego.k8skill.com/acme/default/api:1.4.0
```

## Sign in with no helper

`docker login` works with an API key or a CI ID token. Send it on stdin, never as an argument:

```sh
printf '%s' "$PREGO_API_KEY" | docker login oci.prego.k8skill.com -u acme --password-stdin
```

The username is the tenant. Docker then stores the key in its config file or keychain. Use the helper when you
can, because it stores nothing. In CI, a GitLab ID token in place of the key expires after the job. See
[ci.md](ci.md#build-and-push-images).

## crane and ORAS

Both read `~/.docker/config.json`, so the helper works with no more setup:

```sh
crane push image.tar oci.prego.k8skill.com/acme/default/api:1.4.0
crane manifest oci.prego.k8skill.com/acme/default/api:1.4.0

oras push oci.prego.k8skill.com/acme/default/files:v1 --artifact-type application/vnd.acme.files.v1 report.txt
oras pull oci.prego.k8skill.com/acme/default/files:v1
```

Prego stores any OCI artifact (SBOMs, files, charts, signatures). It does not read their content.

## Helm charts

Helm reads the Docker config when you point `HELM_REGISTRY_CONFIG` at it:

```sh
export HELM_REGISTRY_CONFIG="$HOME/.docker/config.json"
helm package ./api-chart
helm push api-chart-0.4.0.tgz oci://oci.prego.k8skill.com/acme/default
helm pull oci://oci.prego.k8skill.com/acme/default/api-chart --version 0.4.0
```

`helm push` adds the chart name to the path, so the chart goes to `acme/default/api-chart`.

## Multi-platform images

Prego stores image indexes (manifest lists) with all their platforms:

```sh
docker buildx build --platform linux/amd64,linux/arm64 \
  -t oci.prego.k8skill.com/acme/default/api:1.4.0 --push .
docker pull --platform linux/arm64 oci.prego.k8skill.com/acme/default/api:1.4.0
```

`podman manifest push --all`, `crane index append` and `oras cp -r` also work.

## cosign signatures

cosign stores signatures and attestations through the OCI referrers API:

```sh
cosign sign --registry-referrers-mode=oci-1-1 oci.prego.k8skill.com/acme/default/api@sha256:<digest>
cosign verify --experimental-oci11=true <verify options> oci.prego.k8skill.com/acme/default/api@sha256:<digest>
```

Sign by digest, not by tag. Prego stores signatures, but it does not check them. A pull of an unsigned image
works. Your deploy step or cluster policy must run `cosign verify`.

## Big layers

`docker push`, Podman and BuildKit send each layer in one request. Prego accepts at most 95 MiB in one request,
so a push of a bigger layer fails with `413`. `prego oci push` sends each layer in parts of at most 95 MiB:

```sh
docker save acme-api:1.4.0 -o api.tar          # or an OCI image layout directory
prego oci push api.tar acme/default/api:1.4.0
```

- The input is a `docker save` tar file or an OCI image layout directory (from `buildah`, `skopeo`, `crane` or
  `docker buildx build --output type=oci,tar=false,dest=api-oci`). Decompress a `.tar.gz` first.
- A multi-platform image goes up with all its platforms. Each platform must be in the input. Use
  `docker save --platform` or an OCI layout export for a multi-platform image.
- After a network error, the push asks the registry how much it has and goes on from there.
- `--from acme/default/base` mounts blobs that are already in that repository, with no upload.
- A blob can be at most 10 GiB. A manifest can be at most 4 MiB.

Pulls of big layers work with all tools. Only the push needs `prego oci push`.

## Kubernetes

In this release, a cluster pulls with an `imagePullSecret` that holds a read-only API key:

- Make an API key principal with a `read` grant on the repositories the cluster pulls. Use one key per cluster.
- The username is the tenant. The password is the key.
- The key lives for at most 90 days. Make a new key and update the secret before the old key expires.

The console **Connect** page writes the secret for you. Or make it with `kubectl`:

```sh
kubectl create secret docker-registry prego-pull --namespace apps \
  --docker-server=oci.prego.k8skill.com --docker-username=acme --docker-password="$PREGO_PULL_KEY"
```

This puts the key in the `kubectl` arguments for a short time. On a shared machine, apply the YAML file instead.

A full example with a pod is in [`examples/kubernetes/image-pull-secret.yaml`](../examples/kubernetes/image-pull-secret.yaml).
A kubelet credential provider that uses the identity of the node or the pod is planned for a later release.

## Errors

| Message | Cause and fix |
| --- | --- |
| `401 Unauthorized` | The identity was refused at the realm. Check the tenant (username), the key, and that `PREGO_TENANT` matches the image name. |
| `prego oci push`: `not at the Prego realm` | The registry asked for the identity at a different realm. The tool sent nothing. Check the host in the image name. |
| `404 NAME_UNKNOWN` | No grant on this repository, or it does not exist. Prego shows a missing grant as "not found". Ask a tenant admin for a grant. |
| `403 DENIED` | You have `read` but not `publish` or `delete`, the tag is immutable, or the tenant is over its quota. |
| `413` on `docker push` | A layer is larger than 95 MiB. Use `prego oci push` ([Big layers](#big-layers)). |
| `429 TOOMANYREQUESTS` | Too many requests. The token realm takes at most 60 requests per minute from one IP address (from registry 1.2.0, only refused requests count per IP, and successful ones count against the tenant's budget per minute). The registry takes at most 1200 requests per minute from one principal. Wait for the time in `Retry-After`. |
| `404` on `/v2/_catalog` | Prego does not list repositories. Use the console or the admin API. |

## Not in this release

Prego registry 1.0.0 does not have these. Plan around them:

- Layers above 95 MiB with stock `docker push`, Podman or BuildKit. Use `prego oci push`.
- Public or anonymous images. Every pull needs an identity.
- `/v2/_catalog`.
- A pull-through cache of Docker Hub, GHCR or other registries.
- Vulnerability scanning, or a signature policy. Signatures are stored, not checked.
- Webhooks and replication.
- A kubelet credential provider. Use an `imagePullSecret`.
