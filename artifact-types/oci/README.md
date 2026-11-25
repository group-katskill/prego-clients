# Containers and OCI artifacts

Prego has an OCI registry at `oci.prego.k8skill.com` for container images and other OCI artifacts, for example
Helm charts and `.deb` files. Docker, Podman, BuildKit, crane, ORAS, Helm and cosign use it through
`docker-credential-prego`. `prego oci push` sends layers above 95 MiB in parts.

**Plans:** Trial, Org and Publisher can publish. Indie does not include containers. Consumer reads through
grants.

## Start

- [OCI quickstart](quickstart.md): each tool, multi-platform images, cosign, big layers, Kubernetes, and the
  errors.
- [Push and pull images](../../README.md#push-and-pull-images) in the root README.
- [Build and push images in CI](../../docs/ci.md#build-and-push-images).
- Full docs: <https://docs.prego.k8skill.com/oci> (sign in with your Prego account).

## Examples

The examples are in the shared [`examples/`](../../examples/) folder:

- [`examples/github-actions/docker-build.yml`](../../examples/github-actions/docker-build.yml): build an image and
  push it from GitHub Actions.
- [`examples/gitlab/docker-build.gitlab-ci.yml`](../../examples/gitlab/docker-build.gitlab-ci.yml): the same from
  GitLab CI, and a template for big layers with `prego oci push`.
- [`examples/kubernetes/image-pull-secret.yaml`](../../examples/kubernetes/image-pull-secret.yaml): an
  `imagePullSecret` with a read-only API key (placeholder only).
