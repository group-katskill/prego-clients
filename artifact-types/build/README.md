# Build artifacts

Build artifacts holds the output of CI pipelines: archives, binaries, `SHA256SUMS` files and reports. A CI job
uploads a build to a build stream with its own OIDC identity, so each build has a publish attestation (ADR-0065):
the CI issuer, the repository, the ref, the commit and the run. You find a build by its ID, its commit, its run, its
label or as the latest one of a ref.

A build expires after the expiry window of the namespace (3 to 360 days, default 30) unless a person or a release
job promotes it. A promoted build gets a label (for example `v1.4.0`), does not expire and does not change.

**Plans:** Trial, Indie, Org and Publisher can upload. Consumer reads through grants. The largest file is 512 MiB
(Trial, Indie), 2 GiB (Org) or 5 GiB (Publisher). Builds count toward the tenant's storage.

## Start

- [Build artifacts quickstart](quickstart.md): push, get, list, promote, the expiry, and the errors.
- [Build artifacts](../../README.md#build-artifacts) in the root README.

## Examples

- [`examples/github-release.yml`](examples/github-release.yml): a GitHub Actions release job that pushes the release
  files to Prego, promoted with the tag, with a link to the GitHub release.
- [`examples/gitlab-release.yml`](examples/gitlab-release.yml): a GitLab job that pushes the release files of a tag,
  promoted with the tag, with a link to the GitLab release.
- [`examples/gitlab-ci-output.yml`](examples/gitlab-ci-output.yml): every pipeline pushes its test reports, which
  expire after 7 days.
