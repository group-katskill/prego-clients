# Go modules

Prego serves private Go modules on `go.prego.k8skill.com` through the GOPROXY protocol. Public modules still come
from `proxy.golang.org`. `prego go-auth` is the GOAUTH helper for Go 1.24 and later. `prego go publish` builds the
module zip from the git tree of a tag.

**Plans:** Trial, Indie, Org and Publisher can publish. Consumer reads through grants.

## Start

- [Go quickstart](quickstart.md): connect Go, use and publish a module, CI, old Go, and the errors.
- [Go modules](../../README.md#go-modules) in the root README.
- Full docs: <https://docs.prego.k8skill.com/go> (sign in with your Prego account).

## Examples

The [Go quickstart](quickstart.md#ci) has the CI jobs for GitLab CI and GitHub Actions.
