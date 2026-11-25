# Release Variables

Release Variables are plain settings that go with a release: an API base URL, feature flags, a list of regions.
Prego keeps them on the tenant, a namespace or a package version, with versions that you pin by hash. A machine
that can pull the release reads them with the same identity.

**Release Variables are plain text, readable by everyone who can pull the release. Do not store passwords, tokens
or keys here.** For public keys and certificates, use [Keys and Certificates](../keys/).

**Plans:** Trial, Indie, Org and Publisher can publish. Consumer reads through grants.

## Start

- [Release Variables guide](quickstart.md): levels, the merge, references, access, CI, and the errors.
- [Release Variables](../../README.md#release-variables) in the root README.
- Full docs: <https://docs.prego.k8skill.com/release-variables> (sign in with your Prego account).

## Examples

The [Release Variables guide](quickstart.md#ci) has the CI jobs.
