# npm

Prego serves private **scoped** npm packages (`@acme/core`) on `npm.prego.k8skill.com`. All other packages still
come from registry.npmjs.org. npm, pnpm, Yarn and Bun read the same registry. `prego setup npm` writes the config
with a variable name only, never a token.

**Plans:** Trial, Indie, Org and Publisher can publish. Consumer reads through grants.

## Start

- [npm quickstart](quickstart.md): connect npm, install, publish, CI, trusted publishing, and the errors.
- [npm packages](../../README.md#npm-packages) in the root README.
- Full docs: <https://docs.prego.k8skill.com/npm> (sign in with your Prego account).

## Examples

The [npm quickstart](quickstart.md#ci) has the CI jobs, and
[trusted publishing from CI](quickstart.md#trusted-publishing-from-ci).
