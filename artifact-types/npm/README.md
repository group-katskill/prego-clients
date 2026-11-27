# npm

Prego serves private **scoped** npm packages (`@acme/core`) on `npm.prego.k8skill.com`. All other packages still
come from registry.npmjs.org. npm, pnpm, Yarn and Bun read the same registry. `prego setup npm` writes the config
with a variable name only, never a token.

**Plans:** Trial, Indie, Org and Publisher can publish. Consumer reads through grants.

## Start

- [npm quickstart](quickstart.md): connect npm, install, publish, CI, trusted publishing, and the errors.
- [npm packages](../../README.md#npm-packages) in the root README.
- Full docs: <https://docs.prego.k8skill.com/npm> (sign in with your Prego account).

## Stop dependency confusion

If npm does not know where your scope is, it asks registry.npmjs.org. A person can publish a public package there with
the same name as your private package. We call this attack dependency confusion. Do these two steps.

1. **Put the scope line in the `.npmrc` of every project, and commit it.** Then npm asks only Prego for `@acme`
   packages:

   ```ini
   @acme:registry=https://npm.prego.k8skill.com/t/acme/default/
   ```

   `prego setup npm --scope @acme` writes this line.

2. **Create the free organization for each scope on npmjs.com,** for example `@acme`. Then nobody else can publish
   `@acme` packages there. Do this also for a scope that you use only in Prego.

## Examples

The [npm quickstart](quickstart.md#ci) has the CI jobs, and
[trusted publishing from CI](quickstart.md#trusted-publishing-from-ci).
