# Crates (Cargo)

Prego hosts private Rust crates for Cargo. Cargo reads them from a sparse index at `cargo.prego.k8skill.com`.
The credential provider `cargo-credential-prego` gives Cargo a short-lived registry token. No token goes into your
config files.

**Plans:** Trial, Indie, Org and Publisher can publish. Consumer reads through grants.

## Start

- [Configure Cargo](../../README.md#configure-cargo) in the root README.
- [Consumer quickstart](../../docs/consumer-quickstart.md): crates on a laptop, in about five minutes.
- [CI guide](../../docs/ci.md): GitLab CI, GitHub Actions, SPIFFE and cloud workloads.
- Full docs: <https://docs.prego.k8skill.com/crates> (sign in with your Prego account).

## Stop dependency confusion

crates.io has no scopes. A dependency without `registry = "..."` comes from crates.io. If a person publishes a public
crate on crates.io with the same name as your private crate, Cargo can use the public crate. We call this attack
dependency confusion. Do these five steps.

1. **Always give the registry on a private dependency.** Use the registry name from `.cargo/config.toml`. Do this in
   every `Cargo.toml`, also for dev and build dependencies:

   ```toml
   [dependencies]
   acme-core = { version = "1", registry = "acme" }
   ```

2. **Refuse other sources with [cargo-deny](https://github.com/EmbarkStudios/cargo-deny).** Put this in `deny.toml`
   and run `cargo deny check sources` in CI:

   ```toml
   [sources]
   unknown-registry = "deny"
   unknown-git = "deny"
   allow-registry = [
     "https://github.com/rust-lang/crates.io-index",
     "sparse+https://cargo.prego.k8skill.com/t/acme/default/index/",
   ]
   ```

3. **Check in CI that each private crate comes from Prego.** cargo-deny allows each registry for all crates. It
   cannot tie one crate to one registry. This check stops the build if a crate with your prefix comes from a
   different source:

   ```sh
   cargo metadata --format-version 1 --locked | jq -e '[.packages[] | select(.name | startswith("acme-")) | select(.source != null and (.source | contains("cargo.prego.k8skill.com") | not))] | length == 0'
   ```

   The command prints `false` and exits with code 1 if a crate with the prefix `acme-` comes from crates.io or from
   git. Crates in your workspace (path dependencies) have no source, and the check ignores them. Use `--locked`, so
   that the check reads the `Cargo.lock` that you build with.

4. **Give your private crates a clear prefix,** for example `acme-`. Then the check in step 3 finds them, and people
   see that a crate is private.

5. **Do not publish placeholder crates on crates.io to keep your names.** The crates.io policy does not allow name
   squatting. Use steps 1 to 3.

## Examples

The examples are in the shared [`examples/`](../../examples/) folder:

- [`examples/cargo/config.toml`](../../examples/cargo/config.toml): the `.cargo/config.toml` registry block.
- [`examples/github-actions/build.yml`](../../examples/github-actions/build.yml): a GitHub Actions build with the
  job's OIDC token.
- [`examples/gitlab/.gitlab-ci.yml`](../../examples/gitlab/.gitlab-ci.yml): a GitLab CI build with `id_tokens`.
- [`examples/opentofu/main.tf`](../../examples/opentofu/main.tf) and
  [`examples/ansible/playbook.yml`](../../examples/ansible/playbook.yml): set up a build machine.
