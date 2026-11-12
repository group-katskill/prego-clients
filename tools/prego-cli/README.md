# prego-cli

`prego-cli` is an alias of the crate [`prego`](https://crates.io/crates/prego), the command-line tool for
**Prego by Katskill**. It has the same source and the same version number as `prego`, and it installs the
same binary, `prego`.

```sh
cargo install prego-cli    # the same as: cargo install prego
```

The main crate is `prego`. Install one of the two, not both: the two crates install the binary `prego`, so
Cargo refuses the second install unless you add `--force`.

Each `prego-cli` version is published from the signed tag `prego-clients-vX.Y.Z` of
[prego-clients](https://github.com/group-katskill/prego-clients). Only the package name, the description and
this README are different from `prego`.

For the commands, see the [`prego` README](https://crates.io/crates/prego) and the clients site:
<https://clients.prego.k8skill.com>.

License: `Apache-2.0`.
