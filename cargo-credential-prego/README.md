# cargo-credential-prego

Cargo credential provider for **Prego by Katskill** registries.

Cargo runs it to get a registry token. The provider finds a machine identity (SPIFFE JWT-SVID, GitLab or
GitHub CI OIDC token, token file, or API key), exchanges it at the Prego STS, and gives Cargo a short-lived
registry token. It never prints a token and never writes a token to disk.

```sh
cargo install cargo-credential-prego
```

```toml
# .cargo/config.toml
[registries.acme]
index = "sparse+https://cargo.prego.k8skill.com/t/acme/default/index/"
credential-provider = ["cargo-credential-prego", "--tenant", "acme"]
```

**Name each registry once.** Set `credential-provider` for a registry in one config file only: the user file
`~/.cargo/config.toml` or the repository file `.cargo/config.toml`, not the two. Cargo joins array values from all
its config files. When two files set `credential-provider` for the same registry, Cargo joins the two arrays into
one command, so the second `cargo-credential-prego` becomes an argument of the first. Then every fetch from that
registry fails with:

```text
prego: unknown argument `cargo-credential-prego`
```

To correct it, remove the `credential-provider` line for that registry from one of the two files. The `index` line
can stay in the two files, because it is not an array.

See the repository `README.md` for all arguments and identity sources, and `PROTOCOL.md` for the STS
contract.

License: `Apache-2.0`.
