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

See the repository `README.md` for all arguments and identity sources, and `PROTOCOL.md` for the STS
contract.

License: `Apache-2.0`.
