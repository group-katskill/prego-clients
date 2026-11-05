# prego-auth

Identity sources and the STS token exchange for **Prego by Katskill** clients.

`cargo-credential-prego` uses this library. A later `prego` CLI will use it too.

```rust,no_run
use prego_auth::{Config, ProcessEnv, TokenClient};

let env = ProcessEnv;
let config = Config::from_args(&["--tenant", "acme"], &env)?;
let client = TokenClient::new("my-tool/1.0");
let token = client.registry_token(&config, &env)?;
// Send token.token.expose() in the Authorization header. Never print it.
# Ok::<(), prego_auth::Error>(())
```

See `PROTOCOL.md` in the repository root for the STS contract and the identity sources.

License: `Apache-2.0`.
