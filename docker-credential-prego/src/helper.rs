//! The Docker credential helper protocol: `get`, `store`, `erase` and `list`.
//!
//! Docker starts the helper with the action as the only argument and writes the request on stdin. A
//! successful action writes its answer on stdout and exits 0. A failed action writes one line of error text
//! on stdout and exits 1. Docker shows that text, and treats the text
//! `credentials not found in native keychain` as "no credentials here", so it falls back.

use prego_auth::http::Http;
use prego_auth::oci::{normalize_host, oci_hosts};
use prego_auth::sources::find_subject_token;
use prego_auth::{Config, Env, FileConfig};
use serde_json::{json, Map, Value};

/// The protocol's not-found text. Docker compares it exactly.
pub const NOT_FOUND: &str = "credentials not found in native keychain";
/// Largest request that the helper reads from stdin.
pub const MAX_INPUT_BYTES: usize = 64 * 1024;

/// The result of one action: the text for stdout and the exit code.
#[derive(Debug, PartialEq, Eq)]
pub struct Outcome {
    /// Text for stdout. It ends with a newline.
    pub stdout: String,
    /// Process exit code.
    pub code: i32,
}

impl Outcome {
    fn ok(value: Value) -> Self {
        Outcome {
            stdout: format!("{value}\n"),
            code: 0,
        }
    }

    fn empty() -> Self {
        Outcome {
            stdout: String::new(),
            code: 0,
        }
    }

    fn fail(message: impl std::fmt::Display) -> Self {
        // One line only: Docker reads the whole stdout as the message.
        let text = message.to_string().replace(['\n', '\r'], " ");
        Outcome {
            stdout: format!("{text}\n"),
            code: 1,
        }
    }
}

/// Runs one action. `flags` are the arguments before the action (`--tenant acme`, ...).
pub fn run(action: &str, flags: &[&str], input: &str, env: &dyn Env) -> Outcome {
    match action {
        "get" => get(flags, input, env),
        // Docker calls `store` after `docker login`, and `erase` on `docker logout`. Prego tokens come from
        // the identity sources, so the helper keeps nothing. Both succeed and do nothing.
        "store" | "erase" => Outcome::empty(),
        "list" => list(flags, env),
        other => Outcome::fail(format!(
            "unknown action `{other}`. Use get, store, erase or list."
        )),
    }
}

fn get(flags: &[&str], input: &str, env: &dyn Env) -> Outcome {
    let server_url = input.trim();
    let file = match FileConfig::load(env) {
        Ok(f) => f,
        Err(e) => return Outcome::fail(e),
    };
    // Check the host first. For a registry that is not Prego, the helper reads no identity source, so it
    // never gives a Prego identity to another registry.
    let is_prego = normalize_host(server_url)
        .map(|h| oci_hosts(&file, env).contains(&h))
        .unwrap_or(false);
    if !is_prego {
        return Outcome::fail(NOT_FOUND);
    }

    let config = match Config::from_parts(flags, env, &file) {
        Ok(c) => c,
        Err(e) => return Outcome::fail(e),
    };
    let ua = concat!("docker-credential-prego/", env!("CARGO_PKG_VERSION"));
    let http = match Http::with_ca_file(ua, config.ca_file.as_deref()) {
        Ok(h) => h,
        Err(e) => return Outcome::fail(format!("prego: PREGO_CA_FILE: {e}")),
    };
    let subject = match find_subject_token(&config, env, &http) {
        Ok(s) => s,
        Err(e) => return Outcome::fail(e),
    };
    // Docker sends Username and Secret to the token realm as HTTP Basic auth. The realm takes the tenant
    // from the username and exchanges the secret at the STS. For a login session the secret is a registry
    // token from the session: the session refresh token never goes to Docker. Docker calls the helper for
    // each command, so the short token lifetime is no problem. The username is never `<token>`, which would
    // make Docker send the secret as a refresh token.
    let secret = match &subject.device {
        Some(device) => match prego_auth::session::registry_token(
            &http,
            &config,
            device,
            None,
            &prego_auth::now_unix,
            &std::thread::sleep,
        ) {
            Ok(t) => t.token,
            Err(e) => return Outcome::fail(e),
        },
        None => subject.value,
    };
    Outcome::ok(json!({
        "ServerURL": server_url,
        "Username": config.tenant,
        "Secret": secret.expose(),
    }))
}

fn list(flags: &[&str], env: &dyn Env) -> Outcome {
    let file = match FileConfig::load(env) {
        Ok(f) => f,
        Err(e) => return Outcome::fail(e),
    };
    let mut map = Map::new();
    // Without a tenant there is nothing to list. That is not an error.
    if let Ok(config) = Config::from_parts(flags, env, &file) {
        for host in oci_hosts(&file, env) {
            map.insert(
                format!("https://{host}"),
                Value::String(config.tenant.clone()),
            );
        }
    }
    Outcome::ok(Value::Object(map))
}

#[cfg(test)]
mod tests {
    use super::*;
    use prego_auth::MapEnv;

    #[test]
    fn store_and_erase_do_nothing() {
        let env = MapEnv::new();
        assert_eq!(run("store", &[], "{}", &env), Outcome::empty());
        assert_eq!(
            run("erase", &[], prego_auth::oci::DEFAULT_OCI_HOST, &env),
            Outcome::empty()
        );
    }

    #[test]
    fn unknown_action_fails() {
        assert_eq!(run("delete", &[], "", &MapEnv::new()).code, 1);
    }

    #[test]
    fn error_text_is_one_line() {
        let o = Outcome::fail("a\nb");
        assert_eq!(o.stdout, "a b\n");
    }
}
