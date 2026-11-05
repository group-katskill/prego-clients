//! The npm host of Prego (scoped packages only).

use crate::env::Env;
use crate::file_config::FileConfig;
use crate::go::scheme;
use crate::oci::normalize_host;

/// The npm host of Prego.
pub const DEFAULT_NPM_HOST: &str = "npm.prego.k8skill.com";

/// The environment variable that npm, pnpm, Yarn and Bun read the registry token from. The client files
/// hold only a reference to it, never the token.
pub const TOKEN_VAR: &str = "PREGO_NPM_TOKEN";

/// The npm host: `PREGO_NPM_HOST`, then `npm_host` from the settings file, then [`DEFAULT_NPM_HOST`].
/// The value is normalized with [`normalize_host`].
pub fn npm_host(file: &FileConfig, env: &dyn Env) -> String {
    env.var("PREGO_NPM_HOST")
        .as_deref()
        .and_then(normalize_host)
        .or_else(|| file.npm_host.as_deref().and_then(normalize_host))
        .unwrap_or_else(|| DEFAULT_NPM_HOST.into())
}

/// The registry URL of one namespace, with the `/` at the end that npm needs:
/// `https://<host>/t/<tenant>/<namespace>/`.
pub fn registry_url(host: &str, tenant: &str, namespace: &str) -> String {
    format!("{}://{host}/t/{tenant}/{namespace}/", scheme(host))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::MapEnv;

    #[test]
    fn host_order() {
        let none = FileConfig::default();
        assert_eq!(npm_host(&none, &MapEnv::new()), DEFAULT_NPM_HOST);
        let file = FileConfig {
            npm_host: Some("https://NPM.Example.Test/".into()),
            ..FileConfig::default()
        };
        assert_eq!(npm_host(&file, &MapEnv::new()), "npm.example.test");
        let env = MapEnv::new().with("PREGO_NPM_HOST", "npm2.example.test");
        assert_eq!(npm_host(&file, &env), "npm2.example.test");
        let empty = MapEnv::new().with("PREGO_NPM_HOST", " ");
        assert_eq!(npm_host(&none, &empty), DEFAULT_NPM_HOST);
    }

    #[test]
    fn urls() {
        assert_eq!(
            registry_url(DEFAULT_NPM_HOST, "acme", "default"),
            "https://npm.prego.k8skill.com/t/acme/default/"
        );
        assert_eq!(
            registry_url("127.0.0.1:8080", "acme", "rel"),
            "http://127.0.0.1:8080/t/acme/rel/"
        );
    }
}
