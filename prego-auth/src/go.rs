//! Go module hosts of Prego (the GOPROXY protocol).

use crate::env::Env;
use crate::file_config::FileConfig;
use crate::oci::normalize_host;

/// The Go host of Prego.
pub const DEFAULT_GO_HOST: &str = "go.prego.k8skill.com";

/// The Go hosts, in order: `PREGO_GO_HOSTS` (comma-separated), then `go_hosts` from the settings file, then
/// [`DEFAULT_GO_HOST`]. Each host is normalized with [`normalize_host`]. No duplicates.
///
/// The first host is the one that `prego go publish`, `prego setup go` and `prego exec` use. `prego go-auth`
/// gives a token for all of them.
pub fn go_hosts(file: &FileConfig, env: &dyn Env) -> Vec<String> {
    let from_env = env.var("PREGO_GO_HOSTS").unwrap_or_default();
    let mut hosts: Vec<String> = Vec::new();
    let all = from_env
        .split(',')
        .chain(file.go_hosts.iter().map(String::as_str))
        .chain(std::iter::once(DEFAULT_GO_HOST));
    for h in all {
        if let Some(h) = normalize_host(h) {
            if !hosts.contains(&h) {
                hosts.push(h);
            }
        }
    }
    hosts
}

/// `http` for a loopback host (local tests only), else `https`.
pub fn scheme(host: &str) -> &'static str {
    let h = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host)
    };
    if matches!(h, "localhost" | "127.0.0.1" | "::1") {
        "http"
    } else {
        "https"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::MapEnv;

    #[test]
    fn host_order() {
        assert_eq!(
            go_hosts(&FileConfig::default(), &MapEnv::new()),
            vec![DEFAULT_GO_HOST]
        );
        let file = FileConfig {
            go_hosts: vec!["https://Go.Example.Test/".into()],
            ..FileConfig::default()
        };
        let env = MapEnv::new().with("PREGO_GO_HOSTS", "go2.example.test, ,go.example.test");
        assert_eq!(
            go_hosts(&file, &env),
            vec!["go2.example.test", "go.example.test", DEFAULT_GO_HOST]
        );
    }

    #[test]
    fn schemes() {
        assert_eq!(scheme("go.prego.k8skill.com"), "https");
        assert_eq!(scheme("127.0.0.1:8080"), "http");
        assert_eq!(scheme("[::1]:1"), "http");
        assert_eq!(scheme("localhost.evil.test"), "https");
    }
}
