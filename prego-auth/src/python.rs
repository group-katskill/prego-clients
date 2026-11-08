//! The Python packages host of Prego (the simple index and the upload API).

use crate::env::Env;
use crate::file_config::FileConfig;
use crate::go::scheme;
use crate::oci::normalize_host;

/// The Python packages host of Prego.
pub const DEFAULT_PYPI_HOST: &str = "pypi.prego.k8skill.com";

/// The Python host: `PREGO_PYPI_HOST`, then `pypi_host` from the settings file, then [`DEFAULT_PYPI_HOST`].
/// The value is normalized with [`normalize_host`].
pub fn pypi_host(file: &FileConfig, env: &dyn Env) -> String {
    env.var("PREGO_PYPI_HOST")
        .as_deref()
        .and_then(normalize_host)
        .or_else(|| file.pypi_host.as_deref().and_then(normalize_host))
        .unwrap_or_else(|| DEFAULT_PYPI_HOST.into())
}

/// The base URL of one namespace, with the `/` at the end: `https://<host>/t/<tenant>/<namespace>/`. It is
/// also the STS `resource` for Python tokens.
pub fn base_url(host: &str, tenant: &str, namespace: &str) -> String {
    format!("{}://{host}/t/{tenant}/{namespace}/", scheme(host))
}

/// The index URL that uv, pip and Poetry read: `<base>simple/`.
pub fn index_url(host: &str, tenant: &str, namespace: &str) -> String {
    format!("{}simple/", base_url(host, tenant, namespace))
}

/// The upload URL that twine and `uv publish` write to: `<base>legacy/`.
pub fn upload_url(host: &str, tenant: &str, namespace: &str) -> String {
    format!("{}legacy/", base_url(host, tenant, namespace))
}

/// True if `host` (normalized) is a Prego Python host: the configured host, or a host under
/// `prego.k8skill.com`.
pub fn is_prego_host(host: &str, configured: &str) -> bool {
    let Some(h) = normalize_host(host) else {
        return false;
    };
    let name = h.split(':').next().unwrap_or(&h);
    h == configured || name.ends_with(".prego.k8skill.com")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::MapEnv;

    #[test]
    fn host_order() {
        let none = FileConfig::default();
        assert_eq!(pypi_host(&none, &MapEnv::new()), DEFAULT_PYPI_HOST);
        let file = FileConfig {
            pypi_host: Some("https://PyPI.Example.Test/".into()),
            ..FileConfig::default()
        };
        assert_eq!(pypi_host(&file, &MapEnv::new()), "pypi.example.test");
        let env = MapEnv::new().with("PREGO_PYPI_HOST", "pypi2.example.test");
        assert_eq!(pypi_host(&file, &env), "pypi2.example.test");
    }

    #[test]
    fn urls() {
        assert_eq!(
            index_url(DEFAULT_PYPI_HOST, "acme", "default"),
            "https://pypi.prego.k8skill.com/t/acme/default/simple/"
        );
        assert_eq!(
            upload_url("127.0.0.1:8080", "acme", "rel"),
            "http://127.0.0.1:8080/t/acme/rel/legacy/"
        );
        assert_eq!(
            base_url(DEFAULT_PYPI_HOST, "acme", "default"),
            "https://pypi.prego.k8skill.com/t/acme/default/"
        );
    }

    #[test]
    fn prego_hosts() {
        assert!(is_prego_host("pypi.prego.k8skill.com", DEFAULT_PYPI_HOST));
        assert!(is_prego_host(
            "PYPI.prego.k8skill.com:443",
            DEFAULT_PYPI_HOST
        ));
        assert!(is_prego_host("127.0.0.1:8080", "127.0.0.1:8080"));
        assert!(!is_prego_host("pypi.org", DEFAULT_PYPI_HOST));
        assert!(!is_prego_host(
            "prego.k8skill.com.evil.test",
            DEFAULT_PYPI_HOST
        ));
    }
}
