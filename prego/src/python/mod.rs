//! Python packages: `prego token --python`, the Python mode of `prego exec`, `prego setup python` and
//! `prego python publish`.
//!
//! A Python token is for one namespace: the STS `resource` is the base URL
//! `https://<host>/t/<tenant>/<namespace>/`, and the token lasts 30 minutes on every plan.

pub mod publish;
pub mod setup;

use std::process::Command;

use prego_auth::{python, Config, Env, FileConfig, Secret};

use crate::go::auth::{cache_key, exchange, Cache};

/// The username for a token in HTTP Basic auth, as on pypi.org.
pub const USERNAME: &str = "__token__";

/// One namespace on the Python host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub tenant: String,
    pub namespace: String,
}

impl Target {
    pub fn base(&self) -> String {
        python::base_url(&self.host, &self.tenant, &self.namespace)
    }
    pub fn index(&self) -> String {
        python::index_url(&self.host, &self.tenant, &self.namespace)
    }
    pub fn upload(&self) -> String {
        python::upload_url(&self.host, &self.tenant, &self.namespace)
    }
}

/// The host and the tenant and namespace of a URL, see [`parse_url`].
pub type UrlParts = (String, Option<(String, String)>);

/// The host (normalized), and the tenant and namespace, of a Python URL
/// `<scheme>://<host>/t/<tenant>/<ns>/...`. The tenant and namespace are `None` if the URL has no such path
/// (pip asks the keyring with the host only). An error if the URL is not on a Prego Python host (`host` or a
/// host under `prego.k8skill.com`): a token must never go to another host.
pub fn parse_url(url: &str, host: &str) -> Result<UrlParts, String> {
    let bad = || {
        format!(
            "prego: `{url}` is not a Prego Python URL. Give the index URL, for example \
             https://{host}/t/<tenant>/<namespace>/simple/"
        )
    };
    let rest = url
        .split_once("://")
        .map_or(url, |(scheme, rest)| match scheme {
            "https" | "http" => rest,
            _ => "",
        });
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    // A user name in the URL (`__token__@host`) is not part of the host.
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let normalized = prego_auth::oci::normalize_host(authority).ok_or_else(bad)?;
    if !python::is_prego_host(&normalized, host) {
        return Err(bad());
    }
    let mut parts = path.split('/').skip(1);
    let names = match (parts.next(), parts.next(), parts.next()) {
        (Some("t"), Some(t), Some(ns)) if !t.is_empty() && !ns.is_empty() => {
            crate::setup::check_slug("tenant", t)?;
            crate::setup::check_slug("namespace", ns)?;
            Some((t.to_string(), ns.to_string()))
        }
        (None | Some(""), _, _) => None,
        _ => return Err(bad()),
    };
    Ok((normalized, names))
}

/// The settings and the namespace for a Python command. `url` (from the keyring helper) wins over
/// `namespace`. If no tenant is set, the tenant of `url` is used.
pub fn target(
    globals: &[&str],
    url: Option<&str>,
    namespace: &str,
    env: &dyn Env,
) -> Result<(Config, Target), String> {
    crate::setup::check_slug("namespace", namespace)?;
    let file = FileConfig::load(env).map_err(|e| e.to_string())?;
    let mut host = python::pypi_host(&file, env);
    let mut from_url = None;
    if let Some(u) = url {
        let (h, names) = parse_url(u, &host)?;
        host = h;
        from_url = names;
    }
    let config = match Config::from_parts(globals, env, &file) {
        Ok(c) => c,
        Err(e) if e.to_string().contains("tenant is not set") => match &from_url {
            Some((t, _)) => {
                let arg = format!("--tenant={t}");
                let mut g: Vec<&str> = globals.to_vec();
                g.push(&arg);
                Config::from_parts(&g, env, &file).map_err(|e| e.to_string())?
            }
            None => return Err(e.to_string()),
        },
        Err(e) => return Err(e.to_string()),
    };
    let (tenant, namespace) = from_url.unwrap_or_else(|| (config.tenant.clone(), namespace.into()));
    Ok((
        config,
        Target {
            host,
            tenant,
            namespace,
        },
    ))
}

/// A Python token for `target`. With a workload identity or an API key, the token is cached (mode 0600 in
/// the private runtime directory) until its expiry minus 60 s, so nested pip runs make no new exchange. The
/// login session keeps its registry tokens in secure storage, never in this cache.
pub fn python_token(config: &Config, target: &Target, env: &dyn Env) -> Result<Secret, String> {
    let resource = target.base();
    let cache = match prego_auth::sources::env_source(config, env) {
        Some(_) => Cache::open_named(env, "python", &cache_key(config, Some(&resource), env)),
        None => None,
    };
    let now = prego_auth::now_unix();
    if let Some(t) = cache.as_ref().and_then(|c| c.get(now)) {
        return Ok(t);
    }
    let t = exchange(config, env, Some(&resource))?;
    if let Some(c) = &cache {
        c.put(&t);
    }
    Ok(t.token)
}

/// `prego token --python [--url URL]`: prints a Python token on stdout, and nothing else.
pub fn token(
    globals: &[&str],
    url: Option<&str>,
    namespace: &str,
    env: &dyn Env,
) -> Result<(), String> {
    let (config, target) = target(globals, url, namespace, env)?;
    let token = python_token(&config, &target, env)?;
    println!("{}", token.expose());
    Ok(())
}

/// True if `program` is a Python tool: then `prego exec` uses the Python mode.
pub fn is_python_program(program: &str) -> bool {
    let name = std::path::Path::new(program)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(program);
    let name = name.strip_suffix(".exe").unwrap_or(name);
    let versioned = |base: &str| {
        name.strip_prefix(base)
            .is_some_and(|v| v.chars().all(|c| c.is_ascii_digit() || c == '.'))
    };
    matches!(name, "uv" | "uvx" | "twine" | "poetry" | "pdm" | "hatch")
        || versioned("python")
        || versioned("pip")
}

/// The variables that the Python mode of `prego exec` sets for the child.
pub fn exec_vars(target: &Target, token: &str, pip: bool) -> Vec<(String, String)> {
    let upload = target.upload();
    let mut v: Vec<(&str, String)> = vec![
        ("UV_INDEX_PREGO_USERNAME", USERNAME.into()),
        ("UV_INDEX_PREGO_PASSWORD", token.into()),
        ("UV_PUBLISH_USERNAME", USERNAME.into()),
        ("UV_PUBLISH_PASSWORD", token.into()),
        ("UV_PUBLISH_URL", upload.clone()),
        ("TWINE_USERNAME", USERNAME.into()),
        ("TWINE_PASSWORD", token.into()),
        ("TWINE_REPOSITORY_URL", upload),
        ("POETRY_HTTP_BASIC_PREGO_USERNAME", USERNAME.into()),
        ("POETRY_HTTP_BASIC_PREGO_PASSWORD", token.into()),
        ("PREGO_TOKEN", token.into()),
    ];
    if pip {
        let index = target.index();
        let (scheme, rest) = index.split_once("://").unwrap_or(("https", &index));
        v.push((
            "PIP_EXTRA_INDEX_URL",
            format!("{scheme}://{USERNAME}:{token}@{rest}"),
        ));
    }
    v.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}

/// The Python mode of `prego exec`: one exchange for the Python resource (30 minutes), the variables for
/// uv, pip (with `pip`), twine and Poetry, and nothing on stderr.
pub fn exec(
    globals: &[&str],
    command: &[String],
    namespace: &str,
    pip: bool,
    env: &dyn Env,
) -> Result<i32, String> {
    let (program, rest) = command
        .split_first()
        .ok_or("prego: usage: prego exec -- <command> [args]")?;
    let (config, target) = target(globals, None, namespace, env)?;
    let token = python_token(&config, &target, env)?;
    let status = Command::new(program)
        .args(rest)
        .envs(exec_vars(&target, token.expose(), pip))
        .status()
        .map_err(|e| format!("prego: cannot run `{program}`: {e}"))?;
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "pypi.prego.k8skill.com";

    #[test]
    fn urls_from_the_keyring() {
        let names = |t: &str, n: &str| Some((t.to_string(), n.to_string()));
        assert_eq!(
            parse_url(
                "https://pypi.prego.k8skill.com/t/acme/rel/simple/acme-core/",
                HOST
            )
            .unwrap(),
            (HOST.to_string(), names("acme", "rel"))
        );
        assert_eq!(
            parse_url(
                "https://__token__@PyPI.prego.k8skill.com/t/acme/default/simple/",
                HOST
            )
            .unwrap(),
            (HOST.to_string(), names("acme", "default"))
        );
        assert_eq!(
            parse_url("https://pypi.prego.k8skill.com/", HOST).unwrap(),
            (HOST.to_string(), None)
        );
        assert_eq!(
            parse_url("pypi-other.prego.k8skill.com", HOST).unwrap(),
            ("pypi-other.prego.k8skill.com".to_string(), None)
        );
        assert_eq!(
            parse_url("http://127.0.0.1:9/t/a/b/legacy/", "127.0.0.1:9").unwrap(),
            ("127.0.0.1:9".to_string(), names("a", "b"))
        );
        for bad in [
            "https://pypi.org/simple/",
            "https://pypi.prego.k8skill.com.evil.test/t/a/b/simple/",
            "https://evil.test/@pypi.prego.k8skill.com/t/a/b/",
            "ftp://pypi.prego.k8skill.com/t/a/b/",
            "https://pypi.prego.k8skill.com/x/a/b/",
            "https://pypi.prego.k8skill.com/t/a b/c/",
        ] {
            assert!(parse_url(bad, HOST).is_err(), "{bad}");
        }
    }

    #[test]
    fn python_programs() {
        for p in [
            "uv",
            "/usr/bin/python3",
            "python3.12",
            "pip",
            "pip3.13",
            "twine",
            "poetry",
            "uvx",
            "python.exe",
        ] {
            assert!(is_python_program(p), "{p}");
        }
        for p in ["npm", "go", "pythonista", "pipx", "make", "uv-run"] {
            assert!(!is_python_program(p), "{p}");
        }
    }

    #[test]
    fn exec_variables() {
        let t = Target {
            host: HOST.into(),
            tenant: "acme".into(),
            namespace: "default".into(),
        };
        let v = exec_vars(&t, "tok", false);
        let get = |k: &str| v.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("UV_INDEX_PREGO_USERNAME"), Some("__token__"));
        assert_eq!(get("UV_INDEX_PREGO_PASSWORD"), Some("tok"));
        assert_eq!(get("TWINE_PASSWORD"), Some("tok"));
        assert_eq!(
            get("UV_PUBLISH_URL"),
            Some("https://pypi.prego.k8skill.com/t/acme/default/legacy/")
        );
        assert_eq!(get("TWINE_REPOSITORY_URL"), get("UV_PUBLISH_URL"));
        assert_eq!(get("PIP_EXTRA_INDEX_URL"), None);
        let v = exec_vars(&t, "tok", true);
        assert_eq!(
            v.iter()
                .find(|(n, _)| n == "PIP_EXTRA_INDEX_URL")
                .unwrap()
                .1,
            "https://__token__:tok@pypi.prego.k8skill.com/t/acme/default/simple/"
        );
    }
}
