//! `prego go-auth`: the GOAUTH command helper (Go 1.24 and later), and its token cache.
//!
//! First call (no arguments): print the Prego URL prefixes of `GOPROXY` and an `Authorization` header for
//! them. Later calls (a URL argument, and the 4xx response on stdin): after a `401` from Prego, get a new
//! token; after any other status, print the cached token again and make no STS call.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use prego_auth::http::Http;
use prego_auth::sources::find_subject_token;
use prego_auth::{go, sts, Config, Env, FileConfig, RegistryToken, Secret};
use sha2::{Digest, Sha256};

use super::publish::TempFile;

/// A Prego entry of `GOPROXY`: `<scheme>://<host>/t/<tenant>/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyPrefix {
    pub url: String,
    pub tenant: String,
}

/// The Prego entries of a `GOPROXY` value, on the allowed hosts only.
pub fn prego_prefixes(goproxy: &str, hosts: &[String]) -> Vec<ProxyPrefix> {
    let mut out: Vec<ProxyPrefix> = Vec::new();
    for entry in goproxy.split([',', '|']) {
        let entry = entry.trim();
        let Some((scheme, rest)) = entry.split_once("://") else {
            continue;
        };
        let (host, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        let Some(host) = prego_auth::oci::normalize_host(host) else {
            continue;
        };
        if !hosts.contains(&host) || scheme != go::scheme(&host) {
            continue;
        }
        let mut parts = path.split('/').skip(1);
        let (Some("t"), Some(tenant)) = (parts.next(), parts.next()) else {
            continue;
        };
        let ok = !tenant.is_empty()
            && tenant.len() <= 128
            && tenant
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
        if !ok {
            continue;
        }
        let p = ProxyPrefix {
            url: format!("{scheme}://{host}/t/{tenant}/"),
            tenant: tenant.to_string(),
        };
        if !out.contains(&p) {
            out.push(p);
        }
    }
    out
}

/// The STS `resource` for a `GOPROXY` value: the base URL `<scheme>://<host>/t/<tenant>/<namespace>` if the
/// Prego entries (on the allowed hosts) name exactly one namespace, else `None` (then the STS gives the
/// shortest lifetime over all grants, which is right for every entry).
pub fn prego_resource(goproxy: &str, hosts: &[String]) -> Option<String> {
    let mut bases: Vec<String> = Vec::new();
    for entry in goproxy.split([',', '|']).map(str::trim) {
        if prego_prefixes(entry, hosts).is_empty() {
            continue;
        }
        let b = sts::resource_base(entry)?;
        if !bases.contains(&b) {
            bases.push(b);
        }
    }
    match bases.as_slice() {
        [one] => Some(one.clone()),
        _ => None,
    }
}

/// The `GOPROXY` value: the environment, else `go env GOPROXY`.
pub fn goproxy(env: &dyn Env) -> String {
    if let Some(v) = env.var("GOPROXY") {
        return v;
    }
    super::go_env(env, "GOPROXY").unwrap_or_default()
}

/// The status code in the first line of an HTTP response (`HTTP/1.1 401 Unauthorized`).
pub fn status_of(response: &str) -> Option<u16> {
    let line = response.lines().next()?;
    let mut f = line.split_whitespace();
    let proto = f.next()?;
    if !proto.starts_with("HTTP/") {
        return None;
    }
    f.next()?.parse().ok()
}

/// The text Go reads: the URL lines, a blank line, the header, a blank line.
pub fn credential_block(prefixes: &[ProxyPrefix], token: &str) -> String {
    let mut s = String::new();
    for p in prefixes {
        s.push_str(&p.url);
        s.push('\n');
    }
    s.push('\n');
    s.push_str("Authorization: Bearer ");
    s.push_str(token);
    s.push_str("\n\n");
    s
}

/// `prego go-auth [<url>]`.
pub fn go_auth(globals: &[&str], args: &[String], env: &dyn Env) -> Result<(), String> {
    let file = FileConfig::load(env).map_err(|e| e.to_string())?;
    let hosts = go::go_hosts(&file, env);
    let proxy = goproxy(env);
    let prefixes = prego_prefixes(&proxy, &hosts);
    let resource = prego_resource(&proxy, &hosts);
    if prefixes.is_empty() {
        // No Prego entry in GOPROXY: nothing to give, and no STS call.
        return Ok(());
    }
    let config = match Config::from_parts(globals, env, &file) {
        Ok(c) => c,
        // No tenant is set: use the tenant of GOPROXY if there is exactly one.
        Err(e) if e.to_string().contains("tenant is not set") => {
            let mut tenants: Vec<&str> = prefixes.iter().map(|p| p.tenant.as_str()).collect();
            tenants.dedup();
            if tenants.len() != 1 {
                return Err(format!(
                    "prego go-auth: GOPROXY has more than one Prego tenant; set PREGO_TENANT to your own tenant ({e})"
                ));
            }
            let arg = format!("--tenant={}", tenants[0]);
            let mut g: Vec<&str> = globals.to_vec();
            g.push(&arg);
            Config::from_parts(&g, env, &file).map_err(|e| e.to_string())?
        }
        Err(e) => return Err(e.to_string()),
    };

    let url = args.first().map(String::as_str);
    let status = if url.is_some() {
        let mut input = Vec::new();
        let _ = std::io::stdin().take(64 * 1024).read_to_end(&mut input);
        status_of(&String::from_utf8_lossy(&input))
    } else {
        None
    };
    let for_prego = url.is_some_and(|u| prefixes.iter().any(|p| u.starts_with(&p.url)));

    let cache = Cache::open(env, &cache_key(&config, resource.as_deref(), env));
    let now = prego_auth::now_unix();
    let cached = cache.as_ref().and_then(|c| c.get(now));
    let token = match (url, status) {
        // Prego refused the token: get a new one.
        (Some(_), Some(401)) if for_prego => None,
        // Any other retry: the cached token, and no STS call.
        (Some(_), _) if !for_prego => match cached {
            Some(t) => Some(t),
            None => return Ok(()),
        },
        _ => cached,
    };
    let token = match token {
        Some(t) => t,
        None => {
            let t = exchange(&config, env, resource.as_deref())?;
            if let Some(c) = &cache {
                c.put(&t);
            }
            t.token
        }
    };
    let mut out = std::io::stdout().lock();
    out.write_all(credential_block(&prefixes, token.expose()).as_bytes())
        .and_then(|()| out.flush())
        .map_err(|e| format!("prego go-auth: {e}"))
}

/// One STS exchange for `resource` (a registry base URL, see [`sts::resource_base`]).
pub fn exchange(
    config: &Config,
    env: &dyn Env,
    resource: Option<&str>,
) -> Result<RegistryToken, String> {
    let http = Http::with_ca_file(crate::USER_AGENT, config.ca_file.as_deref())
        .map_err(|e| format!("prego: PREGO_CA_FILE: {e}"))?;
    let subject = find_subject_token(config, env, &http).map_err(|e| e.to_string())?;
    sts::exchange(
        &http,
        config,
        &subject,
        resource,
        prego_auth::now_unix(),
        &std::thread::sleep,
    )
    .map_err(|e| e.to_string())
}

/// The cache key: the STS, tenant, audience and source settings, the `resource`, and a hash of the variables
/// that pick the identity. Values are hashed; no identity value is written to disk.
fn cache_key(config: &Config, resource: Option<&str>, env: &dyn Env) -> String {
    let mut h = Sha256::new();
    for part in [
        config.sts_url.as_str(),
        config.tenant.as_str(),
        config.audience.as_str(),
        &format!("{:?}", config.source),
        resource.unwrap_or(""),
    ] {
        h.update(part.as_bytes());
        h.update([0]);
    }
    for var in [
        "PREGO_API_KEY",
        "PREGO_ID_TOKEN",
        "PREGO_TOKEN_FILE",
        "PREGO_SVID_FILE",
        "SPIFFE_ENDPOINT_SOCKET",
        "ACTIONS_ID_TOKEN_REQUEST_URL",
    ] {
        h.update(env.var(var).unwrap_or_default().as_bytes());
        h.update([0]);
    }
    h.finalize()[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The token cache: one file (mode 0600) in a private directory (mode 0700). Any failed check means no
/// cache, never an error.
pub struct Cache {
    path: PathBuf,
    dir: PathBuf,
}

impl Cache {
    /// `$XDG_RUNTIME_DIR/prego/`, else `$TMPDIR/prego-<uid>/`. `None` if the directory is not safe.
    pub fn open(env: &dyn Env, key: &str) -> Option<Cache> {
        let dir = cache_dir(env)?;
        Some(Cache {
            path: dir.join(format!("goauth-{key}.json")),
            dir,
        })
    }

    /// The private directory of the cache.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The cached token, if it is still fresh: until its expiry minus `min(60 s, lifetime / 4)`. A file
    /// with no lifetime (from prego 0.4) uses 60 s. A token that is no longer fresh is deleted.
    pub fn get(&self, now: i64) -> Option<Secret> {
        let text = read_private_file(&self.path)?;
        let v: serde_json::Value = serde_json::from_str(&text).ok()?;
        let exp = v["expires_at"].as_i64()?;
        let margin = v["lifetime"]
            .as_i64()
            .map_or(sts::MAX_MARGIN_SECONDS, sts::cache_margin);
        if now >= exp - margin {
            let _ = std::fs::remove_file(&self.path);
            return None;
        }
        v["token"].as_str().map(Secret::new)
    }

    /// Stores a token. Errors are ignored: the cache is only an optimization.
    pub fn put(&self, t: &RegistryToken) {
        let Ok(mut tmp) = TempFile::create(&self.dir, ".goauth-new") else {
            return;
        };
        let body = serde_json::json!({
            "token": t.token.expose(),
            "expires_at": t.expires_at,
            "lifetime": t.lifetime,
        });
        if tmp.file.write_all(body.to_string().as_bytes()).is_ok() && tmp.file.sync_all().is_ok() {
            // rename does not follow a symlink at the target; it replaces it.
            let _ = std::fs::rename(&tmp.path, &self.path);
        }
    }
}

#[cfg(unix)]
fn cache_dir(env: &dyn Env) -> Option<PathBuf> {
    if let Some(run) = env
        .var("XDG_RUNTIME_DIR")
        .filter(|d| Path::new(d).is_absolute())
    {
        let base = PathBuf::from(run);
        let uid = current_uid(&base)?;
        return private_dir(&base.join("prego"), uid);
    }
    let tmp = env
        .var("TMPDIR")
        .filter(|d| Path::new(d).is_absolute())
        .unwrap_or_else(|| "/tmp".into());
    let base = PathBuf::from(tmp);
    let uid = current_uid(&base)?;
    private_dir(&base.join(format!("prego-{uid}")), uid)
}

#[cfg(not(unix))]
fn cache_dir(_env: &dyn Env) -> Option<PathBuf> {
    None
}

/// The uid of this process: the owner of a new file in `dir` (no libc call is needed).
#[cfg(unix)]
fn current_uid(dir: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    let probe = TempFile::create(dir, ".prego-uid").ok()?;
    probe.file.metadata().ok().map(|m| m.uid())
}

/// Uses `dir` only if it is a real directory (not a symlink), owned by `uid`, with mode 0700. Creates it
/// with mode 0700 if it is missing.
#[cfg(unix)]
fn private_dir(dir: &Path, uid: u32) -> Option<PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    let meta = match std::fs::symlink_metadata(dir) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new().mode(0o700).create(dir).ok()?;
            std::fs::symlink_metadata(dir).ok()?
        }
        Err(_) => return None,
    };
    let ok = meta.file_type().is_dir()
        && meta.uid() == uid
        && meta.permissions().mode() & 0o777 == 0o700;
    ok.then(|| dir.to_path_buf())
}

/// Reads a small file only if it is a regular file (not a symlink) owned by this user with mode 0600, and
/// the open file is the same file that was checked.
#[cfg(unix)]
fn read_private_file(path: &Path) -> Option<String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let before = std::fs::symlink_metadata(path).ok()?;
    if !before.file_type().is_file() || before.permissions().mode() & 0o777 != 0o600 {
        return None;
    }
    let dir_owner = std::fs::symlink_metadata(path.parent()?).ok()?.uid();
    if before.uid() != dir_owner {
        return None;
    }
    let f = std::fs::File::open(path).ok()?;
    let after = f.metadata().ok()?;
    if after.dev() != before.dev() || after.ino() != before.ino() {
        return None;
    }
    let mut text = String::new();
    f.take(16 * 1024).read_to_string(&mut text).ok()?;
    Some(text)
}

#[cfg(not(unix))]
fn read_private_file(_path: &Path) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use prego_auth::MapEnv;

    fn hosts() -> Vec<String> {
        vec!["go.prego.k8skill.com".into(), "go2.example.test".into()]
    }

    #[test]
    fn prefixes_from_goproxy() {
        let p = prego_prefixes(
            "https://go.prego.k8skill.com/t/acme/default,https://proxy.golang.org|https://GO.prego.k8skill.com:443/t/acme/rel,https://go2.example.test/t/beta/x,https://evil.test/t/acme/default,http://go.prego.k8skill.com/t/acme/default,https://go.prego.k8skill.com/x/acme,https://go.prego.k8skill.com/t/a%20b/c,direct",
            &hosts(),
        );
        assert_eq!(
            p,
            vec![
                ProxyPrefix {
                    url: "https://go.prego.k8skill.com/t/acme/".into(),
                    tenant: "acme".into()
                },
                ProxyPrefix {
                    url: "https://go2.example.test/t/beta/".into(),
                    tenant: "beta".into()
                },
            ]
        );
        assert!(prego_prefixes("off", &hosts()).is_empty());
    }

    #[test]
    fn resources() {
        let h = hosts();
        assert_eq!(
            prego_resource(
                "https://go.prego.k8skill.com/t/acme/default,https://proxy.golang.org,direct",
                &h
            ),
            Some("https://go.prego.k8skill.com/t/acme/default".into())
        );
        // Two namespaces, or two tenants: no resource.
        assert_eq!(
            prego_resource(
                "https://go.prego.k8skill.com/t/acme/default,https://go.prego.k8skill.com/t/acme/rel",
                &h
            ),
            None
        );
        assert_eq!(
            prego_resource(
                "https://go.prego.k8skill.com/t/acme/default|https://go.prego.k8skill.com/t/vendor/default",
                &h
            ),
            None
        );
        // The same entry twice is one namespace.
        assert_eq!(
            prego_resource(
                "https://go.prego.k8skill.com/t/acme/default,https://go.prego.k8skill.com/t/acme/default/",
                &h
            ),
            Some("https://go.prego.k8skill.com/t/acme/default".into())
        );
        assert_eq!(prego_resource("https://proxy.golang.org,direct", &h), None);
    }

    #[test]
    fn block_format() {
        let p = prego_prefixes("https://go.prego.k8skill.com/t/acme/default", &hosts());
        assert_eq!(
            credential_block(&p, "tok"),
            "https://go.prego.k8skill.com/t/acme/\n\nAuthorization: Bearer tok\n\n"
        );
    }

    #[test]
    fn statuses() {
        assert_eq!(
            status_of("HTTP/1.1 401 Unauthorized\r\nX: y\r\n\r\n"),
            Some(401)
        );
        assert_eq!(status_of("HTTP/2.0 404 Not Found\n"), Some(404));
        assert_eq!(status_of(""), None);
        assert_eq!(status_of("garbage 401"), None);
    }

    #[cfg(unix)]
    #[test]
    fn cache_dir_checks() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!("prego-cache-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let env = MapEnv::new().with("XDG_RUNTIME_DIR", base.to_str().unwrap());
        let cache = Cache::open(&env, "k").expect("a new private dir");
        let mode = std::fs::metadata(base.join("prego"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
        cache.put(&RegistryToken::new(Secret::new("tok"), 1000, 900));
        assert_eq!(cache.get(1000).unwrap().expose(), "tok");
        assert_eq!(cache.get(1839).unwrap().expose(), "tok");
        let fmode = std::fs::metadata(&cache.path).unwrap().permissions().mode();
        assert_eq!(fmode & 0o777, 0o600);
        // Expiry minus 60 s: no token, and the file is deleted.
        assert!(cache.get(1840).is_none());
        assert!(!cache.path.exists());
        // A 1-minute token: margin 15 s, so the cache never outlives it.
        cache.put(&RegistryToken::new(Secret::new("short"), 1000, 60));
        assert_eq!(cache.get(1044).unwrap().expose(), "short");
        assert!(cache.get(1045).is_none());
        // A file from prego 0.4 (no lifetime): margin 60 s.
        std::fs::write(&cache.path, r#"{"token":"old","expires_at":2000}"#).unwrap();
        std::fs::set_permissions(&cache.path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(cache.get(1939).unwrap().expose(), "old");
        assert!(cache.get(1940).is_none());

        // A symlink in place of the cache file is never read.
        let target = base.join("other");
        std::fs::write(&target, r#"{"token":"evil","expires_at":99999}"#).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&target, &cache.path).unwrap();
        assert!(cache.get(1000).is_none());

        // A group-readable directory is not used.
        std::fs::set_permissions(base.join("prego"), std::fs::Permissions::from_mode(0o750))
            .unwrap();
        assert!(Cache::open(&env, "k").is_none());
        // A symlink in place of the directory is not used.
        std::fs::remove_dir_all(base.join("prego")).unwrap();
        std::os::unix::fs::symlink(&base, base.join("prego")).unwrap();
        assert!(Cache::open(&env, "k").is_none());
        std::fs::remove_dir_all(&base).unwrap();
    }
}
