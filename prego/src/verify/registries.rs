//! The content step of `prego verify` for the package registries: cargo, npm, python and go. Each downloads
//! the files of the version through the registry routes that the package tools use, with a registry token
//! for that route, and computes the subject digests (wire contract item 5).

use base64::Engine as _;
use prego_auth::http::Http;
use prego_auth::{Config, Env, FileConfig};
use serde_json::Value;
use sha2::{Digest, Sha256, Sha512};

use super::content::Content;
use super::statement::Subject;
use super::Target;
use crate::snippet::seg;

/// The Prego cargo host.
pub const DEFAULT_CARGO_HOST: &str = "cargo.prego.k8skill.com";

/// The largest package file that verify hashes (streamed, not kept in memory).
const MAX_FILE: u64 = 5 * 1024 * 1024 * 1024;
/// A Go module zip is at most 300 MiB (it is read into memory for the h1 hash).
const MAX_GO_ZIP: u64 = 300 * 1024 * 1024;
const MAX_META: u64 = 32 * 1024 * 1024;

/// The SHA-256 and SHA-512 of a download, computed while it streams.
#[derive(Default)]
struct Hasher {
    sha256: Sha256,
    sha512: Sha512,
}

impl std::io::Write for Hasher {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.sha256.update(b);
        self.sha512.update(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn scheme(host: &str) -> &'static str {
    if crate::oci::reference::is_loopback(host) {
        "http"
    } else {
        "https"
    }
}

/// The configuration with the tenant of the reference when none is configured (a cross-tenant read uses the
/// configured tenant, as the other types do).
fn config(globals: &[&str], env: &dyn Env, t: &Target) -> Result<(Config, FileConfig), String> {
    let file = FileConfig::load(env).map_err(|e| e.to_string())?;
    let has_tenant = globals.iter().any(|g| g.starts_with("--tenant="))
        || env.var("PREGO_TENANT").is_some()
        || file.tenant.is_some();
    let tenant_arg = format!("--tenant={}", t.tenant);
    let mut all: Vec<&str> = globals.to_vec();
    if !has_tenant {
        all.push(&tenant_arg);
    }
    let config = Config::from_parts(&all, env, &file).map_err(|e| e.to_string())?;
    Ok((config, file))
}

struct Client {
    http: Http,
    auth: String,
}

impl Client {
    fn new(
        config: &Config,
        env: &dyn Env,
        resource: Option<&str>,
        basic: bool,
    ) -> Result<Client, String> {
        let token = crate::go::auth::exchange(config, env, resource)?;
        let t = token.token.expose();
        let auth = if basic {
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD
                    .encode(format!("{}:{t}", crate::python::USERNAME))
            )
        } else {
            format!("Bearer {t}")
        };
        let http = Http::for_transfers(crate::USER_AGENT, config.ca_file.as_deref())
            .map_err(|e| format!("prego: PREGO_CA_FILE: {e}"))?;
        Ok(Client { http, auth })
    }

    fn get(&self, url: &str, accept: &str, max: u64, what: &str) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        self.get_into(url, accept, max, what, &mut out)?;
        Ok(out)
    }

    /// The SHA-256 (hex) and SHA-512 (bytes) of a file, streamed.
    fn hash(&self, url: &str, what: &str) -> Result<(String, Vec<u8>), String> {
        let mut h = Hasher::default();
        self.get_into(url, "application/octet-stream", MAX_FILE, what, &mut h)?;
        Ok((hex(&h.sha256.finalize()), h.sha512.finalize().to_vec()))
    }

    fn get_into(
        &self,
        url: &str,
        accept: &str,
        max: u64,
        what: &str,
        out: &mut dyn std::io::Write,
    ) -> Result<(), String> {
        let (res, _) = self
            .http
            .get_to(
                url,
                &[("Authorization", self.auth.as_str()), ("Accept", accept)],
                out,
                max,
            )
            .map_err(|e| format!("prego: {url}: {e}"))?;
        match res.status {
            200 => Ok(()),
            // A download link (Prego gives large files as a short-lived storage link). It is followed one time,
            // without the token, so the token never goes to another host.
            301 | 302 | 303 | 307 | 308 => {
                let loc = res.header("location").ok_or_else(|| {
                    format!("prego: {what}: a redirect without a Location header")
                })?;
                let target = download_link(url, loc).map_err(|e| format!("prego: {what}: {e}"))?;
                let (r, _) = self
                    .http
                    .get_to(&target, &[("Accept", accept)], out, max)
                    .map_err(|e| format!("prego: {what}: the download link: {e}"))?;
                if r.status == 200 {
                    Ok(())
                } else {
                    Err(format!(
                        "prego: {what}: HTTP {} from the download link",
                        r.status
                    ))
                }
            }
            404 => Err(format!(
                "prego: {what}: not found, or you have no grant for it"
            )),
            s => Err(format!("prego: {what}: {url}: {s}")),
        }
    }

    fn json(&self, url: &str, accept: &str, what: &str) -> Result<Value, String> {
        let b = self.get(url, accept, MAX_META, what)?;
        serde_json::from_slice(&b)
            .map_err(|e| format!("prego: {what}: the answer is not JSON: {e}"))
    }
}

/// The target of a redirect from `url`: a path on the same host, or an `https://` link (`http://` only when
/// `url` is `http://`, for local tests).
pub fn download_link(url: &str, loc: &str) -> Result<String, String> {
    let loc = loc.trim();
    if loc.starts_with('/') && !loc.starts_with("//") {
        let origin_end = url
            .find("://")
            .and_then(|i| url[i + 3..].find('/').map(|j| i + 3 + j))
            .unwrap_or(url.len());
        return Ok(format!("{}{loc}", &url[..origin_end]));
    }
    if loc.starts_with("https://") || (url.starts_with("http://") && loc.starts_with("http://")) {
        return Ok(loc.to_string());
    }
    Err(format!(
        "the registry sent a download link that is not https: `{loc}`"
    ))
}

/// Compares two version texts: numeric parts as numbers, a pre-release (`-...`, or a Python `a`, `b`, `rc`,
/// `dev`) before the release. Enough to find the latest release; not a full SemVer or PEP 440 order.
pub fn version_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    fn split(v: &str) -> (Vec<u64>, bool, &str) {
        let v = v.split('+').next().unwrap_or(v);
        let (core, pre) = match v.find(|c: char| c == '-' || c.is_ascii_alphabetic()) {
            Some(i) => (&v[..i], &v[i..]),
            None => (v, ""),
        };
        let nums = core
            .trim_start_matches('v')
            .split('.')
            .map(|p| p.parse::<u64>().unwrap_or(0))
            .collect();
        (nums, !pre.is_empty(), pre)
    }
    let (na, pa, ra) = split(a);
    let (nb, pb, rb) = split(b);
    let n = na.len().max(nb.len());
    for i in 0..n {
        let x = na.get(i).copied().unwrap_or(0);
        let y = nb.get(i).copied().unwrap_or(0);
        if x != y {
            return x.cmp(&y);
        }
    }
    match (pa, pb) {
        (false, true) => std::cmp::Ordering::Greater,
        (true, false) => std::cmp::Ordering::Less,
        _ => ra.cmp(rb),
    }
}

fn is_pre(v: &str) -> bool {
    let core = v.split('+').next().unwrap_or(v).trim_start_matches('v');
    core.contains('-') || core.chars().any(|c| c.is_ascii_alphabetic())
}

/// The latest version: the highest release, or the highest pre-release when there is no release.
pub fn latest<'a>(versions: impl Iterator<Item = &'a str>) -> Option<&'a str> {
    let all: Vec<&str> = versions.collect();
    let pick = |pre: bool| {
        all.iter()
            .copied()
            .filter(|v| is_pre(v) == pre)
            .max_by(|a, b| version_cmp(a, b))
    };
    pick(false).or_else(|| pick(true))
}

// ---- cargo ----

/// The sparse index path of a crate (lowercase): `1/a`, `2/ab`, `3/a/abc`, `ab/cd/abcd...`.
pub fn cargo_index_path(name: &str) -> String {
    let n = name.to_ascii_lowercase();
    match n.len() {
        1 => format!("1/{n}"),
        2 => format!("2/{n}"),
        3 => format!("3/{}/{n}", &n[..1]),
        _ => format!("{}/{}/{n}", &n[..2], &n[2..4]),
    }
}

/// The download URL from the `dl` value of `config.json` (the Cargo registry rules).
pub fn cargo_dl_url(dl: &str, name: &str, version: &str, cksum: &str) -> String {
    let markers = [
        "{crate}",
        "{version}",
        "{prefix}",
        "{lowerprefix}",
        "{sha256-checksum}",
    ];
    if !markers.iter().any(|m| dl.contains(m)) {
        return format!("{}/{name}/{version}/download", dl.trim_end_matches('/'));
    }
    let lower = name.to_ascii_lowercase();
    let prefix = |s: &str| match s.len() {
        1 => "1".to_string(),
        2 => "2".to_string(),
        3 => format!("3/{}", &s[..1]),
        _ => format!("{}/{}", &s[..2], &s[2..4]),
    };
    dl.replace("{crate}", name)
        .replace("{version}", version)
        .replace("{prefix}", &prefix(name))
        .replace("{lowerprefix}", &prefix(&lower))
        .replace("{sha256-checksum}", cksum)
}

pub fn cargo(
    globals: &[&str],
    env: &dyn Env,
    t: &Target,
    host: Option<&str>,
) -> Result<Content, String> {
    let (config, _) = config(globals, env, t)?;
    let host = host.unwrap_or(DEFAULT_CARGO_HOST);
    let base = format!(
        "{}://{host}/t/{}/{}",
        scheme(host),
        seg(&t.tenant),
        seg(&t.namespace)
    );
    let index = format!("{base}/index");
    let c = Client::new(&config, env, Some(&format!("{base}/")), false)?;
    // Cargo sends the token itself, with no scheme.
    let c = Client {
        auth: c.auth.trim_start_matches("Bearer ").to_string(),
        ..c
    };
    let what = format!("crate {}", t.name);
    let cfg = c.json(&format!("{index}/config.json"), "application/json", &what)?;
    let dl = cfg["dl"]
        .as_str()
        .ok_or_else(|| format!("prego: {what}: the index config.json has no dl"))?;
    let lines = c.get(
        &format!("{index}/{}", cargo_index_path(&t.name)),
        "text/plain",
        MAX_META,
        &what,
    )?;
    let entries: Vec<Value> = String::from_utf8_lossy(&lines)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let version = match &t.version {
        Some(v) => v.clone(),
        None => latest(
            entries
                .iter()
                .filter(|e| e["yanked"] != true)
                .filter_map(|e| e["vers"].as_str()),
        )
        .ok_or_else(|| format!("prego: {what}: the index has no version that is not yanked"))?
        .to_string(),
    };
    let entry = entries
        .iter()
        .find(|e| e["vers"].as_str() == Some(version.as_str()))
        .ok_or_else(|| format!("prego: {what}: the index has no version {version}"))?;
    let name = entry["name"].as_str().unwrap_or(&t.name).to_string();
    let cksum = entry["cksum"].as_str().unwrap_or("").to_ascii_lowercase();
    let (sha, _) = c.hash(
        &cargo_dl_url(dl, &name, &version, &cksum),
        &format!("{what}@{version}"),
    )?;
    if !cksum.is_empty() && cksum != sha {
        return Err(format!(
            "prego verify: {what}@{version}: the .crate has sha256 {sha}; the index cksum is {cksum}"
        ));
    }
    Ok(Content {
        version: version.clone(),
        subjects: vec![Subject {
            name: format!("{name}-{version}.crate"),
            digest: vec![("sha256".into(), sha)],
        }],
        go_h1: None,
        name: Some(name),
    })
}

// ---- npm ----

/// The packument path of a package: a scoped name keeps `@` and encodes `/` (`@acme%2fhello`).
pub fn npm_path(name: &str) -> String {
    match name.strip_prefix('@').and_then(|s| s.split_once('/')) {
        Some((scope, n)) => format!("@{}%2f{}", seg(scope), seg(n)),
        None => seg(name),
    }
}

pub fn npm(
    globals: &[&str],
    env: &dyn Env,
    t: &Target,
    host: Option<&str>,
) -> Result<Content, String> {
    let (config, file) = config(globals, env, t)?;
    let host = host
        .map(str::to_string)
        .unwrap_or_else(|| prego_auth::npm::npm_host(&file, env));
    let registry = format!(
        "{}://{host}/t/{}/{}/",
        scheme(&host),
        seg(&t.tenant),
        seg(&t.namespace)
    );
    let c = Client::new(&config, env, None, false)?;
    let what = format!("npm package {}", t.name);
    let doc = c.json(
        &format!("{registry}{}", npm_path(&t.name)),
        "application/json",
        &what,
    )?;
    let version = match &t.version {
        Some(v) => v.clone(),
        None => doc["dist-tags"]["latest"]
            .as_str()
            .ok_or_else(|| format!("prego: {what}: the package has no latest tag"))?
            .to_string(),
    };
    let dist = &doc["versions"][&version]["dist"];
    let tarball = dist["tarball"]
        .as_str()
        .ok_or_else(|| format!("prego: {what}: there is no version {version}"))?;
    let (sha256, sha512) = c.hash(tarball, &format!("{what}@{version}"))?;
    if let Some(i) = dist["integrity"].as_str() {
        let want = i
            .strip_prefix("sha512-")
            .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok());
        if want.as_deref() != Some(&sha512[..]) {
            return Err(format!(
                "prego verify: {what}@{version}: the tarball does not match its integrity value"
            ));
        }
    }
    let file = tarball.rsplit('/').next().unwrap_or("").to_string();
    Ok(Content {
        version,
        subjects: vec![Subject {
            name: file,
            digest: vec![("sha256".into(), sha256), ("sha512".into(), hex(&sha512))],
        }],
        go_h1: None,
        name: None,
    })
}

// ---- python ----

/// PEP 503 name normalization.
pub fn pep503(name: &str) -> String {
    let mut out = String::new();
    let mut sep = false;
    for c in name.chars() {
        if c == '-' || c == '_' || c == '.' {
            sep = true;
        } else {
            if sep && !out.is_empty() {
                out.push('-');
            }
            sep = false;
            out.push(c.to_ascii_lowercase());
        }
    }
    out
}

/// The version in a wheel or sdist file name, for a normalized project name.
pub fn python_file_version(file: &str, project: &str) -> Option<String> {
    let stem = file
        .strip_suffix(".whl")
        .or_else(|| file.strip_suffix(".tar.gz"))
        .or_else(|| file.strip_suffix(".zip"))?;
    let (dist, rest) = if file.ends_with(".whl") {
        let mut parts = stem.splitn(3, '-');
        (parts.next()?, parts.next()?)
    } else {
        let i = stem.rfind('-')?;
        (&stem[..i], &stem[i + 1..])
    };
    (pep503(dist) == project).then(|| rest.to_string())
}

pub fn python(
    globals: &[&str],
    env: &dyn Env,
    t: &Target,
    host: Option<&str>,
) -> Result<Content, String> {
    let (config, file) = config(globals, env, t)?;
    let host = host
        .map(str::to_string)
        .unwrap_or_else(|| prego_auth::python::pypi_host(&file, env));
    let base = format!(
        "{}://{host}/t/{}/{}",
        scheme(&host),
        seg(&t.tenant),
        seg(&t.namespace)
    );
    let c = Client::new(&config, env, Some(&base), true)?;
    let project = pep503(&t.name);
    let what = format!("Python project {project}");
    let doc = c.json(
        &format!("{base}/simple/{project}/"),
        "application/vnd.pypi.simple.v1+json",
        &what,
    )?;
    let files: Vec<&Value> = doc["files"]
        .as_array()
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    let with_version: Vec<(String, &Value)> = files
        .iter()
        .filter(|f| f["yanked"].as_bool() != Some(true) && f["yanked"].as_str().is_none())
        .filter_map(|f| {
            let name = f["filename"].as_str()?;
            Some((python_file_version(name, &project)?, *f))
        })
        .collect();
    let version = match &t.version {
        Some(v) => v.clone(),
        None => latest(with_version.iter().map(|(v, _)| v.as_str()))
            .ok_or_else(|| format!("prego: {what}: the index has no file"))?
            .to_string(),
    };
    let chosen: Vec<&Value> = files
        .iter()
        .filter(|f| {
            f["filename"]
                .as_str()
                .and_then(|n| python_file_version(n, &project))
                .as_deref()
                == Some(version.as_str())
        })
        .copied()
        .collect();
    if chosen.is_empty() {
        return Err(format!(
            "prego: {what}: there is no file of version {version}"
        ));
    }
    let mut subjects = Vec::new();
    for f in chosen {
        let name = f["filename"].as_str().unwrap_or("").to_string();
        let url = f["url"].as_str().unwrap_or("");
        let url = if url.starts_with("http://") || url.starts_with("https://") {
            url.to_string()
        } else {
            crate::oci::registry::resolve(&format!("{base}/simple/{project}/"), url)?
        };
        let (sha, _) = c.hash(&url, &format!("{what} {name}"))?;
        if let Some(want) = f["hashes"]["sha256"].as_str() {
            if !want.eq_ignore_ascii_case(&sha) {
                return Err(format!(
                    "prego verify: {what} {name}: the file has sha256 {sha}; the index says {want}"
                ));
            }
        }
        subjects.push(Subject {
            name,
            digest: vec![("sha256".into(), sha)],
        });
    }
    Ok(Content {
        version,
        subjects,
        go_h1: None,
        name: Some(project),
    })
}

// ---- go ----

pub fn go(
    globals: &[&str],
    env: &dyn Env,
    t: &Target,
    host: Option<&str>,
) -> Result<Content, String> {
    let (config, file) = config(globals, env, t)?;
    let host = match host {
        Some(h) => h.to_string(),
        None => prego_auth::go::go_hosts(&file, env)
            .into_iter()
            .next()
            .unwrap_or_else(|| prego_auth::go::DEFAULT_GO_HOST.to_string()),
    };
    let base = format!(
        "{}://{host}/t/{}/{}",
        scheme(&host),
        seg(&t.tenant),
        seg(&t.namespace)
    );
    let c = Client::new(&config, env, Some(&base), false)?;
    let module = crate::go::module::escape(&t.name);
    let what = format!("Go module {}", t.name);
    let version = match &t.version {
        Some(v) => v.clone(),
        None => c.json(
            &format!("{base}/{module}/@latest"),
            "application/json",
            &what,
        )?["Version"]
            .as_str()
            .ok_or_else(|| format!("prego: {what}: @latest has no Version"))?
            .to_string(),
    };
    let zip = c.get(
        &format!(
            "{base}/{module}/@v/{}.zip",
            crate::go::module::escape(&version)
        ),
        "application/zip",
        MAX_GO_ZIP,
        &format!("{what}@{version}"),
    )?;
    let h1 = crate::go::zip::zip_hash1(std::io::Cursor::new(&zip))?;
    Ok(Content {
        version: version.clone(),
        subjects: vec![Subject {
            name: format!("{}@{version}.zip", t.name),
            digest: vec![("sha256".into(), hex(&Sha256::digest(&zip)))],
        }],
        go_h1: Some(h1),
        name: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latest_versions() {
        assert_eq!(
            latest(["1.2.0", "1.10.0", "1.9.9"].into_iter()),
            Some("1.10.0")
        );
        assert_eq!(latest(["1.0.0", "2.0.0-rc.1"].into_iter()), Some("1.0.0"));
        assert_eq!(
            latest(["2.0.0-rc.1", "2.0.0-beta"].into_iter()),
            Some("2.0.0-rc.1")
        );
        assert_eq!(
            latest(["1.0", "1.1rc1", "1.0.1"].into_iter()),
            Some("1.0.1")
        );
        assert_eq!(latest(std::iter::empty()), None);
    }

    #[test]
    fn download_links() {
        assert_eq!(
            download_link("https://npm.example/t/a/d/x", "/r2/x?sig=1").unwrap(),
            "https://npm.example/r2/x?sig=1"
        );
        assert_eq!(
            download_link("https://npm.example/t/a/d/x", "https://r2.example/x").unwrap(),
            "https://r2.example/x"
        );
        assert!(download_link("https://npm.example/x", "http://r2.example/x").is_err());
        assert!(download_link("https://npm.example/x", "//r2.example/x").is_err());
        assert!(download_link("http://127.0.0.1:9/x", "http://127.0.0.1:9/y").is_ok());
    }

    #[test]
    fn cargo_paths() {
        assert_eq!(cargo_index_path("a"), "1/a");
        assert_eq!(cargo_index_path("ab"), "2/ab");
        assert_eq!(cargo_index_path("Abc"), "3/a/abc");
        assert_eq!(cargo_index_path("Payments"), "pa/ym/payments");
        assert_eq!(
            cargo_dl_url("https://h/t/a/d/api/v1/crates", "x", "1.0.0", "c"),
            "https://h/t/a/d/api/v1/crates/x/1.0.0/download"
        );
        assert_eq!(
            cargo_dl_url(
                "https://h/dl/{lowerprefix}/{crate}/{version}/{sha256-checksum}",
                "Abcd",
                "1.0.0",
                "c"
            ),
            "https://h/dl/ab/cd/Abcd/1.0.0/c"
        );
    }

    #[test]
    fn npm_and_python_names() {
        assert_eq!(npm_path("@acme/hello"), "@acme%2fhello");
        assert_eq!(npm_path("hello"), "hello");
        assert_eq!(pep503("Foo__Bar.baz"), "foo-bar-baz");
        assert_eq!(
            python_file_version("foo_bar-1.2.0-py3-none-any.whl", "foo-bar").as_deref(),
            Some("1.2.0")
        );
        assert_eq!(
            python_file_version("foo-bar-1.2.0.tar.gz", "foo-bar").as_deref(),
            Some("1.2.0")
        );
        assert_eq!(python_file_version("other-1.0.tar.gz", "foo-bar"), None);
    }
}
