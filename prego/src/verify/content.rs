//! The content step of `prego verify`: gets the version (the latest when none is given), downloads its
//! content through the existing routes, and recomputes the subject digests (wire contract items 5, 7, 11, 12).

use prego_auth::http::Http;
use prego_auth::oci::{normalize_host, oci_hosts, DEFAULT_OCI_HOST};
use prego_auth::sources::find_subject_token;
use prego_auth::{Config, Env, FileConfig};
use sha2::{Digest, Sha256};

use super::statement::Subject;
use super::Target;

/// The resolved version and the digests computed here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Content {
    /// The version as the attestation route and the predicate name it.
    pub version: String,
    pub subjects: Vec<Subject>,
    /// Go: the `h1:` hash of the module zip, compared with the predicate field `go_h1`.
    pub go_h1: Option<String>,
    /// The canonical name when it differs from the typed one (Python: PEP 503; cargo: the name in the index).
    pub name: Option<String>,
}

/// `registry`: the registry host of the type (oci, cargo, npm, python, go), instead of the configured or
/// default host.
pub fn fetch(
    globals: &[&str],
    env: &dyn Env,
    t: &Target,
    registry: Option<&str>,
) -> Result<Content, String> {
    match t.typ.as_str() {
        "snippet" => {
            let r = snip_ref(t)?;
            let (v, h) = crate::snippet::checked_version(globals, env, &r)?;
            version_hash(v, &h)
        }
        "key" => {
            let r = snip_ref(t)?;
            let (v, h) = crate::keys::checked_version(globals, env, &r)?;
            version_hash(v, &h)
        }
        "a2a" => {
            let r = snip_ref(t)?;
            let (v, h) = crate::a2a::checked_version(globals, env, &r)?;
            version_hash(v, &h)
        }
        "context" => {
            let r = crate::context::reference::CtxRef::parse(&plain_ref(t))?;
            let (v, h) = crate::context::checked_version(globals, env, &r)?;
            version_hash(v, &h)
        }
        "sqlite" => {
            let r = crate::sqlite::reference::DbRef::parse(&plain_ref(t))?;
            let (v, file_sha) = crate::sqlite::checked_snapshot(globals, env, &r)?;
            Ok(Content {
                version: v,
                subjects: vec![sha256_subject(&file_sha)],
                go_h1: None,
                name: None,
            })
        }
        "rv" => rv(globals, env, t),
        "apispec" => {
            let r = crate::apispec::SpecRef::parse(&plain_ref(t))?;
            let (v, h) = crate::apispec::checked_version(globals, env, &r)?;
            version_hash(v, &h)
        }
        "oci" => oci(globals, env, t, registry),
        "cargo" => super::registries::cargo(globals, env, t, registry),
        "npm" => super::registries::npm(globals, env, t, registry),
        "python" => super::registries::python(globals, env, t, registry),
        "go" => super::registries::go(globals, env, t, registry),
        other => Err(format!(
            "prego verify: the content check of type {other} is not in this version of prego yet; use \
             --no-content with <ref>@<version> to check the signature and the policy"
        )),
    }
}

/// `<tenant>/<namespace>/<name>[@<version>]`.
fn plain_ref(t: &Target) -> String {
    let v = t
        .version
        .as_deref()
        .map(|v| format!("@{v}"))
        .unwrap_or_default();
    format!("{}/{}/{}{v}", t.tenant, t.namespace, t.name)
}

fn snip_ref(t: &Target) -> Result<crate::snippet::reference::SnipRef, String> {
    crate::snippet::reference::SnipRef::parse(&plain_ref(t))
}

/// The types with a version hash `sha256:<hex>`: the subject is its hex part (wire contract item 5).
fn version_hash(version: String, hash: &str) -> Result<Content, String> {
    let hex = hash
        .strip_prefix("sha256:")
        .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| format!("prego verify: the version hash `{hash}` is not sha256:<hex>"))?;
    Ok(Content {
        version,
        subjects: vec![Subject {
            name: String::new(),
            digest: vec![("sha256".into(), hex.to_ascii_lowercase())],
        }],
        go_h1: None,
        name: None,
    })
}

fn sha256_subject(hex: &str) -> Subject {
    Subject {
        name: String::new(),
        digest: vec![("sha256".into(), hex.to_ascii_lowercase())],
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Release Variables (wire contract item 11): the name is `<package>@<package-version>`, `_namespace` or
/// `_tenant`; the version is the set version number.
fn rv(globals: &[&str], env: &dyn Env, t: &Target) -> Result<Content, String> {
    use crate::env::reference::{Level, Ref};
    let r = match t.name.as_str() {
        "_tenant" if t.namespace == "_tenant" => Ref::parse(&t.tenant, Level::Tenant)?,
        "_tenant" => {
            return Err("prego verify: the tenant set is rv:<tenant>/_tenant/_tenant[#<n>]".into())
        }
        "_namespace" => Ref::parse(&format!("{}/{}", t.tenant, t.namespace), Level::Namespace)?,
        _ => Ref::parse(
            &format!("{}/{}/{}", t.tenant, t.namespace, t.name),
            Level::Version,
        )?,
    };
    let number = match &t.version {
        Some(v) => Some(v.parse::<u64>().map_err(|_| {
            format!("prego verify: the set version `{v}` is not a number (rv:...#<n>)")
        })?),
        None => None,
    };
    let (n, h) = crate::env::checked_set(globals, env, &r, number)?;
    version_hash(n, &h)
}

/// OCI (wire contract item 12): the version is the manifest digest. A tag is resolved to the digest here.
fn oci(
    globals: &[&str],
    env: &dyn Env,
    t: &Target,
    registry: Option<&str>,
) -> Result<Content, String> {
    use crate::oci::input::MAX_MANIFEST_BYTES;
    use crate::oci::registry::Registry;
    let file = FileConfig::load(env).map_err(|e| e.to_string())?;
    let host = match registry {
        Some(r) => normalize_host(r).ok_or("prego verify: --registry is empty")?,
        None => DEFAULT_OCI_HOST.to_string(),
    };
    if !oci_hosts(&file, env).contains(&host) {
        return Err(format!(
            "prego verify: `{host}` is not a Prego OCI host. Add it to oci_hosts in ~/.config/prego/config.toml \
             or to PREGO_OCI_HOSTS"
        ));
    }
    // The token's tenant: the configured tenant, else the tenant of the reference (as for the other types).
    let has_tenant = globals.iter().any(|g| g.starts_with("--tenant="))
        || env.var("PREGO_TENANT").is_some()
        || file.tenant.is_some();
    let tenant_arg = format!("--tenant={}", t.tenant);
    let mut all: Vec<&str> = globals.to_vec();
    if !has_tenant {
        all.push(&tenant_arg);
    }
    let config = Config::from_parts(&all, env, &file).map_err(|e| e.to_string())?;
    let auth_http = Http::with_ca_file(crate::USER_AGENT, config.ca_file.as_deref())
        .map_err(|e| format!("prego: PREGO_CA_FILE: {e}"))?;
    let subject = find_subject_token(&config, env, &auth_http).map_err(|e| e.to_string())?;
    let http = Http::for_transfers(crate::USER_AGENT, config.ca_file.as_deref())
        .map_err(|e| format!("prego: PREGO_CA_FILE: {e}"))?;
    let scheme = if crate::oci::reference::is_loopback(&host) {
        "http"
    } else {
        "https"
    };
    let base = format!("{scheme}://{host}");
    let name = format!("{}/{}/{}", t.tenant, t.namespace, t.name);
    let sleep = std::thread::sleep;
    let mut reg = Registry::connect_pull(&http, &base, &name, &config, &subject, &sleep)?;
    let reference = t.version.as_deref().unwrap_or("latest");
    let (_, bytes, header) = reg.get_manifest(reference, MAX_MANIFEST_BYTES)?;
    let digest = format!("sha256:{}", hex(&Sha256::digest(&bytes)));
    if let Some(h) = header {
        if h != digest {
            return Err(format!(
                "prego verify: the manifest of {name}:{reference} does not match its digest header ({h}, the \
                 content is {digest})"
            ));
        }
    }
    if reference.starts_with("sha256:") && reference != digest {
        return Err(format!(
            "prego verify: the manifest of {name}@{reference} has the digest {digest}"
        ));
    }
    Ok(Content {
        subjects: vec![sha256_subject(&digest["sha256:".len()..])],
        version: digest,
        go_h1: None,
        name: None,
    })
}
