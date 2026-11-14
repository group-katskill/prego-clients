//! `prego adapter push` and `prego adapter get`: AI model adapters (LoRA and the other peft methods) as one
//! checked OCI artifact (ADR-0052). Publisher and Trial tenants push them; any identity with a `read` grant
//! gets them.

pub mod check;

use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

use prego_auth::http::Http;
use prego_auth::oci::oci_hosts;
use prego_auth::sources::find_subject_token;
use prego_auth::{Config, Env, FileConfig, SubjectToken};

use crate::oci::input::{hex, Blob, Manifest, Source, MAX_MANIFEST_BYTES};
use crate::oci::reference::Reference;
use crate::oci::registry::{BlobResult, Registry};
use check::{Digests, Folder, OCI_MANIFEST};

/// `prego adapter push <folder> <repo>:<version>`.
pub fn push(
    globals: &[&str],
    folder: &str,
    reference: &str,
    license: Option<&str>,
    base_revision: Option<&str>,
    env: &dyn Env,
) -> Result<(), String> {
    let r = parse_reference(reference)?;
    // Read and check the folder before any network call.
    let f = check::read_folder(Path::new(folder)).map_err(|e| format!("prego: {e}"))?;
    let (license, from) = check::license(license, &f).map_err(|e| format!("prego: {e}"))?;
    if let Some(rev) = base_revision {
        check::check_revision(rev).map_err(|e| format!("prego: {e}"))?;
    }
    let config = load_config(globals, &r, env)?;
    if r.tenant() != config.tenant {
        return Err(format!(
            "prego: the adapter name must start with the tenant `{}`: {}/<namespace>/<repo>:<version>",
            config.tenant, config.tenant
        ));
    }
    let digests = Digests {
        config: check::file_digest(&f.config).map_err(|e| format!("prego: {e}"))?,
        weights: check::file_digest(&f.weights).map_err(|e| format!("prego: {e}"))?,
        extras: f
            .extras
            .iter()
            .map(check::file_digest)
            .collect::<Result<_, _>>()
            .map_err(|e| format!("prego: {e}"))?,
    };
    let manifest = check::manifest(&f, &digests, &license, base_revision);
    print_summary(&f, &license, from, base_revision, &r);

    let auth_http = Http::with_ca_file(crate::USER_AGENT, config.ca_file.as_deref())
        .map_err(|e| format!("prego: PREGO_CA_FILE: {e}"))?;
    let subject = find_subject_token(&config, env, &auth_http).map_err(|e| e.to_string())?;
    let http = Http::for_transfers(crate::USER_AGENT, config.ca_file.as_deref())
        .map_err(|e| format!("prego: PREGO_CA_FILE: {e}"))?;
    let sleep = std::thread::sleep;
    let base = format!("{}://{}", r.scheme(), r.host);
    let mut reg = Registry::connect(&http, &base, &r.name, &config, &subject, None, None, &sleep)?;

    let files = [(&f.config, &digests.config), (&f.weights, &digests.weights)]
        .into_iter()
        .chain(f.extras.iter().zip(&digests.extras));
    for (file, digest) in files {
        let blob = Blob {
            digest: digest.clone(),
            size: file.size,
            source: Source {
                path: file.path.clone(),
                offset: 0,
                size: file.size,
            },
            verified: true,
        };
        let what = if reg.has_blob(digest)? {
            "exists".to_string()
        } else {
            match reg.push_blob(&blob)? {
                BlobResult::Mounted => "mounted".to_string(),
                BlobResult::Uploaded { parts, .. } => format!("uploaded in {parts} part(s)"),
            }
        };
        eprintln!("  {:<32} {:>10}  {what}", file.name, human(file.size));
    }
    let m = Manifest {
        digest: sha256(&manifest),
        media_type: OCI_MANIFEST.into(),
        bytes: manifest,
    };
    reg.put_manifest(&m, Some(&r.tag))?;
    eprintln!("Token requests: {}", reg.token_requests());
    println!("{}/{}:{}@{}", r.host, r.name, r.tag, m.digest);
    Ok(())
}

/// `prego adapter get <repo>:<version> <folder>`.
pub fn get(globals: &[&str], reference: &str, folder: &str, env: &dyn Env) -> Result<(), String> {
    let r = parse_reference(reference)?;
    let dir = PathBuf::from(folder);
    let created = prepare_folder(&dir)?;
    let result = get_into(globals, &r, &dir, env);
    if result.is_err() && created {
        let _ = std::fs::remove_dir_all(&dir);
    }
    result
}

fn get_into(globals: &[&str], r: &Reference, dir: &Path, env: &dyn Env) -> Result<(), String> {
    let config = load_config(globals, r, env)?;
    let auth_http = Http::with_ca_file(crate::USER_AGENT, config.ca_file.as_deref())
        .map_err(|e| format!("prego: PREGO_CA_FILE: {e}"))?;
    let subject: SubjectToken =
        find_subject_token(&config, env, &auth_http).map_err(|e| e.to_string())?;
    let http = Http::for_transfers(crate::USER_AGENT, config.ca_file.as_deref())
        .map_err(|e| format!("prego: PREGO_CA_FILE: {e}"))?;
    let sleep = std::thread::sleep;
    let base = format!("{}://{}", r.scheme(), r.host);
    let mut reg = Registry::connect_pull(&http, &base, &r.name, &config, &subject, &sleep)?;

    let (media_type, bytes, header_digest) = reg.get_manifest(&r.tag, MAX_MANIFEST_BYTES)?;
    let digest = sha256(&bytes);
    if let Some(h) = header_digest {
        if h != digest {
            return Err(format!(
                "prego: the manifest of {}:{} does not match its digest ({h}, the content is {digest})",
                r.name, r.tag
            ));
        }
    }
    if !media_type.is_empty() && media_type != OCI_MANIFEST {
        return Err(format!(
            "prego: {}:{} is not a Prego adapter (media type {media_type}). Use docker pull or oras pull \
             for other artifacts",
            r.name, r.tag
        ));
    }
    let pulled =
        check::check_pulled(&bytes).map_err(|e| format!("prego: {}:{}: {e}", r.name, r.tag))?;
    eprintln!("Getting adapter {}/{}:{}@{digest}", r.host, r.name, r.tag);
    eprintln!(
        "  base model {}{}, license {}",
        pulled.base.as_deref().unwrap_or("(not given)"),
        pulled
            .revision
            .as_deref()
            .map(|v| format!(" at {v}"))
            .unwrap_or_default(),
        pulled.license.as_deref().unwrap_or("(not given)")
    );

    // Download each part to a temporary name, check it, then give it its name.
    let mut temps: Vec<PathBuf> = Vec::new();
    let result: Result<(), String> = (|| {
        for (i, part) in pulled.parts.iter().enumerate() {
            let tmp = dir.join(format!(".prego-{i}.part"));
            temps.push(tmp.clone());
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&tmp)
                .map_err(|e| format!("prego: cannot write {}: {e}", tmp.display()))?;
            reg.get_blob(&part.digest, part.size, &mut file)?;
            drop(file);
            check_part(part, &tmp, pulled.base.as_deref())?;
            eprintln!("  {:<32} {:>10}  ok", part.name, human(part.size));
        }
        for (part, tmp) in pulled.parts.iter().zip(&temps) {
            let target = dir.join(&part.name);
            std::fs::rename(tmp, &target)
                .map_err(|e| format!("prego: cannot write {}: {e}", target.display()))?;
        }
        Ok(())
    })();
    if result.is_err() {
        for t in &temps {
            let _ = std::fs::remove_file(t);
        }
    }
    result?;
    eprintln!("Token requests: {}", reg.token_requests());
    println!("{}", dir.display());
    Ok(())
}

/// Checks a downloaded part again: the config is peft JSON with the base model of the annotation, the
/// weights have a valid safetensors header, and the extra files are text.
fn check_part(part: &check::Part, path: &Path, base: Option<&str>) -> Result<(), String> {
    let bad = |e: String| format!("prego: {}: {e}", part.name);
    match part.media_type.as_str() {
        check::CONFIG_TYPE => {
            let bytes = std::fs::read(path).map_err(|e| bad(e.to_string()))?;
            let (_, _, config_base) = check::check_config(&bytes).map_err(bad)?;
            if base.is_some_and(|b| b != config_base) {
                return Err(bad(
                    "base_model_name_or_path is not the base model of the manifest".into(),
                ));
            }
            Ok(())
        }
        check::WEIGHTS_TYPE => check::check_safetensors(path, part.size)
            .map(|_| ())
            .map_err(bad),
        _ => check::check_text_file(path).map_err(bad),
    }
}

/// Creates the folder, or checks that it is empty. Returns true if it was created.
fn prepare_folder(dir: &Path) -> Result<bool, String> {
    match std::fs::read_dir(dir) {
        Ok(mut entries) => {
            if entries.next().is_some() {
                return Err(format!(
                    "prego: the folder {} is not empty. Give a new or empty folder",
                    dir.display()
                ));
            }
            Ok(false)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(dir)
                .map_err(|e| format!("prego: cannot make the folder {}: {e}", dir.display()))?;
            Ok(true)
        }
        Err(e) => Err(format!(
            "prego: cannot read the folder {}: {e}",
            dir.display()
        )),
    }
}

/// `[host/]<tenant>/<namespace>/<repo>:<version>`. The version (tag) is required.
fn parse_reference(reference: &str) -> Result<Reference, String> {
    let last = reference.rsplit('/').next().unwrap_or("");
    if !last.contains(':') {
        return Err(format!(
            "prego: give the version of the adapter as a tag: {reference}:<version>"
        ));
    }
    Reference::parse(reference).map_err(|e| {
        format!(
            "prego: {}",
            e.replace("image reference", "adapter reference")
        )
    })
}

/// The configuration, after a check that the host is a Prego OCI host.
fn load_config(globals: &[&str], r: &Reference, env: &dyn Env) -> Result<Config, String> {
    let file = FileConfig::load(env).map_err(|e| e.to_string())?;
    if !oci_hosts(&file, env).contains(&r.host) {
        return Err(format!(
            "prego: `{}` is not a Prego OCI host. Add it to oci_hosts in ~/.config/prego/config.toml or to \
             PREGO_OCI_HOSTS",
            r.host
        ));
    }
    Config::from_args(globals, env).map_err(|e| e.to_string())
}

fn print_summary(f: &Folder, license: &str, from: &str, revision: Option<&str>, r: &Reference) {
    eprintln!(
        "Pushing adapter {} ({} {}, {} tensors) to {}/{}:{}",
        human(f.total),
        f.peft_type,
        f.weights.name,
        f.tensors,
        r.host,
        r.name,
        r.tag
    );
    eprintln!("  base model {}", f.base);
    match revision {
        Some(rev) => eprintln!("  base model revision {rev}"),
        None => eprintln!(
            "  warning: no --base-revision. Give the commit of the base model so a loader gets the same \
             base model"
        ),
    }
    eprintln!("  license {license} (from {from})");
    for s in &f.skipped {
        eprintln!("  skipped {s} (hidden)");
    }
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{}", hex(&Sha256::digest(bytes)))
}

fn human(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_need_a_version() {
        assert!(parse_reference("acme/ml/support-bot").is_err());
        assert!(parse_reference("127.0.0.1:5000/acme/ml/support-bot").is_err());
        let r = parse_reference("acme/ml/support-bot:2026-11-14").unwrap();
        assert_eq!(r.host, "oci.prego.k8skill.com");
        assert_eq!(r.name, "acme/ml/support-bot");
        assert_eq!(r.tag, "2026-11-14");
        assert!(parse_reference("acme/ml/support-bot@sha256:00").is_err());
    }

    #[test]
    fn get_needs_an_empty_folder() {
        let dir = check::tests::temp_dir("prepare");
        assert!(!prepare_folder(&dir).unwrap());
        std::fs::write(dir.join("x"), "x").unwrap();
        assert!(prepare_folder(&dir).is_err());
        let new = dir.join("new/sub");
        assert!(prepare_folder(&new).unwrap());
        assert!(new.is_dir());
    }
}
