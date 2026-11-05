//! `prego oci push`: pushes an image from an OCI image layout or a `docker save` tar file, with chunked
//! uploads for layers above the 95 MiB body limit.

mod input;
mod reference;
mod registry;

use std::path::Path;

use prego_auth::http::Http;
use prego_auth::oci::oci_hosts;
use prego_auth::sources::find_subject_token;
use prego_auth::{Config, Env, FileConfig};

use reference::{check_name, Reference};
use registry::{BlobResult, Registry};

/// `prego oci push <input> <ref>`.
pub fn push(
    globals: &[&str],
    input: &str,
    reference: &str,
    from: Option<&str>,
    chunk_size_mib: Option<u64>,
    env: &dyn Env,
) -> Result<(), String> {
    let r = Reference::parse(reference).map_err(|e| format!("prego: {e}"))?;
    let file = FileConfig::load(env).map_err(|e| e.to_string())?;
    if !oci_hosts(&file, env).contains(&r.host) {
        return Err(format!(
            "prego: `{}` is not a Prego OCI host. Add it to oci_hosts in ~/.config/prego/config.toml or to \
             PREGO_OCI_HOSTS",
            r.host
        ));
    }
    let config = Config::from_args(globals, env).map_err(|e| e.to_string())?;
    if r.tenant() != config.tenant {
        return Err(format!(
            "prego: the image name must start with the tenant `{}`: {}/<namespace>/<repo>",
            config.tenant, config.tenant
        ));
    }
    if let Some(f) = from {
        check_name(f).map_err(|e| format!("prego: bad --from `{f}`: {e}"))?;
        if f.split('/').next() != Some(config.tenant.as_str()) {
            return Err("prego: --from must be a repository of the same tenant".into());
        }
    }
    let requested_part = chunk_size_mib.map(|m| m.saturating_mul(1024 * 1024));

    // Read and check the input before any network call.
    let image = input::load(Path::new(input), &r.tag).map_err(|e| format!("prego: {e}"))?;
    let total: u64 = image.blobs.iter().map(|b| b.size).sum();
    eprintln!(
        "Pushing {} blobs ({}) and {} manifests to {}/{}:{}",
        image.blobs.len(),
        human(total),
        image.manifests.len(),
        r.host,
        r.name,
        r.tag
    );

    let auth_http = Http::with_ca_file(crate::USER_AGENT, config.ca_file.as_deref())
        .map_err(|e| format!("prego: PREGO_CA_FILE: {e}"))?;
    let subject = find_subject_token(&config, env, &auth_http).map_err(|e| e.to_string())?;
    let http = Http::for_transfers(crate::USER_AGENT, config.ca_file.as_deref())
        .map_err(|e| format!("prego: PREGO_CA_FILE: {e}"))?;
    let sleep = std::thread::sleep;
    let base = format!("{}://{}", r.scheme(), r.host);
    let mut reg = Registry::connect(
        &http,
        &base,
        &r.name,
        &config,
        &subject,
        from,
        requested_part,
        &sleep,
    )?;

    // Find the blobs that the repository does not have, and check their content before any upload.
    let mut missing = Vec::new();
    for blob in &image.blobs {
        if reg.has_blob(&blob.digest)? {
            eprintln!(
                "  {}  {:>10}  exists",
                short(&blob.digest),
                human(blob.size)
            );
        } else {
            missing.push(blob);
        }
    }
    for blob in missing.iter().filter(|b| !b.verified) {
        let actual = blob.source.sha256().map_err(|e| format!("prego: {e}"))?;
        if actual != blob.digest {
            return Err(format!(
                "prego: blob {} in the input does not match its digest (the content is {actual}). Nothing \
                 was uploaded",
                blob.digest
            ));
        }
    }
    for blob in missing {
        let what = match reg.push_blob(blob)? {
            BlobResult::Mounted => "mounted".to_string(),
            BlobResult::Uploaded { parts, part_size } => {
                format!("uploaded in {parts} part(s) of up to {}", human(part_size))
            }
        };
        eprintln!(
            "  {}  {:>10}  {what}",
            short(&blob.digest),
            human(blob.size)
        );
    }
    let last = image.manifests.len() - 1;
    for (i, m) in image.manifests.iter().enumerate() {
        let tag = (i == last).then_some(r.tag.as_str());
        reg.put_manifest(m, tag)?;
    }
    let top = &image.manifests[last];
    eprintln!("Token requests: {}", reg.token_requests());
    println!("{}/{}:{}@{}", r.host, r.name, r.tag, top.digest);
    Ok(())
}

fn short(digest: &str) -> &str {
    &digest[..19.min(digest.len())]
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
