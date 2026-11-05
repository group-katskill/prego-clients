//! `prego go publish`: builds the module zip from the git tree of a tag and uploads it to Prego.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Duration;

use prego_auth::http::{Body, FullResponse, Http};
use prego_auth::sources::find_subject_token;
use prego_auth::{go, sts, Config, Env, FileConfig, RegistryToken};
use serde_json::{json, Value};

use super::git;
use super::module;
use super::zip::{self, Omit, ZipWriter};

/// Largest zip sent in one `PUT`. Above it, the chunked session is used.
pub const MAX_SINGLE_PUT: u64 = 95 << 20;
/// Largest chunk the registry takes.
pub const MAX_CHUNK: u64 = 95 << 20;
const RETRY_5XX: usize = 2;
const MAX_429_RETRIES: usize = 5;

/// What the user asked for.
pub struct Options<'a> {
    pub dir: &'a str,
    pub tag: Option<&'a str>,
    pub namespace: &'a str,
    pub dry_run: bool,
    pub json: bool,
}

/// A module zip on disk, ready to upload. The file is deleted on drop.
pub struct Built {
    pub module: String,
    pub version: String,
    pub tag: String,
    pub commit: String,
    /// The tag prefix directory (`Subdir` of the Origin), or empty.
    pub code_dir: String,
    pub files: Vec<(String, u64)>,
    pub omitted: Vec<(String, Omit)>,
    pub zip: TempFile,
    pub zip_size: u64,
    pub h1: String,
    pub mod_h1: String,
}

/// A temporary file (mode 0600) that is deleted on drop.
pub struct TempFile {
    pub path: PathBuf,
    pub file: File,
}

impl TempFile {
    pub fn create(dir: &Path, stem: &str) -> Result<TempFile, String> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = dir.join(format!("{stem}-{}-{nanos}", std::process::id()));
        let mut o = std::fs::OpenOptions::new();
        o.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let file = o
            .open(&path)
            .map_err(|e| format!("prego: cannot create {}: {e}", path.display()))?;
        Ok(TempFile { path, file })
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Reads the `module` path from a `go.mod` file.
pub fn module_line(go_mod: &str) -> Option<String> {
    for line in go_mod.lines() {
        let line = line.split("//").next().unwrap_or("").trim();
        let Some(rest) = line.strip_prefix("module") else {
            continue;
        };
        if !rest.starts_with([' ', '\t', '"', '`']) {
            continue;
        }
        let rest = rest.trim();
        let path = rest
            .strip_prefix('"')
            .and_then(|r| r.strip_suffix('"'))
            .or_else(|| rest.strip_prefix('`').and_then(|r| r.strip_suffix('`')))
            .unwrap_or(rest);
        return Some(path.to_string());
    }
    None
}

/// The tag prefixes that fit a module directory: the directory, and the directory without a final
/// `vN` element (the major version subdirectory layout).
fn prefixes(subdir: &str) -> Vec<String> {
    let mut out = vec![subdir.to_string()];
    let (parent, last) = match subdir.rsplit_once('/') {
        Some((p, l)) => (p, l),
        None => ("", subdir),
    };
    if last.len() > 1 && last.starts_with('v') && last[1..].bytes().all(|b| b.is_ascii_digit()) {
        out.push(parent.to_string());
    }
    out
}

fn split_tag<'t>(tag: &'t str, prefix: &str) -> Option<&'t str> {
    if prefix.is_empty() {
        Some(tag).filter(|t| !t.contains('/'))
    } else {
        tag.strip_prefix(prefix)?.strip_prefix('/')
    }
}

/// Builds the zip for `opts.dir` at the tag.
pub fn build(opts: &Options<'_>) -> Result<Built, String> {
    let loc = git::locate(Path::new(opts.dir))?;
    let candidates = prefixes(&loc.subdir);
    let tag = match opts.tag {
        Some(t) => t.to_string(),
        None => {
            let fits: Vec<String> = git::tags_at_head(&loc)?
                .into_iter()
                .filter(|t| {
                    candidates
                        .iter()
                        .any(|p| split_tag(t, p).is_some_and(|v| module::parse_version(v).is_ok()))
                })
                .collect();
            match fits.as_slice() {
                [one] => one.clone(),
                [] => {
                    let want = if loc.subdir.is_empty() {
                        "vX.Y.Z".to_string()
                    } else {
                        format!("{}/vX.Y.Z", loc.subdir)
                    };
                    return Err(format!(
                        "prego: HEAD has no tag of the form {want}. Tag the commit, or give the tag."
                    ));
                }
                many => {
                    return Err(format!(
                        "prego: HEAD has more than one module tag ({}). Give the tag.",
                        many.join(", ")
                    ))
                }
            }
        }
    };
    let commit = git::tag_commit(&loc, &tag)?;
    let entries = git::ls_tree(&loc, &commit)?;

    let go_mod_path = if loc.subdir.is_empty() {
        "go.mod".to_string()
    } else {
        format!("{}/go.mod", loc.subdir)
    };
    let go_mod_entry = entries
        .iter()
        .find(|e| e.path == go_mod_path && e.mode != "120000")
        .ok_or_else(|| format!("prego: the tag {tag} has no {go_mod_path}"))?;
    if go_mod_entry.size > zip::MAX_GO_MOD_BYTES {
        return Err(format!(
            "prego: {go_mod_path} is larger than {} bytes",
            zip::MAX_GO_MOD_BYTES
        ));
    }
    let mut blobs = git::Blobs::open(&loc)?;
    let go_mod = blobs.read(&go_mod_entry.object)?;
    let go_mod_text = String::from_utf8_lossy(&go_mod);
    let module_path = module_line(&go_mod_text)
        .ok_or_else(|| format!("prego: {go_mod_path} at {tag} has no module line"))?;
    module::check_path(&module_path).map_err(|e| format!("prego: {e}"))?;

    // The tag prefix: the directory, or the directory without the major version element.
    let major_dir = module::split_path_major(&module_path)
        .and_then(|(_, m)| m)
        .map(|n| format!("v{n}"));
    let code_dir = match (&major_dir, loc.subdir.rsplit_once('/')) {
        (Some(v), Some((parent, last))) if last == v => parent.to_string(),
        (Some(v), None) if loc.subdir == *v => String::new(),
        _ => loc.subdir.clone(),
    };
    let version_text = split_tag(&tag, &code_dir).ok_or_else(|| {
        if code_dir.is_empty() {
            format!("prego: tag `{tag}` must be vX.Y.Z for a module at the repository root")
        } else {
            format!("prego: tag `{tag}` must be {code_dir}/vX.Y.Z for the module in {code_dir}")
        }
    })?;
    let version = module::parse_version(version_text).map_err(|e| format!("prego: {e}"))?;
    module::check_major(&module_path, &version).map_err(|e| format!("prego: {e}"))?;

    let selection =
        zip::select(git::module_files(&entries, &loc.subdir)).map_err(|e| format!("prego: {e}"))?;
    let zip_file = TempFile::create(&std::env::temp_dir(), "prego-go-zip")?;
    let handle = zip_file
        .file
        .try_clone()
        .map_err(|e| format!("prego: {e}"))?;
    let mut w = ZipWriter::new(handle, &module_path, &version.text);
    let mut files = Vec::new();
    for f in &selection.files {
        let content = blobs.read(&f.object)?;
        w.add(&f.path, &content)
            .map_err(|e| format!("prego: {e}"))?;
        files.push((f.path.clone(), content.len() as u64));
    }
    let (_, zip_size, h1) = w.finish().map_err(|e| format!("prego: {e}"))?;
    Ok(Built {
        module: module_path,
        version: version.text,
        tag,
        commit,
        code_dir,
        files,
        omitted: selection.omitted,
        zip: zip_file,
        zip_size,
        h1,
        mod_h1: zip::mod_hash1(&go_mod),
    })
}

/// The Origin JSON (no URL).
pub fn origin(b: &Built) -> Value {
    let mut o = json!({ "VCS": "git", "Hash": b.commit, "Ref": format!("refs/tags/{}", b.tag) });
    if !b.code_dir.is_empty() {
        o["Subdir"] = json!(b.code_dir);
    }
    o
}

/// `prego go publish`.
pub fn publish(globals: &[&str], opts: &Options<'_>, env: &dyn Env) -> Result<(), String> {
    crate::setup::check_slug("namespace", opts.namespace)?;
    let built = build(opts)?;
    if opts.dry_run {
        print_dry_run(&built, opts.json);
        return Ok(());
    }

    let file_cfg = FileConfig::load(env).map_err(|e| e.to_string())?;
    let config = Config::from_parts(globals, env, &file_cfg).map_err(|e| e.to_string())?;
    let host = go::go_hosts(&file_cfg, env)
        .into_iter()
        .next()
        .unwrap_or_else(|| go::DEFAULT_GO_HOST.to_string());
    let base = format!(
        "{}://{host}/t/{}/{}",
        go::scheme(&host),
        config.tenant,
        opts.namespace
    );
    let sts_http = Http::with_ca_file(crate::USER_AGENT, config.ca_file.as_deref())
        .map_err(|e| format!("prego: PREGO_CA_FILE: {e}"))?;
    let http = Http::for_transfers(crate::USER_AGENT, config.ca_file.as_deref())
        .map_err(|e| format!("prego: PREGO_CA_FILE: {e}"))?;
    let mut tokens = Tokens {
        http: &sts_http,
        config: &config,
        env,
        resource: sts::resource_base(&base),
        token: None,
    };
    eprintln!(
        "prego: publishing {}@{} ({} files, {} bytes) to {base}",
        built.module,
        built.version,
        built.files.len(),
        built.zip_size
    );
    let answer = upload(
        &http,
        &mut tokens,
        &base,
        built.zip_size,
        &built,
        &std::thread::sleep,
    )?;
    let got = |k: &str| {
        answer
            .get(k)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let (h1, mod_h1) = (got("h1"), got("mod_h1"));
    if h1 != built.h1 {
        return Err(format!(
            "prego: the registry computed h1 {h1}, but the local zip has {}. Do not use this version; tell your Prego admin.",
            built.h1
        ));
    }
    if !mod_h1.is_empty() && mod_h1 != built.mod_h1 {
        return Err(format!(
            "prego: the registry computed the go.mod h1 {mod_h1}, but the local go.mod has {}",
            built.mod_h1
        ));
    }
    if opts.json {
        println!(
            "{}",
            json!({ "module": built.module, "version": built.version, "h1": h1, "mod_h1": mod_h1 })
        );
    } else {
        eprintln!("prego: published, h1 {h1}");
        println!("go get {}@{}", built.module, built.version);
    }
    Ok(())
}

fn print_dry_run(b: &Built, as_json: bool) {
    if as_json {
        let files: Vec<Value> = b
            .files
            .iter()
            .map(|(p, s)| json!({ "path": p, "size": s }))
            .collect();
        println!(
            "{}",
            json!({ "module": b.module, "version": b.version, "h1": b.h1, "mod_h1": b.mod_h1,
                    "zip_size": b.zip_size, "origin": origin(b), "files": files })
        );
        return;
    }
    println!("module:   {}", b.module);
    println!(
        "version:  {} (tag {}, commit {})",
        b.version, b.tag, b.commit
    );
    println!("files:");
    for (p, s) in &b.files {
        println!("  {s:>10}  {p}");
    }
    for (p, why) in &b.omitted {
        let why = match why {
            Omit::Vendored => "vendored package",
            Omit::Submodule => "in a nested module",
            Omit::HgArchival => ".hg_archival.txt",
            Omit::NotRegular => "not a regular file",
        };
        println!("  left out    {p} ({why})");
    }
    println!("zip size: {} bytes", b.zip_size);
    println!("h1:       {}", b.h1);
    println!("go.mod:   {}", b.mod_h1);
    println!("Dry run: nothing was sent. Check that the file list holds no secret.");
}

/// Registry tokens for the publish: one from the STS for the namespace (`resource`), a new one before a
/// request when the current one is no longer fresh (less than `min(60 s, lifetime / 4)` left, so also
/// between chunks), and a new one after a `401`.
struct Tokens<'a> {
    http: &'a Http,
    config: &'a Config,
    env: &'a dyn Env,
    resource: Option<String>,
    token: Option<RegistryToken>,
}

impl Tokens<'_> {
    fn get(&mut self, fresh: bool) -> Result<String, String> {
        let now = prego_auth::now_unix();
        let stale = self.token.as_ref().is_none_or(|t| !t.is_fresh(now));
        if fresh || stale {
            let subject =
                find_subject_token(self.config, self.env, self.http).map_err(|e| e.to_string())?;
            let t = sts::exchange(
                self.http,
                self.config,
                &subject,
                self.resource.as_deref(),
                now,
                &std::thread::sleep,
            )
            .map_err(|e| e.to_string())?;
            self.token = Some(t);
        }
        Ok(self
            .token
            .as_ref()
            .map(|t| t.token.expose().to_string())
            .unwrap_or_default())
    }
}

/// What a request body is.
enum Payload<'a> {
    Empty,
    Json(&'a [u8]),
    Range(&'a File, u64, u64),
}

/// Sends one request with the registry token. A `401` gets one new token. A `429` waits for `Retry-After`.
/// With `retry`, network errors and `5xx` are sent again (at most [`RETRY_5XX`] times).
#[allow(clippy::too_many_arguments)]
fn call(
    http: &Http,
    tokens: &mut Tokens<'_>,
    method: &str,
    url: &str,
    extra: &[(&str, &str)],
    payload: &Payload<'_>,
    retry: bool,
    sleep: &dyn Fn(Duration),
) -> Result<FullResponse, String> {
    let mut fresh = false;
    let mut retried_401 = false;
    let mut errors = 0;
    let mut throttled = 0;
    loop {
        let token = tokens.get(fresh)?;
        fresh = false;
        let auth = format!("Bearer {token}");
        let mut headers: Vec<(&str, &str)> = vec![("Authorization", &auth)];
        headers.extend_from_slice(extra);
        let res = match payload {
            Payload::Empty => http.send(method, url, &headers, Body::Empty),
            Payload::Json(b) => {
                headers.push(("Content-Type", "application/json"));
                http.send(method, url, &headers, Body::Bytes(b))
            }
            Payload::Range(file, start, len) => {
                let mut f = (*file)
                    .try_clone()
                    .map_err(|e| format!("prego: cannot read the zip: {e}"))?;
                f.seek(SeekFrom::Start(*start))
                    .map_err(|e| format!("prego: cannot read the zip: {e}"))?;
                let mut part = f.take(*len);
                headers.push(("Content-Type", "application/octet-stream"));
                http.send(method, url, &headers, Body::Reader(&mut part, *len))
            }
        };
        match res {
            Ok(r) if r.status == 401 && !retried_401 => {
                retried_401 = true;
                fresh = true;
            }
            Ok(r) if r.status == 429 && throttled < MAX_429_RETRIES => {
                throttled += 1;
                let wait = r
                    .header("retry-after")
                    .and_then(|v| v.trim().parse::<u64>().ok())
                    .unwrap_or(5)
                    .min(60);
                eprintln!("prego: the registry asks to wait {wait} s (429)");
                sleep(Duration::from_secs(wait));
            }
            Ok(r) if r.status >= 500 && retry && errors < RETRY_5XX => {
                errors += 1;
                eprintln!("prego: {method} got {}; trying again", r.status);
                sleep(Duration::from_secs(2 * errors as u64));
            }
            Ok(r) => return Ok(r),
            Err(e) if retry && errors < RETRY_5XX => {
                errors += 1;
                eprintln!("prego: {method} failed ({e}); trying again");
                sleep(Duration::from_secs(2 * errors as u64));
            }
            Err(e) => return Err(format!("prego: {method} {url}: {e}")),
        }
    }
}

fn refused(what: &str, r: &FullResponse) -> String {
    let body = r.body.trim();
    let hint = match r.status {
        401 => " (the identity was refused; check the tenant and the identity source)",
        404 => " (no grant on this module in this namespace, or the namespace does not exist)",
        403 => " (you can read this module but not publish it, or a plan or quota limit applies)",
        _ => "",
    };
    if body.is_empty() {
        format!("prego: {what}: HTTP {}{hint}", r.status)
    } else {
        format!("prego: {what}: HTTP {}: {body}{hint}", r.status)
    }
}

/// Uploads the zip in one `PUT`, or in a chunked session if it is larger than [`MAX_SINGLE_PUT`]. Returns
/// the JSON answer of the registry.
fn upload(
    http: &Http,
    tokens: &mut Tokens<'_>,
    base: &str,
    size: u64,
    b: &Built,
    sleep: &dyn Fn(Duration),
) -> Result<Value, String> {
    let module = module::escape(&b.module);
    let version = module::escape(&b.version);
    let origin = origin(b).to_string();
    let res = if size <= MAX_SINGLE_PUT {
        let url = format!("{base}/-/publish/{module}/@v/{version}.zip");
        call(
            http,
            tokens,
            "PUT",
            &url,
            &[
                ("Content-Type", "application/zip"),
                ("X-Prego-Go-H1", &b.h1),
                ("X-Prego-Go-Origin", &origin),
            ],
            &Payload::Range(&b.zip.file, 0, size),
            false,
            sleep,
        )?
    } else {
        chunked(http, tokens, base, &module, &version, size, b, sleep)?
    };
    if res.status != 201 && res.status != 200 {
        return Err(refused("publish refused", &res));
    }
    serde_json::from_str(&res.body).map_err(|_| {
        format!(
            "prego: the registry answered {} with no JSON body",
            res.status
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn chunked(
    http: &Http,
    tokens: &mut Tokens<'_>,
    base: &str,
    module: &str,
    version: &str,
    size: u64,
    b: &Built,
    sleep: &dyn Fn(Duration),
) -> Result<FullResponse, String> {
    let start_url = format!("{base}/-/publish/{module}/@v/{version}/uploads");
    let body = json!({ "size": size, "h1": b.h1, "origin": origin(b) }).to_string();
    let r = call(
        http,
        tokens,
        "POST",
        &start_url,
        &[],
        &Payload::Json(body.as_bytes()),
        false,
        sleep,
    )?;
    if r.status != 201 && r.status != 200 {
        return Err(refused("the registry refused the upload session", &r));
    }
    let v: Value = serde_json::from_str(&r.body)
        .map_err(|_| "prego: the upload session answer is not JSON".to_string())?;
    let id = v["upload_id"].as_str().unwrap_or("").to_string();
    let chunk = v["chunk_bytes"].as_u64().unwrap_or(0);
    if id.is_empty()
        || !id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        || chunk == 0
        || chunk > MAX_CHUNK
    {
        return Err("prego: the upload session answer has a bad upload_id or chunk_bytes".into());
    }
    let session = format!("{base}/-/uploads/{id}");
    let result = send_parts(http, tokens, &session, size, chunk, b, sleep).and_then(|()| {
        let r = call(
            http,
            tokens,
            "PUT",
            &session,
            &[],
            &Payload::Empty,
            false,
            sleep,
        )?;
        Ok(r)
    });
    match result {
        Ok(r) if r.status == 201 || r.status == 200 => Ok(r),
        other => {
            // Abort the session; it holds storage until it expires.
            let _ = call(
                http,
                tokens,
                "DELETE",
                &session,
                &[],
                &Payload::Empty,
                false,
                sleep,
            );
            other
        }
    }
}

fn send_parts(
    http: &Http,
    tokens: &mut Tokens<'_>,
    session: &str,
    size: u64,
    chunk: u64,
    b: &Built,
    sleep: &dyn Fn(Duration),
) -> Result<(), String> {
    let parts = size.div_ceil(chunk);
    for n in 1..=parts {
        let start = (n - 1) * chunk;
        let len = chunk.min(size - start);
        let url = format!("{session}?part={n}");
        let r = call(
            http,
            tokens,
            "PATCH",
            &url,
            &[],
            &Payload::Range(&b.zip.file, start, len),
            true,
            sleep,
        )?;
        match r.status {
            204 | 200 => {
                if let Some(got) = r
                    .header("x-prego-go-received")
                    .and_then(|v| v.trim().parse::<u64>().ok())
                {
                    if got != start + len {
                        return Err(format!(
                            "prego: after part {n} the registry has {got} bytes, not {}",
                            start + len
                        ));
                    }
                }
            }
            // The part was stored before (for example, the answer to an earlier try was lost).
            409 => {}
            _ => return Err(refused(&format!("part {n} of {parts} refused"), &r)),
        }
        eprintln!("prego: sent part {n} of {parts}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_lines() {
        assert_eq!(
            module_line("// x\nmodule go.acme.com/x // c\n").unwrap(),
            "go.acme.com/x"
        );
        assert_eq!(
            module_line("module \"go.acme.com/q\"\n").unwrap(),
            "go.acme.com/q"
        );
        assert_eq!(module_line("modulex a\nmodule\tb.c/d\n").unwrap(), "b.c/d");
        assert!(module_line("go 1.22\n").is_none());
    }

    #[test]
    fn tag_prefixes() {
        assert_eq!(prefixes(""), [""]);
        assert_eq!(prefixes("v2"), ["v2", ""]);
        assert_eq!(prefixes("tools/v3"), ["tools/v3", "tools"]);
        assert_eq!(prefixes("tools"), ["tools"]);
        assert_eq!(split_tag("v1.0.0", ""), Some("v1.0.0"));
        assert_eq!(split_tag("tools/v1.0.0", ""), None);
        assert_eq!(split_tag("tools/v1.0.0", "tools"), Some("v1.0.0"));
        assert_eq!(split_tag("toolsx/v1.0.0", "tools"), None);
    }
}
