//! `prego snippet`: Snippets (ADR-0057). Named sets of text files (scripts, prompts, agent skills,
//! templates) with immutable versions, diff by hash and forcing by hash, on the control host under
//! `/v1/snippets/`, with a registry token.

pub mod files;
pub mod reference;

use std::io::IsTerminal;
use std::path::Path;

use prego_auth::http::{Body, FullResponse};
use prego_auth::Env;
use reference::{check_selector, SnipRef};
use serde_json::{json, Value};

use crate::env::{query, text, Connection};
use files::{Entry, File};

/// The exit code when `--expect` does not match (the same as `prego env pull`).
pub const EXIT_EXPECT: i32 = 3;

/// The exit code when a snippet uses an encryption mode that this version cannot read.
pub const EXIT_ENCRYPTION: i32 = 2;

/// Stops with [`EXIT_ENCRYPTION`] if `mode` is not `none`. Nothing was written yet: every read is checked
/// before its content is used.
fn require_plain(mode: Option<&str>) {
    if let Some(m) = mode.filter(|m| *m != "none") {
        eprintln!(
            "prego: this snippet uses encryption mode {m}, which this prego version cannot read"
        );
        std::process::exit(EXIT_ENCRYPTION);
    }
}

/// The encryption mode of a JSON answer: `encryption.mode` at the top or under `version`. Missing is `none`.
fn body_mode(v: &Value) -> Option<String> {
    for e in [&v["encryption"], &v["version"]["encryption"]] {
        match e {
            Value::Null => {}
            Value::String(m) => return Some(m.clone()),
            other => match &other["mode"] {
                Value::Null => {}
                Value::String(m) => return Some(m.clone()),
                m => return Some(m.to_string()),
            },
        }
    }
    None
}

fn require_plain_body(v: &Value) {
    require_plain(body_mode(v).as_deref());
}

/// The largest JSON answer that is read (a diff has at most 1 MiB of diff text, escaped).
const MAX_JSON: u64 = 4 * 1024 * 1024;
/// The largest tarball that is read: the content, the headers and a gzip that does not compress.
const MAX_TARBALL: u64 = files::MAX_VERSION_BYTES + 1024 * 1024;

/// The line that the help and the docs show.
/// Used by the help test only.
#[cfg_attr(not(test), allow(dead_code))]
pub const TRUST: &str =
    "A snippet that an agent reads is an instruction to that agent: pin it by hash \
(--expect) and grant read only on snippets you trust.";

#[derive(Debug, PartialEq, Eq)]
pub enum SnippetCommand {
    Push {
        source: String,
        reference: String,
        tag: Option<String>,
        message: Option<String>,
        if_current: Option<String>,
        tar: bool,
    },
    Get {
        reference: String,
        folder: Option<String>,
        file: Option<String>,
        tar: bool,
        expect: Option<String>,
    },
    Ls {
        scope: String,
    },
    Log {
        reference: String,
    },
    Diff {
        reference: String,
        from: String,
        to: String,
    },
    Tag {
        reference: String,
        tag: String,
    },
    Rollback {
        reference: String,
        to: String,
        reason: String,
    },
    Hash {
        source: String,
        tar: bool,
    },
}

pub fn run(globals: &[&str], command: &SnippetCommand, env: &dyn Env) -> Result<(), String> {
    match command {
        SnippetCommand::Hash { source, tar } => {
            let (files, _) = load(source, *tar)?;
            println!("{}", files::version_hash(&entries(&files)).map_err(err)?);
            Ok(())
        }
        SnippetCommand::Push {
            source,
            reference,
            tag,
            message,
            if_current,
            tar,
        } => {
            let r = SnipRef::parse(reference)?.no_version("push")?;
            let (files, raw) = load(source, *tar)?;
            let api = Api::new(globals, &r.tenant, env)?;
            push(
                &api,
                &r,
                &files,
                raw,
                tag.as_deref(),
                message.as_deref(),
                if_current.as_deref(),
            )
        }
        SnippetCommand::Get {
            reference,
            folder,
            file,
            tar,
            expect,
        } => {
            let r = SnipRef::parse(reference)?;
            let api = Api::new(globals, &r.tenant, env)?;
            if *tar {
                get_tar(&api, &r, folder.as_deref(), expect.as_deref())
            } else {
                get(
                    &api,
                    &r,
                    folder.as_deref(),
                    file.as_deref(),
                    expect.as_deref(),
                )
            }
        }
        SnippetCommand::Ls { scope } => {
            let (tenant, namespace) = reference::parse_scope(scope)?;
            ls(&Api::new(globals, &tenant, env)?, &tenant, &namespace)
        }
        SnippetCommand::Log { reference } => {
            let r = SnipRef::parse(reference)?.no_version("log")?;
            log(&Api::new(globals, &r.tenant, env)?, &r)
        }
        SnippetCommand::Diff {
            reference,
            from,
            to,
        } => {
            let r = SnipRef::parse(reference)?.no_version("diff")?;
            check_selector(from)?;
            check_selector(to)?;
            diff(&Api::new(globals, &r.tenant, env)?, &r, from, to)
        }
        SnippetCommand::Tag { reference, tag } => {
            let r = SnipRef::parse(reference)?;
            if r.version.is_none() {
                return Err(
                    "prego: give the version to tag: prego snippet tag <ref>@<version> <tag>"
                        .into(),
                );
            }
            reference::check_tag(tag).map_err(err)?;
            set_tag(&Api::new(globals, &r.tenant, env)?, &r, tag)
        }
        SnippetCommand::Rollback {
            reference,
            to,
            reason,
        } => {
            let r = SnipRef::parse(reference)?.no_version("rollback")?;
            check_selector(to)?;
            rollback(&Api::new(globals, &r.tenant, env)?, &r, to, reason)
        }
    }
}

fn err(e: String) -> String {
    format!("prego: {e}")
}

fn entries(files: &[File]) -> Vec<Entry> {
    files.iter().map(Entry::of).collect()
}

/// The files of a push or a hash, checked. With `tar`, the source is a `.tar.gz` or `.tar` that is also
/// returned as it is, to be sent unchanged.
fn load(source: &str, tar: bool) -> Result<(Vec<File>, Option<Vec<u8>>), String> {
    if tar {
        let meta = std::fs::metadata(source).map_err(|e| format!("prego: {source}: {e}"))?;
        if meta.len() > files::MAX_UPLOAD_BYTES {
            return Err(format!(
                "prego: {source}: {} bytes: an upload is at most 8 MiB ({} bytes)",
                meta.len(),
                files::MAX_UPLOAD_BYTES
            ));
        }
        let raw = std::fs::read(source).map_err(|e| format!("prego: {source}: {e}"))?;
        let files = files::untar(&raw).map_err(|e| format!("prego: {source}: {e}"))?;
        return Ok((files, Some(raw)));
    }
    let files = files::collect(Path::new(source)).map_err(err)?;
    files::check_files(&files).map_err(|e| format!("prego: {source}: {e}"))?;
    Ok((files, None))
}

/// Percent-encodes one path segment. `:` and `+` stay (they are allowed in a segment, and `sha256:<hex>`
/// and tags use them).
pub(crate) fn seg(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b':' | b'+' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// A file path in a URL: each segment encoded, `/` kept.
fn file_path(path: &str) -> String {
    path.split('/').map(seg).collect::<Vec<_>>().join("/")
}

/// The machine routes under `/v1/snippets/`.
struct Api {
    c: Connection,
}

impl Api {
    fn new(globals: &[&str], tenant: &str, env: &dyn Env) -> Result<Api, String> {
        Ok(Api {
            c: crate::env::connect(globals, tenant, true, env)?,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}/v1/snippets/{path}", self.c.base)
    }

    /// `<tenant>/<namespace>/<snippet>` encoded.
    fn snippet(r: &SnipRef) -> String {
        format!("{}/{}/{}", seg(&r.tenant), seg(&r.namespace), seg(&r.name))
    }

    fn send(
        &self,
        method: &str,
        path: &str,
        content_type: Option<&str>,
        body: Body<'_>,
    ) -> Result<FullResponse, String> {
        let url = self.url(path);
        let mut headers = vec![
            ("Authorization", self.c.auth.as_str()),
            ("Accept", "application/json"),
        ];
        if let Some(t) = content_type {
            headers.push(("Content-Type", t));
        }
        self.c
            .http
            .send(method, &url, &headers, body)
            .map_err(|e| format!("prego: {url}: {e}"))
    }

    /// A `PUT` or `POST` with a JSON body; a 2xx JSON answer.
    fn write_json(
        &self,
        method: &str,
        path: &str,
        body: &Value,
        what: &str,
    ) -> Result<Value, String> {
        let text = body.to_string();
        let res = self.send(
            method,
            path,
            Some("application/json"),
            Body::Bytes(text.as_bytes()),
        )?;
        if !(200..300).contains(&res.status) {
            return Err(api_error(&res, what));
        }
        parse_json(res.body.as_bytes(), what)
    }

    /// A `GET` whose `200` body is read into memory, at most `max` bytes.
    fn get_bytes(
        &self,
        path: &str,
        accept: &str,
        max: u64,
    ) -> Result<(FullResponse, Vec<u8>), String> {
        let url = self.url(path);
        let headers = [("Authorization", self.c.auth.as_str()), ("Accept", accept)];
        let mut out = Vec::new();
        let (res, _) = self
            .c
            .http
            .get_to(&url, &headers, &mut out, max)
            .map_err(|e| format!("prego: {url}: {e}"))?;
        // Every snippet read carries X-Prego-Encryption; a missing header is `none`.
        if res.status == 200 {
            require_plain(res.header("x-prego-encryption").map(str::trim));
        }
        Ok((res, out))
    }

    /// A `GET` with a `200` JSON answer. A `412 hash_mismatch` exits with [`EXIT_EXPECT`].
    fn get_json(&self, path: &str, what: &str) -> Result<(FullResponse, Value), String> {
        let (res, body) = self.get_bytes(path, "application/json", MAX_JSON)?;
        if res.status != 200 {
            expect_exit(&res, what);
            return Err(api_error(&res, what));
        }
        Ok((res, parse_json(&body, what)?))
    }
}

pub(crate) fn parse_json(bytes: &[u8], what: &str) -> Result<Value, String> {
    serde_json::from_slice(bytes).map_err(|e| format!("prego: {what}: the answer is not JSON: {e}"))
}

/// On `412 hash_mismatch`, prints the message and exits with [`EXIT_EXPECT`]. Nothing was written yet.
fn expect_exit(res: &FullResponse, what: &str) {
    if res.status == 412 {
        let body: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
        let hash = body["error"]["hash"]
            .as_str()
            .or(body["error"]["current_hash"].as_str())
            .map(|h| format!(" (the hash is {h})"))
            .unwrap_or_default();
        eprintln!("prego: {what}: the version hash is not the expected one{hash}");
        std::process::exit(EXIT_EXPECT);
    }
}

fn mismatch_exit(what: &str, local: &str, want: &str) -> ! {
    eprintln!("prego: {what}: the version hash is {local}, not the expected {want}");
    std::process::exit(EXIT_EXPECT);
}

/// The error text for a refused request. `404` means no snippet or no grant: the registry does not say which.
fn api_error(res: &FullResponse, what: &str) -> String {
    let body: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
    let err = &body["error"];
    let code = err["code"].as_str().or(err.as_str()).unwrap_or("");
    let message = err["message"]
        .as_str()
        .or(body["message"].as_str())
        .unwrap_or("");
    let mut msg = match res.status {
        404 => format!("prego: {what}: not found, or you have no grant for it"),
        401 => format!("prego: {what}: the registry refused the token (401). {message}"),
        403 if code != "plan_limit" => format!(
            "prego: {what}: 403 {code}: {message} (you can read it, but you have no publish grant, or the \
             plan does not allow it)"
        ),
        _ => format!("prego: {what}: {} {code}: {message}", res.status),
    };
    if let Some(p) = err["path"].as_str() {
        msg.push_str(&format!(" (file: {p}"));
        if let Some(l) = err.get("line").filter(|l| !l.is_null()) {
            msg.push_str(&format!(", line {}", text(l)));
        }
        if let Some(r) = err["reason"].as_str() {
            msg.push_str(&format!(", {r}"));
        }
        msg.push(')');
    }
    if let Some(f) = err["field"].as_str() {
        msg.push_str(&format!(" (field: {f})"));
    }
    if code == "conflict" {
        if let Some(h) = err.get("current_hash") {
            msg.push_str(&format!(" (current hash: {})", text(h)));
        }
    }
    if let Some(s) = res.header("retry-after") {
        msg.push_str(&format!(" (retry after {s} s)"));
    }
    if let Some(id) = err["request_id"].as_str() {
        msg.push_str(&format!(" (request {id})"));
    }
    if code == "looks_like_secret" {
        msg.push_str(
            "\nSnippets are readable by everyone with a read grant. Do not store passwords, tokens or keys here.",
        );
    }
    msg
}

fn push(
    api: &Api,
    r: &SnipRef,
    files: &[File],
    raw: Option<Vec<u8>>,
    tag: Option<&str>,
    message: Option<&str>,
    if_current: Option<&str>,
) -> Result<(), String> {
    let local = files::version_hash(&entries(files)).map_err(err)?;
    let (body, content_type) = match raw {
        Some(b) if b.starts_with(&[0x1f, 0x8b]) => (b, "application/gzip"),
        Some(b) => (b, "application/x-tar"),
        None => (files::tar_gz(files), "application/gzip"),
    };
    if body.len() as u64 > files::MAX_UPLOAD_BYTES {
        return Err(format!(
            "prego: the tarball is {} bytes: an upload is at most 8 MiB ({} bytes)",
            body.len(),
            files::MAX_UPLOAD_BYTES
        ));
    }
    let mut q: Vec<(&str, String)> = Vec::new();
    if let Some(m) = message {
        q.push(("message", m.to_string()));
    }
    if let Some(h) = if_current {
        q.push(("if_current", h.to_string()));
    }
    if let Some(t) = tag {
        q.push(("tag", t.to_string()));
    }
    let mut path = Api::snippet(r);
    if !q.is_empty() {
        path = format!("{path}?{}", query(&q));
    }
    let what = format!("push to {}", r.long());
    let res = api.send("PUT", &path, Some(content_type), Body::Bytes(&body))?;
    if !(200..300).contains(&res.status) {
        return Err(api_error(&res, &what));
    }
    let answer = parse_json(res.body.as_bytes(), &what)?;
    let v = &answer["version"];
    let hash = v["hash"].as_str().unwrap_or("");
    let number = text(&v["number"]);
    if !hash.is_empty() && hash != local {
        eprintln!("prego: warning: the registry hash {hash} is not the local hash {local}");
    }
    let created = answer["created"].as_bool().unwrap_or(res.status == 201);
    let count = files.len();
    if created {
        println!("{}: version {number} ({hash}), {count} files", r.long());
    } else {
        println!(
            "{}: no change, version {number} is current ({hash})",
            r.long()
        );
    }
    if let Some(t) = tag {
        println!("{}: tag {t} -> version {number}", r.long());
    }
    Ok(())
}

/// The checked file list of the selected version, and its hash computed here.
struct Listing {
    number: String,
    hash: String,
    entries: Vec<Entry>,
}

fn listing(api: &Api, r: &SnipRef, expect: Option<&str>) -> Result<Listing, String> {
    let v = r.selector();
    let mut path = format!("{}/v/{}", Api::snippet(r), seg(v));
    if let Some(h) = expect {
        path = format!("{path}?{}", query(&[("expect", h.to_string())]));
    }
    let what = format!("{}@{v}", r.long());
    let (res, answer) = api.get_json(&path, &what)?;
    require_plain_body(&answer);
    let list = answer["files"]
        .as_array()
        .ok_or_else(|| format!("prego: {what}: the answer has no file list"))?;
    let mut out = Vec::with_capacity(list.len());
    for f in list {
        let p = f["path"]
            .as_str()
            .ok_or_else(|| format!("prego: {what}: a file has no path"))?;
        files::check_path(p).map_err(|e| format!("prego: {what}: {p}: {e}"))?;
        let mode = files::mode_from(&f["mode"])
            .ok_or_else(|| format!("prego: {what}: {p}: the mode is not 0644 or 0755"))?;
        let size = f["size"]
            .as_u64()
            .ok_or_else(|| format!("prego: {what}: {p}: no size"))?;
        let sha256 = files::sha_from(&f["sha256"])
            .ok_or_else(|| format!("prego: {what}: {p}: no sha256"))?;
        out.push(Entry {
            path: p.to_string(),
            mode,
            size,
            sha256,
        });
    }
    // The hash is computed here, so a changed answer cannot pass --expect.
    let local = files::version_hash(&out).map_err(err)?;
    for server in [answer["hash"].as_str(), res.header("x-prego-snippet-hash")]
        .into_iter()
        .flatten()
    {
        if server != local {
            return Err(format!(
                "prego: {what}: the hash in the answer ({server}) is not the hash of the file list ({local})"
            ));
        }
    }
    if let Some(want) = expect {
        if want != local {
            mismatch_exit(&what, &local, want);
        }
    }
    let number = res
        .header("x-prego-snippet-version")
        .map(str::to_string)
        .unwrap_or_else(|| {
            text(
                answer
                    .get("version")
                    .or(answer.get("number"))
                    .unwrap_or(&Value::Null),
            )
        });
    Ok(Listing {
        number,
        hash: local,
        entries: out,
    })
}

/// Downloads one file of the listed version (by its hash, so it is the same version) and checks it.
fn fetch(api: &Api, r: &SnipRef, l: &Listing, e: &Entry) -> Result<File, String> {
    let path = format!(
        "{}/v/{}/files/{}",
        Api::snippet(r),
        seg(&l.hash),
        file_path(&e.path)
    );
    let what = format!("{}@{} file {}", r.long(), l.number, e.path);
    let (res, data) = api.get_bytes(&path, "text/plain", files::MAX_FILE_BYTES)?;
    if res.status != 200 {
        expect_exit(&res, &what);
        return Err(api_error(&res, &what));
    }
    if data.len() as u64 != e.size || files::hex_sha256(&data) != e.sha256 {
        return Err(format!(
            "prego: {what}: the content does not match the file list (size or sha256)"
        ));
    }
    Ok(File {
        path: e.path.clone(),
        mode: e.mode,
        data,
    })
}

fn get(
    api: &Api,
    r: &SnipRef,
    folder: Option<&str>,
    file: Option<&str>,
    expect: Option<&str>,
) -> Result<(), String> {
    let l = listing(api, r, expect)?;
    if let Some(p) = file {
        let e = l
            .entries
            .iter()
            .find(|e| e.path == p)
            .ok_or_else(|| format!("prego: {}@{}: there is no file {p}", r.long(), l.number))?;
        let f = fetch(api, r, &l, e)?;
        files::check_text(&f.data).map_err(|e| format!("prego: {p}: {e}"))?;
        use std::io::Write;
        let mut out = std::io::stdout().lock();
        out.write_all(&f.data)
            .and_then(|_| out.flush())
            .map_err(|e| format!("prego: stdout: {e}"))?;
        return Ok(());
    }
    // The folder is checked first, but made only after all files are downloaded and checked: a stop on the
    // way (an error, --expect, an encryption mode) leaves nothing behind.
    let dir = Path::new(folder.unwrap_or(r.name.as_str())).to_path_buf();
    files::check_folder(&dir).map_err(err)?;
    let mut got = Vec::with_capacity(l.entries.len());
    for e in &l.entries {
        got.push(fetch(api, r, &l, e)?);
    }
    files::check_files(&got).map_err(|e| format!("prego: {}@{}: {e}", r.long(), l.number))?;
    let created = files::prepare_folder(&dir).map_err(err)?;
    if let Err(e) = files::write_all(&dir, &got) {
        if created {
            let _ = std::fs::remove_dir_all(&dir);
        }
        return Err(err(e));
    }
    eprintln!("{}@{} {} ({} files)", r.long(), l.number, l.hash, got.len());
    println!("{}", dir.display());
    Ok(())
}

fn get_tar(api: &Api, r: &SnipRef, out: Option<&str>, expect: Option<&str>) -> Result<(), String> {
    if out.is_none() && std::io::stdout().is_terminal() {
        return Err(
            "prego: --tar writes a .tar.gz: give a file name, or send stdout to a file or a pipe"
                .into(),
        );
    }
    let v = r.selector();
    let mut path = format!("{}/v/{}.tar.gz", Api::snippet(r), seg(v));
    if let Some(h) = expect {
        path = format!("{path}?{}", query(&[("expect", h.to_string())]));
    }
    let what = format!("{}@{v}", r.long());
    let (res, bytes) = api.get_bytes(&path, "application/gzip", MAX_TARBALL)?;
    if res.status != 200 {
        expect_exit(&res, &what);
        return Err(api_error(&res, &what));
    }
    // The tarball is unpacked in memory and its file list hashed, so a changed tarball is not written.
    let got = files::untar(&bytes).map_err(|e| format!("prego: {what}: {e}"))?;
    let local = files::version_hash(&entries(&got)).map_err(err)?;
    if let Some(server) = res.header("x-prego-snippet-hash") {
        if server != local {
            return Err(format!(
                "prego: {what}: the hash in the answer ({server}) is not the hash of the tarball's files ({local})"
            ));
        }
    }
    if let Some(want) = expect {
        if want != local {
            mismatch_exit(&what, &local, want);
        }
    }
    match out {
        Some(p) => write_bytes_atomic(p, &bytes)?,
        None => {
            use std::io::Write;
            let mut o = std::io::stdout().lock();
            o.write_all(&bytes)
                .and_then(|_| o.flush())
                .map_err(|e| format!("prego: stdout: {e}"))?;
        }
    }
    let number = res.header("x-prego-snippet-version").unwrap_or(v);
    eprintln!("{}@{number} {local} ({} files)", r.long(), got.len());
    Ok(())
}

fn write_bytes_atomic(path: &str, bytes: &[u8]) -> Result<(), String> {
    let p = Path::new(path);
    let tmp = p.with_extension("prego-tmp");
    std::fs::write(&tmp, bytes).map_err(|e| format!("prego: {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, p).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("prego: {path}: {e}")
    })
}

/// Follows `next` cursors. At most 1,000 pages.
fn pages(api: &Api, base: &str, what: &str, mut each: impl FnMut(&Value)) -> Result<(), String> {
    let mut after: Option<String> = None;
    for _ in 0..1000 {
        let mut q = vec![("limit", "100".to_string())];
        if let Some(a) = &after {
            q.push(("after", a.clone()));
        }
        let (_, answer) = api.get_json(&format!("{base}?{}", query(&q)), what)?;
        let items = answer["items"]
            .as_array()
            .ok_or_else(|| format!("prego: {what}: the answer has no items list"))?;
        items.iter().for_each(&mut each);
        match answer["next"].as_str().filter(|s| !s.is_empty()) {
            Some(n) if !items.is_empty() => after = Some(n.to_string()),
            _ => return Ok(()),
        }
    }
    Ok(())
}

fn ls(api: &Api, tenant: &str, namespace: &str) -> Result<(), String> {
    let what = format!("the snippets of {tenant}/{namespace}");
    let mut n = 0;
    pages(
        api,
        &format!("{}/{}", seg(tenant), seg(namespace)),
        &what,
        |s| {
            n += 1;
            println!(
                "{:<40} {:>5}  {}  {:>4} versions  {}",
                text(&s["name"]),
                text(&s["current_version"]),
                text(&s["current_hash"]),
                text(&s["version_count"]),
                text(&s["updated_at"]),
            );
        },
    )?;
    if n == 0 {
        eprintln!("no snippets in {tenant}/{namespace} that you can read");
    }
    Ok(())
}

fn log(api: &Api, r: &SnipRef) -> Result<(), String> {
    let what = format!("the history of {}", r.long());
    println!("{}", r.long());
    pages(api, &format!("{}/versions", Api::snippet(r)), &what, |v| {
        require_plain_body(v);
        let mark = if v["current"] == true { "*" } else { " " };
        let tags: Vec<String> = v["tags"]
            .as_array()
            .into_iter()
            .flatten()
            .map(text)
            .collect();
        let tags = if tags.is_empty() {
            String::new()
        } else {
            format!("  [{}]", tags.join(", "))
        };
        println!(
            "{mark}{:>5}  {}  {:>8} B  {:>3} files  {}  {}{tags}  {}",
            text(&v["number"]),
            text(&v["hash"]),
            text(&v["size_bytes"]),
            text(&v["file_count"]),
            text(&v["created_at"]),
            text(&v["pushed_by"]),
            v["message"].as_str().unwrap_or("")
        );
    })
}

fn diff(api: &Api, r: &SnipRef, from: &str, to: &str) -> Result<(), String> {
    let what = format!("the diff of {} from {from} to {to}", r.long());
    let path = format!(
        "{}/diff?{}",
        Api::snippet(r),
        query(&[("from", from.to_string()), ("to", to.to_string())])
    );
    let (_, d) = api.get_json(&path, &what)?;
    require_plain_body(&d);
    let side = |s: &Value, sel: &str| match s {
        Value::Object(_) => format!("{} ({})", text(&s["number"]), text(&s["hash"])),
        Value::Null => sel.to_string(),
        other => text(other),
    };
    println!(
        "{} from {} to {}",
        r.long(),
        side(&d["from"], from),
        side(&d["to"], to)
    );
    let list = |k: &str| d[k].as_array().cloned().unwrap_or_default();
    let (added, removed, changed) = (list("added"), list("removed"), list("changed"));
    if added.is_empty() && removed.is_empty() && changed.is_empty() {
        println!("no changes");
        return Ok(());
    }
    for a in &added {
        println!("+ {}", text(&a["path"]));
    }
    for x in &removed {
        println!("- {}", text(&x["path"]));
    }
    for c in &changed {
        println!("~ {}", text(&c["path"]));
    }
    for c in &changed {
        if let Some(t) = c["diff"].as_str().filter(|t| !t.is_empty()) {
            println!();
            print!("{t}");
            if !t.ends_with('\n') {
                println!();
            }
        }
    }
    if d["truncated"] == true {
        eprintln!("prego: the diff text is cut at 1 MiB (truncated)");
    }
    Ok(())
}

fn set_tag(api: &Api, r: &SnipRef, tag: &str) -> Result<(), String> {
    let v = r.selector();
    let what = format!("tag {tag} on {}@{v}", r.long());
    let body = json!({ "version": reference::selector_json(v) });
    let answer = api.write_json(
        "PUT",
        &format!("{}/tags/{}", Api::snippet(r), seg(tag)),
        &body,
        &what,
    )?;
    let number = answer.get("version").or(answer.get("version_number"));
    println!(
        "{}: tag {tag} -> version {}{}",
        r.long(),
        number.map(text).unwrap_or_else(|| v.to_string()),
        answer["hash"]
            .as_str()
            .map(|h| format!(" ({h})"))
            .unwrap_or_default()
    );
    Ok(())
}

fn rollback(api: &Api, r: &SnipRef, to: &str, reason: &str) -> Result<(), String> {
    let what = format!("move the current version of {}", r.long());
    let body = json!({ "version": reference::selector_json(to), "reason": reason });
    let answer = api.write_json(
        "POST",
        &format!("{}/current", Api::snippet(r)),
        &body,
        &what,
    )?;
    println!(
        "{}: current version is now {} ({})",
        r.long(),
        text(&answer["current_version"]),
        text(&answer["current_hash"])
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encryption_mode_of_an_answer() {
        assert_eq!(body_mode(&json!({"files": []})), None);
        assert_eq!(
            body_mode(&json!({"encryption": {"mode": "none"}})).as_deref(),
            Some("none")
        );
        assert_eq!(
            body_mode(&json!({"encryption": {"mode": "age-v1"}})).as_deref(),
            Some("age-v1")
        );
        assert_eq!(
            body_mode(&json!({"version": {"encryption": {"mode": "kms"}}})).as_deref(),
            Some("kms")
        );
        assert_eq!(body_mode(&json!({"encryption": "x"})).as_deref(), Some("x"));
        assert_eq!(body_mode(&json!({"encryption": {}})), None);
    }

    #[test]
    fn url_segments() {
        assert_eq!(seg("sha256:ab"), "sha256:ab");
        assert_eq!(seg("v1.0+b"), "v1.0+b");
        assert_eq!(seg("a b&c/d"), "a%20b%26c%2Fd");
        assert_eq!(file_path("dir/my file.md"), "dir/my%20file.md");
    }

    #[test]
    fn error_text() {
        let res = |status, body: &str| FullResponse {
            status,
            headers: vec![],
            body: body.into(),
        };
        assert_eq!(
            api_error(&res(404, ""), "x"),
            "prego: x: not found, or you have no grant for it"
        );
        let t = api_error(
            &res(
                422,
                r#"{"error":{"code":"looks_like_secret","message":"a file looks like it holds a secret","path":"deploy.sh","line":12,"request_id":"r1"}}"#,
            ),
            "push",
        );
        assert!(t.starts_with(
            "prego: push: 422 looks_like_secret: a file looks like it holds a secret (file: deploy.sh, line 12) (request r1)\n"
        ), "{t}");
        let t = api_error(
            &res(
                400,
                r#"{"error":{"code":"snippet_invalid","message":"bad entry","path":"x","reason":"symlink"}}"#,
            ),
            "push",
        );
        assert_eq!(
            t,
            "prego: push: 400 snippet_invalid: bad entry (file: x, symlink)"
        );
        let t = api_error(
            &res(
                409,
                r#"{"error":{"code":"conflict","message":"m","current_hash":"sha256:aa"}}"#,
            ),
            "push",
        );
        assert!(t.ends_with("(current hash: sha256:aa)"));
        assert!(api_error(
            &res(403, r#"{"error":{"code":"forbidden","message":"m"}}"#),
            "p"
        )
        .contains("no publish grant"));
    }
}
