//! `prego context`: agent context (ADR-0058). Checkpoints of text files (memory, notes, plans, transcripts)
//! that agents save and restore with their own identity, on the control host under `/v1/context/`, with a
//! registry token. The file rules, the hash and the fixed tar form are the Snippets ones (ADR-0057), with the
//! Context limits.

pub mod redact;
pub mod reference;

use std::path::{Path, PathBuf};

use prego_auth::http::{Body, FullResponse};
use prego_auth::Env;
use reference::CtxRef;
use serde_json::{json, Value};

use crate::env::{query, text, Connection};
use crate::snippet::files::{self, Entry, File, CONTEXT};
use crate::snippet::{parse_json, seg};

/// The exit code when `--expect` does not match.
pub const EXIT_EXPECT: i32 = 3;
/// The exit code when a checkpoint uses an encryption mode that this version cannot read.
pub const EXIT_ENCRYPTION: i32 = 2;
/// The exit code when a save is refused. The checkpoint is kept in a local file.
pub const EXIT_REFUSED: i32 = 4;

/// The folder, under the current folder, where a refused save is kept.
pub const KEEP_DIR: &str = ".prego-context";

/// The largest JSON answer that is read: a file list of 1,000 entries, with its metadata.
const MAX_JSON: u64 = 4 * 1024 * 1024;
/// The largest checkpoint content that is read: the upload limit and some room.
const MAX_CONTENT: u64 = CONTEXT.max_upload_bytes + 1024 * 1024;

const TRIGGERS: [&str; 4] = ["compact", "stop", "manual", "schedule"];
const ON_FULL: [&str; 2] = ["refuse", "drop_oldest"];

/// The line that the help and the docs show.
#[cfg_attr(not(test), allow(dead_code))]
pub const TRUST: &str =
    "An agent follows the text in the context that it restores: pin it by hash \
(--expect) and grant read only to agents you trust.";

#[derive(Debug, PartialEq, Eq)]
pub enum ContextCommand {
    Save {
        folder: String,
        reference: String,
        session: Option<String>,
        parent: Option<String>,
        trigger: Option<String>,
        labels: Vec<(String, String)>,
        message: Option<String>,
        tag: Option<String>,
        redact: bool,
    },
    Restore {
        reference: String,
        folder: String,
        session: Option<String>,
        expect: Option<String>,
    },
    Ls {
        scope: String,
    },
    Log {
        reference: String,
        session: Option<String>,
    },
    Tag {
        reference: String,
        tag: String,
    },
    Rm {
        reference: String,
        session: Option<String>,
    },
    Set {
        reference: String,
        keep_days: Option<u32>,
        on_full: Option<String>,
    },
    Hash {
        folder: String,
        redact: bool,
    },
}

pub fn run(globals: &[&str], command: &ContextCommand, env: &dyn Env) -> Result<(), String> {
    match command {
        ContextCommand::Hash { folder, redact } => {
            let files = load(folder, *redact)?;
            println!("{}", files::version_hash(&entries(&files)).map_err(err)?);
            Ok(())
        }
        ContextCommand::Save {
            folder,
            reference,
            session,
            parent,
            trigger,
            labels,
            message,
            tag,
            redact,
        } => {
            let r = CtxRef::parse(reference)?.no_sel("save")?;
            let files = load(folder, *redact)?;
            let opts = SaveOptions {
                session: session.as_deref(),
                parent: parent.as_deref(),
                trigger: trigger.as_deref(),
                labels,
                message: message.as_deref(),
                tag: tag.as_deref(),
            };
            save(globals, &r, &files, &opts, env)
        }
        ContextCommand::Restore {
            reference,
            folder,
            session,
            expect,
        } => {
            let r = CtxRef::parse(reference)?;
            if session.is_some() && r.selector() != "latest" {
                return Err(
                    "prego: --session goes with the latest checkpoint only (no @<checkpoint>, or @latest)"
                        .into(),
                );
            }
            let api = Api::new(globals, &r.tenant, env)?;
            restore(
                &api,
                &r,
                Path::new(folder),
                session.as_deref(),
                expect.as_deref(),
            )
        }
        ContextCommand::Ls { scope } => {
            let (tenant, namespace) = crate::snippet::reference::parse_scope(scope)?;
            ls(&Api::new(globals, &tenant, env)?, &tenant, &namespace)
        }
        ContextCommand::Log { reference, session } => {
            let r = CtxRef::parse(reference)?.no_sel("log")?;
            log(&Api::new(globals, &r.tenant, env)?, &r, session.as_deref())
        }
        ContextCommand::Tag { reference, tag } => {
            let r = CtxRef::parse(reference)?;
            if r.sel.is_none() {
                return Err(
                    "prego: give the checkpoint to tag: prego context tag <ref>@<checkpoint> <tag>"
                        .into(),
                );
            }
            reference::check_tag(tag).map_err(err)?;
            set_tag(&Api::new(globals, &r.tenant, env)?, &r, tag)
        }
        ContextCommand::Rm { reference, session } => {
            let r = CtxRef::parse(reference)?;
            match (&r.sel, session) {
                (Some(_), Some(_)) | (None, None) => Err(
                    "prego: give one checkpoint (<ref>@<checkpoint>) or one session (--session <s>) to remove"
                        .into(),
                ),
                _ => rm(&Api::new(globals, &r.tenant, env)?, &r, session.as_deref()),
            }
        }
        ContextCommand::Set {
            reference,
            keep_days,
            on_full,
        } => {
            let r = CtxRef::parse(reference)?.no_sel("set")?;
            set(
                &Api::new(globals, &r.tenant, env)?,
                &r,
                *keep_days,
                on_full.as_deref(),
            )
        }
    }
}

fn err(e: String) -> String {
    format!("prego: {e}")
}

fn entries(files: &[File]) -> Vec<Entry> {
    files.iter().map(Entry::of).collect()
}

/// The files of a folder, checked with the Context limits, and redacted unless `redact` is false. Prints the
/// number of replaced strings, never the strings.
fn load(folder: &str, redact: bool) -> Result<Vec<File>, String> {
    let mut list = files::collect_with(Path::new(folder), &CONTEXT).map_err(err)?;
    files::check_files_with(&list, &CONTEXT).map_err(|e| format!("prego: {folder}: {e}"))?;
    if !redact {
        return Ok(list);
    }
    let (mut strings, mut in_files) = (0, 0);
    for f in &mut list {
        // check_files_with checked that every file is UTF-8.
        let t = std::str::from_utf8(&f.data).map_err(|e| format!("prego: {}: {e}", f.path))?;
        let (new, n) = redact::redact(t);
        if n > 0 {
            strings += n;
            in_files += 1;
            f.data = new.into_bytes();
        }
    }
    let s = if strings == 1 { "" } else { "s" };
    let fs = if in_files == 1 { "" } else { "s" };
    eprintln!("prego: redacted {strings} secret-shaped string{s} in {in_files} file{fs}");
    // A replacement can be longer than the string it replaces.
    files::check_files_with(&list, &CONTEXT).map_err(|e| format!("prego: {folder}: {e}"))?;
    Ok(list)
}

/// Stops with [`EXIT_ENCRYPTION`] if `mode` is not `none`. Nothing was written yet.
fn require_plain(mode: Option<&str>) {
    if let Some(m) = mode.filter(|m| *m != "none") {
        eprintln!(
            "prego: this checkpoint uses encryption mode {m}, which this prego version cannot read"
        );
        std::process::exit(EXIT_ENCRYPTION);
    }
}

/// The encryption mode in a JSON answer: `encryption.mode` or `enc_mode`, at the top or under
/// `checkpoint`. Missing is `none`.
fn body_mode(v: &Value) -> Option<String> {
    for o in [v, &v["checkpoint"]] {
        for e in [&o["encryption"]["mode"], &o["encryption"], &o["enc_mode"]] {
            match e {
                Value::Null | Value::Object(_) => {}
                Value::String(m) => return Some(m.clone()),
                m => return Some(m.to_string()),
            }
        }
    }
    None
}

fn require_plain_body(v: &Value) {
    require_plain(body_mode(v).as_deref());
}

/// A field at the top of an answer or under `checkpoint`.
fn field<'a>(v: &'a Value, key: &str) -> &'a Value {
    match &v[key] {
        Value::Null => &v["checkpoint"][key],
        x => x,
    }
}

/// The machine routes under `/v1/context/`.
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
        format!("{}/v1/context/{path}", self.c.base)
    }

    /// `<tenant>/<namespace>/<context>` encoded.
    fn context(r: &CtxRef) -> String {
        format!("{}/{}/{}", seg(&r.tenant), seg(&r.namespace), seg(&r.name))
    }

    fn send(
        &self,
        method: &str,
        path: &str,
        extra: &[(&str, &str)],
        body: Body<'_>,
    ) -> Result<FullResponse, String> {
        let url = self.url(path);
        let mut headers = vec![
            ("Authorization", self.c.auth.as_str()),
            ("Accept", "application/json"),
        ];
        headers.extend_from_slice(extra);
        self.c
            .http
            .send(method, &url, &headers, body)
            .map_err(|e| format!("prego: {url}: {e}"))
    }

    /// A request with an optional JSON body; a 2xx JSON answer (an empty body is `null`).
    fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
        what: &str,
    ) -> Result<Value, String> {
        let text = body.map(Value::to_string);
        let res = match &text {
            Some(t) => self.send(
                method,
                path,
                &[("Content-Type", "application/json")],
                Body::Bytes(t.as_bytes()),
            )?,
            None => self.send(method, path, &[], Body::Empty)?,
        };
        if !(200..300).contains(&res.status) {
            return Err(api_error(&res, what));
        }
        if res.body.trim().is_empty() {
            return Ok(Value::Null);
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
        // Every read with content carries X-Prego-Encryption; a missing header is `none`.
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

/// On `412 hash_mismatch`, prints the message and exits with [`EXIT_EXPECT`]. Nothing was written yet.
fn expect_exit(res: &FullResponse, what: &str) {
    if res.status == 412 {
        let body: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
        let hash = body["error"]["hash"]
            .as_str()
            .or(body["hash"].as_str())
            .map(|h| format!(" (the hash is {h})"))
            .unwrap_or_default();
        eprintln!("prego: {what}: the checkpoint hash is not the expected one{hash}");
        std::process::exit(EXIT_EXPECT);
    }
}

fn mismatch_exit(what: &str, local: &str, want: &str) -> ! {
    eprintln!("prego: {what}: the checkpoint hash is {local}, not the expected {want}");
    std::process::exit(EXIT_EXPECT);
}

/// The error text for a refused request. `404` means no context or no grant: the registry does not say
/// which.
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
            "prego: {what}: 403 {code}: {message} (you can read it, but you have no grant for this, or the \
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
    // `looks_like_secret` lists every match in `secrets`; the first is also in `path` and `line`.
    if let Some(more) = err["secrets"].as_array().filter(|a| a.len() > 1) {
        let list: Vec<String> = more
            .iter()
            .map(|m| format!("{}:{}", text(&m["path"]), text(&m["line"])))
            .collect();
        msg.push_str(&format!(" ({} matches: {})", list.len(), list.join(", ")));
    }
    if let Some(f) = err["field"].as_str() {
        msg.push_str(&format!(" (field: {f})"));
    }
    if let Some(s) = res.header("retry-after") {
        msg.push_str(&format!(" (retry after {s} s)"));
    }
    if let Some(id) = err["request_id"].as_str() {
        msg.push_str(&format!(" (request {id})"));
    }
    msg
}

// ---- save ----

struct SaveOptions<'a> {
    session: Option<&'a str>,
    parent: Option<&'a str>,
    trigger: Option<&'a str>,
    labels: &'a [(String, String)],
    message: Option<&'a str>,
    tag: Option<&'a str>,
}

/// The labels as one JSON object in ASCII (non-ASCII as `\u` escapes), for the `X-Prego-Labels` header.
pub fn labels_header(labels: &[(String, String)]) -> String {
    let map: serde_json::Map<String, Value> = labels
        .iter()
        .map(|(k, v)| (k.clone(), Value::String(v.clone())))
        .collect();
    let mut out = String::new();
    for c in Value::Object(map).to_string().chars() {
        if c.is_ascii() {
            out.push(c);
        } else {
            let mut buf = [0u16; 2];
            for u in c.encode_utf16(&mut buf) {
                out.push_str(&format!("\\u{u:04x}"));
            }
        }
    }
    out
}

/// Checks the labels: at most 16, a key of 1 to 64 characters, a value of at most 256 characters, keys
/// unique, at most 2 KiB together.
pub fn check_labels(labels: &[(String, String)]) -> Result<(), String> {
    if labels.len() > 16 {
        return Err(format!(
            "{} labels: a checkpoint has at most 16",
            labels.len()
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for (k, v) in labels {
        let n = k.chars().count();
        if n == 0 || n > 64 || k.chars().any(char::is_control) {
            return Err(format!(
                "bad label key `{}`: 1 to 64 characters, no control characters",
                k.escape_debug()
            ));
        }
        if v.chars().count() > 256 || v.chars().any(char::is_control) {
            return Err(format!(
                "bad label `{k}`: the value is at most 256 characters, with no control characters"
            ));
        }
        if !seen.insert(k.as_str()) {
            return Err(format!("the label `{k}` is there two times"));
        }
    }
    let size = labels_header(labels).len();
    if size > 2048 {
        return Err(format!(
            "the labels are {size} bytes as JSON: at most 2 KiB (2048 bytes) together"
        ));
    }
    Ok(())
}

fn save(
    globals: &[&str],
    r: &CtxRef,
    files: &[File],
    o: &SaveOptions<'_>,
    env: &dyn Env,
) -> Result<(), String> {
    let local = files::version_hash(&entries(files)).map_err(err)?;
    let bundle = files::tar_gz(files);
    match send_save(globals, r, files, &bundle, &local, o, env) {
        Ok(()) => Ok(()),
        Err(e) => {
            // The context is not lost: the checkpoint is kept in a local file, and the exit code says so.
            eprintln!("{e}");
            match keep_bundle(Path::new(KEEP_DIR), &r.name, &bundle) {
                Ok(p) => eprintln!(
                    "prego: the save was refused; the checkpoint ({local}) is kept in {}",
                    p.display()
                ),
                Err(k) => eprintln!("prego: the save was refused, and it cannot be kept: {k}"),
            }
            std::process::exit(EXIT_REFUSED);
        }
    }
}

fn send_save(
    globals: &[&str],
    r: &CtxRef,
    files: &[File],
    bundle: &[u8],
    local: &str,
    o: &SaveOptions<'_>,
    env: &dyn Env,
) -> Result<(), String> {
    if bundle.len() as u64 > CONTEXT.max_upload_bytes {
        return Err(format!(
            "prego: the tarball is {} bytes: an upload is at most {} ({} bytes)",
            bundle.len(),
            files::mib(CONTEXT.max_upload_bytes),
            CONTEXT.max_upload_bytes
        ));
    }
    let api = Api::new(globals, &r.tenant, env)?;
    let mut q: Vec<(&str, String)> = Vec::new();
    for (k, v) in [
        ("session", o.session),
        ("parent", o.parent),
        ("trigger", Some(o.trigger.unwrap_or("manual"))),
        ("message", o.message),
        ("tag", o.tag),
    ] {
        if let Some(v) = v {
            q.push((k, v.to_string()));
        }
    }
    let path = format!("{}?{}", Api::context(r), query(&q));
    let labels = (!o.labels.is_empty()).then(|| labels_header(o.labels));
    let mut extra = vec![("Content-Type", "application/gzip")];
    if let Some(l) = &labels {
        extra.push(("X-Prego-Labels", l.as_str()));
    }
    let what = format!("save to {}", r.long());
    let res = api.send("PUT", &path, &extra, Body::Bytes(bundle))?;
    if !(200..300).contains(&res.status) {
        return Err(api_error(&res, &what));
    }
    // The save is in. From here an error does not keep the bundle.
    let answer: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
    let hash = field(&answer, "hash").as_str().unwrap_or(local).to_string();
    let seq = text(field(&answer, "seq"));
    if hash != local {
        eprintln!("prego: warning: the registry hash {hash} is not the local hash {local}");
    }
    let created = answer["created"].as_bool().unwrap_or(res.status == 201);
    let session = o
        .session
        .map(|s| format!(", session {s}"))
        .unwrap_or_default();
    if created {
        println!(
            "{}: checkpoint {seq} ({hash}), {} files{session}",
            r.long(),
            files.len()
        );
    } else {
        println!(
            "{}: no change, checkpoint {seq} is the latest{session} ({hash})",
            r.long()
        );
    }
    if let Some(d) = answer["dropped"]["seq"].as_u64() {
        println!(
            "{}: removed checkpoint {d}, the oldest without a tag (on_full drop_oldest)",
            r.long()
        );
    }
    if let Some(t) = o.tag {
        println!("{}: tag {t} -> checkpoint {seq}", r.long());
    }
    Ok(())
}

/// Writes a refused checkpoint to `<dir>/<context>-<utc time>.tar.gz` (mode `0600`, a new file).
pub fn keep_bundle(dir: &Path, name: &str, bundle: &[u8]) -> Result<PathBuf, String> {
    use std::io::Write;
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    let stamp = stamp(prego_auth::now_unix());
    for n in 1..100 {
        let file = if n == 1 {
            format!("{name}-{stamp}.tar.gz")
        } else {
            format!("{name}-{stamp}-{n}.tar.gz")
        };
        let p = dir.join(file);
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        match o.open(&p) {
            Ok(mut f) => {
                f.write_all(bundle)
                    .and_then(|_| f.sync_all())
                    .map_err(|e| format!("{}: {e}", p.display()))?;
                return Ok(p);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("{}: {e}", p.display())),
        }
    }
    Err(format!("{}: no free file name", dir.display()))
}

/// A Unix time as `20261120T031500Z`.
pub fn stamp(t: i64) -> String {
    let days = t.div_euclid(86_400);
    let secs = t.rem_euclid(86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

// ---- restore ----

fn restore(
    api: &Api,
    r: &CtxRef,
    dir: &Path,
    session: Option<&str>,
    expect: Option<&str>,
) -> Result<(), String> {
    let sel = r.selector();
    let what = format!("{}@{sel}", r.long());
    let mut q: Vec<(&str, String)> = Vec::new();
    if let Some(s) = session {
        q.push(("session", s.to_string()));
    }
    if let Some(h) = expect {
        q.push(("expect", h.to_string()));
    }
    let mut path = format!("{}/at/{}", Api::context(r), seg(sel));
    if !q.is_empty() {
        path = format!("{path}?{}", query(&q));
    }
    let (res, meta) = api.get_json(&path, &what)?;
    require_plain_body(&meta);
    let list = field(&meta, "files")
        .as_array()
        .ok_or_else(|| format!("prego: {what}: the answer has no file list"))?;
    let mut listed = Vec::with_capacity(list.len());
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
        listed.push(Entry {
            path: p.to_string(),
            mode,
            size,
            sha256,
        });
    }
    // The hash is computed here, so a changed answer cannot pass --expect.
    let local = files::version_hash(&listed).map_err(err)?;
    for server in [
        field(&meta, "hash").as_str(),
        res.header("x-prego-context-hash"),
    ]
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
    let seq = res
        .header("x-prego-context-seq")
        .map(str::to_string)
        .unwrap_or_else(|| text(field(&meta, "seq")));
    // The folder is checked first, but made only after the content is downloaded and checked.
    files::check_folder(dir).map_err(err)?;
    let content = format!("{}/at/{}/content", Api::context(r), seg(&local));
    let (res, bytes) =
        api.get_bytes(&content, "application/gzip, application/x-tar", MAX_CONTENT)?;
    if res.status != 200 {
        expect_exit(&res, &what);
        return Err(api_error(&res, &what));
    }
    let got = files::untar_with(&bytes, &CONTEXT).map_err(|e| format!("prego: {what}: {e}"))?;
    let got_hash = files::version_hash(&entries(&got)).map_err(err)?;
    if got_hash != local {
        return Err(format!(
            "prego: {what}: the content ({got_hash}) does not match the file list ({local})"
        ));
    }
    let created = files::prepare_folder(dir).map_err(err)?;
    if let Err(e) = files::write_all(dir, &got) {
        if created {
            let _ = std::fs::remove_dir_all(dir);
        }
        return Err(err(e));
    }
    eprintln!("{}@{seq} {local} ({} files)", r.long(), got.len());
    println!("{}", dir.display());
    Ok(())
}

// ---- ls, log, tag, rm, set ----

/// Follows `next` cursors. At most 1,000 pages.
fn pages(
    api: &Api,
    base: &str,
    extra: &[(&str, String)],
    what: &str,
    mut each: impl FnMut(&Value),
) -> Result<(), String> {
    let mut after: Option<String> = None;
    for _ in 0..1000 {
        let mut q: Vec<(&str, String)> = extra.to_vec();
        q.push(("limit", "100".to_string()));
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
    Err(format!("prego: {what}: more than 1,000 pages"))
}

fn ls(api: &Api, tenant: &str, namespace: &str) -> Result<(), String> {
    let what = format!("the contexts of {tenant}/{namespace}");
    let mut n = 0;
    pages(
        api,
        &format!("{}/{}", seg(tenant), seg(namespace)),
        &[],
        &what,
        |c| {
            n += 1;
            println!(
                "{:<40} {:>6}  {}  {:>6} checkpoints  {}",
                text(&c["name"]),
                text(&c["latest_seq"]),
                text(&c["latest_hash"]),
                text(&c["checkpoint_count"]),
                text(&c["updated_at"]),
            );
        },
    )?;
    if n == 0 {
        eprintln!("no contexts in {tenant}/{namespace} that you can read");
    }
    Ok(())
}

fn log(api: &Api, r: &CtxRef, session: Option<&str>) -> Result<(), String> {
    let what = format!("the checkpoints of {}", r.long());
    let extra: Vec<(&str, String)> = session
        .map(|s| vec![("session", s.to_string())])
        .unwrap_or_default();
    println!("{}", r.long());
    pages(
        api,
        &format!("{}/checkpoints", Api::context(r)),
        &extra,
        &what,
        |c| {
            require_plain_body(c);
            let mark = if c["latest"] == true { "*" } else { " " };
            let tags: Vec<String> = c["tags"]
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
                "{mark}{:>6}  {}  {}  {:>10} B  {:>4} files  {:<8}  session {}  agent {}{tags}  {}",
                text(&c["seq"]),
                text(&c["hash"]),
                text(&c["created_at"]),
                text(&c["size"]),
                text(&c["file_count"]),
                text(&c["trigger"]),
                text(&c["session"]),
                text(&c["agent"]),
                c["message"].as_str().unwrap_or("")
            );
        },
    )
}

/// The JSON form of a selector in a request body: a number stays a number.
fn selector_json(s: &str) -> Value {
    match s.parse::<u64>() {
        Ok(n) => json!(n),
        Err(_) => json!(s),
    }
}

fn set_tag(api: &Api, r: &CtxRef, tag: &str) -> Result<(), String> {
    let sel = r.selector();
    let what = format!("tag {tag} on {}@{sel}", r.long());
    let body = json!({ "checkpoint": selector_json(sel) });
    let answer = api.call(
        "PUT",
        &format!("{}/tags/{}", Api::context(r), seg(tag)),
        Some(&body),
        &what,
    )?;
    let seq = match field(&answer, "seq") {
        Value::Null => sel.to_string(),
        v => text(v),
    };
    println!(
        "{}: tag {tag} -> checkpoint {seq}{}",
        r.long(),
        field(&answer, "hash")
            .as_str()
            .map(|h| format!(" ({h})"))
            .unwrap_or_default()
    );
    Ok(())
}

fn rm(api: &Api, r: &CtxRef, session: Option<&str>) -> Result<(), String> {
    match session {
        Some(s) => {
            let what = format!("remove session {s} of {}", r.long());
            let answer = api.call(
                "DELETE",
                &format!("{}/sessions/{}", Api::context(r), seg(s)),
                None,
                &what,
            )?;
            let n = match &answer["deleted"] {
                Value::Null => String::new(),
                v => format!(" ({} checkpoints)", text(v)),
            };
            println!("{}: removed session {s}{n}", r.long());
        }
        None => {
            let sel = r.selector();
            let what = format!("remove {}@{sel}", r.long());
            api.call(
                "DELETE",
                &format!("{}/at/{}", Api::context(r), seg(sel)),
                None,
                &what,
            )?;
            println!("{}: removed checkpoint {sel}", r.long());
        }
    }
    Ok(())
}

fn set(api: &Api, r: &CtxRef, keep_days: Option<u32>, on_full: Option<&str>) -> Result<(), String> {
    let mut body = serde_json::Map::new();
    if let Some(d) = keep_days {
        body.insert("keep_days".into(), json!(d));
    }
    if let Some(o) = on_full {
        body.insert("on_full".into(), json!(o));
    }
    let what = format!("settings of {}", r.long());
    let answer = api.call("PATCH", &Api::context(r), Some(&Value::Object(body)), &what)?;
    let show = |k: &str, given: Option<String>| match field(&answer, k) {
        Value::Null => given.unwrap_or_else(|| "-".into()),
        v => text(v),
    };
    println!(
        "{}: keep_days {}, on_full {}",
        r.long(),
        show("keep_days", keep_days.map(|d| d.to_string())),
        show("on_full", on_full.map(str::to_string))
    );
    Ok(())
}

/// Checks a trigger value.
pub fn check_trigger(t: &str) -> Result<(), String> {
    if TRIGGERS.contains(&t) {
        Ok(())
    } else {
        Err(format!(
            "bad trigger `{t}`: use compact, stop, manual or schedule"
        ))
    }
}

/// Checks an `--on-full` value.
pub fn check_on_full(o: &str) -> Result<(), String> {
    if ON_FULL.contains(&o) {
        Ok(())
    } else {
        Err(format!("bad --on-full `{o}`: use refuse or drop_oldest"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamps() {
        assert_eq!(stamp(0), "19700101T000000Z");
        assert_eq!(stamp(1_795_142_100), "20261120T023500Z");
    }

    #[test]
    fn labels() {
        let l = |pairs: &[(&str, &str)]| -> Vec<(String, String)> {
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        };
        assert_eq!(
            labels_header(&l(&[("ticket", "OPS-412"), ("by", "zoë")])),
            "{\"ticket\":\"OPS-412\",\"by\":\"zo\\u00eb\"}"
        );
        assert!(check_labels(&l(&[("ticket", "OPS-412")])).is_ok());
        let many: Vec<(String, String)> = (0..17).map(|i| (format!("k{i}"), "v".into())).collect();
        assert!(check_labels(&many).is_err());
        assert!(check_labels(&l(&[("", "v")])).is_err());
        assert!(check_labels(&l(&[(&"k".repeat(65), "v")])).is_err());
        assert!(check_labels(&l(&[("k", &"v".repeat(257))])).is_err());
        assert!(check_labels(&l(&[("k", "a"), ("k", "b")])).is_err());
        let big: Vec<(String, String)> = (0..16)
            .map(|i| (format!("key{i}"), "v".repeat(200)))
            .collect();
        assert!(check_labels(&big).unwrap_err().contains("2 KiB"));
    }

    #[test]
    fn modes_in_answers() {
        assert_eq!(body_mode(&json!({})), None);
        assert_eq!(
            body_mode(&json!({"encryption": {"mode": "none"}})).as_deref(),
            Some("none")
        );
        assert_eq!(
            body_mode(&json!({"checkpoint": {"enc_mode": "envelope_v1"}})).as_deref(),
            Some("envelope_v1")
        );
        assert_eq!(
            body_mode(&json!({"checkpoint": {"encryption": {"mode": "x"}}})).as_deref(),
            Some("x")
        );
    }

    #[test]
    fn keep_bundle_writes_new_private_files() {
        let g = prego_auth::testing::TempDir::new("prego-keep");
        let d = g.join("d");
        let a = keep_bundle(&d, "agent", b"one").unwrap();
        let b = keep_bundle(&d, "agent", b"two").unwrap();
        assert_ne!(a, b);
        assert_eq!(std::fs::read(&a).unwrap(), b"one");
        assert!(a
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("agent-"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(&a).unwrap().permissions().mode();
            assert_eq!(m & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(&d);
    }
}
