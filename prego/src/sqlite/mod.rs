//! `prego sqlite`: SQLite snapshots (ADR-0059). Checked, immutable snapshots of SQLite database files that
//! machines, agents and developers save and restore with their own identity, on the control host under
//! `/v1/sqlite/`, with a registry token. Prego is for sharing, not for keeping the only copy of data.
//!
//! A save makes a consistent copy with SQLite (the online backup API, or `VACUUM INTO` with `--compact`),
//! checks the copy, splits it into 64 MiB gzip frames and sends them: one `PUT` for one frame, an upload
//! session for more. A restore streams the frames into `<target>.prego-tmp`, checks both hashes and
//! `PRAGMA quick_check`, and then renames the file into place.

pub mod db;
pub mod frames;
pub mod reference;

use std::fs::File;
use std::io::{BufReader, BufWriter, IsTerminal, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use db::{Check, TempDir};
use frames::{Hashes, MAX_COMPRESSED_FRAME};
use prego_auth::http::{Body, FullResponse};
use prego_auth::Env;
use reference::DbRef;
use serde_json::{json, Value};

use crate::context::labels_header;
use crate::env::{query, text, Connection};
use crate::snippet::{parse_json, seg};

/// The exit code when a snapshot uses an encryption mode that this version cannot read. Nothing is written.
pub const EXIT_ENCRYPTION: i32 = 2;
/// The exit code when `--expect` does not match. Nothing is written.
pub const EXIT_EXPECT: i32 = 3;
/// The exit code when Prego refuses a save, or the save cannot be sent.
pub const EXIT_REFUSED: i32 = 4;
/// The exit code when `PRAGMA quick_check` or `integrity_check` fails. Nothing is sent or replaced.
pub const EXIT_CHECK: i32 = 5;

/// The purpose line (ADR-0059 item 2). The help shows it.
#[cfg_attr(not(test), allow(dead_code))]
pub const PURPOSE: &str = "We are not your backup. We are for sharing.";

/// The reserved label that carries the result of the client check.
pub const CHECK_LABEL: &str = "prego.check";

/// The largest JSON answer that is read.
const MAX_JSON: u64 = 8 * 1024 * 1024;
/// The largest compressed snapshot that a restore reads: more than the largest plan limit (10 GiB), with
/// room for the gzip framing.
const MAX_DOWNLOAD: u64 = 16 << 30;
/// Attempts for one frame when the network or the server fails for a short time.
const FRAME_ATTEMPTS: u32 = 3;

#[derive(Debug, PartialEq, Eq)]
pub enum SqliteCommand {
    Save {
        file: String,
        reference: String,
        compact: bool,
        check: Check,
        labels: Vec<(String, String)>,
        message: Option<String>,
        tag: Option<String>,
    },
    Restore {
        reference: String,
        file: String,
        expect: Option<String>,
        force: bool,
    },
    Ls {
        scope: String,
    },
    Log {
        reference: String,
    },
    Tag {
        reference: String,
        tag: String,
    },
    Rm {
        reference: String,
        yes: bool,
    },
    Prune {
        reference: String,
        keep: Option<u32>,
        older_than: Option<u64>,
        yes: bool,
    },
    Set {
        reference: String,
        keep_count: Option<u32>,
        keep_days: Option<u32>,
    },
    Hash {
        file: String,
        compact: bool,
    },
}

pub fn run(globals: &[&str], command: &SqliteCommand, env: &dyn Env) -> Result<(), String> {
    match command {
        SqliteCommand::Hash { file, compact } => {
            let tmp = TempDir::new().map_err(err)?;
            let copy = tmp.path().join("snapshot.db");
            db::copy(Path::new(file), &copy, *compact).map_err(err)?;
            let h = hash_file(&copy)?;
            eprintln!(
                "{file}: {} bytes, {} frame{}, file sha256 {}",
                h.size,
                h.frames.len(),
                plural(h.frames.len()),
                h.file
            );
            println!("{}", h.snapshot);
            Ok(())
        }
        SqliteCommand::Save {
            file,
            reference,
            compact,
            check,
            labels,
            message,
            tag,
        } => {
            let r = DbRef::parse(reference)?.no_sel("save")?;
            let o = SaveOptions {
                compact: *compact,
                check: *check,
                labels,
                message: message.as_deref(),
                tag: tag.as_deref(),
            };
            save(globals, &r, Path::new(file), &o, env)
        }
        SqliteCommand::Restore {
            reference,
            file,
            expect,
            force,
        } => {
            let r = DbRef::parse(reference)?;
            let target = Path::new(file);
            // The local checks first: a refused restore does not call Prego.
            if let Err(Failure::Message(m)) = check_target(target, *force) {
                return Err(m);
            }
            let api = Api::new(globals, &r.tenant, env)?;
            restore(&api, &r, target, expect.as_deref(), *force)
        }
        SqliteCommand::Ls { scope } => {
            let (tenant, namespace) = crate::snippet::reference::parse_scope(scope)?;
            ls(&Api::new(globals, &tenant, env)?, &tenant, &namespace)
        }
        SqliteCommand::Log { reference } => {
            let r = DbRef::parse(reference)?.no_sel("log")?;
            log(&Api::new(globals, &r.tenant, env)?, &r)
        }
        SqliteCommand::Tag { reference, tag } => {
            let r = DbRef::parse(reference)?;
            if r.sel.is_none() {
                return Err(
                    "prego: give the snapshot to tag: prego sqlite tag <ref>@<snapshot> <tag>"
                        .into(),
                );
            }
            reference::check_tag(tag).map_err(err)?;
            set_tag(&Api::new(globals, &r.tenant, env)?, &r, tag)
        }
        SqliteCommand::Rm { reference, yes } => {
            let r = DbRef::parse(reference)?;
            rm(&Api::new(globals, &r.tenant, env)?, &r, *yes)
        }
        SqliteCommand::Prune {
            reference,
            keep,
            older_than,
            yes,
        } => {
            let r = DbRef::parse(reference)?.no_sel("prune")?;
            let api = Api::new(globals, &r.tenant, env)?;
            prune(&api, &r, *keep, *older_than, *yes, prego_auth::now_unix())
        }
        SqliteCommand::Set {
            reference,
            keep_count,
            keep_days,
        } => {
            let r = DbRef::parse(reference)?.no_sel("set")?;
            set(
                &Api::new(globals, &r.tenant, env)?,
                &r,
                *keep_count,
                *keep_days,
            )
        }
    }
}

fn err(e: String) -> String {
    format!("prego: {e}")
}

fn plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

fn hash_file(path: &Path) -> Result<Hashes, String> {
    let f = File::open(path).map_err(|e| format!("prego: {}: {e}", path.display()))?;
    frames::hash_reader(&mut BufReader::with_capacity(1 << 20, f))
        .map_err(|e| format!("prego: {}: {e}", path.display()))
}

/// Checks the user labels: the Context label rules, and the `prego.` keys are kept for Prego.
pub fn check_user_labels(labels: &[(String, String)]) -> Result<(), String> {
    if let Some((k, _)) = labels.iter().find(|(k, _)| k.starts_with("prego.")) {
        return Err(format!(
            "bad label key `{k}`: keys that start with `prego.` are kept for Prego"
        ));
    }
    crate::context::check_labels(labels)
        .map_err(|e| e.replace("a checkpoint has", "a snapshot has"))
}

/// Gives [`EXIT_ENCRYPTION`] if `mode` is not `none`.
fn require_plain(mode: Option<&str>) -> Result<(), i32> {
    match mode.filter(|m| *m != "none") {
        Some(m) => {
            eprintln!(
                "prego: this snapshot uses encryption mode {m}, which this prego version cannot read. \
                 Update prego"
            );
            Err(EXIT_ENCRYPTION)
        }
        None => Ok(()),
    }
}

/// The encryption mode in a JSON answer: `encryption.mode` or `enc_mode`, at the top or under `snapshot`.
/// Missing is `none`.
fn body_mode(v: &Value) -> Option<String> {
    for o in [v, &v["snapshot"]] {
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

/// A field at the top of an answer or under `snapshot`.
fn field<'a>(v: &'a Value, key: &str) -> &'a Value {
    match &v[key] {
        Value::Null => &v["snapshot"][key],
        x => x,
    }
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The machine routes under `/v1/sqlite/`.
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
        format!("{}/v1/sqlite/{path}", self.c.base)
    }

    /// `<tenant>/<namespace>/<database>` encoded.
    fn db(r: &DbRef) -> String {
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
        answer(&res, what)
    }

    /// A `GET` with a `200` JSON answer. `412 hash_mismatch` gives [`EXIT_EXPECT`].
    fn get_json(&self, path: &str, what: &str) -> Result<(FullResponse, Value), Failure> {
        let url = self.url(path);
        let headers = [
            ("Authorization", self.c.auth.as_str()),
            ("Accept", "application/json"),
        ];
        let mut out = Vec::new();
        let (res, _) = self
            .c
            .http
            .get_to(&url, &headers, &mut out, MAX_JSON)
            .map_err(|e| Failure::Message(format!("prego: {url}: {e}")))?;
        if res.status != 200 {
            if let Some(code) = expect_failure(&res, what) {
                return Err(Failure::Exit(code));
            }
            return Err(Failure::Message(api_error(&res, what)));
        }
        Ok((res, parse_json(&out, what).map_err(Failure::Message)?))
    }
}

/// A failure that is a message (exit code 1), or an exit code whose message is printed already.
enum Failure {
    Message(String),
    Exit(i32),
}

impl From<String> for Failure {
    fn from(s: String) -> Failure {
        Failure::Message(s)
    }
}

/// A 2xx JSON answer, or the error text.
fn answer(res: &FullResponse, what: &str) -> Result<Value, String> {
    if !(200..300).contains(&res.status) {
        return Err(api_error(res, what));
    }
    if res.body.trim().is_empty() {
        return Ok(Value::Null);
    }
    parse_json(res.body.as_bytes(), what)
}

/// On `412 hash_mismatch`, prints the message and gives [`EXIT_EXPECT`].
fn expect_failure(res: &FullResponse, what: &str) -> Option<i32> {
    if res.status != 412 {
        return None;
    }
    let body: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
    let hash = body["error"]["hash"]
        .as_str()
        .or(body["hash"].as_str())
        .map(|h| format!(" (the hash is {h})"))
        .unwrap_or_default();
    eprintln!("prego: {what}: the snapshot hash is not the expected one{hash}");
    Some(EXIT_EXPECT)
}

/// The error text for a refused request. `404` means no database or no grant: Prego does not say which.
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
    for k in ["reason", "field", "hint"] {
        if let Some(v) = err[k].as_str() {
            msg.push_str(&format!(" ({k}: {v})"));
        }
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
    compact: bool,
    check: Check,
    labels: &'a [(String, String)],
    message: Option<&'a str>,
    tag: Option<&'a str>,
}

fn save(
    globals: &[&str],
    r: &DbRef,
    source: &Path,
    o: &SaveOptions<'_>,
    env: &dyn Env,
) -> Result<(), String> {
    let tmp = TempDir::new().map_err(err)?;
    let copy = tmp.path().join("snapshot.db");
    db::copy(source, &copy, o.compact).map_err(err)?;
    if let Some(lines) = db::check(&copy, o.check).map_err(err)? {
        eprintln!(
            "prego: {}: PRAGMA {} failed on the snapshot; nothing was sent:",
            source.display(),
            if o.check == Check::Full {
                "integrity_check"
            } else {
                "quick_check"
            }
        );
        for l in lines.iter().take(10) {
            eprintln!("  {l}");
        }
        drop(tmp);
        std::process::exit(EXIT_CHECK);
    }
    let h = hash_file(&copy)?;
    let head = db::header(&copy).map_err(err)?;
    eprintln!(
        "prego: snapshot of {}: {} bytes ({} pages of {} bytes), {} frame{}, {}",
        source.display(),
        h.size,
        head.page_count,
        head.page_size,
        h.frames.len(),
        plural(h.frames.len()),
        o.check.label()
    );
    let result = Api::new(globals, &r.tenant, env).and_then(|api| send_save(&api, r, &copy, &h, o));
    if let Err(e) = result {
        eprintln!("{e}");
        drop(tmp);
        std::process::exit(EXIT_REFUSED);
    }
    Ok(())
}

/// The labels that a save sends: the user labels and `prego.check`.
fn all_labels(o: &SaveOptions<'_>) -> Vec<(String, String)> {
    let mut l = o.labels.to_vec();
    l.push((CHECK_LABEL.into(), o.check.label().into()));
    l
}

fn send_save(
    api: &Api,
    r: &DbRef,
    copy: &Path,
    h: &Hashes,
    o: &SaveOptions<'_>,
) -> Result<(), String> {
    let what = format!("save to {}", r.long());
    let mut f = BufReader::with_capacity(
        1 << 20,
        File::open(copy).map_err(|e| format!("prego: {}: {e}", copy.display()))?,
    );
    let labels = all_labels(o);
    let (a, status) = if h.frames.len() == 1 {
        let (body, hash, _) = frames::read_frame(&mut f).map_err(|e| format!("prego: {e}"))?;
        if hash != h.frames[0] {
            return Err(format!("prego: {what}: the copy changed while it was sent"));
        }
        frame_size(&body, &what)?;
        let mut q: Vec<(&str, String)> = Vec::new();
        for (k, v) in [("message", o.message), ("tag", o.tag)] {
            if let Some(v) = v {
                q.push((k, v.to_string()));
            }
        }
        let mut path = Api::db(r);
        if !q.is_empty() {
            path = format!("{path}?{}", query(&q));
        }
        let header = labels_header(&labels);
        let extra = [
            ("Content-Type", "application/gzip"),
            ("X-Prego-File-Sha256", h.file.as_str()),
            ("X-Prego-Snapshot-Hash", h.snapshot.as_str()),
            ("X-Prego-Labels", header.as_str()),
        ];
        let res = api.send("PUT", &path, &extra, Body::Bytes(&body))?;
        (answer(&res, &what)?, res.status)
    } else {
        session_save(api, r, &mut f, h, &labels, o, &what)?
    };
    report(r, h, &a, status, o.tag);
    Ok(())
}

fn frame_size(body: &[u8], what: &str) -> Result<(), String> {
    if body.len() as u64 > MAX_COMPRESSED_FRAME {
        return Err(format!(
            "prego: {what}: a frame is {} bytes compressed: at most {} bytes",
            body.len(),
            MAX_COMPRESSED_FRAME
        ));
    }
    Ok(())
}

/// An upload session: open, one `PUT` for each frame, commit. On a failure, the session is cancelled.
fn session_save(
    api: &Api,
    r: &DbRef,
    f: &mut BufReader<File>,
    h: &Hashes,
    labels: &[(String, String)],
    o: &SaveOptions<'_>,
    what: &str,
) -> Result<(Value, u16), String> {
    let open = json!({
        "frames": h.frames.len(),
        "file_sha256": h.file,
        "snapshot_hash": h.snapshot,
    });
    let a = api.call(
        "POST",
        &format!("{}/uploads", Api::db(r)),
        Some(&open),
        what,
    )?;
    let id = a["id"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("prego: {what}: the answer has no upload session id"))?
        .to_string();
    let base = format!("{}/uploads/{}", Api::db(r), seg(&id));
    let result = (|| -> Result<(Value, u16), String> {
        f.seek(SeekFrom::Start(0))
            .map_err(|e| format!("prego: {e}"))?;
        for (i, want) in h.frames.iter().enumerate() {
            let (body, hash, n) = frames::read_frame(f).map_err(|e| format!("prego: {e}"))?;
            if &hash != want {
                return Err(format!("prego: {what}: the copy changed while it was sent"));
            }
            frame_size(&body, what)?;
            let fw = format!("{what}: frame {} of {}", i + 1, h.frames.len());
            let a = send_frame(api, &format!("{base}/frames/{i}"), &body, &fw)?;
            if let Some(got) = a["hash"].as_str() {
                if got != want {
                    return Err(format!(
                        "prego: {fw}: Prego has the frame hash {got}, not {want}"
                    ));
                }
            }
            eprintln!(
                "prego: frame {}/{} sent ({n} bytes, {} compressed)",
                i + 1,
                h.frames.len(),
                body.len()
            );
        }
        let mut map = serde_json::Map::new();
        for (k, v) in labels {
            map.insert(k.clone(), Value::String(v.clone()));
        }
        let mut commit = json!({ "labels": Value::Object(map) });
        if let Some(m) = o.message {
            commit["message"] = json!(m);
        }
        if let Some(t) = o.tag {
            commit["tag"] = json!(t);
        }
        let s = commit.to_string();
        let res = api.send(
            "POST",
            &format!("{base}/commit"),
            &[("Content-Type", "application/json")],
            Body::Bytes(s.as_bytes()),
        )?;
        Ok((answer(&res, what)?, res.status))
    })();
    if result.is_err() {
        // Best effort: an open session holds storage until it expires.
        let _ = api.send("DELETE", &base, &[], Body::Empty);
    }
    result
}

/// Sends one frame. A network failure, a `5xx` or a `429` is tried again, at most [`FRAME_ATTEMPTS`] times.
fn send_frame(api: &Api, path: &str, body: &[u8], what: &str) -> Result<Value, String> {
    let mut last = String::new();
    for attempt in 1..=FRAME_ATTEMPTS {
        let wait = match api.send(
            "PUT",
            path,
            &[("Content-Type", "application/gzip")],
            Body::Bytes(body),
        ) {
            Ok(res) if res.status == 429 || res.status >= 500 => {
                last = api_error(&res, what);
                res.header("retry-after")
                    .and_then(|s| s.trim().parse::<u64>().ok())
                    .unwrap_or(2 * u64::from(attempt))
                    .min(60)
            }
            Ok(res) => return answer(&res, what),
            Err(e) => {
                last = e;
                2 * u64::from(attempt)
            }
        };
        if attempt < FRAME_ATTEMPTS {
            eprintln!("{last}; trying again in {wait} s");
            std::thread::sleep(Duration::from_secs(wait));
        }
    }
    Err(last)
}

fn report(r: &DbRef, h: &Hashes, a: &Value, status: u16, tag: Option<&str>) {
    let hash = field(a, "hash").as_str().unwrap_or(&h.snapshot).to_string();
    if hash != h.snapshot {
        eprintln!(
            "prego: warning: Prego has the snapshot hash {hash}, not the local hash {}",
            h.snapshot
        );
    }
    let seq = text(field(a, "seq"));
    let stored = match field(a, "stored_bytes") {
        Value::Null => String::new(),
        v => format!(", {} bytes stored", text(v)),
    };
    if a["created"].as_bool().unwrap_or(status == 201) {
        println!(
            "{}: snapshot {seq} ({hash}), {} bytes{stored}",
            r.long(),
            h.size
        );
    } else {
        println!(
            "{}: no change, snapshot {seq} is the latest ({hash})",
            r.long()
        );
    }
    if let Some(t) = tag {
        println!("{}: tag {t} -> snapshot {seq}", r.long());
    }
}

// ---- restore ----

/// `<target>.prego-tmp`, removed when dropped unless it was renamed into place.
struct Partial {
    path: PathBuf,
    keep: bool,
}

impl Drop for Partial {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn with_suffix(p: &Path, s: &str) -> PathBuf {
    let mut o = p.as_os_str().to_owned();
    o.push(s);
    PathBuf::from(o)
}

fn restore(
    api: &Api,
    r: &DbRef,
    target: &Path,
    expect: Option<&str>,
    force: bool,
) -> Result<(), String> {
    // The temporary file is removed (Partial is dropped) before the process exits.
    match restore_inner(api, r, target, expect, force) {
        Ok(()) => Ok(()),
        Err(Failure::Message(m)) => Err(m),
        Err(Failure::Exit(code)) => std::process::exit(code),
    }
}

fn restore_inner(
    api: &Api,
    r: &DbRef,
    target: &Path,
    expect: Option<&str>,
    force: bool,
) -> Result<(), Failure> {
    let sel = r.selector();
    let what = format!("{}@{sel}", r.long());
    check_target(target, force)?;
    let mut path = format!("{}/at/{}", Api::db(r), seg(sel));
    if let Some(h) = expect {
        path = format!("{path}?{}", query(&[("expect", h.to_string())]));
    }
    let (res, meta) = api.get_json(&path, &what)?;
    require_plain(body_mode(&meta).as_deref()).map_err(Failure::Exit)?;
    let hash = field(&meta, "hash")
        .as_str()
        .filter(|h| crate::env::jcs::is_hash(h))
        .ok_or_else(|| format!("prego: {what}: the answer has no snapshot hash"))?
        .to_string();
    if let Some(etag) = res.header("etag") {
        let etag = etag.trim().trim_start_matches("W/").trim_matches('"');
        if etag != hash {
            return Err(format!(
                "prego: {what}: the ETag ({etag}) is not the snapshot hash in the answer ({hash})"
            )
            .into());
        }
    }
    if let Some(want) = expect {
        if want != hash {
            eprintln!("prego: {what}: the snapshot hash is {hash}, not the expected {want}");
            return Err(Failure::Exit(EXIT_EXPECT));
        }
    }
    let file_sha = field(&meta, "file_sha256").as_str().map(str::to_string);
    if let Some(s) = &file_sha {
        if !is_hex64(s) {
            return Err(
                format!("prego: {what}: the file sha256 in the answer is not 64 hex").into(),
            );
        }
    }
    let size = field(&meta, "size").as_u64();
    let seq = text(field(&meta, "seq"));

    if let Some(dir) = target.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).map_err(|e| format!("prego: {}: {e}", dir.display()))?;
    }
    let tmp_path = with_suffix(target, ".prego-tmp");
    // A file left by a stopped restore is removed. remove_file does not follow a symbolic link.
    match std::fs::remove_file(&tmp_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("prego: {}: {e}", tmp_path.display()).into()),
    }
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)
        .map_err(|e| format!("prego: {}: {e}", tmp_path.display()))?;
    let mut partial = Partial {
        path: tmp_path.clone(),
        keep: false,
    };

    // The content, by hash, so that it is the snapshot that the metadata gave.
    let content = format!("{}/at/{}.db.gz", Api::db(r), seg(&hash));
    let url = api.url(&content);
    let headers = [
        ("Authorization", api.c.auth.as_str()),
        ("Accept", "application/gzip"),
    ];
    let hasher = frames::FrameHasher::new(BufWriter::with_capacity(1 << 20, file));
    let mut gz = flate2::write::MultiGzDecoder::new(hasher);
    let (res, _) = api
        .c
        .http
        .get_to(&url, &headers, &mut gz, MAX_DOWNLOAD)
        .map_err(|e| format!("prego: {url}: {e}"))?;
    if res.status != 200 {
        if let Some(code) = expect_failure(&res, &what) {
            return Err(Failure::Exit(code));
        }
        return Err(api_error(&res, &what).into());
    }
    require_plain(res.header("x-prego-encryption").map(str::trim)).map_err(Failure::Exit)?;
    let hasher = gz
        .finish()
        .map_err(|e| format!("prego: {what}: the content is not valid gzip: {e}"))?;
    let (got, w) = hasher.finish();
    let file = w
        .into_inner()
        .map_err(|e| format!("prego: {}: {}", tmp_path.display(), e.error()))?;
    file.sync_all()
        .map_err(|e| format!("prego: {}: {e}", tmp_path.display()))?;
    drop(file);
    if got.snapshot != hash {
        return Err(format!(
            "prego: {what}: the content has the snapshot hash {}, not {hash}",
            got.snapshot
        )
        .into());
    }
    if let Some(s) = &file_sha {
        if &got.file != s {
            return Err(format!(
                "prego: {what}: the content has the file sha256 {}, not {s}",
                got.file
            )
            .into());
        }
    }
    if let Some(n) = size {
        if got.size != n {
            return Err(
                format!("prego: {what}: the content is {} bytes, not {n}", got.size).into(),
            );
        }
    }
    if let Some(lines) = db::check(&tmp_path, Check::Quick).map_err(err)? {
        eprintln!(
            "prego: {what}: PRAGMA quick_check failed; {} was not changed:",
            target.display()
        );
        for l in lines.iter().take(10) {
            eprintln!("  {l}");
        }
        return Err(Failure::Exit(EXIT_CHECK));
    }
    // Again, just before the rename: a program can have opened the database since the start.
    refuse_side_files(target, force)?;
    if force {
        // A -wal or -journal file of the old database must not be applied to the new one.
        for s in ["-wal", "-shm", "-journal"] {
            let p = with_suffix(target, s);
            match std::fs::remove_file(&p) {
                Ok(()) => eprintln!("prego: removed {} (--force)", p.display()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("prego: {}: {e}", p.display()).into()),
            }
        }
    }
    if let Ok(m) = std::fs::metadata(target) {
        // The new file gets the permissions of the file that it replaces.
        let _ = std::fs::set_permissions(&tmp_path, m.permissions());
    }
    std::fs::rename(&tmp_path, target)
        .map_err(|e| format!("prego: {} -> {}: {e}", tmp_path.display(), target.display()))?;
    partial.keep = true;
    #[cfg(unix)]
    {
        let dir = match target.parent() {
            Some(d) if !d.as_os_str().is_empty() => d,
            _ => Path::new("."),
        };
        if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
        }
    }
    eprintln!(
        "{}@{seq} {hash} ({} bytes, quick_check ok)",
        r.long(),
        got.size
    );
    println!("{}", target.display());
    Ok(())
}

/// The target is a file path, and has no `-wal` or `-journal` file next to it unless `force`.
fn check_target(target: &Path, force: bool) -> Result<(), Failure> {
    if target.as_os_str().is_empty() || target.is_dir() {
        return Err(format!("prego: {}: give a file, not a folder", target.display()).into());
    }
    refuse_side_files(target, force)
}

fn refuse_side_files(target: &Path, force: bool) -> Result<(), Failure> {
    let side = db::side_files(target);
    if side.is_empty() || force {
        return Ok(());
    }
    let names: Vec<String> = side.iter().map(|p| p.display().to_string()).collect();
    Err(format!(
        "prego: {} is in use or was not closed cleanly ({} exists). Stop the program that uses it, or give \
         --force to replace it and remove the -wal, -shm and -journal files",
        target.display(),
        names.join(", ")
    )
    .into())
}

// ---- ls, log, tag, rm, prune, set ----

/// Follows `next` cursors. At most 1,000 pages.
fn pages(api: &Api, base: &str, what: &str, mut each: impl FnMut(&Value)) -> Result<(), String> {
    let mut after: Option<String> = None;
    for _ in 0..1000 {
        let mut q: Vec<(&str, String)> = vec![("limit", "1000".to_string())];
        if let Some(a) = &after {
            q.push(("after", a.clone()));
        }
        let (_, answer) = match api.get_json(&format!("{base}?{}", query(&q)), what) {
            Ok(x) => x,
            Err(Failure::Message(m)) => return Err(m),
            Err(Failure::Exit(c)) => std::process::exit(c),
        };
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
    let what = format!("the SQLite databases of {tenant}/{namespace}");
    let mut n = 0;
    pages(
        api,
        &format!("{}/{}", seg(tenant), seg(namespace)),
        &what,
        |d| {
            n += 1;
            println!(
                "{:<40} {:>6}  {}  {:>5} snapshots  {:>12} B stored  {}",
                text(&d["name"]),
                text(&d["latest_seq"]),
                text(&d["latest_hash"]),
                text(&d["snapshot_count"]),
                text(&d["stored_bytes"]),
                text(&d["updated_at"]),
            );
        },
    )?;
    if n == 0 {
        eprintln!("no SQLite databases in {tenant}/{namespace} that you can read");
    }
    Ok(())
}

fn tags_of(s: &Value) -> Vec<String> {
    s["tags"]
        .as_array()
        .into_iter()
        .flatten()
        .map(text)
        .collect()
}

fn log(api: &Api, r: &DbRef) -> Result<(), String> {
    let what = format!("the snapshots of {}", r.long());
    println!("{}", r.long());
    pages(api, &format!("{}/snapshots", Api::db(r)), &what, |s| {
        if let Err(code) = require_plain(body_mode(s).as_deref()) {
            std::process::exit(code);
        }
        let mark = if s["latest"] == true { "*" } else { " " };
        let tags = tags_of(s);
        let tags = if tags.is_empty() {
            String::new()
        } else {
            format!("  [{}]", tags.join(", "))
        };
        let check = match (&s["client_check"], &s["labels"][CHECK_LABEL]) {
            (Value::String(c), _) | (_, Value::String(c)) => c.clone(),
            _ => "-".into(),
        };
        println!(
            "{mark}{:>6}  {}  {}  {:>12} B  {:>8} pages  user_version {}  {}  agent {}{tags}  {}",
            text(&s["seq"]),
            text(&s["hash"]),
            text(&s["created_at"]),
            text(&s["size"]),
            text(&s["page_count"]),
            text(&s["user_version"]),
            check,
            text(&s["agent"]),
            s["message"].as_str().unwrap_or("")
        );
    })
}

/// The JSON form of a selector in a request body: a number stays a number.
fn selector_json(s: &str) -> Value {
    match s.parse::<u64>() {
        Ok(n) => json!(n),
        Err(_) => json!(s),
    }
}

fn set_tag(api: &Api, r: &DbRef, tag: &str) -> Result<(), String> {
    let sel = r.selector();
    let what = format!("tag {tag} on {}@{sel}", r.long());
    let body = json!({ "snapshot": selector_json(sel) });
    let a = api.call(
        "PUT",
        &format!("{}/tags/{}", Api::db(r), seg(tag)),
        Some(&body),
        &what,
    )?;
    let seq = match field(&a, "seq") {
        Value::Null => sel.to_string(),
        v => text(v),
    };
    println!(
        "{}: tag {tag} -> snapshot {seq}{}",
        r.long(),
        field(&a, "hash")
            .as_str()
            .map(|h| format!(" ({h})"))
            .unwrap_or_default()
    );
    Ok(())
}

/// Asks on the terminal. Without a terminal, `--yes` is necessary.
fn confirm(question: &str) -> Result<bool, String> {
    if !std::io::stdin().is_terminal() {
        return Err(format!(
            "prego: {question}: there is no terminal to ask; give --yes"
        ));
    }
    eprint!("{question}? [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| format!("prego: {e}"))?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes" | "YES" | "Yes"))
}

fn rm(api: &Api, r: &DbRef, yes: bool) -> Result<(), String> {
    match &r.sel {
        Some(sel) => {
            let what = format!("remove {}@{sel}", r.long());
            api.call(
                "DELETE",
                &format!("{}/at/{}", Api::db(r), seg(sel)),
                None,
                &what,
            )?;
            println!("{}: removed snapshot {sel}", r.long());
        }
        None => {
            if !yes
                && !confirm(&format!(
                    "Remove the database {} and all its snapshots",
                    r.long()
                ))?
            {
                return Err("prego: nothing was removed".into());
            }
            let what = format!("remove {}", r.long());
            let a = api.call("DELETE", &Api::db(r), None, &what)?;
            let purge = a["purge_after"]
                .as_str()
                .map(|p| format!(" (it can be restored until {p})"))
                .unwrap_or_default();
            println!("{}: removed the database{purge}", r.long());
        }
    }
    Ok(())
}

/// Seconds from `<n>h`, `<n>d` or `<n>w`.
pub fn parse_age(s: &str) -> Result<u64, String> {
    let bad = || format!("bad --older-than `{s}`: use <n>h, <n>d or <n>w, for example 7d");
    let (n, unit) = s.split_at(s.len().saturating_sub(1));
    if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    let n: u64 = n.parse().map_err(|_| bad())?;
    let mult = match unit {
        "h" => 3600,
        "d" => 86_400,
        "w" => 7 * 86_400,
        _ => return Err(bad()),
    };
    if n == 0 {
        return Err(bad());
    }
    n.checked_mul(mult)
        .filter(|s| *s < i64::MAX as u64 / 2)
        .ok_or_else(bad)
}

/// A Unix time from an RFC 3339 UTC time (`2026-11-20T08:24:26Z`, with or without a fraction, or with
/// `+00:00`), or from a number of seconds or milliseconds.
pub fn unix_time(v: &Value) -> Option<i64> {
    if let Some(n) = v.as_i64() {
        return Some(if n > 100_000_000_000 { n / 1000 } else { n });
    }
    let s = v.as_str()?;
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't' | b' ') {
        return None;
    }
    let num = |a: usize, z: usize| s.get(a..z)?.parse::<i64>().ok();
    let (y, mo, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (h, mi, se) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    let mut rest = s.get(19..)?;
    if let Some(r) = rest.strip_prefix('.') {
        rest = r.trim_start_matches(|c: char| c.is_ascii_digit());
    }
    if !matches!(rest, "Z" | "z" | "+00:00") {
        return None;
    }
    // Days from 1970-01-01 (Howard Hinnant's algorithm).
    let yy = if mo <= 2 { y - 1 } else { y };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3600 + mi * 60 + se)
}

/// The snapshots that a prune removes, from a list in any order, newest first. Never a tagged snapshot,
/// never the newest one. With `keep` and `older_than` both, a snapshot must match both.
pub fn prune_plan(
    list: &[Value],
    keep: Option<u32>,
    older_than: Option<u64>,
    now: i64,
) -> Vec<Value> {
    let mut all: Vec<&Value> = list
        .iter()
        .filter(|s| s["seq"].as_u64().is_some())
        .collect();
    all.sort_by_key(|s| std::cmp::Reverse(s["seq"].as_u64()));
    let newest = all.first().and_then(|s| s["seq"].as_u64());
    all.iter()
        .enumerate()
        .filter(|(i, s)| {
            if s["seq"].as_u64() == newest || s["latest"] == true || !tags_of(s).is_empty() {
                return false;
            }
            let by_count = keep.is_none_or(|k| *i as u64 >= u64::from(k));
            let by_age = older_than.is_none_or(|age| {
                unix_time(&s["created_at"]).is_some_and(|t| t < now - age as i64)
            });
            by_count && by_age
        })
        .map(|(_, s)| (*s).clone())
        .collect()
}

fn prune(
    api: &Api,
    r: &DbRef,
    keep: Option<u32>,
    older_than: Option<u64>,
    yes: bool,
    now: i64,
) -> Result<(), String> {
    let what = format!("the snapshots of {}", r.long());
    let mut list = Vec::new();
    pages(api, &format!("{}/snapshots", Api::db(r)), &what, |s| {
        list.push(s.clone())
    })?;
    let plan = prune_plan(&list, keep, older_than, now);
    if plan.is_empty() {
        println!(
            "{}: nothing to remove ({} snapshot{}; tagged snapshots and the newest one are kept)",
            r.long(),
            list.len(),
            plural(list.len())
        );
        return Ok(());
    }
    let mut bytes = 0u64;
    for s in &plan {
        bytes += s["stored_bytes"].as_u64().unwrap_or(0);
        println!(
            "  {:>6}  {}  {}  {:>12} B stored",
            text(&s["seq"]),
            text(&s["hash"]),
            text(&s["created_at"]),
            text(&s["stored_bytes"])
        );
    }
    let q = format!(
        "Remove these {} snapshot{} of {} ({bytes} bytes stored)",
        plan.len(),
        plural(plan.len()),
        r.long()
    );
    if !yes && !confirm(&q)? {
        return Err("prego: nothing was removed".into());
    }
    let mut removed = 0;
    for s in &plan {
        let seq = text(&s["seq"]);
        let w = format!("remove {}@{seq}", r.long());
        api.call(
            "DELETE",
            &format!("{}/at/{}", Api::db(r), seg(&seq)),
            None,
            &w,
        )
        .map_err(|e| format!("{e} ({removed} of {} removed before this)", plan.len()))?;
        removed += 1;
    }
    println!(
        "{}: removed {removed} snapshot{}",
        r.long(),
        plural(removed)
    );
    Ok(())
}

fn set(
    api: &Api,
    r: &DbRef,
    keep_count: Option<u32>,
    keep_days: Option<u32>,
) -> Result<(), String> {
    let mut body = serde_json::Map::new();
    if let Some(n) = keep_count {
        body.insert("keep_count".into(), json!(n));
    }
    if let Some(d) = keep_days {
        body.insert("keep_days".into(), json!(d));
    }
    let what = format!("settings of {}", r.long());
    let a = api.call("PATCH", &Api::db(r), Some(&Value::Object(body)), &what)?;
    let show = |k: &str, given: Option<u32>| match field(&a, k) {
        Value::Null => given.map(|g| g.to_string()).unwrap_or_else(|| "-".into()),
        v => text(v),
    };
    println!(
        "{}: keep_count {}, keep_days {}",
        r.long(),
        show("keep_count", keep_count),
        show("keep_days", keep_days)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ages() {
        assert_eq!(parse_age("7d").unwrap(), 7 * 86_400);
        assert_eq!(parse_age("12h").unwrap(), 12 * 3600);
        assert_eq!(parse_age("2w").unwrap(), 14 * 86_400);
        for bad in [
            "",
            "d",
            "7",
            "0d",
            "7m",
            "-1d",
            "1.5d",
            "+3d",
            "99999999999999999999w",
        ] {
            assert!(parse_age(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn times() {
        assert_eq!(unix_time(&json!("1970-01-01T00:00:00Z")), Some(0));
        let t = unix_time(&json!("2026-11-20T03:15:00Z")).unwrap();
        assert_eq!(crate::context::stamp(t), "20261120T031500Z");
        assert_eq!(unix_time(&json!("2026-11-20T03:15:00.123Z")), Some(t));
        assert_eq!(unix_time(&json!("2026-11-20T03:15:00+00:00")), Some(t));
        assert_eq!(unix_time(&json!(t * 1000)), Some(t));
        assert_eq!(unix_time(&json!(t)), Some(t));
        assert_eq!(unix_time(&json!("2026-11-20T03:15:00+02:00")), None);
        assert_eq!(unix_time(&json!("yesterday")), None);
        assert_eq!(
            crate::context::stamp(unix_time(&json!("2024-02-29T23:59:59Z")).unwrap()),
            "20240229T235959Z"
        );
    }

    #[test]
    fn prune_keeps_tags_and_the_newest() {
        let day = 86_400i64;
        let now = 100 * day;
        let s = |seq: u64, age_days: i64, tags: &[&str]| json!({ "seq": seq, "created_at": now - age_days * day, "tags": tags });
        // seq 10 is 0 days old .. seq 1 is 9 days old; 7 has a tag.
        let list: Vec<Value> = (1..=10u64)
            .map(|q| s(q, 10 - q as i64, if q == 7 { &["keep"] } else { &[] }))
            .collect();
        let seqs = |v: Vec<Value>| {
            v.iter()
                .map(|s| s["seq"].as_u64().unwrap())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            seqs(prune_plan(&list, Some(5), None, now)),
            vec![5, 4, 3, 2, 1]
        );
        assert_eq!(
            seqs(prune_plan(&list, Some(2), None, now)),
            vec![8, 6, 5, 4, 3, 2, 1]
        );
        assert_eq!(
            seqs(prune_plan(&list, None, Some(6 * day as u64), now)),
            vec![3, 2, 1]
        );
        assert_eq!(
            seqs(prune_plan(&list, Some(8), Some(day as u64), now)),
            vec![2, 1]
        );
        // --keep 0 still keeps the newest.
        assert!(!seqs(prune_plan(&list, Some(0), None, now)).contains(&10));
        // The newest is kept even when it is old.
        let old = vec![s(1, 50, &[])];
        assert!(prune_plan(&old, None, Some(day as u64), now).is_empty());
    }

    #[test]
    fn user_labels() {
        let l = |k: &str| vec![(k.to_string(), "v".to_string())];
        assert!(check_user_labels(&l("prego.check")).is_err());
        assert!(check_user_labels(&l("prego.x")).is_err());
        assert!(check_user_labels(&l("build")).is_ok());
        let labels = l("build");
        let o = SaveOptions {
            compact: false,
            check: Check::Full,
            labels: &labels,
            message: None,
            tag: None,
        };
        assert_eq!(
            labels_header(&all_labels(&o)),
            r#"{"build":"v","prego.check":"integrity_check:ok"}"#
        );
    }

    #[test]
    fn modes() {
        assert_eq!(
            body_mode(&json!({"encryption": {"mode": "none"}})).as_deref(),
            Some("none")
        );
        assert_eq!(
            body_mode(&json!({"snapshot": {"enc_mode": "envelope_v1"}})).as_deref(),
            Some("envelope_v1")
        );
        assert_eq!(body_mode(&json!({})), None);
        assert_eq!(require_plain(Some("envelope_v1")), Err(EXIT_ENCRYPTION));
        assert_eq!(require_plain(Some("none")), Ok(()));
    }
}
