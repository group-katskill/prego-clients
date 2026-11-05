//! A small Prego Go host and STS on 127.0.0.1, for the `prego go` tests.
//!
//! It follows the publish contract: Bearer registry tokens from its STS, the single `PUT` with
//! `X-Prego-Go-H1` and `X-Prego-Go-Origin`, and the chunked session (exact part sizes, `409` for a part that
//! was already sent, `X-Prego-Go-Received`). It reads each zip it gets and computes the h1 and the go.mod h1
//! itself, so the tests check the zip, not only the client's own numbers. Tests can inject faults.
//!
//! It also serves the npm routes of one namespace (`/t/acme/default/@scope%2fname`): packuments, tarballs
//! and publish, with the same Bearer check, for the `prego setup npm` and live npm and pnpm tests.

#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// One request that the server received.
#[derive(Debug, Clone)]
pub struct Seen {
    pub method: String,
    pub target: String,
    pub headers: HashMap<String, String>,
    pub body_len: usize,
}

#[derive(Default)]
pub struct Session {
    pub module: String,
    pub version: String,
    pub size: u64,
    pub h1: String,
    pub parts: BTreeMap<u64, Vec<u8>>,
    pub aborted: bool,
}

#[derive(Default)]
pub struct State {
    pub requests: Vec<Seen>,
    /// Form fields of each STS request.
    pub sts: Vec<HashMap<String, String>>,
    tokens: HashSet<String>,
    pub admin_ok: bool,
    /// Published zips by (module, version).
    pub zips: HashMap<(String, String), Vec<u8>>,
    pub sessions: HashMap<String, Session>,
    pub chunk_bytes: u64,
    /// Scripted answers: the next request with this method gets this status and body.
    pub fail_next: HashMap<String, Vec<(u16, String)>>,
    /// Store this part, then close the connection with no answer (one time).
    pub drop_after_part: Option<u64>,
    /// Answer `503` to the first try of this part.
    pub fail_part_once: Option<u64>,
    /// Answer this h1 instead of the computed one.
    pub wrong_h1: bool,
    /// The `expires_in` of registry tokens (default 900). When set, a token older than this gets `401`.
    pub expires_in: Option<u64>,
    /// When each registry token was issued.
    issued: HashMap<String, Instant>,
    /// The number of `401` answers for a token that was too old.
    pub too_old: usize,
    /// Wait this long before the answer to each `PATCH`.
    pub patch_delay: Option<Duration>,
    /// The port, for tarball URLs.
    pub port: u16,
    /// The npm scopes that the admin API returns.
    pub npm_scopes: Vec<String>,
    /// npm packages: name, then version, then (manifest, tarball).
    pub npm: HashMap<String, BTreeMap<String, (Value, Vec<u8>)>>,
}

pub struct MockGo {
    pub port: u16,
    pub state: Arc<Mutex<State>>,
}

impl MockGo {
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(Mutex::new(State {
            chunk_bytes: 40 << 20,
            port,
            ..State::default()
        }));
        let st = Arc::clone(&state);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let st = Arc::clone(&st);
                thread::spawn(move || serve(stream, &st));
            }
        });
        MockGo { port, state }
    }

    pub fn host(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    pub fn sts_url(&self) -> String {
        format!("http://127.0.0.1:{}/v1/sts/token/e/k7mq", self.port)
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut State) -> R) -> R {
        f(&mut self.state.lock().unwrap())
    }

    pub fn requests(&self) -> Vec<Seen> {
        self.with(|s| s.requests.clone())
    }

    pub fn sts_count(&self) -> usize {
        self.with(|s| s.sts.len())
    }
}

struct Req {
    method: String,
    path: String,
    query: HashMap<String, String>,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

struct Res {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    /// Close the connection with no answer.
    drop: bool,
}

impl Res {
    fn new(status: u16) -> Self {
        Res {
            status,
            headers: Vec::new(),
            body: Vec::new(),
            drop: false,
        }
    }
    fn text(status: u16, t: &str) -> Self {
        let mut r = Res::new(status);
        r.body = t.as_bytes().to_vec();
        r.headers
            .push(("Content-Type".into(), "text/plain; charset=utf-8".into()));
        r
    }
    fn json(status: u16, v: Value) -> Self {
        let mut r = Res::new(status);
        r.body = v.to_string().into_bytes();
        r.headers
            .push(("Content-Type".into(), "application/json".into()));
        r
    }
}

fn serve(stream: TcpStream, st: &Mutex<State>) {
    let mut reader = BufReader::new(stream);
    loop {
        let Some(req) = read(&mut reader) else {
            return;
        };
        let res = {
            let mut s = st.lock().unwrap();
            s.requests.push(Seen {
                method: req.method.clone(),
                target: format!(
                    "{}{}",
                    req.path,
                    if req.query.is_empty() {
                        String::new()
                    } else {
                        let mut q: Vec<String> =
                            req.query.iter().map(|(k, v)| format!("{k}={v}")).collect();
                        q.sort();
                        format!("?{}", q.join("&"))
                    }
                ),
                headers: req.headers.clone(),
                body_len: req.body.len(),
            });
            handle(&mut s, &req)
        };
        if res.drop {
            return;
        }
        let stream = reader.get_mut();
        let mut head = format!(
            "HTTP/1.1 {} Mock\r\nContent-Length: {}\r\n",
            res.status,
            res.body.len()
        );
        for (n, v) in &res.headers {
            head.push_str(&format!("{n}: {v}\r\n"));
        }
        head.push_str("\r\n");
        if stream.write_all(head.as_bytes()).is_err() || stream.write_all(&res.body).is_err() {
            return;
        }
        let _ = stream.flush();
    }
}

fn read(reader: &mut BufReader<TcpStream>) -> Option<Req> {
    let mut line = String::new();
    if reader.read_line(&mut line).ok()? == 0 {
        return None;
    }
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let mut headers = HashMap::new();
    loop {
        let mut h = String::new();
        reader.read_line(&mut h).ok()?;
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        let (n, v) = h.split_once(':')?;
        headers.insert(n.trim().to_ascii_lowercase(), v.trim().to_string());
    }
    let len: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0; len];
    reader.read_exact(&mut body).ok()?;
    let (path, q) = target.split_once('?').unwrap_or((&target, ""));
    let query = q
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_string(), decode(v)))
        .collect();
    Some(Req {
        method,
        path: path.to_string(),
        query,
        headers,
        body,
    })
}

fn decode(v: &str) -> String {
    let b = v.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                let h = std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(h, 16) {
                    Ok(x) => {
                        out.push(x);
                        i += 2;
                    }
                    Err(_) => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn handle(s: &mut State, req: &Req) -> Res {
    if let Some(list) = s.fail_next.get_mut(&req.method) {
        if !list.is_empty() {
            let (status, body) = list.remove(0);
            return Res::text(status, &body);
        }
    }
    // Registry tokens only on the edge code path; the bare path serves admin tokens only (as the STS).
    if req.method == "POST" && req.path == "/v1/sts/token/e/k7mq" {
        return sts(s, req);
    }
    if req.method == "POST" && req.path == "/v1/sts/token" {
        if form(&req.body).get("audience").map(String::as_str) == Some("prego-admin") {
            return sts(s, req);
        }
        return Res::json(
            400,
            json!({"error": "invalid_request", "error_description": "this client uses an old token URL"}),
        );
    }
    if req.path.starts_with("/v1/admin/") {
        return admin(s, req);
    }
    if let Some(rest) = req.path.strip_prefix("/t/acme/default/") {
        if !rest.starts_with("-/") {
            return npm(s, req, rest);
        }
    }
    let Some(rest) = req.path.strip_prefix("/t/acme/default/-/") else {
        return Res::text(404, "not found");
    };
    let auth = req
        .headers
        .get("authorization")
        .cloned()
        .unwrap_or_default();
    let token = auth.strip_prefix("Bearer ").unwrap_or_default();
    if !s.tokens.contains(token) {
        return Res::text(401, "prego: run \"prego setup go\"");
    }
    if let (Some(max), Some(at)) = (s.expires_in, s.issued.get(token)) {
        if at.elapsed() > Duration::from_secs(max) {
            s.too_old += 1;
            return Res::text(401, "token older than this grant allows; get a new token");
        }
    }
    if let Some(p) = rest.strip_prefix("publish/") {
        if req.method == "PUT" {
            if let Some((m, v)) = p.strip_suffix(".zip").and_then(|x| x.split_once("/@v/")) {
                return single_put(s, req, &unescape(m), &unescape(v));
            }
        }
        if req.method == "POST" {
            if let Some((m, v)) = p
                .strip_suffix("/uploads")
                .and_then(|x| x.split_once("/@v/"))
            {
                return start_session(s, req, &unescape(m), &unescape(v));
            }
        }
        return Res::text(400, "bad publish route");
    }
    if let Some(id) = rest.strip_prefix("uploads/") {
        return session(s, req, id);
    }
    Res::text(404, "not found")
}

fn unescape(s: &str) -> String {
    let mut out = String::new();
    let mut up = false;
    for c in s.chars() {
        if c == '!' {
            up = true;
        } else if up {
            out.push(c.to_ascii_uppercase());
            up = false;
        } else {
            out.push(c);
        }
    }
    out
}

fn form(body: &[u8]) -> HashMap<String, String> {
    String::from_utf8_lossy(body)
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_string(), decode(v)))
        .collect()
}

fn sts(s: &mut State, req: &Req) -> Res {
    let f = form(&req.body);
    s.sts.push(f.clone());
    if f.get("audience").map(String::as_str) == Some("prego-admin") {
        if !s.admin_ok {
            return Res::json(400, json!({"error": "invalid_scope"}));
        }
        s.tokens.insert("admintok".into());
        return Res::json(200, json!({"access_token": "admintok", "expires_in": 900}));
    }
    let token = format!("regtok-{}", s.sts.len());
    s.tokens.insert(token.clone());
    s.issued.insert(token.clone(), Instant::now());
    let expires_in = s.expires_in.unwrap_or(900);
    Res::json(
        200,
        json!({"access_token": token, "token_type": "Bearer", "expires_in": expires_in}),
    )
}

fn admin(_s: &mut State, req: &Req) -> Res {
    if req.headers.get("authorization").map(String::as_str) != Some("Bearer admintok") {
        return Res::text(401, "no");
    }
    if req.path == "/v1/admin/tenants/acme/go/prefixes" {
        return Res::json(
            200,
            json!({"items": [
                {"id": "gmp_1", "prefix": "go.acme.com", "created_at": "2026-11-04T00:00:00Z"},
                {"id": "gmp_2", "prefix": "github.com/acme", "created_at": "2026-11-04T00:00:00Z"}
            ]}),
        );
    }
    if req.path == "/v1/admin/tenants/acme/npm/scopes" {
        let items: Vec<Value> = _s
            .npm_scopes
            .iter()
            .enumerate()
            .map(|(i, sc)| json!({"id": format!("scp_{i}"), "scope": sc}))
            .collect();
        return Res::json(200, json!({ "items": items }));
    }
    Res::text(404, "no")
}

/// A package tarball: `package/package.json` and `package/index.js`.
pub fn npm_tarball(name: &str, version: &str) -> Vec<u8> {
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    {
        let mut tar = tar::Builder::new(&mut gz);
        let files = [
            (
                "package/package.json",
                json!({"name": name, "version": version, "main": "index.js"}).to_string(),
            ),
            (
                "package/index.js",
                format!("module.exports = \"{name}@{version}\";\n"),
            ),
        ];
        for (path, body) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o644);
            h.set_mtime(0);
            h.set_cksum();
            tar.append_data(&mut h, path, body.as_bytes()).unwrap();
        }
        tar.finish().unwrap();
    }
    gz.finish().unwrap()
}

fn integrity(data: &[u8]) -> String {
    let d = sha2::Sha512::digest(data);
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(d)
    )
}

/// Adds a version of an npm package, as a publish would.
pub fn add_npm(s: &mut State, name: &str, version: &str) {
    let tgz = npm_tarball(name, version);
    let manifest = json!({"name": name, "version": version, "main": "index.js"});
    s.npm
        .entry(name.to_string())
        .or_default()
        .insert(version.to_string(), (manifest, tgz));
}

fn npm(s: &mut State, req: &Req, rest: &str) -> Res {
    let auth = req
        .headers
        .get("authorization")
        .cloned()
        .unwrap_or_default();
    let token = auth.strip_prefix("Bearer ").unwrap_or_default();
    if token == "${PREGO_NPM_TOKEN}" {
        return Res::json(
            401,
            json!({"error": "PREGO_NPM_TOKEN is not set in this shell"}),
        );
    }
    if token == "admintok" || !s.tokens.contains(token) {
        return Res::json(
            401,
            json!({"error": "Prego needs a registry token from the STS. Run `prego setup npm`"}),
        );
    }
    let rest = rest.replace("%2f", "/").replace("%2F", "/");
    if let Some((name, file)) = rest.split_once("/-/") {
        let short = name.rsplit('/').next().unwrap_or_default();
        let version = file
            .strip_prefix(&format!("{short}-"))
            .and_then(|f| f.strip_suffix(".tgz"));
        let found = version.and_then(|v| s.npm.get(name).and_then(|p| p.get(v)));
        return match (req.method.as_str(), found) {
            ("GET", Some((_, tgz))) => {
                let mut r = Res::new(200);
                r.body = tgz.clone();
                r.headers
                    .push(("Content-Type".into(), "application/octet-stream".into()));
                r
            }
            _ => Res::json(404, json!({"error": "not found"})),
        };
    }
    let name = rest.as_str();
    if !name.starts_with('@') {
        return Res::json(404, json!({"error": "Prego serves scoped packages only"}));
    }
    match req.method.as_str() {
        "GET" => {
            let Some(pkg) = s.npm.get(name) else {
                return Res::json(404, json!({"error": "not found"}));
            };
            let short = name.rsplit('/').next().unwrap_or_default();
            let mut versions = serde_json::Map::new();
            let mut latest = String::new();
            for (v, (manifest, tgz)) in pkg {
                let mut m = manifest.clone();
                m["dist"] = json!({
                    "tarball": format!("http://127.0.0.1:{}/t/acme/default/{name}/-/{short}-{v}.tgz", s.port),
                    "integrity": integrity(tgz),
                });
                versions.insert(v.clone(), m);
                latest = v.clone();
            }
            Res::json(
                200,
                json!({"name": name, "dist-tags": {"latest": latest}, "versions": versions}),
            )
        }
        "PUT" => {
            let Ok(body) = serde_json::from_slice::<Value>(&req.body) else {
                return Res::json(400, json!({"error": "bad JSON"}));
            };
            let Some((version, manifest)) = body["versions"]
                .as_object()
                .and_then(|v| v.iter().next())
                .map(|(k, v)| (k.clone(), v.clone()))
            else {
                return Res::json(400, json!({"error": "no version"}));
            };
            let Some(data) = body["_attachments"]
                .as_object()
                .and_then(|a| a.values().next())
                .and_then(|a| a["data"].as_str())
            else {
                return Res::json(400, json!({"error": "no attachment"}));
            };
            let Ok(tgz) = base64::engine::general_purpose::STANDARD.decode(data) else {
                return Res::json(400, json!({"error": "bad base64"}));
            };
            if manifest["dist"]["integrity"].as_str() != Some(integrity(&tgz).as_str()) {
                return Res::json(400, json!({"error": "integrity does not match"}));
            }
            let pkg = s.npm.entry(name.to_string()).or_default();
            if pkg.contains_key(&version) {
                return Res::json(
                    403,
                    json!({"error": format!("cannot publish over previously published version {version}")}),
                );
            }
            let mut m = manifest;
            if let Some(o) = m.as_object_mut() {
                o.remove("dist");
                o.retain(|k, _| !k.starts_with('_'));
            }
            pkg.insert(version, (m, tgz));
            Res::json(200, json!({"ok": true}))
        }
        _ => Res::json(405, json!({"error": "method not allowed"})),
    }
}

/// Computes (h1, mod_h1) of a module zip, and checks its entry names.
pub fn check_zip(zip: &[u8], module: &str, version: &str) -> Result<(String, String), String> {
    let prefix = format!("{module}@{version}/");
    let entries = read_entries(zip)?;
    let mut files = Vec::new();
    let mut go_mod = None;
    for (name, content) in &entries {
        let rel = name
            .strip_prefix(&prefix)
            .ok_or_else(|| format!("entry {name} is outside {prefix}"))?;
        if rel == "go.mod" {
            go_mod = Some(content.clone());
        }
        files.push((name.clone(), Sha256::digest(content)));
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let mut summary = String::new();
    for (n, d) in &files {
        let hex: String = d.iter().map(|b| format!("{b:02x}")).collect();
        summary.push_str(&format!("{hex}  {n}\n"));
    }
    let b64 = base64::engine::general_purpose::STANDARD;
    let h1 = format!("h1:{}", b64.encode(Sha256::digest(summary.as_bytes())));
    let go_mod = go_mod.ok_or("no go.mod")?;
    let hex: String = Sha256::digest(&go_mod)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mod_h1 = format!(
        "h1:{}",
        b64.encode(Sha256::digest(format!("{hex}  go.mod\n").as_bytes()))
    );
    Ok((h1, mod_h1))
}

fn read_entries(data: &[u8]) -> Result<Vec<(String, Vec<u8>)>, String> {
    let u16_at = |i: usize| u16::from_le_bytes([data[i], data[i + 1]]) as usize;
    let u32_at =
        |i: usize| u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]) as usize;
    if data.len() < 22 {
        return Err("too short".into());
    }
    let eocd = (0..=data.len() - 22)
        .rev()
        .find(|&i| u32_at(i) == 0x0605_4b50)
        .ok_or("no end record")?;
    let count = u16_at(eocd + 10);
    let mut at = u32_at(eocd + 16);
    let mut out = Vec::new();
    for _ in 0..count {
        if u32_at(at) != 0x0201_4b50 {
            return Err("bad central directory".into());
        }
        let method = u16_at(at + 10);
        let crc = u32_at(at + 16) as u32;
        let packed = u32_at(at + 20);
        let size = u32_at(at + 24);
        let n = u16_at(at + 28);
        let name = String::from_utf8(data[at + 46..at + 46 + n].to_vec()).map_err(|_| "name")?;
        let local = u32_at(at + 42);
        at += 46 + n + u16_at(at + 30) + u16_at(at + 32);
        if u32_at(local) != 0x0403_4b50 {
            return Err("bad local header".into());
        }
        let ln = u16_at(local + 26);
        if data[local + 30..local + 30 + ln] != *name.as_bytes() {
            return Err("local and central names differ".into());
        }
        let start = local + 30 + ln + u16_at(local + 28);
        let raw = &data[start..start + packed];
        let content = match method {
            0 => raw.to_vec(),
            8 => {
                let mut v = Vec::new();
                flate2::read::DeflateDecoder::new(raw)
                    .read_to_end(&mut v)
                    .map_err(|e| e.to_string())?;
                v
            }
            m => return Err(format!("method {m}")),
        };
        if content.len() != size || crc32fast::hash(&content) != crc {
            return Err(format!("size or CRC of {name} is wrong"));
        }
        out.push((name, content));
    }
    Ok(out)
}

fn answer(s: &State, module: &str, version: &str, zip: &[u8]) -> Res {
    match check_zip(zip, module, version) {
        Ok((h1, mod_h1)) => {
            let h1 = if s.wrong_h1 {
                "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string()
            } else {
                h1
            };
            Res::json(
                201,
                json!({"module": module, "version": version, "h1": h1, "mod_h1": mod_h1}),
            )
        }
        Err(e) => Res::text(400, &format!("bad zip: {e}")),
    }
}

fn single_put(s: &mut State, req: &Req, module: &str, version: &str) -> Res {
    if !req.headers.contains_key("content-length") {
        return Res::text(411, "length required");
    }
    if req.body.len() > 95 << 20 {
        return Res::text(413, "too large");
    }
    if let Some(origin) = req.headers.get("x-prego-go-origin") {
        let v: Value = serde_json::from_str(origin).unwrap_or(Value::Null);
        let ok = v.as_object().is_some_and(|o| {
            o.keys()
                .all(|k| ["VCS", "Hash", "Ref", "Subdir"].contains(&k.as_str()))
        }) && origin.len() <= 1024;
        if !ok {
            return Res::text(400, "bad origin");
        }
    }
    if s.zips.contains_key(&(module.into(), version.into())) {
        return Res::text(
            409,
            "version was already published; Go versions are immutable",
        );
    }
    let res = answer(s, module, version, &req.body);
    if let Some(h) = req.headers.get("x-prego-go-h1") {
        if res.status == 201
            && !String::from_utf8_lossy(&res.body).contains(h.as_str())
            && !s.wrong_h1
        {
            return Res::text(400, "h1 mismatch");
        }
    }
    if res.status == 201 {
        s.zips
            .insert((module.into(), version.into()), req.body.clone());
    }
    res
}

fn start_session(s: &mut State, req: &Req, module: &str, version: &str) -> Res {
    let v: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
    let (Some(size), Some(h1)) = (v["size"].as_u64(), v["h1"].as_str()) else {
        return Res::text(400, "need size and h1");
    };
    let id = format!("gup_{}", s.sessions.len() + 1);
    s.sessions.insert(
        id.clone(),
        Session {
            module: module.into(),
            version: version.into(),
            size,
            h1: h1.into(),
            ..Session::default()
        },
    );
    Res::json(201, json!({"upload_id": id, "chunk_bytes": s.chunk_bytes}))
}

fn session(s: &mut State, req: &Req, id: &str) -> Res {
    let chunk = s.chunk_bytes;
    let drop_part = s.drop_after_part;
    if !s.sessions.contains_key(id) {
        return Res::text(404, "no such upload");
    }
    match req.method.as_str() {
        "PATCH" => {
            if let Some(d) = s.patch_delay {
                thread::sleep(d);
            }
            let Some(n) = req.query.get("part").and_then(|p| p.parse::<u64>().ok()) else {
                return Res::text(400, "need part");
            };
            if s.fail_part_once == Some(n) {
                s.fail_part_once = None;
                return Res::text(503, "try again");
            }
            let Some(sess) = s.sessions.get_mut(id) else {
                return Res::text(404, "no such upload");
            };
            if sess.parts.contains_key(&n) {
                return Res::text(409, &format!("part {n} was already sent"));
            }
            let parts = sess.size.div_ceil(chunk);
            let want = if n < parts {
                chunk
            } else {
                sess.size - chunk * (parts - 1)
            };
            if n == 0 || n > parts || req.body.len() as u64 != want {
                return Res::text(400, &format!("part {n} must have {want} bytes"));
            }
            sess.parts.insert(n, req.body.clone());
            let total: usize = sess.parts.values().map(Vec::len).sum();
            if drop_part == Some(n) {
                s.drop_after_part = None;
                let mut r = Res::new(204);
                r.drop = true;
                return r;
            }
            let mut r = Res::new(204);
            r.headers
                .push(("X-Prego-Go-Received".into(), total.to_string()));
            r
        }
        "PUT" => {
            let sess = &s.sessions[id];
            let zip: Vec<u8> = sess.parts.values().flatten().copied().collect();
            if zip.len() as u64 != sess.size {
                return Res::text(
                    400,
                    &format!("upload is incomplete: {} of {} bytes", zip.len(), sess.size),
                );
            }
            let (m, v, h1) = (sess.module.clone(), sess.version.clone(), sess.h1.clone());
            let res = answer(s, &m, &v, &zip);
            if res.status == 201 && !String::from_utf8_lossy(&res.body).contains(&h1) && !s.wrong_h1
            {
                return Res::text(400, "h1 mismatch");
            }
            if res.status == 201 {
                s.zips.insert((m, v), zip);
            }
            res
        }
        "DELETE" => {
            if let Some(sess) = s.sessions.get_mut(id) {
                sess.aborted = true;
            }
            Res::new(204)
        }
        _ => Res::text(405, "method"),
    }
}
