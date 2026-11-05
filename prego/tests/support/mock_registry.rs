//! A small OCI registry and token realm on 127.0.0.1, for the `prego oci push` tests.
//!
//! It keeps blobs and manifests in memory and checks the rules of the Prego registry: Bearer tokens from
//! its realm, `OCI-Chunk-Min-Length`, equal part sizes except the last (else `416`), `Content-Range`, the
//! digest on the final `PUT`, and that a manifest points only to known blobs and manifests. Tests can
//! inject faults.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use serde_json::Value;
use sha2::{Digest, Sha256};

/// The realm of the repositories: the edge code of the repository's tenant (`State::repo_code`).
pub const REALM_PREFIX: &str = "/v1/oci/token/e/";
/// The realm without a code, as in the challenge of `GET /v2/` (no repository).
pub const BARE_REALM: &str = "/v1/oci/token";

pub fn sha256(b: &[u8]) -> String {
    let d = Sha256::digest(b);
    let mut s = String::from("sha256:");
    for x in d {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// One request that the registry received.
#[derive(Debug, Clone)]
pub struct Seen {
    pub method: String,
    pub target: String,
    pub content_length: Option<u64>,
    pub content_range: Option<String>,
    pub chunked: bool,
    pub authorization: Option<String>,
}

#[derive(Default)]
struct Session {
    name: String,
    data: Vec<u8>,
    part: Option<u64>,
    short_seen: bool,
}

#[derive(Default)]
pub struct State {
    /// Blobs by (repository, digest).
    pub blobs: HashMap<(String, String), Vec<u8>>,
    /// Manifests by (repository, digest), and tags by (repository, tag) to digest.
    pub manifests: HashMap<(String, String), (String, Vec<u8>)>,
    pub tags: HashMap<(String, String), String>,
    sessions: HashMap<u64, Session>,
    next_id: u64,
    tokens: HashSet<String>,
    pub token_requests: usize,
    pub requests: Vec<Seen>,
    /// `OCI-Chunk-Min-Length` to advertise.
    pub min_chunk: u64,
    /// The realm in the challenge. `None` means this server's own realm.
    pub realm_override: Option<String>,
    /// The edge code in the realm of repository challenges. `k7mq` if not set.
    pub repo_code: Option<String>,
    /// Expected Basic credentials `tenant:secret`.
    pub basic: String,
    // Faults.
    /// PATCH numbers (1-based, over all uploads) that store the bytes but answer 500.
    pub patch_500_after_store: HashSet<usize>,
    /// PATCH numbers that answer 416 without storing.
    pub patch_416: HashSet<usize>,
    /// Request numbers (1-based, `/v2/` only, with a token) that answer 401 and forget all tokens.
    pub revoke_at: HashSet<usize>,
    /// Request numbers (`/v2/` only) that answer 429 with `Retry-After: 1`.
    pub throttle_at: HashSet<usize>,
    patches: usize,
    v2_requests: usize,
}

pub struct MockRegistry {
    pub port: u16,
    pub state: Arc<Mutex<State>>,
}

impl MockRegistry {
    pub fn start(basic: &str, min_chunk: u64) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(Mutex::new(State {
            min_chunk,
            basic: basic.to_string(),
            ..State::default()
        }));
        let st = Arc::clone(&state);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let st = Arc::clone(&st);
                thread::spawn(move || serve(stream, port, &st));
            }
        });
        MockRegistry { port, state }
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

    pub fn blob(&self, repo: &str, digest: &str) -> Option<Vec<u8>> {
        self.with(|s| s.blobs.get(&(repo.into(), digest.into())).cloned())
    }

    pub fn tag(&self, repo: &str, tag: &str) -> Option<(String, String, Vec<u8>)> {
        self.with(|s| {
            let d = s.tags.get(&(repo.into(), tag.into()))?.clone();
            let (mt, body) = s.manifests.get(&(repo.into(), d.clone()))?.clone();
            Some((d, mt, body))
        })
    }

    pub fn requests(&self) -> Vec<Seen> {
        self.with(|s| s.requests.clone())
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
}

impl Res {
    fn new(status: u16) -> Self {
        Res {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }
    fn h(mut self, n: &str, v: impl Into<String>) -> Self {
        self.headers.push((n.into(), v.into()));
        self
    }
    fn json(mut self, v: &str) -> Self {
        self.body = v.as_bytes().to_vec();
        self.h("Content-Type", "application/json")
    }
    fn err(status: u16, code: &str, msg: &str) -> Self {
        Res::new(status).json(&format!(
            r#"{{"errors":[{{"code":"{code}","message":"{msg}"}}]}}"#
        ))
    }
}

fn serve(stream: TcpStream, port: u16, st: &Mutex<State>) {
    let mut reader = BufReader::new(stream);
    loop {
        let Some((req, seen)) = read(&mut reader) else {
            return;
        };
        let res = {
            let mut s = st.lock().unwrap();
            s.requests.push(seen);
            handle(&mut s, port, &req)
        };
        let stream = reader.get_mut();
        let mut head = format!("HTTP/1.1 {} Mock\r\n", res.status);
        let has_len = res.headers.iter().any(|(n, _)| n == "Content-Length");
        if !has_len {
            head.push_str(&format!("Content-Length: {}\r\n", res.body.len()));
        }
        for (n, v) in &res.headers {
            head.push_str(&format!("{n}: {v}\r\n"));
        }
        head.push_str("\r\n");
        if stream.write_all(head.as_bytes()).is_err() {
            return;
        }
        if req.method != "HEAD" && stream.write_all(&res.body).is_err() {
            return;
        }
        let _ = stream.flush();
    }
}

fn read(reader: &mut BufReader<TcpStream>) -> Option<(Req, Seen)> {
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
    let chunked = headers
        .get("transfer-encoding")
        .is_some_and(|v| v.contains("chunked"));
    let len = headers
        .get("content-length")
        .and_then(|v| v.parse::<u64>().ok());
    let mut body = Vec::new();
    if chunked {
        // Read it, so the connection stays usable, but the tests check that it never happens.
        loop {
            let mut size = String::new();
            reader.read_line(&mut size).ok()?;
            let n = usize::from_str_radix(size.trim(), 16).ok()?;
            let mut chunk = vec![0; n + 2];
            reader.read_exact(&mut chunk).ok()?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
        }
    } else if let Some(n) = len {
        body = vec![0; n as usize];
        reader.read_exact(&mut body).ok()?;
    }
    let (path, q) = target.split_once('?').unwrap_or((&target, ""));
    let query = q
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_string(), v.replace("%3A", ":").replace("%2F", "/")))
        .collect();
    let seen = Seen {
        method: method.clone(),
        target: target.clone(),
        content_length: len,
        content_range: headers.get("content-range").cloned(),
        chunked,
        authorization: headers.get("authorization").cloned(),
    };
    Some((
        Req {
            method,
            path: path.to_string(),
            query,
            headers,
            body,
        },
        seen,
    ))
}

fn handle(s: &mut State, port: u16, req: &Req) -> Res {
    if req.path.starts_with(REALM_PREFIX) {
        return realm(s, req);
    }
    if req.path == BARE_REALM {
        // The bare realm serves only the scope-less login check.
        return Res::err(
            400,
            "invalid_request",
            "this token URL does not issue repository tokens",
        );
    }
    if !req.path.starts_with("/v2/") {
        return Res::new(404);
    }
    let auth = req
        .headers
        .get("authorization")
        .and_then(|a| a.strip_prefix("Bearer "))
        .map(str::to_string);
    let code = s.repo_code.clone().unwrap_or_else(|| "k7mq".into());
    let realm = s.realm_override.clone().unwrap_or_else(|| {
        if req.path == "/v2/" {
            format!("http://127.0.0.1:{port}{BARE_REALM}")
        } else {
            format!("http://127.0.0.1:{port}{REALM_PREFIX}{code}")
        }
    });
    let challenge = || {
        Res::err(401, "UNAUTHORIZED", "authentication required").h(
            "WWW-Authenticate",
            format!(r#"Bearer realm="{realm}",service="127.0.0.1:{port}""#),
        )
    };
    let Some(token) = auth.filter(|t| s.tokens.contains(t)) else {
        return challenge();
    };
    let _ = token;
    s.v2_requests += 1;
    let n = s.v2_requests;
    if s.revoke_at.remove(&n) {
        s.tokens.clear();
        return challenge();
    }
    if s.throttle_at.remove(&n) {
        return Res::err(429, "TOOMANYREQUESTS", "slow down").h("Retry-After", "1");
    }
    if req.path == "/v2/" {
        return Res::new(200).json("{}");
    }
    route(s, req)
}

fn realm(s: &mut State, req: &Req) -> Res {
    use base64_lite::decode;
    let ok = req
        .headers
        .get("authorization")
        .and_then(|a| a.strip_prefix("Basic "))
        .and_then(decode)
        .is_some_and(|c| c == s.basic);
    if !ok {
        return Res::err(401, "UNAUTHORIZED", "refused");
    }
    s.token_requests += 1;
    let t = format!("reg-token-{}", s.token_requests);
    s.tokens.insert(t.clone());
    Res::new(200).json(&format!(
        r#"{{"token":"{t}","access_token":"{t}","expires_in":900}}"#
    ))
}

fn route(s: &mut State, req: &Req) -> Res {
    let p = &req.path["/v2/".len()..];
    if let Some((name, digest)) = p.split_once("/blobs/uploads/") {
        let name = name.to_string();
        if digest.is_empty() {
            return start_upload(s, &name, req);
        }
        let id: u64 = match digest.parse() {
            Ok(i) => i,
            Err(_) => return Res::err(404, "BLOB_UPLOAD_UNKNOWN", "bad id"),
        };
        return upload(s, &name, id, req);
    }
    if let Some((name, digest)) = p.split_once("/blobs/") {
        return match req.method.as_str() {
            "HEAD" | "GET" => match s.blobs.get(&(name.into(), digest.into())) {
                Some(b) => Res::new(200)
                    .h("Content-Length", b.len().to_string())
                    .h("Docker-Content-Digest", digest),
                None => Res::err(404, "BLOB_UNKNOWN", "blob unknown"),
            },
            _ => Res::new(405),
        };
    }
    if let Some((name, reference)) = p.split_once("/manifests/") {
        if req.method == "PUT" {
            return put_manifest(s, name, reference, req);
        }
        return Res::new(405);
    }
    Res::new(404)
}

fn location(name: &str, id: u64) -> String {
    format!("/v2/{name}/blobs/uploads/{id}?_state=s{id}")
}

fn start_upload(s: &mut State, name: &str, req: &Req) -> Res {
    if let (Some(d), Some(from)) = (req.query.get("mount"), req.query.get("from")) {
        if let Some(b) = s.blobs.get(&(from.clone(), d.clone())).cloned() {
            s.blobs.insert((name.into(), d.clone()), b);
            return Res::new(201).h("Location", format!("/v2/{name}/blobs/{d}"));
        }
    }
    s.next_id += 1;
    let id = s.next_id;
    s.sessions.insert(
        id,
        Session {
            name: name.into(),
            ..Session::default()
        },
    );
    Res::new(202)
        .h("Location", location(name, id))
        .h("Range", "0-0")
        .h("OCI-Chunk-Min-Length", s.min_chunk.to_string())
}

fn range(n: usize) -> String {
    format!("0-{}", n.saturating_sub(1))
}

fn upload(s: &mut State, name: &str, id: u64, req: &Req) -> Res {
    let min = s.min_chunk;
    match req.method.as_str() {
        "PATCH" => {
            s.patches += 1;
            let n = s.patches;
            if s.patch_416.remove(&n) {
                return Res::err(416, "BLOB_UPLOAD_INVALID", "injected");
            }
            let fail_after = s.patch_500_after_store.remove(&n);
            let Some(sess) = s.sessions.get_mut(&id) else {
                return Res::err(404, "BLOB_UPLOAD_UNKNOWN", "no session");
            };
            let len = req.body.len() as u64;
            let start = sess.data.len() as u64;
            if let Some(cr) = req.headers.get("content-range") {
                let want = format!("{}-{}", start, start + len - 1);
                if cr != &want {
                    return Res::err(416, "BLOB_UPLOAD_INVALID", "range")
                        .h("Range", range(sess.data.len()));
                }
            } else if start != 0 {
                return Res::err(416, "BLOB_UPLOAD_INVALID", "range needed");
            }
            if sess.short_seen {
                return Res::err(416, "BLOB_UPLOAD_INVALID", "part after the last part");
            }
            match sess.part {
                None => sess.part = Some(len),
                Some(p) if len > p => {
                    return Res::err(416, "BLOB_UPLOAD_INVALID", "part size changed")
                }
                Some(p) if len < p => sess.short_seen = true,
                Some(_) => {}
            }
            if len < min {
                sess.short_seen = true;
            }
            sess.data.extend_from_slice(&req.body);
            if fail_after {
                return Res::err(500, "UNKNOWN", "injected");
            }
            Res::new(202)
                .h("Location", location(name, id))
                .h("Range", range(sess.data.len()))
        }
        "GET" => match s.sessions.get(&id) {
            Some(sess) => Res::new(204)
                .h("Location", location(name, id))
                .h("Range", range(sess.data.len())),
            None => Res::err(404, "BLOB_UPLOAD_UNKNOWN", "no session"),
        },
        "DELETE" => {
            s.sessions.remove(&id);
            Res::new(204)
        }
        "PUT" => {
            let Some(mut sess) = s.sessions.remove(&id) else {
                return Res::err(404, "BLOB_UPLOAD_UNKNOWN", "no session");
            };
            sess.data.extend_from_slice(&req.body);
            let Some(d) = req.query.get("digest") else {
                return Res::err(400, "DIGEST_INVALID", "no digest");
            };
            if sha256(&sess.data) != *d {
                return Res::err(400, "DIGEST_INVALID", "digest mismatch");
            }
            s.blobs.insert((sess.name, d.clone()), sess.data);
            Res::new(201)
                .h("Location", format!("/v2/{name}/blobs/{d}"))
                .h("Docker-Content-Digest", d.clone())
        }
        _ => Res::new(405),
    }
}

fn put_manifest(s: &mut State, name: &str, reference: &str, req: &Req) -> Res {
    let digest = sha256(&req.body);
    if reference.starts_with("sha256:") && reference != digest {
        return Res::err(400, "DIGEST_INVALID", "manifest digest");
    }
    let Ok(v) = serde_json::from_slice::<Value>(&req.body) else {
        return Res::err(400, "MANIFEST_INVALID", "not JSON");
    };
    let mt = req.headers.get("content-type").cloned().unwrap_or_default();
    if let Some(children) = v.get("manifests").and_then(Value::as_array) {
        for c in children {
            let cd = c["digest"].as_str().unwrap_or("");
            if !s.manifests.contains_key(&(name.into(), cd.into())) {
                return Res::err(400, "MANIFEST_BLOB_UNKNOWN", "child manifest unknown");
            }
        }
    } else {
        let mut refs = vec![v["config"]["digest"].as_str().unwrap_or("").to_string()];
        for l in v["layers"].as_array().cloned().unwrap_or_default() {
            refs.push(l["digest"].as_str().unwrap_or("").to_string());
        }
        for r in refs {
            if !s.blobs.contains_key(&(name.into(), r.clone())) {
                return Res::err(400, "MANIFEST_BLOB_UNKNOWN", "blob unknown");
            }
        }
    }
    s.manifests
        .insert((name.into(), digest.clone()), (mt, req.body.clone()));
    if !reference.starts_with("sha256:") {
        s.tags
            .insert((name.into(), reference.into()), digest.clone());
    }
    Res::new(201)
        .h("Location", format!("/v2/{name}/manifests/{digest}"))
        .h("Docker-Content-Digest", digest)
}

/// A tiny base64 decoder, so the tests need no extra crate.
mod base64_lite {
    pub fn decode(s: &str) -> Option<String> {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = Vec::new();
        let mut buf = 0u32;
        let mut bits = 0;
        for c in s.trim().bytes() {
            if c == b'=' {
                break;
            }
            let v = A.iter().position(|&x| x == c)? as u32;
            buf = (buf << 6) | v;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((buf >> bits) as u8);
                buf &= (1 << bits) - 1;
            }
        }
        String::from_utf8(out).ok()
    }
}
