//! A small OCI Distribution client for pushes: the token challenge, blob checks, mounts, chunked uploads
//! with resume, and manifests.

use std::time::Duration;

use prego_auth::http::{Body, FullResponse, Http};
use prego_auth::oci::{check_challenge_realm, RealmTokens};
use prego_auth::{Config, SubjectToken};
use serde_json::Value;

use super::input::{Blob, Manifest, Source};

/// Largest upload part. The registry body limit is 100 MB.
pub const MAX_PART: u64 = 95 * 1024 * 1024;
/// Upload part size if `--chunk-size` is not given.
pub const DEFAULT_PART: u64 = 64 * 1024 * 1024;
/// Waits before a retry after a network error or a `5xx`.
const RETRY_DELAYS: [Duration; 3] = [
    Duration::from_secs(1),
    Duration::from_secs(4),
    Duration::from_secs(15),
];
/// Retries after `429 TOOMANYREQUESTS`.
const MAX_429_RETRIES: usize = 5;
/// Times one blob upload can resume from the upload status, and times it can start again.
const MAX_RESUMES: usize = 8;
const MAX_RESTARTS: usize = 2;

/// What happened to one blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobResult {
    /// Mounted from the `--from` repository. No bytes sent.
    Mounted,
    /// Uploaded in this many parts.
    Uploaded { parts: u64, part_size: u64 },
}

/// A request body that can be made again for a retry.
enum Payload<'a> {
    Empty,
    Bytes(&'a [u8]),
    Range(&'a Source, u64, u64),
}

/// A push session for one repository.
pub struct Registry<'a> {
    http: &'a Http,
    base: String,
    name: String,
    scopes: Vec<String>,
    tokens: Option<RealmTokens<'a>>,
    sleep: &'a dyn Fn(Duration),
    from: Option<String>,
    requested_part: Option<u64>,
}

impl<'a> Registry<'a> {
    /// Calls `GET /v2/` without a token, then `GET /v2/<name>/tags/list` without a token for the challenge of
    /// the repository, gets a token from that realm and checks it with a second `GET /v2/`. The realm must be
    /// on the host of the configured STS, so the subject token never goes to another host.
    #[allow(clippy::too_many_arguments)]
    pub fn connect(
        http: &'a Http,
        base: &str,
        name: &str,
        config: &'a Config,
        subject: &'a SubjectToken,
        from: Option<&str>,
        requested_part: Option<u64>,
        sleep: &'a dyn Fn(Duration),
    ) -> Result<Self, String> {
        let mut scopes = vec![format!("repository:{name}:pull,push")];
        if let Some(f) = from {
            scopes.push(format!("repository:{f}:pull"));
        }
        let mut reg = Registry {
            http,
            base: base.trim_end_matches('/').to_string(),
            name: name.to_string(),
            scopes,
            tokens: None,
            sleep,
            from: from.map(str::to_string),
            requested_part,
        };
        let url = format!("{}/v2/", reg.base);
        let first = reg.send_once("GET", &url, &[], &Payload::Empty, None)?;
        match first.status {
            200 => return Ok(reg),
            401 => {}
            s => return Err(registry_error("GET /v2/", &first, s)),
        }
        // The `/v2/` challenge names no repository, so its realm has no edge code. The challenge of a
        // repository path has the realm of the repository's tenant.
        let tags = format!("{}/v2/{}/tags/list", reg.base, reg.name);
        let probe = reg.send_once("GET", &tags, &[], &Payload::Empty, None)?;
        if probe.status != 401 {
            return Err(registry_error(
                "GET /v2/<name>/tags/list",
                &probe,
                probe.status,
            ));
        }
        let challenge = probe
            .header("www-authenticate")
            .and_then(parse_bearer_challenge)
            .ok_or("prego: the registry answered 401 without a Bearer challenge")?;
        let realm = check_challenge_realm(config, &challenge.realm)?;
        let host = reg
            .base
            .split_once("://")
            .map(|(_, h)| h.to_string())
            .unwrap_or_default();
        let service = challenge.service.unwrap_or(host);
        reg.tokens = Some(RealmTokens::new(
            http, realm, config, &service, subject, sleep,
        ));
        let check = reg.call("GET", &url, &[], &Payload::Empty, true)?;
        if check.status != 200 {
            return Err(registry_error("GET /v2/", &check, check.status));
        }
        Ok(reg)
    }

    /// Number of realm requests sent.
    pub fn token_requests(&self) -> usize {
        self.tokens.as_ref().map_or(0, RealmTokens::requests)
    }

    /// True if the repository has the blob (`HEAD`).
    pub fn has_blob(&mut self, digest: &str) -> Result<bool, String> {
        let head = format!("{}/v2/{}/blobs/{digest}", self.base, self.name);
        let res = self.call("HEAD", &head, &[], &Payload::Empty, true)?;
        match res.status {
            200 => Ok(true),
            404 => Ok(false),
            s => Err(registry_error(&format!("HEAD blob {digest}"), &res, s)),
        }
    }

    /// Sends a blob that the repository does not have: a mount if `--from` is given, else (or if the mount
    /// is refused) a chunked upload (`POST`, `PATCH` parts with `Content-Range`, `PUT ?digest=`).
    pub fn push_blob(&mut self, blob: &Blob) -> Result<BlobResult, String> {
        let mut restarts = 0;
        loop {
            let session = match self.start_upload(&blob.digest)? {
                Start::Mounted => return Ok(BlobResult::Mounted),
                Start::Session(s) => s,
            };
            match self.upload(blob, session)? {
                Upload::Done(parts, part_size) => {
                    return Ok(BlobResult::Uploaded { parts, part_size })
                }
                Upload::Restart(location) => {
                    restarts += 1;
                    let _ = self.call("DELETE", &location, &[], &Payload::Empty, false);
                    if restarts > MAX_RESTARTS {
                        return Err(format!(
                            "prego: the upload of blob {} failed {restarts} times. Try again later",
                            blob.digest
                        ));
                    }
                }
            }
        }
    }

    fn start_upload(&mut self, digest: &str) -> Result<Start, String> {
        let mut url = format!("{}/v2/{}/blobs/uploads/", self.base, self.name);
        if let Some(from) = &self.from {
            url.push_str(&format!("?mount={digest}&from={from}"));
        }
        let res = self.call("POST", &url, &[], &Payload::Empty, true)?;
        match res.status {
            201 if self.from.is_some() => Ok(Start::Mounted),
            202 => {
                let location = self.location(&res)?;
                let min = res
                    .header("oci-chunk-min-length")
                    .and_then(|v| v.trim().parse::<u64>().ok());
                Ok(Start::Session(Session { location, min }))
            }
            s => Err(registry_error("start upload", &res, s)),
        }
    }

    fn upload(&mut self, blob: &Blob, session: Session) -> Result<Upload, String> {
        let part = part_size(self.requested_part, session.min)?;
        let mut location = session.location;
        let mut offset = 0u64;
        let mut resumes = 0usize;
        while offset < blob.size {
            let len = part.min(blob.size - offset);
            let range = format!("{}-{}", offset, offset + len - 1);
            let headers = [
                ("Content-Type", "application/octet-stream".to_string()),
                ("Content-Range", range),
            ];
            let res = self.call(
                "PATCH",
                &location,
                &headers,
                &Payload::Range(&blob.source, offset, len),
                false,
            );
            let next = match res {
                Ok(r) if r.status == 202 => {
                    location = self.location(&r).unwrap_or(location);
                    // The registry says how much it has. Without a usable Range header, trust the part.
                    match r.header("range").and_then(parse_range_end) {
                        Some(end) if end > 0 => end,
                        _ => offset + len,
                    }
                }
                Ok(r) if r.status != 416 && r.status < 500 => {
                    return Err(registry_error(
                        &format!("upload blob {}", blob.digest),
                        &r,
                        r.status,
                    ))
                }
                // 416 (offset or part size does not match), 5xx, or a network error: ask the registry how
                // much it has, and go on from there.
                other => {
                    resumes += 1;
                    if resumes > MAX_RESUMES {
                        return Ok(Upload::Restart(location));
                    }
                    if !matches!(other, Ok(ref r) if r.status == 416) {
                        (self.sleep)(RETRY_DELAYS[(resumes - 1).min(RETRY_DELAYS.len() - 1)]);
                    }
                    match self.status(&location)? {
                        Some((loc, have)) => {
                            location = loc;
                            have
                        }
                        None => return Ok(Upload::Restart(location)),
                    }
                }
            };
            // Parts must all have the same size, except the last. If the registry has a byte count that
            // is not on a part boundary, start again.
            if next > blob.size || (next != blob.size && next % part != 0) {
                return Ok(Upload::Restart(location));
            }
            offset = next;
        }
        let sep = if location.contains('?') { '&' } else { '?' };
        let url = format!("{location}{sep}digest={}", blob.digest);
        let res = self.call("PUT", &url, &[], &Payload::Empty, true)?;
        // A retried PUT can fail after the first one was stored. Then the repository has the blob.
        if res.status != 201 && !self.has_blob(&blob.digest)? {
            return Err(registry_error(
                &format!("finish blob {}", blob.digest),
                &res,
                res.status,
            ));
        }
        Ok(Upload::Done(blob.size.div_ceil(part).max(1), part))
    }

    /// `GET` upload status: the new location and the number of bytes the registry has.
    fn status(&mut self, location: &str) -> Result<Option<(String, u64)>, String> {
        let res = self.call("GET", location, &[], &Payload::Empty, true)?;
        if res.status != 204 && res.status != 202 {
            return Ok(None);
        }
        let loc = self.location(&res).unwrap_or_else(|_| location.to_string());
        let have = res.header("range").and_then(parse_range_end).unwrap_or(0);
        Ok(Some((loc, have)))
    }

    /// Pushes a manifest by digest, or by `tag` if given.
    pub fn put_manifest(&mut self, m: &Manifest, tag: Option<&str>) -> Result<(), String> {
        let reference = tag.unwrap_or(&m.digest);
        let url = format!("{}/v2/{}/manifests/{reference}", self.base, self.name);
        let headers = [("Content-Type", m.media_type.clone())];
        let res = self.call("PUT", &url, &headers, &Payload::Bytes(&m.bytes), true)?;
        if res.status != 201 {
            return Err(registry_error(
                &format!("push manifest {reference}"),
                &res,
                res.status,
            ));
        }
        if let Some(d) = res.header("docker-content-digest") {
            if d.trim() != m.digest {
                return Err(format!(
                    "prego: the registry stored manifest {reference} as {d}, expected {}",
                    m.digest
                ));
            }
        }
        Ok(())
    }

    /// The `Location` header as an absolute URL on the registry host.
    fn location(&self, res: &FullResponse) -> Result<String, String> {
        let loc = res
            .header("location")
            .ok_or("prego: the registry answered without a Location header")?;
        resolve(&self.base, loc)
    }

    /// Sends a request with the registry token. On `401` it gets a new token and tries once more. On `429`
    /// it waits for `Retry-After`. With `retry`, it also retries network errors and `5xx`.
    fn call(
        &mut self,
        method: &str,
        url: &str,
        headers: &[(&str, String)],
        payload: &Payload<'_>,
        retry: bool,
    ) -> Result<FullResponse, String> {
        let mut new_token = false;
        let mut transient = 0;
        let mut throttled = 0;
        loop {
            let token = match self.tokens.as_mut() {
                Some(t) => Some(t.token(&self.scopes).map_err(|e| e.to_string())?),
                None => None,
            };
            let res = self.send_once(method, url, headers, payload, token.as_ref());
            match res {
                Ok(r) if r.status == 401 && self.tokens.is_some() && !new_token => {
                    new_token = true;
                    if let Some(t) = self.tokens.as_mut() {
                        t.invalidate(&self.scopes);
                    }
                }
                Ok(r) if r.status == 429 && throttled < MAX_429_RETRIES => {
                    throttled += 1;
                    (self.sleep)(retry_after(&r));
                }
                Ok(r) if r.status >= 500 && retry && transient < RETRY_DELAYS.len() => {
                    (self.sleep)(RETRY_DELAYS[transient]);
                    transient += 1;
                }
                Err(_) if retry && transient < RETRY_DELAYS.len() => {
                    (self.sleep)(RETRY_DELAYS[transient]);
                    transient += 1;
                }
                Err(e) => return Err(format!("prego: {method} {}: {e}", path_of(url))),
                Ok(r) => return Ok(r),
            }
        }
    }

    fn send_once(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, String)],
        payload: &Payload<'_>,
        token: Option<&prego_auth::Secret>,
    ) -> Result<FullResponse, String> {
        let auth = token.map(|t| format!("Bearer {}", t.expose()));
        let mut h: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
        if let Some(a) = &auth {
            h.push(("Authorization", a));
        }
        h.push((
            "Accept",
            "application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json, application/json",
        ));
        match payload {
            Payload::Empty => self.http.send(method, url, &h, Body::Empty),
            Payload::Bytes(b) => self.http.send(method, url, &h, Body::Bytes(b)),
            Payload::Range(src, start, len) => {
                let mut r = src
                    .reader(*start, *len)
                    .map_err(|e| format!("cannot read {}: {e}", src.path.display()))?;
                self.http.send(method, url, &h, Body::Reader(&mut r, *len))
            }
        }
    }
}

enum Start {
    Mounted,
    Session(Session),
}

struct Session {
    location: String,
    min: Option<u64>,
}

enum Upload {
    Done(u64, u64),
    Restart(String),
}

/// The part size: the requested size (or [`DEFAULT_PART`]), at least `OCI-Chunk-Min-Length`, at most
/// [`MAX_PART`].
pub fn part_size(requested: Option<u64>, min: Option<u64>) -> Result<u64, String> {
    let min = min.unwrap_or(1).max(1);
    if min > MAX_PART {
        return Err(format!(
            "prego: the registry needs parts of at least {min} bytes, more than the 95 MiB limit"
        ));
    }
    Ok(requested.unwrap_or(DEFAULT_PART).clamp(min, MAX_PART))
}

/// The byte after the end of a `Range: 0-<last>` header (that is, the number of bytes the registry has).
/// `0-0` before any data is ambiguous; it is read as 0 bytes.
pub fn parse_range_end(v: &str) -> Option<u64> {
    let v = v.trim();
    let v = v.strip_prefix("bytes=").unwrap_or(v);
    let (start, end) = v.split_once('-')?;
    if start.trim() != "0" {
        return None;
    }
    let end: u64 = end.trim().parse().ok()?;
    Some(if end == 0 { 0 } else { end + 1 })
}

/// A `Bearer` challenge.
#[derive(Debug, PartialEq, Eq)]
pub struct Challenge {
    pub realm: String,
    pub service: Option<String>,
}

/// Parses `Bearer realm="...",service="...",scope="..."`.
pub fn parse_bearer_challenge(h: &str) -> Option<Challenge> {
    let h = h.trim();
    let (scheme, rest) = h.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let mut realm = None;
    let mut service = None;
    let mut s = rest.trim();
    while !s.is_empty() {
        let (key, after) = s.split_once('=')?;
        let key = key
            .trim()
            .trim_start_matches(',')
            .trim()
            .to_ascii_lowercase();
        let after = after.trim_start();
        let (value, tail) = if let Some(q) = after.strip_prefix('"') {
            let end = q.find('"')?;
            (&q[..end], &q[end + 1..])
        } else {
            let end = after.find(',').unwrap_or(after.len());
            (&after[..end], &after[end..])
        };
        match key.as_str() {
            "realm" => realm = Some(value.to_string()),
            "service" => service = Some(value.to_string()),
            _ => {}
        }
        s = tail.trim_start().trim_start_matches(',').trim_start();
    }
    Some(Challenge {
        realm: realm?,
        service,
    })
}

/// Resolves a `Location` against the registry base URL. A URL on another host is refused, so the token
/// is never sent there.
pub fn resolve(base: &str, loc: &str) -> Result<String, String> {
    let loc = loc.trim();
    if loc.starts_with('/') && !loc.starts_with("//") {
        return Ok(format!("{base}{loc}"));
    }
    if let Some(rest) = loc.strip_prefix(base) {
        if rest.starts_with('/') {
            return Ok(loc.to_string());
        }
    }
    Err(format!(
        "prego: the registry sent an upload location on another host or in an unknown form: `{}`",
        path_of(loc)
    ))
}

/// The URL without its query (the query can hold an upload state).
fn path_of(url: &str) -> &str {
    url.split('?').next().unwrap_or(url)
}

fn retry_after(r: &FullResponse) -> Duration {
    let secs = r
        .header("retry-after")
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(5);
    Duration::from_secs(secs.clamp(1, 60))
}

/// A one-line error from a registry response.
fn registry_error(what: &str, res: &FullResponse, status: u16) -> String {
    let first = serde_json::from_str::<Value>(&res.body)
        .ok()
        .and_then(|v| v.pointer("/errors/0").cloned());
    let code = first
        .as_ref()
        .and_then(|e| e.get("code"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let message = first
        .as_ref()
        .and_then(|e| e.get("message"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let hint = match (status, code) {
        (404, _) | (_, "NAME_UNKNOWN") => {
            ". No grant for this repository, or the name is wrong. Check the grants in the console"
        }
        (403, _) => {
            ". The identity cannot push to this repository, or the tenant is over its storage quota"
        }
        (401, _) => ". The registry refused the registry token",
        _ => "",
    };
    let mut out = format!("prego: {what}: HTTP {status}");
    if !code.is_empty() {
        out.push_str(&format!(" {code}"));
    }
    if !message.is_empty() {
        out.push_str(&format!(": {message}"));
    }
    out.push_str(hint);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn part_sizes() {
        let mib = 1024 * 1024;
        assert_eq!(part_size(None, None).unwrap(), DEFAULT_PART);
        assert_eq!(part_size(None, Some(5 * mib)).unwrap(), DEFAULT_PART);
        assert_eq!(part_size(Some(mib), Some(5 * mib)).unwrap(), 5 * mib);
        assert_eq!(part_size(Some(500 * mib), None).unwrap(), MAX_PART);
        assert_eq!(part_size(Some(10 * mib), None).unwrap(), 10 * mib);
        assert!(part_size(None, Some(96 * mib)).is_err());
    }

    #[test]
    fn ranges() {
        assert_eq!(parse_range_end("0-0"), Some(0));
        assert_eq!(parse_range_end("0-99"), Some(100));
        assert_eq!(parse_range_end("bytes=0-4"), Some(5));
        assert_eq!(parse_range_end("5-9"), None);
        assert_eq!(parse_range_end("x"), None);
    }

    #[test]
    fn challenges() {
        let c = parse_bearer_challenge(
            r#"Bearer realm="https://sts.prego.k8skill.com/v1/oci/token",service="oci.prego.k8skill.com",scope="repository:a/b/c:pull""#,
        )
        .unwrap();
        assert_eq!(c.realm, "https://sts.prego.k8skill.com/v1/oci/token");
        assert_eq!(c.service.as_deref(), Some("oci.prego.k8skill.com"));
        let c = parse_bearer_challenge("bearer realm=https://x.test/t, service=s").unwrap();
        assert_eq!(c.realm, "https://x.test/t");
        assert_eq!(c.service.as_deref(), Some("s"));
        assert!(parse_bearer_challenge(r#"Basic realm="x""#).is_none());
        assert!(parse_bearer_challenge(r#"Bearer service="x""#).is_none());
    }

    #[test]
    fn locations_stay_on_the_registry() {
        let base = "https://oci.prego.k8skill.com";
        assert_eq!(
            resolve(base, "/v2/a/b/c/blobs/uploads/1?s=2").unwrap(),
            "https://oci.prego.k8skill.com/v2/a/b/c/blobs/uploads/1?s=2"
        );
        assert_eq!(
            resolve(base, "https://oci.prego.k8skill.com/v2/x").unwrap(),
            "https://oci.prego.k8skill.com/v2/x"
        );
        for bad in [
            "https://evil.test/v2/x",
            "https://oci.prego.k8skill.com.evil.test/v2/x",
            "v2/x",
            "//evil.test/v2/x",
        ] {
            assert!(resolve(base, bad).is_err(), "{bad}");
        }
    }
}
