//! Device sessions for `prego login` (device authorization flow, RFC 8628). See `PROTOCOL.md` section 11.
//!
//! `prego login` starts a device request at `<sts>/v1/sts/device/e/<edge code>/start`, shows the user code,
//! and polls `.../token` until the person approves it in the console. The answer has a **session refresh
//! token** and a first registry token. The refresh token is kept in secure storage only ([`store`]), and
//! changes on every use: the new one is stored before the registry token is used.
//!
//! Clients use the session only when no workload identity and no `PREGO_API_KEY` is set
//! ([`crate::SourceKind::Device`]).

pub mod store;

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::config::{Config, STS_PATH};
use crate::env::Env;
use crate::error::Error;
use crate::http::{Http, Response};
use crate::secret::Secret;
use crate::sts::{self, send_rate_limited, RegistryToken};

pub use store::{open_store, SessionStore};

/// The secure storage of the sessions and the lock directory for refreshes.
#[derive(Clone)]
pub struct DeviceHandle {
    /// The secure storage.
    pub store: Arc<dyn SessionStore>,
    lock_dir: Option<PathBuf>,
}

impl DeviceHandle {
    /// Opens the secure storage of this computer ([`open_store`]).
    pub fn open(env: &dyn Env) -> Result<Self, Error> {
        Ok(DeviceHandle {
            store: Arc::from(open_store(env)?),
            lock_dir: store::lock_dir(env),
        })
    }

    /// A handle with a given store and lock directory. For tests.
    pub fn with_store(store: Arc<dyn SessionStore>, lock_dir: Option<PathBuf>) -> Self {
        DeviceHandle { store, lock_dir }
    }
}

impl fmt::Debug for DeviceHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceHandle({})", self.store.name())
    }
}

/// The `grant_type` of a device code poll (RFC 8628).
pub const DEVICE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";
/// The `grant_type` of a session refresh.
pub const REFRESH_GRANT_TYPE: &str = "refresh_token";
/// The text when the STS ends a session (revoked, expired or reused).
pub const SESSION_ENDED: &str = "the login session ended; run prego login again";
/// The most registry tokens kept with a session (one per registry base URL).
const MAX_CACHED_TOKENS: usize = 4;

/// One access item of a device request or a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Access {
    /// `any`, `cargo`, `oci`, `go` or `npm`.
    pub ecosystem: String,
    /// The namespace. `None` means `default`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// `read`, `publish`, `delete`.
    pub actions: Vec<String>,
}

impl Access {
    /// What `prego login` asks for: read on every package type, and publish with `--publish`.
    pub fn request(publish: bool) -> Vec<Access> {
        let mut actions = vec!["read".to_string()];
        if publish {
            actions.push("publish".to_string());
        }
        vec![Access {
            ecosystem: "any".into(),
            namespace: None,
            actions,
        }]
    }
}

/// The session data that `prego status` shows. It holds no token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    /// `dvs_...`.
    pub id: String,
    /// `<client> on <host>`, as the console shows it.
    #[serde(default)]
    pub name: Option<String>,
    /// The approved access.
    #[serde(default)]
    pub access: Vec<Access>,
    /// Unix time when the session ends if it is not used.
    pub idle_expires_at: i64,
    /// Unix time when the session ends in any case.
    pub expires_at: i64,
}

/// The answer to `start`.
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceCode {
    /// The code for the polls. Not shown to the person.
    pub device_code: String,
    /// The code the person types or confirms, `ABCD-EFGH`.
    pub user_code: String,
    /// The approval page.
    pub verification_uri: String,
    /// The approval page with the user code in it.
    #[serde(default)]
    pub verification_uri_complete: Option<String>,
    /// Seconds until the request expires.
    pub expires_in: i64,
    /// Seconds between polls.
    #[serde(default = "default_interval")]
    pub interval: u64,
}

fn default_interval() -> u64 {
    5
}

/// The stored session. Never printed: it holds the refresh token.
#[derive(Serialize, Deserialize)]
struct Record {
    refresh_token: String,
    session: SessionInfo,
    /// The keys of the registry tokens kept with the session.
    #[serde(default)]
    token_keys: Vec<String>,
}

/// One registry token kept with the session.
#[derive(Serialize, Deserialize)]
struct TokenRecord {
    token: String,
    expires_at: i64,
    lifetime: i64,
}

/// The token answer of a poll or a refresh.
#[derive(Deserialize)]
struct TokenAnswer {
    access_token: Option<String>,
    expires_in: Option<i64>,
    refresh_token: Option<String>,
    session: Option<SessionAnswer>,
}

#[derive(Deserialize)]
struct SessionAnswer {
    id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    access: Option<Vec<Access>>,
    idle_expires_at: i64,
    expires_at: i64,
}

#[derive(Deserialize)]
struct Failure {
    error: Option<String>,
    error_description: Option<String>,
}

fn failure(res: &Response) -> (Option<String>, Option<String>) {
    match serde_json::from_str::<Failure>(&res.body) {
        Ok(f) => (f.error, f.error_description),
        Err(_) => (None, None),
    }
}

/// The key of a session in the store: tenant and STS.
pub fn session_key(config: &Config) -> String {
    format!("session:{}@{}", config.tenant, config.sts_url)
}

fn token_key(config: &Config, resource: Option<&str>) -> String {
    format!(
        "token:{}@{}#{:016x}",
        config.tenant,
        config.sts_url,
        store::fnv1a(resource.unwrap_or(""))
    )
}

/// `<sts origin>/v1/sts/device/e/<edge code>/<op>`.
pub fn device_url(config: &Config, op: &str) -> Result<String, Error> {
    let base = config.sts_url.strip_suffix(STS_PATH).ok_or_else(|| {
        Error::Config(format!(
            "the STS URL must end with {STS_PATH} for prego login: {}",
            config.sts_url
        ))
    })?;
    let code = config.edge_code.as_deref().ok_or_else(|| {
        // Same text as for registry tokens.
        config.token_url().err().unwrap_or(Error::Config(
            "the edge code of your tenant is not set".into(),
        ))
    })?;
    Ok(format!("{base}/v1/sts/device/e/{code}/{op}"))
}

/// Starts a device request.
pub fn start(
    http: &Http,
    config: &Config,
    client: &str,
    access: &[Access],
    sleep: &dyn Fn(Duration),
) -> Result<DeviceCode, Error> {
    let url = device_url(config, "start")?;
    let body = json!({ "client": client, "access": access });
    let res = send_rate_limited(|| http.post_json(&url, &body), sleep)?;
    if res.status == 200 {
        return serde_json::from_str(&res.body)
            .map_err(|_| Error::BadResponse("the device start answer is not valid".into()));
    }
    Err(sts_error(&res, &config.tenant))
}

fn sts_error(res: &Response, tenant: &str) -> Error {
    let (code, description) = failure(res);
    if res.status == 429 {
        // A stop of the tenant (its usage limit, or the reads of a trial) has its own text: the retries do not
        // help, the person must wait for the reset or ask the owner.
        if let Some(d) = description
            .as_deref()
            .filter(|d| d.contains("usage limit") || d.contains("reads of its trial"))
        {
            return Error::Login(format!(
                "usage limit reached: {d}. Try again after the reset or ask the owner"
            ));
        }
        return Error::RateLimited {
            tenant: tenant.to_string(),
            retry_after: res.retry_after,
        };
    }
    Error::Sts {
        status: res.status,
        code,
        description,
    }
}

/// Polls until the person approves or denies the request, or it expires. On approval the session is
/// stored, and its data is returned.
pub fn wait_for_approval(
    http: &Http,
    config: &Config,
    store: &dyn SessionStore,
    code: &DeviceCode,
    now: &dyn Fn() -> i64,
    sleep: &dyn Fn(Duration),
) -> Result<SessionInfo, Error> {
    let url = device_url(config, "token")?;
    let deadline = now() + code.expires_in.max(1);
    let mut interval = code.interval.max(1);
    loop {
        sleep(Duration::from_secs(interval));
        if now() > deadline {
            return Err(Error::Login(
                "the login request expired before it was approved. Run prego login again".into(),
            ));
        }
        let fields = [
            ("grant_type", DEVICE_GRANT_TYPE),
            ("device_code", code.device_code.as_str()),
        ];
        let sent_at = now();
        let res = send_rate_limited(|| http.post_form(&url, &fields), sleep)?;
        if res.status == 200 {
            let (info, _) = save_answer(config, store, &res, None, sent_at, None)?;
            return Ok(info);
        }
        match failure(&res).0.as_deref() {
            Some("authorization_pending") => {}
            Some("slow_down") => interval += 5,
            Some("expired_token") => {
                return Err(Error::Login(
                    "the login request expired before it was approved. Run prego login again"
                        .into(),
                ))
            }
            Some("access_denied") => {
                return Err(Error::Login(
                    "the login request was denied in the console".into(),
                ))
            }
            _ => return Err(sts_error(&res, &config.tenant)),
        }
    }
}

/// Stores a poll or refresh answer: first the new refresh token and the session, then the registry token.
/// `old` is the stored record of a refresh, for the fields that a refresh answer does not repeat.
fn save_answer(
    config: &Config,
    store: &dyn SessionStore,
    res: &Response,
    resource: Option<&str>,
    sent_at: i64,
    old: Option<Record>,
) -> Result<(SessionInfo, RegistryToken), Error> {
    let answer: TokenAnswer = serde_json::from_str(&res.body)
        .map_err(|_| Error::BadResponse("body is not JSON".into()))?;
    let refresh_token = answer
        .refresh_token
        .filter(|t| !t.is_empty())
        .ok_or_else(|| Error::BadResponse("no refresh_token".into()))?;
    let s = answer
        .session
        .ok_or_else(|| Error::BadResponse("no session".into()))?;
    let token = answer
        .access_token
        .filter(|t| !t.is_empty())
        .ok_or_else(|| Error::BadResponse("no access_token".into()))?;
    let lifetime = sts::lifetime(answer.expires_in, &token)
        .ok_or_else(|| Error::BadResponse("no expires_in".into()))?;
    let (old_name, old_access, mut token_keys) = match old {
        Some(r) => (r.session.name, r.session.access, r.token_keys),
        None => (None, Vec::new(), Vec::new()),
    };
    let info = SessionInfo {
        id: s.id,
        name: s.name.or(old_name),
        access: s.access.unwrap_or(old_access),
        idle_expires_at: s.idle_expires_at,
        expires_at: s.expires_at,
    };
    let key = token_key(config, resource);
    if !token_keys.contains(&key) {
        token_keys.push(key.clone());
    }
    // Keep the list short; the oldest entries are deleted.
    while token_keys.len() > MAX_CACHED_TOKENS {
        let gone = token_keys.remove(0);
        let _ = store.delete(&gone);
    }
    let record = Record {
        refresh_token,
        session: info.clone(),
        token_keys,
    };
    let text = serde_json::to_string(&record).map_err(|e| Error::Storage(e.to_string()))?;
    store
        .save(&session_key(config), &text)
        .map_err(|e| Error::Storage(format!("cannot store the login session: {e}")))?;

    let t = RegistryToken::new(Secret::new(token), sent_at, lifetime);
    let cached = TokenRecord {
        token: t.token.expose().to_string(),
        expires_at: t.expires_at,
        lifetime: t.lifetime,
    };
    // The session is stored. A registry token that cannot be stored is only a lost cache entry.
    if let Ok(text) = serde_json::to_string(&cached) {
        let _ = store.save(&key, &text);
    }
    Ok((info, t))
}

fn load_record(config: &Config, store: &dyn SessionStore) -> Result<Option<Record>, Error> {
    let Some(text) = store
        .load(&session_key(config))
        .map_err(|e| Error::Storage(format!("cannot read the login session: {e}")))?
    else {
        return Ok(None);
    };
    serde_json::from_str(&text).map(Some).map_err(|_| {
        Error::Storage("the stored login session is not valid. Run prego login again".into())
    })
}

/// The stored session of `config`, if there is one.
pub fn status(config: &Config, store: &dyn SessionStore) -> Result<Option<SessionInfo>, Error> {
    Ok(load_record(config, store)?.map(|r| r.session))
}

/// True if a session is stored for `config`.
pub fn has_session(config: &Config, store: &dyn SessionStore) -> Result<bool, Error> {
    Ok(load_record(config, store)?.is_some())
}

fn delete_all(
    config: &Config,
    store: &dyn SessionStore,
    record: Option<&Record>,
) -> Result<(), String> {
    if let Some(r) = record {
        for k in &r.token_keys {
            store.delete(k)?;
        }
    }
    store.delete(&session_key(config))
}

/// Returns a registry token from the session: a stored one that is still fresh, or a new one from a
/// refresh. A refresh runs under an exclusive lock, and the new refresh token is stored before the
/// registry token is returned.
pub fn registry_token(
    http: &Http,
    config: &Config,
    device: &DeviceHandle,
    resource: Option<&str>,
    now: &dyn Fn() -> i64,
    sleep: &dyn Fn(Duration),
) -> Result<RegistryToken, Error> {
    registry_token_inner(http, config, device, resource, false, now, sleep)
}

/// Like [`registry_token`], for the Docker credential helper. The token realm caps the token that it issues
/// at the expiry of this token, and Docker keeps the helper's secret for the whole command. So a stored token
/// is used only while at least half of its lifetime is left; else the session is refreshed. The token always
/// comes from the session (a poll or a refresh), never from the realm: the realm refuses its own tokens.
pub fn registry_token_for_docker(
    http: &Http,
    config: &Config,
    device: &DeviceHandle,
    now: &dyn Fn() -> i64,
    sleep: &dyn Fn(Duration),
) -> Result<RegistryToken, Error> {
    registry_token_inner(http, config, device, None, true, now, sleep)
}

fn registry_token_inner(
    http: &Http,
    config: &Config,
    device: &DeviceHandle,
    resource: Option<&str>,
    half_left: bool,
    now: &dyn Fn() -> i64,
    sleep: &dyn Fn(Duration),
) -> Result<RegistryToken, Error> {
    let store = device.store.as_ref();
    let _lock = store::refresh_lock(device.lock_dir.as_deref(), &session_key(config));
    let record = load_record(config, store)?.ok_or_else(not_logged_in)?;

    let key = token_key(config, resource);
    if let Ok(Some(text)) = store.load(&key) {
        if let Ok(t) = serde_json::from_str::<TokenRecord>(&text) {
            let t = RegistryToken {
                token: Secret::new(t.token),
                expires_at: t.expires_at,
                lifetime: t.lifetime,
            };
            let t_now = now();
            let enough_left = !half_left || t.expires_at - t_now >= t.lifetime / 2;
            if t.is_fresh(t_now) && enough_left {
                return Ok(t);
            }
        }
    }

    let url = config.token_url()?;
    let mut fields = vec![
        ("grant_type", REFRESH_GRANT_TYPE),
        ("refresh_token", record.refresh_token.as_str()),
    ];
    if let Some(r) = resource {
        fields.push(("resource", r));
    }
    let sent_at = now();
    let mut res = send_rate_limited(|| http.post_form(&url, &fields), sleep)?;
    if resource.is_some()
        && res.status == 400
        && failure(&res).0.as_deref() == Some("invalid_target")
    {
        // The STS refused the resource and did not use the refresh token. Ask once more without it.
        fields.pop();
        res = send_rate_limited(|| http.post_form(&url, &fields), sleep)?;
    }
    if res.status == 200 {
        return save_answer(config, store, &res, resource, sent_at, Some(record)).map(|(_, t)| t);
    }
    let (code, description) = failure(&res);
    // Only a 400 ends the session. A 401 invalid_grant is the ended trial of the tenant: the session stays,
    // and the person sees the text of the STS.
    if res.status == 400 && code.as_deref() == Some("invalid_grant") {
        let _ = delete_all(config, store, Some(&record));
        return Err(Error::SessionEnded(
            description.unwrap_or_else(|| SESSION_ENDED.to_string()),
        ));
    }
    Err(sts_error(&res, &config.tenant))
}

/// The error when no session is stored.
pub fn not_logged_in() -> Error {
    Error::Login("you are not logged in. Run prego login, or set PREGO_API_KEY".into())
}

/// What `prego logout` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Logout {
    /// No session was stored.
    NoSession,
    /// The STS ended the session, and the local data is deleted.
    Revoked,
    /// The STS call failed (the text says why). The local data is deleted all the same.
    LocalOnly(String),
}

/// Ends the session at the STS and deletes the local data. The local data is deleted also when the STS call
/// fails.
pub fn logout(
    http: &Http,
    config: &Config,
    store: &dyn SessionStore,
    sleep: &dyn Fn(Duration),
) -> Result<Logout, Error> {
    let Some(record) = load_record(config, store)? else {
        return Ok(Logout::NoSession);
    };
    let remote = device_url(config, "revoke").and_then(|url| {
        let fields = [("refresh_token", record.refresh_token.as_str())];
        let res = sts::send_with_retry(|| http.post_form(&url, &fields), sleep)?;
        if res.status == 200 {
            Ok(())
        } else {
            Err(sts_error(&res, &config.tenant))
        }
    });
    delete_all(config, store, Some(&record))
        .map_err(|e| Error::Storage(format!("cannot delete the login session: {e}")))?;
    Ok(match remote {
        Ok(()) => Logout::Revoked,
        Err(e) => Logout::LocalOnly(e.to_string()),
    })
}

#[cfg(test)]
mod tests;
