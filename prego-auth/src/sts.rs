//! The STS token exchange (RFC 8693). See `PROTOCOL.md`.

use std::time::Duration;

use serde::Deserialize;

use crate::config::Config;
use crate::error::Error;
use crate::http::{Http, Response};
use crate::jwt;
use crate::secret::Secret;
use crate::sources::SubjectToken;

/// The `grant_type` for token exchange.
pub const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
/// Wait times before retry 1 and retry 2.
pub const RETRY_DELAYS: [Duration; 2] = [Duration::from_millis(250), Duration::from_secs(1)];

/// The cache margin is at most this many seconds.
pub const MAX_MARGIN_SECONDS: i64 = 60;
/// The longest `Retry-After` wait for a `429` from the STS.
pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(60);
/// The number of retries after a `429` from the STS.
pub const RATE_LIMIT_RETRIES: usize = 2;

/// A registry token from the STS.
#[derive(Debug, Clone)]
pub struct RegistryToken {
    /// The token value (a JWT).
    pub token: Secret,
    /// Unix time in seconds, on the local clock, when the token expires: the local time of the request plus
    /// [`lifetime`](Self::lifetime). Never taken from the `exp` claim, so a wrong local clock does not matter.
    pub expires_at: i64,
    /// The lifetime in seconds that the server gave (`expires_in`).
    pub lifetime: i64,
}

impl RegistryToken {
    /// A token with `lifetime` seconds, received at local time `received_at`.
    pub fn new(token: Secret, received_at: i64, lifetime: i64) -> Self {
        RegistryToken {
            token,
            expires_at: received_at + lifetime,
            lifetime,
        }
    }

    /// The cache margin: `min(60 s, lifetime / 4)`.
    pub fn margin(&self) -> i64 {
        cache_margin(self.lifetime)
    }

    /// The last local time at which a cache may still give out this token: expiry minus the margin.
    pub fn fresh_until(&self) -> i64 {
        self.expires_at - self.margin()
    }

    /// True if a cache may still give out this token at `now`.
    pub fn is_fresh(&self, now: i64) -> bool {
        now < self.fresh_until()
    }
}

/// The cache margin for a token lifetime: `min(60 s, lifetime / 4)`.
pub fn cache_margin(lifetime: i64) -> i64 {
    (lifetime.max(0) / 4).min(MAX_MARGIN_SECONDS)
}

/// The token lifetime in seconds: `expires_in`, else `exp - iat` from the token (read without a signature
/// check; both are server times, so the local clock does not matter). If both are there, the shorter one.
/// `None` if neither gives a positive number.
pub fn lifetime(expires_in: Option<i64>, token: &str) -> Option<i64> {
    let from_claims = jwt::unverified_claims(token).and_then(|c| {
        let n = |k: &str| {
            c.get(k)
                .and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64)))
        };
        Some(n("exp")? - n("iat")?)
    });
    match (
        expires_in.filter(|s| *s > 0),
        from_claims.filter(|s| *s > 0),
    ) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// The `resource` for a registry URL: `<scheme>://<host>/t/<tenant>/<namespace>`, from any URL under that
/// path (a sparse index URL, a GOPROXY entry). A `sparse+` prefix is removed. `None` if the URL has no
/// such path.
pub fn resource_base(url: &str) -> Option<String> {
    let url = url.strip_prefix("sparse+").unwrap_or(url);
    let (scheme, rest) = url.split_once("://")?;
    if scheme != "https" && scheme != "http" {
        return None;
    }
    let mut parts = rest.split('/');
    let host = parts.next().filter(|h| !h.is_empty())?;
    if parts.next()? != "t" {
        return None;
    }
    let ok = |s: &&str| !s.is_empty() && !s.contains(['?', '#']);
    let tenant = parts.next().filter(ok)?;
    let ns = parts.next().filter(ok)?;
    Some(format!("{scheme}://{host}/t/{tenant}/{ns}"))
}

#[derive(Deserialize)]
struct Success {
    access_token: Option<String>,
    expires_in: Option<i64>,
}

#[derive(Deserialize)]
struct Failure {
    error: Option<String>,
    error_description: Option<String>,
}

/// Exchanges `subject` for a registry token. Retries on network errors and `5xx`, and after a `429` waits
/// for `Retry-After` (at most 60 s, plus a little jitter) up to two times.
///
/// `resource` is the registry base URL the token is for (see [`resource_base`]). The STS then gives the
/// lifetime of the grants for that namespace. If the STS refuses it with `400 invalid_target`, the client
/// asks once more without it.
///
/// `now` is the local time before the request. The expiry is `now + lifetime`, so it is never later than
/// the real one.
pub fn exchange(
    http: &Http,
    config: &Config,
    subject: &SubjectToken,
    resource: Option<&str>,
    now: i64,
    sleep: &dyn Fn(Duration),
) -> Result<RegistryToken, Error> {
    let mut fields = vec![
        ("grant_type", GRANT_TYPE),
        ("subject_token", subject.value.expose()),
        ("subject_token_type", subject.token_type.urn()),
        ("tenant", config.tenant.as_str()),
    ];
    if let Some(r) = resource {
        fields.push(("resource", r));
    }
    let url = config.token_url()?;
    let res = send_rate_limited(|| http.post_form(&url, &fields), sleep)?;
    if resource.is_some()
        && res.status == 400
        && error_code(&res).as_deref() == Some("invalid_target")
    {
        fields.pop();
        let res = send_rate_limited(|| http.post_form(&url, &fields), sleep)?;
        return parse_response(&res, &config.tenant, now);
    }
    parse_response(&res, &config.tenant, now)
}

fn error_code(res: &Response) -> Option<String> {
    serde_json::from_str::<Failure>(&res.body).ok()?.error
}

/// [`send_with_retry`], and after a `429` a wait for `Retry-After` (at most [`MAX_RETRY_AFTER`], plus up to
/// 500 ms of jitter) and a new try, at most [`RATE_LIMIT_RETRIES`] times.
pub fn send_rate_limited(
    mut send: impl FnMut() -> Result<Response, String>,
    sleep: &dyn Fn(Duration),
) -> Result<Response, Error> {
    let mut waits = 0;
    loop {
        let res = send_with_retry(&mut send, sleep)?;
        if res.status != 429 || waits == RATE_LIMIT_RETRIES {
            return Ok(res);
        }
        let wait = Duration::from_secs(res.retry_after.unwrap_or(1)).min(MAX_RETRY_AFTER);
        sleep(wait + jitter());
        waits += 1;
    }
}

/// 0 to 499 ms from the clock, so that parallel jobs do not retry at the same moment.
fn jitter() -> Duration {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    Duration::from_millis(u64::from(nanos % 500))
}

/// Calls `send` up to 3 times. Retries only on `Err` (network) and `5xx`.
pub fn send_with_retry(
    mut send: impl FnMut() -> Result<Response, String>,
    sleep: &dyn Fn(Duration),
) -> Result<Response, Error> {
    let mut attempt = 0;
    loop {
        let result = send();
        let retry = match &result {
            Ok(r) => r.status >= 500,
            Err(_) => true,
        };
        if !retry || attempt == RETRY_DELAYS.len() {
            return result.map_err(Error::Network);
        }
        sleep(RETRY_DELAYS[attempt]);
        attempt += 1;
    }
}

/// Turns an STS response into a token or an error. Pure, for tests. `now` is the local time of the request.
pub fn parse_response(res: &Response, tenant: &str, now: i64) -> Result<RegistryToken, Error> {
    if res.status == 200 {
        let body: Success = serde_json::from_str(&res.body)
            .map_err(|_| Error::BadResponse("body is not JSON".into()))?;
        let token = body
            .access_token
            .filter(|t| !t.is_empty())
            .ok_or_else(|| Error::BadResponse("no access_token".into()))?;
        let lifetime = lifetime(body.expires_in, &token)
            .ok_or_else(|| Error::BadResponse("no expires_in and no exp and iat claims".into()))?;
        return Ok(RegistryToken::new(Secret::new(token), now, lifetime));
    }

    let failure: Option<Failure> = serde_json::from_str(&res.body).ok();
    let (code, description) = match failure {
        Some(f) => (f.error, f.error_description),
        None => (None, None),
    };
    if code.as_deref() == Some("invalid_grant") {
        return Err(Error::Refused {
            tenant: tenant.to_string(),
        });
    }
    if res.status == 429 {
        return Err(Error::RateLimited {
            tenant: tenant.to_string(),
            retry_after: res.retry_after,
        });
    }
    Err(Error::Sts {
        status: res.status,
        code,
        description,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn resp(status: u16, body: &str) -> Response {
        Response {
            status,
            body: body.into(),
            retry_after: None,
        }
    }

    fn jwt(payload: &str) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        format!(
            "eyJhbGciOiJFUzI1NiJ9.{}.c2ln",
            URL_SAFE_NO_PAD.encode(payload)
        )
    }

    #[test]
    fn expiry_comes_from_expires_in_and_the_local_clock() {
        // The exp claim is far in the past (a wrong local clock, or a wrong server clock): not used.
        let token = jwt(r#"{"exp":1000060,"iat":1000000}"#);
        let body = format!(
            r#"{{"access_token":"{token}","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":60}}"#
        );
        let t = parse_response(&resp(200, &body), "acme", 1_700_000_000).unwrap();
        assert_eq!(t.token.expose(), token);
        assert_eq!(t.lifetime, 60);
        assert_eq!(t.expires_at, 1_700_000_060);
        assert_eq!(t.margin(), 15);
        assert_eq!(t.fresh_until(), 1_700_000_045);
        assert!(t.is_fresh(1_700_000_044));
        assert!(!t.is_fresh(1_700_000_045));
    }

    #[test]
    fn lifetime_sources() {
        let t = parse_response(
            &resp(200, r#"{"access_token":"opaque","expires_in":900}"#),
            "acme",
            1000,
        )
        .unwrap();
        assert_eq!((t.lifetime, t.expires_at, t.margin()), (900, 1900, 60));
        // No expires_in: exp - iat.
        let token = jwt(r#"{"exp":1300,"iat":1000}"#);
        let body = format!(r#"{{"access_token":"{token}"}}"#);
        let t = parse_response(&resp(200, &body), "acme", 5000).unwrap();
        assert_eq!((t.lifetime, t.expires_at), (300, 5300));
        // Both: the shorter one, so a cache never outlives the token.
        assert_eq!(
            lifetime(Some(900), &jwt(r#"{"exp":1060,"iat":1000}"#)),
            Some(60)
        );
        assert_eq!(
            lifetime(Some(60), &jwt(r#"{"exp":1900,"iat":1000}"#)),
            Some(60)
        );
        assert_eq!(lifetime(Some(0), "opaque"), None);
        assert_eq!(lifetime(None, &jwt(r#"{"exp":1000}"#)), None);
    }

    #[test]
    fn margins() {
        assert_eq!(cache_margin(60), 15);
        assert_eq!(cache_margin(120), 30);
        assert_eq!(cache_margin(240), 60);
        assert_eq!(cache_margin(900), 60);
        assert_eq!(cache_margin(1800), 60);
        assert_eq!(cache_margin(0), 0);
    }

    #[test]
    fn resource_bases() {
        let want = Some("https://cargo.prego.k8skill.com/t/acme/default".to_string());
        assert_eq!(
            resource_base("sparse+https://cargo.prego.k8skill.com/t/acme/default/index/"),
            want
        );
        assert_eq!(
            resource_base("sparse+https://cargo.prego.k8skill.com/t/acme/default/index"),
            want
        );
        assert_eq!(
            resource_base("https://cargo.prego.k8skill.com/t/acme/default/"),
            want
        );
        assert_eq!(
            resource_base("https://go.prego.k8skill.com/t/acme/default"),
            Some("https://go.prego.k8skill.com/t/acme/default".into())
        );
        assert_eq!(
            resource_base("http://127.0.0.1:8080/t/acme/rel/x"),
            Some("http://127.0.0.1:8080/t/acme/rel".into())
        );
        assert_eq!(resource_base("sparse+https://index.crates.io/"), None);
        assert_eq!(resource_base("https://cargo.example.test/t/acme"), None);
        assert_eq!(resource_base("https://cargo.example.test/t/acme/"), None);
        assert_eq!(resource_base("file:///t/acme/default"), None);
    }

    #[test]
    fn bad_success_bodies() {
        for body in [
            "",
            "{}",
            r#"{"access_token":""}"#,
            r#"{"access_token":"x"}"#,
        ] {
            assert!(matches!(
                parse_response(&resp(200, body), "acme", 0),
                Err(Error::BadResponse(_))
            ));
        }
    }

    #[test]
    fn invalid_grant_is_refused() {
        let e = parse_response(
            &resp(
                401,
                r#"{"error":"invalid_grant","error_description":"subject token not accepted"}"#,
            ),
            "acme",
            0,
        )
        .unwrap_err();
        assert_eq!(
            e,
            Error::Refused {
                tenant: "acme".into()
            }
        );
    }

    #[test]
    fn other_errors_keep_code() {
        let mut r = resp(429, r#"{"error":"rate_limited"}"#);
        r.retry_after = Some(7);
        let e = parse_response(&r, "acme", 0).unwrap_err();
        assert_eq!(
            e,
            Error::RateLimited {
                tenant: "acme".into(),
                retry_after: Some(7)
            }
        );
        let e = parse_response(&resp(400, r#"{"error":"invalid_target"}"#), "acme", 0).unwrap_err();
        assert_eq!(
            e,
            Error::Sts {
                status: 400,
                code: Some("invalid_target".into()),
                description: None
            }
        );
        let e = parse_response(&resp(502, "<html>"), "acme", 0).unwrap_err();
        assert!(matches!(
            e,
            Error::Sts {
                status: 502,
                code: None,
                ..
            }
        ));
    }

    fn run(
        script: Vec<Result<Response, String>>,
    ) -> (Result<Response, Error>, usize, Vec<Duration>) {
        let script = RefCell::new(script.into_iter());
        let calls = RefCell::new(0);
        let sleeps = RefCell::new(Vec::new());
        let r = send_with_retry(
            || {
                *calls.borrow_mut() += 1;
                script.borrow_mut().next().unwrap()
            },
            &|d| sleeps.borrow_mut().push(d),
        );
        (r, calls.into_inner(), sleeps.into_inner())
    }

    #[test]
    fn retries_network_and_5xx_twice_with_backoff() {
        let (r, calls, sleeps) = run(vec![
            Err("reset".into()),
            Ok(resp(503, "")),
            Ok(resp(200, "ok")),
        ]);
        assert_eq!(r.unwrap().body, "ok");
        assert_eq!(calls, 3);
        assert_eq!(sleeps, RETRY_DELAYS.to_vec());
    }

    #[test]
    fn gives_up_after_two_retries() {
        let (r, calls, _) = run(vec![Err("a".into()), Err("b".into()), Err("c".into())]);
        assert_eq!(r.unwrap_err(), Error::Network("c".into()));
        assert_eq!(calls, 3);

        let (r, calls, _) = run(vec![
            Ok(resp(500, "")),
            Ok(resp(500, "")),
            Ok(resp(500, "")),
        ]);
        assert_eq!(r.unwrap().status, 500);
        assert_eq!(calls, 3);
    }

    #[test]
    fn no_retry_on_4xx() {
        let (r, calls, sleeps) = run(vec![Ok(resp(400, ""))]);
        assert_eq!(r.unwrap().status, 400);
        assert_eq!(calls, 1);
        assert!(sleeps.is_empty());
    }
}
