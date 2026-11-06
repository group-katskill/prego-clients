//! The Prego OCI registry: its hosts and the Docker token realm.
//!
//! An OCI client sends the tenant and a subject token as HTTP Basic auth to the realm,
//! `https://<STS host>/v1/oci/token/e/<edge code>`. The realm does the normal STS exchange and returns a registry token.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Deserialize;

use crate::config::Config;
use crate::env::Env;
use crate::error::Error;
use crate::file_config::FileConfig;
use crate::http::Http;
use crate::secret::Secret;
use crate::sources::SubjectToken;
use crate::sts::{self, send_with_retry, RegistryToken};

/// The Prego OCI registry host. It is also the `service` value for the realm.
pub const DEFAULT_OCI_HOST: &str = "oci.prego.k8skill.com";
/// The realm path on the STS host.
pub const REALM_PATH: &str = "/v1/oci/token";

/// The OCI hosts of Prego: [`DEFAULT_OCI_HOST`], then `oci_hosts` from the settings file, then
/// `PREGO_OCI_HOSTS` (comma-separated). Each host is normalized with [`normalize_host`]. No duplicates.
pub fn oci_hosts(file: &FileConfig, env: &dyn Env) -> Vec<String> {
    let mut hosts = vec![DEFAULT_OCI_HOST.to_string()];
    let from_env = env.var("PREGO_OCI_HOSTS").unwrap_or_default();
    let extra = file
        .oci_hosts
        .iter()
        .map(String::as_str)
        .chain(from_env.split(','));
    for h in extra {
        if let Some(h) = normalize_host(h) {
            if !hosts.contains(&h) {
                hosts.push(h);
            }
        }
    }
    hosts
}

/// Reduces a server URL (`https://oci.prego.k8skill.com/v2/`, `oci.prego.k8skill.com`, ...) to a lowercase
/// host, with a port only if it is not 443. Returns `None` for an empty value.
pub fn normalize_host(server_url: &str) -> Option<String> {
    let s = server_url.trim();
    let s = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .unwrap_or(s);
    let host = s.split(['/', '?', '#']).next().unwrap_or("");
    // Drop user info, if any.
    let host = host.rsplit('@').next().unwrap_or("");
    let host = host.strip_suffix(":443").unwrap_or(host);
    let host = host.to_ascii_lowercase();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

/// `scheme://authority` of the STS URL in `config`.
fn sts_origin(config: &Config) -> Result<String, Error> {
    let uri: ureq::http::Uri = config
        .sts_url
        .parse()
        .map_err(|_| Error::Config(format!("bad STS URL `{}`", config.sts_url)))?;
    match (uri.scheme_str(), uri.authority()) {
        (Some(scheme), Some(authority)) => Ok(format!("{scheme}://{authority}")),
        _ => Err(Error::Config(format!("bad STS URL `{}`", config.sts_url))),
    }
}

/// The realm URL on the same scheme and host as the STS URL in `config`, with the configured (home) edge
/// code: `<origin>/v1/oci/token/e/<edge code>`. An error if the edge code is not set. `prego token --scope`
/// uses it for all scopes, also for repositories of another tenant. `prego push` uses the realm from the
/// repository's challenge ([`check_challenge_realm`]).
pub fn realm_url(config: &Config) -> Result<String, Error> {
    let origin = sts_origin(config)?;
    let code = config
        .edge_code
        .as_deref()
        .ok_or_else(|| Error::Config(crate::config::MISSING_EDGE_CODE.into()))?;
    Ok(format!("{origin}{REALM_PATH}/e/{code}"))
}

/// Checks the realm from a registry's `401` challenge for a repository and returns it. The realm must be on
/// the STS host of `config`, with the path `/v1/oci/token/e/<edge code>`, so the subject token never goes to
/// another host. The code is the edge code of the repository's tenant. It can be another tenant's code (a
/// grant from that tenant): the subject token still names the caller, so the code is not compared with the
/// configured one.
pub fn check_challenge_realm(config: &Config, realm: &str) -> Result<String, String> {
    let origin = sts_origin(config).map_err(|e| e.to_string())?;
    let refuse = || {
        format!(
            "prego: the registry asks for credentials at `{realm}`, not at the Prego realm \
             `{origin}{REALM_PATH}/e/<edge code>`. The identity was not sent. Check the repository name, or \
             try again later."
        )
    };
    let code = realm
        .strip_prefix(&origin)
        .and_then(|p| p.strip_prefix(REALM_PATH))
        .and_then(|p| p.strip_prefix("/e/"))
        .ok_or_else(refuse)?;
    crate::config::check_edge_code(code).map_err(|_| refuse())?;
    Ok(realm.to_string())
}

#[derive(Deserialize)]
struct Success {
    token: Option<String>,
    access_token: Option<String>,
    expires_in: Option<i64>,
}

#[derive(Deserialize)]
struct Failure {
    errors: Option<Vec<FailureItem>>,
}

#[derive(Deserialize)]
struct FailureItem {
    code: Option<String>,
    message: Option<String>,
}

/// Gets a registry token from the realm: `GET <realm>?service=<service>&scope=<scope>...` with HTTP Basic
/// auth (`tenant`, subject token). Retries on network errors and `5xx`.
pub fn realm_token(
    http: &Http,
    config: &Config,
    service: &str,
    scopes: &[String],
    subject: &SubjectToken,
    now: i64,
    sleep: &dyn Fn(Duration),
) -> Result<RegistryToken, Error> {
    let url = realm_url(config)?;
    realm_token_at(http, &url, config, service, scopes, subject, now, sleep)
}

/// [`realm_token`] at a given realm URL, for example one that [`check_challenge_realm`] accepted.
#[allow(clippy::too_many_arguments)]
pub fn realm_token_at(
    http: &Http,
    url: &str,
    config: &Config,
    service: &str,
    scopes: &[String],
    subject: &SubjectToken,
    now: i64,
    sleep: &dyn Fn(Duration),
) -> Result<RegistryToken, Error> {
    // A device session: the Basic password is a registry token from the session. The realm accepts it for
    // device principals.
    let from_session = match &subject.device {
        Some(device) => Some(crate::session::registry_token(
            http,
            config,
            device,
            None,
            &|| now,
            sleep,
        )?),
        None => None,
    };
    let password = match &from_session {
        Some(t) => t.token.expose(),
        None => subject.value.expose(),
    };
    let basic = Secret::new(STANDARD.encode(format!("{}:{password}", config.tenant)));
    let mut query: Vec<(&str, &str)> = vec![("service", service)];
    query.extend(scopes.iter().map(|s| ("scope", s.as_str())));
    let res = send_with_retry(|| http.get_with_basic(url, &query, &basic), sleep)?;
    parse_realm_response(res.status, &res.body, &config.tenant, now)
}

/// Turns a realm response into a token or an error. Pure, for tests.
pub fn parse_realm_response(
    status: u16,
    body: &str,
    tenant: &str,
    now: i64,
) -> Result<RegistryToken, Error> {
    if status == 200 {
        let body: Success = serde_json::from_str(body)
            .map_err(|_| Error::BadResponse("body is not JSON".into()))?;
        let token = body
            .token
            .or(body.access_token)
            .filter(|t| !t.is_empty())
            .ok_or_else(|| Error::BadResponse("no token".into()))?;
        // The distribution token spec: no `expires_in` means 60 s, and less than 60 s counts as 60 s.
        let lifetime = sts::lifetime(body.expires_in, &token)
            .unwrap_or(MIN_REALM_LIFETIME_SECONDS)
            .max(MIN_REALM_LIFETIME_SECONDS);
        return Ok(RegistryToken::new(Secret::new(token), now, lifetime));
    }
    if status == 401 {
        return Err(Error::Refused {
            tenant: tenant.to_string(),
        });
    }
    let first = serde_json::from_str::<Failure>(body)
        .ok()
        .and_then(|f| f.errors)
        .and_then(|e| e.into_iter().next());
    let (code, description) = match first {
        Some(i) => (i.code, i.message),
        None => (None, None),
    };
    Err(Error::Sts {
        status,
        code,
        description,
    })
}

/// The realm accepts at most this many token requests per minute from one IP address.
pub const MAX_REALM_REQUESTS_PER_MINUTE: usize = 60;
/// The shortest realm token lifetime, and the lifetime when the realm gives no `expires_in` (the distribution
/// token spec).
pub const MIN_REALM_LIFETIME_SECONDS: i64 = 60;

/// Counts requests in a sliding window of one minute, and tells how long to wait before the next one.
#[derive(Debug, Clone)]
pub struct Pacer {
    limit: usize,
    window: Duration,
    sent: VecDeque<Duration>,
}

impl Pacer {
    /// A pacer for `limit` requests in each `window`.
    pub fn new(limit: usize, window: Duration) -> Self {
        Pacer {
            limit: limit.max(1),
            window,
            sent: VecDeque::new(),
        }
    }

    /// Returns how long to wait at time `now` (time since a fixed start) before one more request.
    /// Zero means "send now". Call [`Pacer::record`] when the request is sent.
    pub fn delay(&mut self, now: Duration) -> Duration {
        while let Some(&first) = self.sent.front() {
            if now.saturating_sub(first) >= self.window {
                self.sent.pop_front();
            } else {
                break;
            }
        }
        if self.sent.len() < self.limit {
            return Duration::ZERO;
        }
        let first = self.sent[self.sent.len() - self.limit];
        (first + self.window).saturating_sub(now)
    }

    /// Records one request at time `now`.
    pub fn record(&mut self, now: Duration) {
        self.sent.push_back(now);
        while self.sent.len() > self.limit {
            self.sent.pop_front();
        }
    }
}

/// Gets registry tokens from the realm for one subject token. It keeps one token per scope set and uses it
/// again until `min(60 s, lifetime / 4)` before it expires ([`RegistryToken::is_fresh`]). It sends at most
/// [`MAX_REALM_REQUESTS_PER_MINUTE`] requests per minute, and waits when it must.
pub struct RealmTokens<'a> {
    http: &'a Http,
    realm: String,
    config: &'a Config,
    service: String,
    subject: &'a SubjectToken,
    cache: HashMap<String, RegistryToken>,
    pacer: Pacer,
    start: Instant,
    sleep: &'a dyn Fn(Duration),
    requests: usize,
}

impl<'a> RealmTokens<'a> {
    /// A token source for `service` (the OCI host) at `realm` (from [`check_challenge_realm`] or
    /// [`realm_url`]). `sleep` is used for pacing and retries.
    pub fn new(
        http: &'a Http,
        realm: String,
        config: &'a Config,
        service: &str,
        subject: &'a SubjectToken,
        sleep: &'a dyn Fn(Duration),
    ) -> Self {
        RealmTokens {
            http,
            realm,
            config,
            service: service.to_string(),
            subject,
            cache: HashMap::new(),
            pacer: Pacer::new(MAX_REALM_REQUESTS_PER_MINUTE, Duration::from_secs(60)),
            start: Instant::now(),
            sleep,
            requests: 0,
        }
    }

    /// Returns a token for `scopes`: the kept one if it is still valid, else a new one from the realm.
    pub fn token(&mut self, scopes: &[String]) -> Result<Secret, Error> {
        let key = scope_key(scopes);
        let now = crate::now_unix();
        if let Some(t) = self.cache.get(&key) {
            if t.is_fresh(now) {
                return Ok(t.token.clone());
            }
        }
        let wait = self.pacer.delay(self.start.elapsed());
        if !wait.is_zero() {
            (self.sleep)(wait);
        }
        self.pacer.record(self.start.elapsed());
        self.requests += 1;
        let t = realm_token_at(
            self.http,
            &self.realm,
            self.config,
            &self.service,
            scopes,
            self.subject,
            now,
            self.sleep,
        )?;
        let secret = t.token.clone();
        self.cache.insert(key, t);
        Ok(secret)
    }

    /// Drops the kept token for `scopes`, for example after the registry refused it with `401`.
    pub fn invalidate(&mut self, scopes: &[String]) {
        self.cache.remove(&scope_key(scopes));
    }

    /// The number of realm requests sent so far (retries of one request count once).
    pub fn requests(&self) -> usize {
        self.requests
    }
}

fn scope_key(scopes: &[String]) -> String {
    let mut s: Vec<&str> = scopes.iter().map(String::as_str).collect();
    s.sort_unstable();
    s.dedup();
    s.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::MapEnv;
    use crate::sources::{SourceKind, TokenType};
    use crate::testing::{MockResponse, MockServer};

    #[test]
    fn normalizes_server_urls() {
        for url in [
            "oci.prego.k8skill.com",
            "https://oci.prego.k8skill.com",
            "https://oci.prego.k8skill.com/v2/",
            "OCI.Prego.K8skill.com:443",
            " https://oci.prego.k8skill.com\n",
        ] {
            assert_eq!(
                normalize_host(url).as_deref(),
                Some(DEFAULT_OCI_HOST),
                "{url}"
            );
        }
        assert_eq!(
            normalize_host("http://localhost:5000/v2/").as_deref(),
            Some("localhost:5000")
        );
        assert_eq!(normalize_host("  "), None);
    }

    #[test]
    fn lookalike_hosts_do_not_match() {
        let hosts = oci_hosts(&FileConfig::default(), &MapEnv::new());
        for url in [
            "oci.prego.k8skill.com.evil.test",
            "evil.test/oci.prego.k8skill.com",
            "https://oci.prego.k8skill.com:8443",
            "prego.k8skill.com",
        ] {
            let h = normalize_host(url).unwrap();
            assert!(!hosts.contains(&h), "{url}");
        }
    }

    #[test]
    fn extra_hosts_from_file_and_env() {
        let file = FileConfig {
            oci_hosts: vec!["https://oci.one.test/".into()],
            ..FileConfig::default()
        };
        let env = MapEnv::new().with("PREGO_OCI_HOSTS", "oci.two.test, ,oci.prego.k8skill.com");
        assert_eq!(
            oci_hosts(&file, &env),
            vec![DEFAULT_OCI_HOST, "oci.one.test", "oci.two.test"]
        );
    }

    fn config(sts_url: &str) -> Config {
        Config {
            tenant: "acme".into(),
            sts_url: sts_url.into(),
            edge_code: Some("k7mq".into()),
            audience: crate::DEFAULT_AUDIENCE.into(),
            source: crate::SourceChoice::Auto,
            ca_file: None,
        }
    }

    #[test]
    fn realm_is_on_the_sts_host() {
        assert_eq!(
            realm_url(&config(crate::DEFAULT_STS_URL)).unwrap(),
            "https://sts.prego.k8skill.com/v1/oci/token/e/k7mq"
        );
        assert_eq!(
            realm_url(&config("http://127.0.0.1:8787/v1/sts/token")).unwrap(),
            "http://127.0.0.1:8787/v1/oci/token/e/k7mq"
        );
        let mut none = config(crate::DEFAULT_STS_URL);
        none.edge_code = None;
        assert!(realm_url(&none)
            .unwrap_err()
            .to_string()
            .contains("PREGO_EDGE_CODE"));
    }

    #[test]
    fn challenge_realm_checks() {
        let cfg = config(crate::DEFAULT_STS_URL);
        let good = "https://sts.prego.k8skill.com/v1/oci/token/e/k7mq";
        assert_eq!(check_challenge_realm(&cfg, good).unwrap(), good);
        for bad in [
            "https://sts.prego.k8skill.com/v1/oci/token",
            "https://sts.prego.k8skill.com/v1/oci/token/t/acme",
            "https://sts.prego.k8skill.com/v1/oci/token/e/K7MQ",
            "https://sts.prego.k8skill.com/v1/oci/token/e/k7mq/x",
            "https://evil.example.test/v1/oci/token/e/k7mq",
            "http://sts.prego.k8skill.com/v1/oci/token/e/k7mq",
            "https://sts.prego.k8skill.com.evil.example.test/v1/oci/token/e/k7mq",
        ] {
            let e = check_challenge_realm(&cfg, bad).unwrap_err();
            assert!(e.contains("not sent"), "{bad}: {e}");
        }
        // Another tenant's code (a cross-tenant grant) is accepted: the subject token names the caller.
        let other = "https://sts.prego.k8skill.com/v1/oci/token/e/ab2c";
        assert_eq!(check_challenge_realm(&cfg, other).unwrap(), other);
        // Without an edge code in the settings, the realm gives it.
        let mut none = cfg.clone();
        none.edge_code = None;
        let other = "https://sts.prego.k8skill.com/v1/oci/token/e/ab2c";
        assert_eq!(check_challenge_realm(&none, other).unwrap(), other);
    }

    #[test]
    fn calls_realm_with_basic_auth_and_scopes() {
        let server = MockServer::start(vec![MockResponse::json(
            200,
            r#"{"token":"reg","access_token":"reg","expires_in":900,"issued_at":"2026-11-03T00:00:00Z"}"#,
        )]);
        let cfg = config(&format!("{}/v1/sts/token", server.base_url()));
        let subject = SubjectToken {
            kind: SourceKind::ApiKey,
            token_type: TokenType::ApiKey,
            value: Secret::new("prk_x"),
            device: None,
        };
        let t = realm_token(
            &Http::new("test"),
            &cfg,
            DEFAULT_OCI_HOST,
            &["repository:acme/default/api:pull,push".into()],
            &subject,
            1_000,
            &|_| {},
        )
        .unwrap();
        assert_eq!(t.token.expose(), "reg");
        assert_eq!(t.expires_at, 1_900);
        let reqs = server.requests();
        assert_eq!(reqs[0].method, "GET");
        assert_eq!(
            reqs[0].target,
            "/v1/oci/token/e/k7mq?service=oci.prego.k8skill.com&scope=repository%3Aacme%2Fdefault%2Fapi%3Apull%2Cpush"
        );
        assert_eq!(
            reqs[0].header("authorization").as_deref(),
            Some(format!("Basic {}", STANDARD.encode("acme:prk_x")).as_str())
        );
    }

    #[test]
    fn realm_errors() {
        assert!(matches!(
            parse_realm_response(401, r#"{"errors":[{"code":"UNAUTHORIZED"}]}"#, "acme", 0),
            Err(Error::Refused { .. })
        ));
        match parse_realm_response(
            429,
            r#"{"errors":[{"code":"TOOMANYREQUESTS","message":"slow down"}]}"#,
            "acme",
            0,
        ) {
            Err(Error::Sts {
                status: 429,
                code,
                description,
            }) => {
                assert_eq!(code.as_deref(), Some("TOOMANYREQUESTS"));
                assert_eq!(description.as_deref(), Some("slow down"));
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            parse_realm_response(200, "{}", "acme", 0),
            Err(Error::BadResponse(_))
        ));
    }

    #[test]
    fn pacer_waits_for_the_oldest_request_to_leave_the_window() {
        let min = Duration::from_secs(60);
        let mut p = Pacer::new(3, min);
        for s in [0, 1, 2] {
            let t = Duration::from_secs(s);
            assert_eq!(p.delay(t), Duration::ZERO);
            p.record(t);
        }
        assert_eq!(p.delay(Duration::from_secs(10)), Duration::from_secs(50));
        assert_eq!(p.delay(Duration::from_secs(60)), Duration::ZERO);
        p.record(Duration::from_secs(60));
        assert_eq!(p.delay(Duration::from_secs(60)), Duration::from_secs(1));
        assert_eq!(p.delay(Duration::from_secs(200)), Duration::ZERO);
    }

    #[test]
    fn pacer_allows_sixty_per_minute() {
        let mut p = Pacer::new(MAX_REALM_REQUESTS_PER_MINUTE, Duration::from_secs(60));
        let mut now = Duration::ZERO;
        for _ in 0..200 {
            now += p.delay(now);
            p.record(now);
        }
        // 200 requests at 60 per minute: the last one goes out after at least 3 full minutes.
        assert!(now >= Duration::from_secs(180), "{now:?}");
        assert!(now < Duration::from_secs(181), "{now:?}");
    }

    fn api_key() -> SubjectToken {
        SubjectToken {
            kind: SourceKind::ApiKey,
            token_type: TokenType::ApiKey,
            value: Secret::new("prk_x"),
            device: None,
        }
    }

    fn realm_ok(token: &str, expires_in: i64) -> MockResponse {
        MockResponse::json(
            200,
            &format!(r#"{{"token":"{token}","expires_in":{expires_in}}}"#),
        )
    }

    #[test]
    fn reuses_one_token_per_scope_set() {
        let server = MockServer::start(vec![
            realm_ok("t1", 900),
            realm_ok("t2", 900),
            realm_ok("t3", 900),
        ]);
        let cfg = config(&format!("{}/v1/sts/token", server.base_url()));
        let http = Http::new("test");
        let subject = api_key();
        let mut tokens = RealmTokens::new(
            &http,
            realm_url(&cfg).unwrap(),
            &cfg,
            DEFAULT_OCI_HOST,
            &subject,
            &|_| {},
        );
        let a = vec![
            "repository:acme/d/a:pull,push".to_string(),
            "repository:acme/d/b:pull".into(),
        ];
        let a_reordered = vec![a[1].clone(), a[0].clone()];
        let b = vec!["repository:acme/d/c:pull".to_string()];

        assert_eq!(tokens.token(&a).unwrap().expose(), "t1");
        assert_eq!(tokens.token(&a_reordered).unwrap().expose(), "t1");
        assert_eq!(tokens.token(&b).unwrap().expose(), "t2");
        assert_eq!(tokens.requests(), 2);
        tokens.invalidate(&a);
        assert_eq!(tokens.token(&a).unwrap().expose(), "t3");
        assert_eq!(tokens.requests(), 3);
        assert_eq!(server.requests().len(), 3);
    }

    #[test]
    fn short_realm_tokens_count_as_60_seconds() {
        // 20 s counts as 60 s (the distribution floor), with a margin of 15 s: the token is kept.
        let server = MockServer::start(vec![realm_ok("t1", 20), realm_ok("t2", 20)]);
        let cfg = config(&format!("{}/v1/sts/token", server.base_url()));
        let http = Http::new("test");
        let subject = api_key();
        let mut tokens = RealmTokens::new(
            &http,
            realm_url(&cfg).unwrap(),
            &cfg,
            DEFAULT_OCI_HOST,
            &subject,
            &|_| {},
        );
        let s = vec!["repository:acme/d/a:pull".to_string()];
        assert_eq!(tokens.token(&s).unwrap().expose(), "t1");
        assert_eq!(tokens.token(&s).unwrap().expose(), "t1");
        assert_eq!(tokens.requests(), 1);
    }

    #[test]
    fn realm_lifetimes() {
        let t = parse_realm_response(200, r#"{"token":"x"}"#, "acme", 1_000).unwrap();
        assert_eq!((t.lifetime, t.expires_at, t.margin()), (60, 1_060, 15));
        let t = parse_realm_response(200, r#"{"token":"x","expires_in":5}"#, "acme", 0).unwrap();
        assert_eq!(t.lifetime, 60);
        let t = parse_realm_response(200, r#"{"token":"x","expires_in":300}"#, "acme", 0).unwrap();
        assert_eq!((t.lifetime, t.fresh_until()), (300, 240));
    }
}
