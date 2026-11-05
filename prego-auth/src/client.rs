use std::time::Duration;

use crate::config::Config;
use crate::env::Env;
use crate::error::Error;
use crate::http::Http;
use crate::sources::find_subject_token;
use crate::sts::{self, RegistryToken};

/// Finds a subject token and exchanges it at the STS for a registry token.
///
/// There is no token cache in the client. Cargo caches the token with the `expires` hint.
/// Tokens are never written to disk.
pub struct TokenClient {
    user_agent: String,
    now: fn() -> i64,
    sleep: fn(Duration),
}

impl TokenClient {
    /// Makes a client. `user_agent` goes in the `User-Agent` header.
    pub fn new(user_agent: &str) -> Self {
        TokenClient {
            user_agent: user_agent.to_string(),
            now: crate::now_unix,
            sleep: std::thread::sleep,
        }
    }

    /// Replaces the clock and the retry sleep. For tests.
    pub fn with_time(mut self, now: fn() -> i64, sleep: fn(Duration)) -> Self {
        self.now = now;
        self.sleep = sleep;
        self
    }

    /// Returns a new registry token for `config`, with no `resource`.
    pub fn registry_token(&self, config: &Config, env: &dyn Env) -> Result<RegistryToken, Error> {
        self.registry_token_for(config, env, None)
    }

    /// Returns a new registry token for `config` and the registry base URL `resource` (see
    /// [`sts::resource_base`]).
    pub fn registry_token_for(
        &self,
        config: &Config,
        env: &dyn Env,
        resource: Option<&str>,
    ) -> Result<RegistryToken, Error> {
        let http = Http::with_ca_file(&self.user_agent, config.ca_file.as_deref())
            .map_err(|e| Error::Config(format!("PREGO_CA_FILE: {e}")))?;
        let subject = find_subject_token(config, env, &http)?;
        sts::exchange(&http, config, &subject, resource, (self.now)(), &self.sleep)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::MapEnv;
    use crate::testing::{MockResponse, MockServer};

    fn fixed_now() -> i64 {
        1_000
    }

    fn no_sleep(_: Duration) {}

    fn config(server: &MockServer) -> Config {
        Config {
            tenant: "acme".into(),
            sts_url: format!("{}/v1/sts/token", server.base_url()),
            edge_code: Some("k7mq".into()),
            audience: crate::DEFAULT_AUDIENCE.into(),
            source: crate::SourceChoice::Auto,
            ca_file: None,
        }
    }

    fn ok_body() -> MockResponse {
        MockResponse::json(
            200,
            r#"{"access_token":"reg-token","token_type":"Bearer","expires_in":900}"#,
        )
    }

    #[test]
    fn exchanges_api_key_with_form_fields() {
        let server = MockServer::start(vec![ok_body()]);
        let client = TokenClient::new("test").with_time(fixed_now, no_sleep);
        let env = MapEnv::new().with("PREGO_API_KEY", "prk_test");
        let t = client.registry_token(&config(&server), &env).unwrap();
        assert_eq!(t.token.expose(), "reg-token");
        assert_eq!(t.expires_at, 1_900);

        let reqs = server.requests();
        assert_eq!(reqs[0].method, "POST");
        assert_eq!(reqs[0].target, "/v1/sts/token/e/k7mq");
        assert_eq!(
            reqs[0].header("content-type").as_deref(),
            Some("application/x-www-form-urlencoded")
        );
        let form = reqs[0].form();
        assert_eq!(form["grant_type"], sts::GRANT_TYPE);
        assert_eq!(form["subject_token"], "prk_test");
        assert_eq!(
            form["subject_token_type"],
            "urn:k8skill:prego:token-type:api-key"
        );
        assert_eq!(form["tenant"], "acme");
    }

    #[test]
    fn sends_resource_and_falls_back_once_on_invalid_target() {
        let server = MockServer::start(vec![
            MockResponse::json(
                200,
                r#"{"access_token":"reg-token","token_type":"Bearer","expires_in":60}"#,
            ),
            MockResponse::json(400, r#"{"error":"invalid_target"}"#),
            ok_body(),
            MockResponse::json(400, r#"{"error":"invalid_target"}"#),
            MockResponse::json(400, r#"{"error":"invalid_target"}"#),
        ]);
        let client = TokenClient::new("test").with_time(fixed_now, no_sleep);
        let env = MapEnv::new().with("PREGO_API_KEY", "prk_test");
        let res = "https://cargo.prego.k8skill.com/t/acme/default/";
        let t = client
            .registry_token_for(&config(&server), &env, Some(res))
            .unwrap();
        assert_eq!((t.lifetime, t.expires_at), (60, 1_060));
        // A refused resource: one more request without it.
        let t = client
            .registry_token_for(&config(&server), &env, Some(res))
            .unwrap();
        assert_eq!(t.lifetime, 900);
        // invalid_target without a resource, or twice: no loop.
        let e = client
            .registry_token_for(&config(&server), &env, Some(res))
            .unwrap_err();
        assert!(matches!(e, Error::Sts { status: 400, .. }), "{e:?}");
        let reqs = server.requests();
        assert_eq!(reqs.len(), 5);
        assert_eq!(reqs[0].form()["resource"], res);
        assert_eq!(reqs[1].form()["resource"], res);
        assert!(!reqs[2].form().contains_key("resource"));
        assert_eq!(reqs[3].form()["resource"], res);
        assert!(!reqs[4].form().contains_key("resource"));
    }

    #[test]
    fn waits_for_retry_after_on_429_at_most_twice() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SLEPT_MS: AtomicU64 = AtomicU64::new(0);
        fn count_sleep(d: Duration) {
            SLEPT_MS.fetch_add(d.as_millis() as u64, Ordering::SeqCst);
        }
        let limited = || {
            MockResponse::json(429, r#"{"error":"rate_limited"}"#).with_header("Retry-After", "3")
        };
        let server = MockServer::start(vec![limited(), ok_body(), limited(), limited(), limited()]);
        let client = TokenClient::new("test").with_time(fixed_now, count_sleep);
        let env = MapEnv::new().with("PREGO_API_KEY", "prk_test");
        client.registry_token(&config(&server), &env).unwrap();
        let first = SLEPT_MS.load(Ordering::SeqCst);
        assert!((3000..3500).contains(&first), "{first}");
        let e = client.registry_token(&config(&server), &env).unwrap_err();
        assert_eq!(
            e,
            Error::RateLimited {
                tenant: "acme".into(),
                retry_after: Some(3)
            }
        );
        assert!(
            e.to_string().contains("budget per minute of tenant acme"),
            "{e}"
        );
        let total = SLEPT_MS.load(Ordering::SeqCst) - first;
        assert!((6000..7000).contains(&total), "{total}");
        assert_eq!(server.requests().len(), 5);
    }

    #[test]
    fn every_call_exchanges_again() {
        let server = MockServer::start(vec![ok_body(), ok_body()]);
        let client = TokenClient::new("test").with_time(fixed_now, no_sleep);
        let env = MapEnv::new().with("PREGO_API_KEY", "prk_test");
        client.registry_token(&config(&server), &env).unwrap();
        client.registry_token(&config(&server), &env).unwrap();
        assert_eq!(server.requests().len(), 2);
    }

    #[test]
    fn bad_ca_file_fails_before_any_request() {
        let server = MockServer::start(vec![ok_body()]);
        let client = TokenClient::new("test").with_time(fixed_now, no_sleep);
        let env = MapEnv::new().with("PREGO_API_KEY", "prk_test");
        let mut cfg = config(&server);
        cfg.ca_file = Some("/nonexistent/prego/ca.pem".into());
        let e = client.registry_token(&cfg, &env).unwrap_err();
        assert!(e.to_string().contains("PREGO_CA_FILE"), "{e}");
        assert!(server.requests().is_empty());
    }

    #[test]
    fn retries_5xx_against_real_http() {
        let server = MockServer::start(vec![
            MockResponse::json(503, ""),
            MockResponse::json(502, ""),
            ok_body(),
        ]);
        let client = TokenClient::new("test").with_time(fixed_now, no_sleep);
        let env = MapEnv::new().with("PREGO_API_KEY", "prk_test");
        client.registry_token(&config(&server), &env).unwrap();
        assert_eq!(server.requests().len(), 3);
    }

    #[test]
    fn does_not_follow_redirects() {
        let server =
            MockServer::start(vec![MockResponse::redirect("http://127.0.0.1:1/elsewhere")]);
        let client = TokenClient::new("test").with_time(fixed_now, no_sleep);
        let env = MapEnv::new().with("PREGO_API_KEY", "prk_test");
        let e = client.registry_token(&config(&server), &env).unwrap_err();
        assert!(matches!(e, Error::Sts { status: 307, .. }), "{e:?}");
        assert_eq!(server.requests().len(), 1);
    }
}
