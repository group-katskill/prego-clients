use std::cell::Cell;
use std::sync::Arc;

use super::store::MemStore;
use super::*;
use crate::testing::{MockResponse, MockServer};

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

fn http() -> Http {
    Http::new("test")
}

fn no_sleep(_: Duration) {}

fn start_answer() -> MockResponse {
    MockResponse::json(
        200,
        r#"{"device_code":"dc-1","user_code":"ABCD-EFGH","verification_uri":"https://console.example.test/device","verification_uri_complete":"https://console.example.test/device?code=ABCD-EFGH","expires_in":300,"interval":5}"#,
    )
}

fn token_answer(access: &str, refresh: &str, with_details: bool) -> MockResponse {
    let session = if with_details {
        r#"{"id":"dvs_1","name":"prego-cli on laptop","access":[{"ecosystem":"any","namespace":"default","actions":["read"]}],"idle_expires_at":1604800,"expires_at":3592000}"#
    } else {
        r#"{"id":"dvs_1","idle_expires_at":1700000,"expires_at":3592000}"#
    };
    MockResponse::json(
        200,
        &format!(
            r#"{{"access_token":"{access}","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":900,"refresh_token":"{refresh}","session":{session}}}"#
        ),
    )
}

fn error(status: u16, code: &str) -> MockResponse {
    MockResponse::json(
        status,
        &format!(r#"{{"error":"{code}","error_description":"text for {code}"}}"#),
    )
}

fn handle(store: &Arc<MemStore>) -> DeviceHandle {
    let dir = std::env::temp_dir().join(format!("prego-lock-test-{}", std::process::id()));
    DeviceHandle::with_store(store.clone(), Some(dir))
}

fn refresh_token_in(store: &MemStore, config: &Config) -> String {
    let text = store.load(&session_key(config)).unwrap().unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    v["refresh_token"].as_str().unwrap().to_string()
}

/// Logs in through the mock: start, then one poll that gives the session.
fn logged_in(server: &MockServer, store: &MemStore) -> Config {
    let cfg = config(server);
    let code = start(
        &http(),
        &cfg,
        "prego-cli/test",
        &Access::request(false),
        &no_sleep,
    )
    .unwrap();
    wait_for_approval(&http(), &cfg, store, &code, &|| 1_000_000, &no_sleep).unwrap();
    cfg
}

#[test]
fn login_sends_the_wire_shapes_and_stores_the_session() {
    let server = MockServer::start(vec![
        start_answer(),
        error(400, "authorization_pending"),
        error(400, "slow_down"),
        token_answer("reg-1", "rt-1", true),
    ]);
    let store = MemStore::default();
    let cfg = config(&server);
    let code = start(
        &http(),
        &cfg,
        "prego-cli/0.7.0",
        &Access::request(true),
        &no_sleep,
    )
    .unwrap();
    assert_eq!(code.user_code, "ABCD-EFGH");
    assert_eq!(code.interval, 5);

    let slept = Cell::new(Vec::new());
    let sleep = |d: Duration| {
        let mut v = slept.take();
        v.push(d.as_secs());
        slept.set(v);
    };
    let info = wait_for_approval(&http(), &cfg, &store, &code, &|| 1_000_000, &sleep).unwrap();
    assert_eq!(info.id, "dvs_1");
    assert_eq!(info.name.as_deref(), Some("prego-cli on laptop"));
    // slow_down adds 5 s to the interval.
    assert_eq!(slept.take(), vec![5, 5, 10]);
    assert_eq!(refresh_token_in(&store, &cfg), "rt-1");

    let reqs = server.requests();
    assert_eq!(reqs[0].target, "/v1/sts/device/e/k7mq/start");
    assert_eq!(
        reqs[0].header("content-type").as_deref(),
        Some("application/json")
    );
    let body: serde_json::Value = serde_json::from_str(&reqs[0].body).unwrap();
    assert_eq!(
        body,
        serde_json::json!({"client":"prego-cli/0.7.0","access":[{"ecosystem":"any","actions":["read","publish"]}]})
    );
    // The edge code picks the tenant: no `tenant` in the start body.
    assert!(body.get("tenant").is_none());
    for r in &reqs[1..] {
        assert_eq!(r.target, "/v1/sts/device/e/k7mq/token");
        let form = r.form();
        assert_eq!(form["grant_type"], DEVICE_GRANT_TYPE);
        assert_eq!(form["device_code"], "dc-1");
    }
    assert_eq!(status(&cfg, &store).unwrap().unwrap(), info);
}

#[test]
fn denied_and_expired_requests_stop() {
    let server = MockServer::start(vec![
        start_answer(),
        error(400, "access_denied"),
        start_answer(),
        error(400, "expired_token"),
    ]);
    let store = MemStore::default();
    let cfg = config(&server);
    for want in ["denied in the console", "expired before it was approved"] {
        let code = start(&http(), &cfg, "c", &Access::request(false), &no_sleep).unwrap();
        let e = wait_for_approval(&http(), &cfg, &store, &code, &|| 0, &no_sleep).unwrap_err();
        assert!(e.to_string().contains(want), "{e}");
    }
    assert!(status(&cfg, &store).unwrap().is_none());
}

#[test]
fn polls_stop_at_the_request_expiry() {
    let server = MockServer::start(vec![start_answer()]);
    let store = MemStore::default();
    let cfg = config(&server);
    let code = start(&http(), &cfg, "c", &Access::request(false), &no_sleep).unwrap();
    let clock = Cell::new(0);
    let now = || {
        clock.set(clock.get() + 400);
        clock.get()
    };
    let e = wait_for_approval(&http(), &cfg, &store, &code, &now, &no_sleep).unwrap_err();
    assert!(e.to_string().contains("expired"), "{e}");
    assert_eq!(server.requests().len(), 1);
}

#[test]
fn start_rate_limit_is_a_429_error() {
    let limited = || error(429, "rate_limited").with_header("Retry-After", "7");
    let server = MockServer::start(vec![limited(), limited(), limited()]);
    let e = start(
        &http(),
        &config(&server),
        "c",
        &Access::request(false),
        &no_sleep,
    )
    .unwrap_err();
    assert!(
        matches!(
            e,
            Error::RateLimited {
                retry_after: Some(7),
                ..
            }
        ),
        "{e:?}"
    );
}

#[test]
fn refresh_rotates_and_keeps_fresh_tokens() {
    let server = MockServer::start(vec![
        start_answer(),
        token_answer("reg-1", "rt-1", true),
        token_answer("reg-2", "rt-2", false),
    ]);
    let store = Arc::new(MemStore::default());
    let cfg = logged_in(&server, &store);
    let device = handle(&store);
    let res = "https://cargo.example.test/t/acme/default/";

    // The poll's token has no resource. A token for a resource needs a refresh.
    let t = registry_token(&http(), &cfg, &device, Some(res), &|| 1_000_100, &no_sleep).unwrap();
    assert_eq!(t.token.expose(), "reg-2");
    assert_eq!(t.expires_at, 1_000_100 + 900);
    // The new refresh token is stored; name and access stay from the login.
    assert_eq!(refresh_token_in(&store, &cfg), "rt-2");
    let info = status(&cfg, store.as_ref()).unwrap().unwrap();
    assert_eq!(info.name.as_deref(), Some("prego-cli on laptop"));
    assert_eq!(info.access.len(), 1);
    assert_eq!(info.idle_expires_at, 1_700_000);

    // Both tokens are fresh now: no more requests.
    let t = registry_token(&http(), &cfg, &device, Some(res), &|| 1_000_200, &no_sleep).unwrap();
    assert_eq!(t.token.expose(), "reg-2");
    let t = registry_token(&http(), &cfg, &device, None, &|| 1_000_200, &no_sleep).unwrap();
    assert_eq!(t.token.expose(), "reg-1");

    let reqs = server.requests();
    assert_eq!(reqs.len(), 3);
    assert_eq!(reqs[2].target, "/v1/sts/token/e/k7mq");
    let form = reqs[2].form();
    assert_eq!(form["grant_type"], "refresh_token");
    assert_eq!(form["refresh_token"], "rt-1");
    assert_eq!(form["resource"], res);
    // The session picks the tenant.
    assert!(!form.contains_key("tenant"));
}

#[test]
fn an_expired_token_is_refreshed() {
    let server = MockServer::start(vec![
        start_answer(),
        token_answer("reg-1", "rt-1", true),
        token_answer("reg-2", "rt-2", false),
    ]);
    let store = Arc::new(MemStore::default());
    let cfg = logged_in(&server, &store);
    let device = handle(&store);
    // 900 s lifetime, 60 s margin: fresh until 1_000_840.
    let t = registry_token(&http(), &cfg, &device, None, &|| 1_000_840, &no_sleep).unwrap();
    assert_eq!(t.token.expose(), "reg-2");
    assert_eq!(server.requests().len(), 3);
}

#[test]
fn an_ended_session_is_deleted() {
    let server = MockServer::start(vec![
        start_answer(),
        token_answer("reg-1", "rt-1", true),
        MockResponse::json(
            400,
            r#"{"error":"invalid_grant","error_description":"the login session ended; run prego login again"}"#,
        ),
    ]);
    let store = Arc::new(MemStore::default());
    let cfg = logged_in(&server, &store);
    let device = handle(&store);
    let e =
        registry_token(&http(), &cfg, &device, Some("r"), &|| 1_000_000, &no_sleep).unwrap_err();
    assert_eq!(
        e.to_string(),
        "prego: the login session ended; run prego login again."
    );
    assert!(store.0.lock().unwrap().is_empty());
    let e = registry_token(&http(), &cfg, &device, None, &|| 1_000_000, &no_sleep).unwrap_err();
    assert!(e.to_string().contains("not logged in"), "{e}");
}

#[test]
fn an_ended_trial_keeps_the_session() {
    let trial =
        "trial ended for tenant acme; an owner can choose a plan at https://app.prego.k8skill.com";
    let server = MockServer::start(vec![
        start_answer(),
        token_answer("reg-1", "rt-1", true),
        MockResponse::json(
            401,
            &format!(r#"{{"error":"invalid_grant","error_description":"{trial}"}}"#),
        ),
    ]);
    let store = Arc::new(MemStore::default());
    let cfg = logged_in(&server, &store);
    let device = handle(&store);
    let e =
        registry_token(&http(), &cfg, &device, Some("r"), &|| 1_000_000, &no_sleep).unwrap_err();
    assert!(e.to_string().contains(trial), "{e}");
    // Only a 400 ends the session.
    assert_eq!(refresh_token_in(&store, &cfg), "rt-1");
    assert!(status(&cfg, store.as_ref()).unwrap().is_some());
}

#[test]
fn docker_gets_a_session_token_with_half_its_lifetime_left() {
    let server = MockServer::start(vec![
        start_answer(),
        token_answer("reg-1", "rt-1", true),
        token_answer("reg-2", "rt-2", false),
    ]);
    let store = Arc::new(MemStore::default());
    let cfg = logged_in(&server, &store);
    let device = handle(&store);
    // reg-1: 900 s from 1_000_000. 500 s left is more than half: no request.
    let t = registry_token_for_docker(&http(), &cfg, &device, &|| 1_000_400, &no_sleep).unwrap();
    assert_eq!(t.token.expose(), "reg-1");
    assert_eq!(server.requests().len(), 2);
    // 400 s left: still fresh for the other tools, but Docker gets a new token from a session refresh.
    let t = registry_token(&http(), &cfg, &device, None, &|| 1_000_500, &no_sleep).unwrap();
    assert_eq!(t.token.expose(), "reg-1");
    let t = registry_token_for_docker(&http(), &cfg, &device, &|| 1_000_500, &no_sleep).unwrap();
    assert_eq!(t.token.expose(), "reg-2");
    let reqs = server.requests();
    assert_eq!(reqs.len(), 3);
    assert_eq!(reqs[2].target, "/v1/sts/token/e/k7mq");
    assert_eq!(reqs[2].form()["grant_type"], "refresh_token");
    assert_eq!(reqs[2].form()["refresh_token"], "rt-1");
    assert!(!reqs[2].form().contains_key("resource"));
}

#[test]
fn logout_revokes_and_deletes() {
    let server = MockServer::start(vec![
        start_answer(),
        token_answer("reg-1", "rt-1", true),
        MockResponse::json(200, "{}"),
    ]);
    let store = MemStore::default();
    let cfg = logged_in(&server, &store);
    assert_eq!(
        logout(&http(), &cfg, &store, &no_sleep).unwrap(),
        Logout::Revoked
    );
    assert!(store.0.lock().unwrap().is_empty());
    let reqs = server.requests();
    assert_eq!(reqs[2].target, "/v1/sts/device/e/k7mq/revoke");
    assert_eq!(reqs[2].form()["refresh_token"], "rt-1");
    assert_eq!(
        logout(&http(), &cfg, &store, &no_sleep).unwrap(),
        Logout::NoSession
    );
}

#[test]
fn logout_deletes_local_data_when_the_sts_fails() {
    let server = MockServer::start(vec![
        start_answer(),
        token_answer("reg-1", "rt-1", true),
        MockResponse::json(503, ""),
        MockResponse::json(503, ""),
        MockResponse::json(503, ""),
    ]);
    let store = MemStore::default();
    let cfg = logged_in(&server, &store);
    let out = logout(&http(), &cfg, &store, &no_sleep).unwrap();
    assert!(matches!(out, Logout::LocalOnly(_)), "{out:?}");
    assert!(store.0.lock().unwrap().is_empty());
}

#[test]
fn no_edge_code_stops_before_any_request() {
    let server = MockServer::start(vec![]);
    let mut cfg = config(&server);
    cfg.edge_code = None;
    let e = start(&http(), &cfg, "c", &Access::request(false), &no_sleep).unwrap_err();
    assert!(e.to_string().contains("edge code"), "{e}");
    assert!(server.requests().is_empty());
}

#[test]
fn stored_record_debug_and_errors_hold_no_token() {
    let server = MockServer::start(vec![start_answer(), token_answer("reg-1", "rt-1", true)]);
    let store = Arc::new(MemStore::default());
    let cfg = logged_in(&server, &store);
    let device = handle(&store);
    let shown = format!("{device:?} {:?}", status(&cfg, store.as_ref()).unwrap());
    assert!(
        !shown.contains("rt-1") && !shown.contains("reg-1"),
        "{shown}"
    );
}
