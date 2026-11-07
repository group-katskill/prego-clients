//! `prego login`, `status`, `logout` and the login session as the last identity source, against a mock STS.
//! The session goes to a test directory store (`PREGO_TEST_SESSION_DIR`, test builds only).

use std::path::PathBuf;
use std::process::Command;

use prego_auth::testing::{MockResponse, MockServer};
use serde_json::json;

const BIN: &str = env!("CARGO_BIN_EXE_prego");
const REG_1: &str = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkcm5fMSJ9.b25l";
const REG_2: &str = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkcm5fMiJ9.dHdv";

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str], env: &[(&str, &str)]) -> Run {
    let mut cmd = Command::new(BIN);
    cmd.args(args).env_clear();
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("run prego");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("prego-login-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn start_answer() -> MockResponse {
    MockResponse::json(
        200,
        &json!({
            "device_code": "dc-1", "user_code": "WXYZ-2345",
            "verification_uri": "https://console.example.test/device",
            "verification_uri_complete": "https://console.example.test/device?code=WXYZ-2345",
            "expires_in": 300, "interval": 1
        })
        .to_string(),
    )
}

fn token_answer(access: &str, refresh: &str) -> MockResponse {
    MockResponse::json(
        200,
        &json!({
            "access_token": access, "token_type": "Bearer", "expires_in": 900,
            "refresh_token": refresh,
            "session": {
                "id": "dvs_01", "name": "prego-cli on laptop",
                "access": [{"ecosystem": "any", "namespace": "default", "actions": ["read", "publish"]}],
                "idle_expires_at": 4_102_444_800i64, "expires_at": 4_102_444_800i64
            }
        })
        .to_string(),
    )
}

struct Env {
    _server_url: String,
    sts: String,
    store: String,
    runtime: String,
}

impl Env {
    fn new(server: &MockServer, name: &str) -> Self {
        Env {
            _server_url: server.base_url(),
            sts: format!("{}/v1/sts/token", server.base_url()),
            store: temp_dir(&format!("{name}-store")).display().to_string(),
            runtime: temp_dir(&format!("{name}-run")).display().to_string(),
        }
    }

    fn vars(&self) -> Vec<(&str, &str)> {
        vec![
            ("PREGO_TENANT", "acme"),
            ("PREGO_EDGE_CODE", "k7mq"),
            ("PREGO_STS_URL", self.sts.as_str()),
            ("PREGO_TEST_SESSION_DIR", self.store.as_str()),
            ("XDG_RUNTIME_DIR", self.runtime.as_str()),
        ]
    }
}

#[test]
fn login_status_token_logout() {
    let server = MockServer::start(vec![
        start_answer(),
        MockResponse::json(400, r#"{"error":"authorization_pending"}"#),
        token_answer(REG_1, "rt-1"),
        token_answer(REG_2, "rt-2"),
        MockResponse::json(200, "{}"),
    ]);
    let env = Env::new(&server, "flow");
    let vars = env.vars();

    let r = run(&["login", "--publish", "--no-browser"], &vars);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stderr.contains("https://console.example.test/device"),
        "{}",
        r.stderr
    );
    assert!(r.stderr.contains("WXYZ-2345"), "{}", r.stderr);
    assert!(
        r.stderr.contains("Logged in to tenant acme."),
        "{}",
        r.stderr
    );
    assert!(r.stdout.is_empty());

    let r = run(&["status"], &vars);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stdout.contains("Tenant:    acme"), "{}", r.stdout);
    assert!(
        r.stdout.contains("prego-cli on laptop (dvs_01)"),
        "{}",
        r.stdout
    );
    assert!(
        r.stdout.contains("read, publish (any, default)"),
        "{}",
        r.stdout
    );
    assert!(!r.stdout.contains("rt-1") && !r.stdout.contains(REG_1));

    // The token from the login is still fresh: no request.
    let r = run(&["token"], &vars);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.stdout, format!("{REG_1}\n"));

    // A token for a resource: one refresh with the stored refresh token.
    let res = "https://cargo.prego.k8skill.com/t/acme/default/";
    let r = run(&["token", "--resource", res], &vars);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.stdout, format!("{REG_2}\n"));

    // An API key comes first: the session is not used, and status says so.
    let mut with_key = vars.clone();
    with_key.push(("PREGO_API_KEY", "prk_x"));
    let r = run(&["status"], &with_key);
    assert!(r.stdout.contains("PREGO_API_KEY is set"), "{}", r.stdout);

    let r = run(&["logout"], &vars);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stderr.contains("Logged out of tenant acme"),
        "{}",
        r.stderr
    );

    let r = run(&["status"], &vars);
    assert_eq!(r.code, 1);
    assert!(r.stderr.contains("not logged in"), "{}", r.stderr);

    let reqs = server.requests();
    assert_eq!(reqs.len(), 5);
    assert_eq!(reqs[0].target, "/v1/sts/device/e/k7mq/start");
    let start: serde_json::Value = serde_json::from_str(&reqs[0].body).unwrap();
    assert_eq!(start["access"][0]["actions"], json!(["read", "publish"]));
    assert!(start["client"].as_str().unwrap().starts_with("prego-cli/"));
    assert_eq!(reqs[3].target, "/v1/sts/token/e/k7mq");
    assert_eq!(reqs[3].form()["grant_type"], "refresh_token");
    assert_eq!(reqs[3].form()["refresh_token"], "rt-1");
    assert_eq!(reqs[3].form()["resource"], res);
    assert_eq!(reqs[4].target, "/v1/sts/device/e/k7mq/revoke");
    assert_eq!(reqs[4].form()["refresh_token"], "rt-2");
}

#[test]
fn no_source_and_no_session_lists_prego_login() {
    let server = MockServer::start(vec![]);
    let env = Env::new(&server, "none");
    let r = run(&["token"], &env.vars());
    assert_eq!(r.code, 1);
    assert!(r.stderr.contains("device (prego login)"), "{}", r.stderr);
    assert!(server.requests().is_empty());
}

#[test]
fn an_ended_session_says_login_again() {
    let server = MockServer::start(vec![
        start_answer(),
        token_answer(REG_1, "rt-1"),
        MockResponse::json(
            400,
            r#"{"error":"invalid_grant","error_description":"the login session ended; run prego login again"}"#,
        ),
    ]);
    let env = Env::new(&server, "ended");
    let vars = env.vars();
    assert_eq!(run(&["login", "--no-browser"], &vars).code, 0);
    let r = run(
        &[
            "token",
            "--resource",
            "https://cargo.prego.k8skill.com/t/acme/default/",
        ],
        &vars,
    );
    assert_eq!(r.code, 1);
    assert!(r.stderr.contains("run prego login again"), "{}", r.stderr);
    assert_eq!(run(&["status"], &vars).code, 1);
}

#[test]
fn exec_with_a_session_writes_no_netrc_file() {
    let server = MockServer::start(vec![start_answer(), token_answer(REG_1, "rt-1")]);
    let env = Env::new(&server, "exec");
    let mut vars = env.vars();
    assert_eq!(run(&["login", "--no-browser"], &vars).code, 0);
    vars.push(("PATH", "/usr/bin:/bin"));
    let r = run(
        &[
            "exec",
            "--",
            "sh",
            "-c",
            "test -z \"$NETRC\" && test -n \"$PREGO_NPM_TOKEN\"",
        ],
        &vars,
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stderr.contains("no NETRC file"), "{}", r.stderr);
}
