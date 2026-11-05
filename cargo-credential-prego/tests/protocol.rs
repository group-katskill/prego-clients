//! Spawns the binary, speaks the Cargo credential protocol, and checks the answers.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use prego_auth::testing::{MockResponse, MockServer};
use serde_json::{json, Value};

const BIN: &str = env!("CARGO_BIN_EXE_cargo-credential-prego");
// Payload {"exp":4102444800} (2100-01-01).
const REG_TOKEN: &str = "eyJhbGciOiJFUzI1NiJ9.eyJleHAiOjQxMDI0NDQ4MDB9.c2ln";

/// Runs one protocol session: hello, then each request line. Returns the hello and the responses.
fn session(env: &[(&str, &str)], requests: &[Value]) -> (Value, Vec<Value>, String) {
    let mut cmd = Command::new(BIN);
    cmd.arg("--cargo-plugin")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn binary");
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let hello: Value = serde_json::from_str(&line).expect("hello is JSON");

    let mut responses = Vec::new();
    for req in requests {
        writeln!(stdin, "{req}").unwrap();
        stdin.flush().unwrap();
        line.clear();
        stdout.read_line(&mut line).unwrap();
        responses.push(serde_json::from_str(&line).expect("response is JSON"));
    }
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "exit status {:?}", out.status);
    (
        hello,
        responses,
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn get_request(args: &[&str]) -> Value {
    json!({
        "v": 1,
        "registry": {
            "index-url": "sparse+https://cargo.prego.k8skill.com/t/acme/default/index/",
            "name": "acme"
        },
        "kind": "get",
        "operation": "read",
        "args": args
    })
}

#[test]
fn hello_announces_protocol_v1() {
    let (hello, _, _) = session(&[], &[]);
    assert_eq!(hello, json!({ "v": [1] }));
}

#[test]
fn get_with_api_key_returns_registry_token() {
    let server = MockServer::start(vec![MockResponse::json(
        200,
        &json!({
            "access_token": REG_TOKEN,
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "token_type": "Bearer",
            "expires_in": 900
        })
        .to_string(),
    )]);
    let sts = format!("{}/v1/sts/token/e/k7mq", server.base_url());
    let (_, responses, stderr) = session(
        &[("PREGO_API_KEY", "prk_protocol_test_key")],
        &[get_request(&["--tenant", "acme", "--sts-url", &sts])],
    );

    let r = &responses[0];
    assert_eq!(r["Ok"]["kind"], "get");
    assert_eq!(r["Ok"]["token"], REG_TOKEN);
    assert_eq!(r["Ok"]["cache"], "expires");
    // From expires_in and the local clock, not from the exp claim (2100-01-01).
    let left = r["Ok"]["expiration"].as_i64().unwrap() - now();
    assert!((835..=840).contains(&left), "{left}");
    assert_eq!(r["Ok"]["operation_independent"], true);

    let reqs = server.requests();
    assert_eq!(reqs.len(), 1);
    let form = reqs[0].form();
    assert_eq!(
        form["resource"],
        "https://cargo.prego.k8skill.com/t/acme/default/"
    );
    assert_eq!(form["subject_token"], "prk_protocol_test_key");
    assert_eq!(form["tenant"], "acme");
    assert!(reqs[0]
        .header("user-agent")
        .unwrap()
        .starts_with("cargo-credential-prego/"));
    assert!(!stderr.contains("prk_protocol_test_key"));
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[test]
fn one_minute_token_is_cached_for_45_seconds() {
    let server = MockServer::start(vec![MockResponse::json(
        200,
        &json!({ "access_token": REG_TOKEN, "expires_in": 60 }).to_string(),
    )]);
    let sts = format!("{}/v1/sts/token/e/k7mq", server.base_url());
    let (_, responses, _) = session(
        &[("PREGO_API_KEY", "prk_protocol_test_key")],
        &[get_request(&["--tenant", "acme", "--sts-url", &sts])],
    );
    let r = &responses[0];
    assert_eq!(r["Ok"]["cache"], "expires");
    let left = r["Ok"]["expiration"].as_i64().unwrap() - now();
    assert!((40..=45).contains(&left), "{left}");
}

#[test]
fn tenant_from_environment() {
    let server = MockServer::start(vec![MockResponse::json(
        200,
        &json!({ "access_token": REG_TOKEN, "expires_in": 900 }).to_string(),
    )]);
    let sts = format!("{}/v1/sts/token/e/k7mq", server.base_url());
    let (_, responses, _) = session(
        &[
            ("PREGO_TENANT", "envco"),
            ("PREGO_STS_URL", &sts),
            (
                "PREGO_ID_TOKEN",
                "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln",
            ),
        ],
        &[get_request(&[])],
    );
    assert_eq!(responses[0]["Ok"]["token"], REG_TOKEN);
    let form = server.requests()[0].form();
    assert_eq!(form["tenant"], "envco");
    assert_eq!(
        form["subject_token_type"],
        "urn:ietf:params:oauth:token-type:jwt"
    );
}

#[test]
fn invalid_grant_gives_clear_error_without_token() {
    let server = MockServer::start(vec![MockResponse::json(
        401,
        r#"{"error":"invalid_grant","error_description":"subject token not accepted"}"#,
    )]);
    let sts = format!("{}/v1/sts/token/e/k7mq", server.base_url());
    let (_, responses, _) = session(
        &[("PREGO_API_KEY", "prk_refused_key")],
        &[get_request(&["--tenant", "acme", "--sts-url", &sts])],
    );
    let err = &responses[0]["Err"];
    assert_eq!(err["kind"], "other");
    assert_eq!(
        err["message"],
        "Prego refused this identity for tenant acme. Check the trust config and principal in the console."
    );
    assert!(!responses[0].to_string().contains("prk_refused_key"));
}

#[test]
fn no_source_lists_checked_sources() {
    let (_, responses, _) = session(&[], &[get_request(&["--tenant", "acme"])]);
    let msg = responses[0]["Err"]["message"].as_str().unwrap();
    for name in [
        "spiffe",
        "svid-file",
        "gitlab",
        "github",
        "token-file",
        "api-key",
    ] {
        assert!(msg.contains(name), "{msg}");
    }
}

#[test]
fn missing_tenant_is_an_error() {
    let (_, responses, _) = session(&[("PREGO_API_KEY", "prk_x")], &[get_request(&[])]);
    let msg = responses[0]["Err"]["message"].as_str().unwrap();
    assert!(msg.contains("tenant"), "{msg}");
}

#[test]
fn login_and_logout_are_not_supported() {
    let base = json!({
        "v": 1,
        "registry": { "index-url": "sparse+https://cargo.prego.k8skill.com/t/acme/default/index/" }
    });
    let mut login = base.clone();
    login["kind"] = json!("login");
    let mut logout = base;
    logout["kind"] = json!("logout");
    let (_, responses, stderr) = session(&[], &[login, logout]);
    for r in &responses {
        assert_eq!(r["Err"]["kind"], "operation-not-supported");
    }
    assert!(stderr.contains("Prego console"), "{stderr}");
}

#[test]
fn version_prints_semver_and_commit() {
    let out = Command::new(BIN).arg("--version").output().unwrap();
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(
        s.starts_with(&format!(
            "cargo-credential-prego {} (",
            env!("CARGO_PKG_VERSION")
        )),
        "{s}"
    );
}

#[test]
fn failing_first_source_fails_closed_and_suggests_source_flag() {
    let (_, responses, _) = session(
        &[
            ("PREGO_ID_TOKEN", "not-a-jwt"),
            ("PREGO_API_KEY", "prk_should_not_be_used"),
        ],
        &[get_request(&["--tenant", "acme"])],
    );
    let msg = responses[0]["Err"]["message"].as_str().unwrap();
    assert!(msg.contains("`gitlab`"), "{msg}");
    assert!(msg.contains("--source <name>"), "{msg}");
}

#[test]
fn bad_ca_file_is_an_error() {
    let (_, responses, _) = session(
        &[
            ("PREGO_API_KEY", "prk_x"),
            ("PREGO_CA_FILE", "/nonexistent/prego/ca.pem"),
        ],
        &[get_request(&["--tenant", "acme"])],
    );
    let msg = responses[0]["Err"]["message"].as_str().unwrap();
    assert!(msg.contains("PREGO_CA_FILE"), "{msg}");
}
