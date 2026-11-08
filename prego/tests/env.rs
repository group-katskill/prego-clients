//! Runs `prego env` against a mock STS host that serves the token exchange and `/v1/vars/*`.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use prego_auth::testing::{MockResponse, MockServer};
use serde_json::{json, Value};

const BIN: &str = env!("CARGO_BIN_EXE_prego");
const API_KEY: &str = "prk_test_env_secret";
// Payload {"sub":"prn_1","tid":"ten_1","exp":4102444800} (2100-01-01).
const REG_TOKEN: &str =
    "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJwcm5fMSIsInRpZCI6InRlbl8xIiwiZXhwIjo0MTAyNDQ0ODAwfQ.c2ln";

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str], stdin: Option<&str>) -> Run {
    let mut cmd = Command::new(BIN);
    cmd.args(args)
        .env_clear()
        .env("PREGO_API_KEY", API_KEY)
        .env("HOME", "/nonexistent")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("run prego");
    if let Some(s) = stdin {
        use std::io::Write;
        child.stdin.take().unwrap().write_all(s.as_bytes()).unwrap();
    }
    drop(child.stdin.take());
    let out = child.wait_with_output().unwrap();
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("prego-env-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn sts_ok() -> MockResponse {
    MockResponse::json(
        200,
        &json!({ "access_token": REG_TOKEN, "token_type": "Bearer", "expires_in": 900 })
            .to_string(),
    )
}

/// The offline hash of a `{key: value}` map, from `prego env hash -`.
fn hash(flat: &Value) -> String {
    let r = run(&["env", "hash", "-"], Some(&flat.to_string()));
    assert_eq!(r.code, 0, "{}", r.stderr);
    r.stdout.trim().to_string()
}

fn resolve_answer(resolved_hash: &str) -> Value {
    json!({
        "ref": "acme/default/payments@1.4.0",
        "resolved_hash": resolved_hash,
        "published": { "cargo": true, "oci": false, "go": false, "npm": false },
        "levels": [
            { "level": "tenant", "set_id": "rvs_t", "version": 7, "hash": "sha256:aa" },
            { "level": "version", "set_id": "rvs_v", "version": 1, "hash": "sha256:bb" }
        ],
        "variables": {
            "API_BASE_URL": { "value": "https://api.acme.example", "type": "string", "from": "tenant" },
            "FEATURES": { "value": { "ledger_v2": true, "a": 1.0 }, "type": "json", "from": "version" },
            "QUOTE": { "value": "it's", "type": "string", "from": "version" }
        }
    })
}

fn flat() -> Value {
    json!({ "API_BASE_URL": "https://api.acme.example", "FEATURES": { "ledger_v2": true, "a": 1 },
            "QUOTE": "it's" })
}

#[test]
fn pull_prints_quoted_env_lines_and_checks_the_expected_hash() {
    let h = hash(&flat());
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(200, &resolve_answer(&h).to_string()),
    ]);
    let sts = format!("{}/v1/sts/token/e/k7mq", server.base_url());
    // No tenant is set: the tenant of the reference is used for the token.
    let r = run(
        &[
            "env",
            "pull",
            "acme/payments@1.4.0",
            "--sts-url",
            &sts,
            "--expect",
            &h,
        ],
        None,
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(
        r.stdout,
        format!(
            "# ref acme/default/payments@1.4.0\n# resolved_hash {h}\n\
             # tenant rvs_t 7 sha256:aa\n# version rvs_v 1 sha256:bb\n\
             API_BASE_URL='https://api.acme.example'\n\
             FEATURES='{{\"a\":1,\"ledger_v2\":true}}'\n\
             QUOTE='it'\\''s'\n"
        )
    );
    let reqs = server.requests();
    assert_eq!(reqs[0].form()["tenant"], "acme");
    assert_eq!(reqs[1].method, "GET");
    assert_eq!(
        reqs[1].target,
        "/v1/vars/resolve?ref=acme%2Fdefault%2Fpayments%401.4.0"
    );
    assert_eq!(
        reqs[1].header("authorization").unwrap(),
        format!("Bearer {REG_TOKEN}")
    );
    assert!(!r.stderr.contains(REG_TOKEN) && !r.stdout.contains(REG_TOKEN));
}

#[test]
fn pull_with_another_expected_hash_exits_3_and_writes_nothing() {
    let h = hash(&flat());
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(200, &resolve_answer(&h).to_string()),
    ]);
    let sts = format!("{}/v1/sts/token/e/k7mq", server.base_url());
    let dir = temp_dir("expect");
    let out = dir.join("release.env");
    let other = format!("sha256:{}", "0".repeat(64));
    let r = run(
        &[
            "env",
            "pull",
            "acme/releases/payments@1.4.0",
            "--tenant",
            "grantee",
            "--sts-url",
            &sts,
            "--expect",
            &other,
            "--out",
            out.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(r.code, 3, "{}", r.stderr);
    assert!(r.stderr.contains(&h) && r.stderr.contains(&other));
    assert!(!out.exists());
    // A cross-tenant pull: the token is for the configured tenant, the reference names the publisher.
    let reqs = server.requests();
    assert_eq!(reqs[0].form()["tenant"], "grantee");
    assert!(reqs[1]
        .target
        .ends_with("ref=acme%2Freleases%2Fpayments%401.4.0"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pull_refuses_an_answer_whose_hash_is_not_the_hash_of_its_variables() {
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(
            200,
            &resolve_answer(&format!("sha256:{}", "1".repeat(64))).to_string(),
        ),
    ]);
    let sts = format!("{}/v1/sts/token/e/k7mq", server.base_url());
    let r = run(
        &["env", "pull", "acme/payments@1.4.0", "--sts-url", &sts],
        None,
    );
    assert_eq!(r.code, 1);
    assert!(
        r.stderr.contains("is not the hash of the variables"),
        "{}",
        r.stderr
    );
    assert!(r.stdout.is_empty());
}

#[test]
fn pull_flat_and_out_file() {
    let h = hash(&flat());
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(200, &resolve_answer(&h).to_string()),
    ]);
    let sts = format!("{}/v1/sts/token/e/k7mq", server.base_url());
    let dir = temp_dir("flat");
    let out = dir.join("vars.json");
    let r = run(
        &[
            "env",
            "pull",
            "acme/payments@1.4.0",
            "--sts-url",
            &sts,
            "--format",
            "flat",
            "--out",
            out.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    let got: Value = serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(hash(&got), h);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn push_sends_the_whole_map_with_env_file_values_as_strings() {
    let dir = temp_dir("push");
    let env_file = dir.join("release.env");
    std::fs::write(
        &env_file,
        "# settings\nPORT=8080\nDEBUG=true\nexport NAME='a b'\n",
    )
    .unwrap();
    let answer = json!({
        "set": { "id": "rvs_v", "current_version": 4 },
        "version": { "number": 4, "hash": "sha256:cc", "current": true },
        "created": true,
        "warnings": [ { "key": "DB_PASSWORD", "code": "secret_like_key" } ]
    });
    let server = MockServer::start(vec![sts_ok(), MockResponse::json(201, &answer.to_string())]);
    let sts = format!("{}/v1/sts/token/e/k7mq", server.base_url());
    let cur = format!("sha256:{}", "d".repeat(64));
    let r = run(
        &[
            "env",
            "push",
            "acme/releases/payments@1.4.0",
            "--tenant",
            "acme",
            "--sts-url",
            &sts,
            "--env-file",
            env_file.to_str().unwrap(),
            "--set",
            "DEBUG=false",
            "--set-json",
            "LIMITS={\"max\":5}",
            "--set",
            "DB_PASSWORD=x",
            "--message",
            "a1b2c3d",
            "--if-current",
            &cur,
        ],
        None,
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stdout.contains("version set version 4 (sha256:cc)"),
        "{}",
        r.stdout
    );
    assert!(
        r.stderr.contains("DB_PASSWORD looks like a secret"),
        "{}",
        r.stderr
    );
    let req = &server.requests()[1];
    assert_eq!(
        (req.method.as_str(), req.target.as_str()),
        ("PUT", "/v1/vars/sets")
    );
    assert_eq!(req.header("content-type").unwrap(), "application/json");
    let body: Value = serde_json::from_str(&req.body).unwrap();
    assert_eq!(
        body,
        json!({
            "tenant": "acme", "level": "version", "namespace": "releases", "package": "payments",
            "version": "1.4.0",
            "variables": { "PORT": "8080", "DEBUG": "false", "NAME": "a b", "LIMITS": { "max": 5 },
                           "DB_PASSWORD": "x" },
            "message": "a1b2c3d", "if_current": cur
        })
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn push_of_a_namespace_set_and_a_refusal() {
    let err = json!({ "error": { "code": "looks_like_secret", "message": "a value looks like a credential",
                                 "keys": ["GH"], "request_id": "req_1" } });
    let server = MockServer::start(vec![sts_ok(), MockResponse::json(422, &err.to_string())]);
    let sts = format!("{}/v1/sts/token/e/k7mq", server.base_url());
    let r = run(
        &[
            "env",
            "push",
            "acme/staging",
            "--level",
            "namespace",
            "--sts-url",
            &sts,
            "--set",
            "GH=ghp_x",
        ],
        None,
    );
    assert_eq!(r.code, 1);
    assert!(r.stderr.contains("422 looks_like_secret") && r.stderr.contains("(keys: GH)"));
    assert!(r
        .stderr
        .contains("Do not store passwords, tokens or keys here."));
    let body: Value = serde_json::from_str(&server.requests()[1].body).unwrap();
    assert_eq!(
        body,
        json!({ "tenant": "acme", "level": "namespace", "namespace": "staging",
                "variables": { "GH": "ghp_x" } })
    );
}

#[test]
fn push_with_no_change() {
    let answer = json!({ "set": { "id": "rvs_t" }, "version": { "number": 7, "hash": "sha256:aa" },
                         "created": false, "warnings": [] });
    let server = MockServer::start(vec![sts_ok(), MockResponse::json(200, &answer.to_string())]);
    let sts = format!("{}/v1/sts/token/e/k7mq", server.base_url());
    let r = run(
        &[
            "env",
            "push",
            "acme",
            "--level",
            "tenant",
            "--sts-url",
            &sts,
            "--set",
            "A=1",
        ],
        None,
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(
        r.stdout,
        "acme: no change, tenant set version 7 is current (sha256:aa)\n"
    );
}

#[test]
fn history_rollback_and_diff() {
    let set = |n: u64, vars: Value| {
        MockResponse::json(
            200,
            &json!({ "id": "rvs_v", "level": "version", "current_version": 3, "number": n,
                     "hash": "sha256:x", "variables": vars })
            .to_string(),
        )
    };
    let wrap = |v: &str| json!({ "value": v, "type": "string" });
    let server = MockServer::start(vec![
        // history
        sts_ok(),
        set(3, json!({})),
        MockResponse::json(
            200,
            &json!({ "items": [
                { "number": 3, "hash": "sha256:c", "size_bytes": 10, "key_count": 1, "pushed_by": "prn_1",
                  "message": "third", "created_at": "2026-11-07T10:00:00Z", "current": true },
                { "number": 2, "hash": "sha256:b", "size_bytes": 9, "key_count": 1, "pushed_by": "prn_1",
                  "message": null, "created_at": "2026-11-06T10:00:00Z", "current": false } ] })
            .to_string(),
        ),
        // rollback
        sts_ok(),
        set(3, json!({})),
        MockResponse::json(
            200,
            &json!({ "id": "rvs_v", "current_version": 2, "current_hash": "sha256:b" }).to_string(),
        ),
        // diff
        sts_ok(),
        set(1, json!({ "A": wrap("1"), "B": wrap("x") })),
        set(2, json!({ "A": wrap("1"), "C": { "value": [1], "type": "json" } })),
    ]);
    let sts = format!("{}/v1/sts/token/e/k7mq", server.base_url());
    let r = run(
        &["env", "history", "acme/payments@1.4.0", "--sts-url", &sts],
        None,
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    let lines: Vec<&str> = r.stdout.lines().collect();
    assert_eq!(lines[0], "acme/default/payments@1.4.0 (version set rvs_v)");
    assert!(
        lines[1].starts_with("*    3  sha256:c") && lines[1].ends_with("third"),
        "{}",
        lines[1]
    );
    assert!(lines[2].starts_with("     2  sha256:b"), "{}", lines[2]);

    let r = run(
        &[
            "env",
            "rollback",
            "acme/payments@1.4.0",
            "--to",
            "2",
            "--reason",
            "bad flag",
            "--sts-url",
            &sts,
        ],
        None,
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(
        r.stdout,
        "acme/default/payments@1.4.0: current version set version is now 2 (sha256:b)\n"
    );

    let r = run(
        &[
            "env",
            "diff",
            "acme/payments@1.4.0",
            "--from",
            "1",
            "--to",
            "2",
            "--sts-url",
            &sts,
        ],
        None,
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.stdout, "- B = \"x\"\n+ C = [1]\n");

    let reqs = server.requests();
    let q = "tenant=acme&level=version&namespace=default&package=payments&version=1.4.0";
    assert_eq!(reqs[1].target, format!("/v1/vars/sets?{q}"));
    assert_eq!(reqs[2].target, "/v1/vars/sets/rvs_v/versions");
    assert_eq!(
        (reqs[5].method.as_str(), reqs[5].target.as_str()),
        ("POST", "/v1/vars/sets/rvs_v/current")
    );
    assert_eq!(
        serde_json::from_str::<Value>(&reqs[5].body).unwrap(),
        json!({ "version": 2, "reason": "bad flag" })
    );
    assert_eq!(
        reqs[7].target,
        format!("/v1/vars/sets?{q}&version_number=1")
    );
    assert_eq!(
        reqs[8].target,
        format!("/v1/vars/sets?{q}&version_number=2")
    );
}

#[test]
fn not_found_says_no_set_or_no_grant() {
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(
            404,
            r#"{"error":{"code":"not_found","message":"not found"}}"#,
        ),
    ]);
    let sts = format!("{}/v1/sts/token/e/k7mq", server.base_url());
    let r = run(
        &["env", "history", "acme/payments@1.4.0", "--sts-url", &sts],
        None,
    );
    assert_eq!(r.code, 1);
    assert!(
        r.stderr.contains("not found, or you have no grant for it"),
        "{}",
        r.stderr
    );
}

#[test]
fn hash_is_offline_and_refuses_bad_input() {
    let r = run(&["env", "hash", "-"], Some(r#"{"b": 1.50, "a": "x"}"#));
    assert_eq!(r.code, 0, "{}", r.stderr);
    // sha256 of {"a":"x","b":1.5}
    assert_eq!(
        r.stdout,
        "sha256:099f4bcf556f24a56bad74cab2ccce1a7c040735ddb42f2a0df2043a865b5271\n"
    );
    for bad in ["[1]", "{\"1A\":1}", "{"] {
        let r = run(&["env", "hash", "-"], Some(bad));
        assert_eq!(r.code, 1, "{bad}");
    }
}
