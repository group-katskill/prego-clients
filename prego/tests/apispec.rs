//! Runs `prego apispec` (ADR-0067) against a mock control host that serves the token exchange and the machine
//! routes `/v1/apispec/...` in the shapes of api.md section 15.2.

use std::process::{Command, Stdio};

use prego_auth::testing::{MockResponse, MockServer, TempDir};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const BIN: &str = env!("CARGO_BIN_EXE_prego");
// Payload {"sub":"prn_1","tid":"ten_1","exp":4102444800} (2100-01-01).
const REG_TOKEN: &str =
    "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJwcm5fMSIsInRpZCI6InRlbl8xIiwiZXhwIjo0MTAyNDQ0ODAwfQ.c2ln";
const DOC: &str = "openapi: 3.1.0\ninfo:\n  title: Payments\n  version: 1.4.0\npaths: {}\n";

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run(server: &MockServer, dir: &std::path::Path, args: &[&str]) -> Run {
    let out = Command::new(BIN)
        .current_dir(dir)
        .args(args)
        .env_clear()
        .env("PREGO_API_KEY", "prk_test_apispec_secret")
        .env("PREGO_TENANT", "acme")
        .env("PREGO_EDGE_CODE", "k7mq")
        .env(
            "PREGO_STS_URL",
            format!("{}/v1/sts/token", server.base_url()),
        )
        .env("HOME", "/nonexistent")
        .stdin(Stdio::null())
        .output()
        .expect("run prego");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn sts_ok() -> MockResponse {
    MockResponse::json(
        200,
        &json!({ "access_token": REG_TOKEN, "token_type": "Bearer", "expires_in": 900 })
            .to_string(),
    )
}

fn hash(b: &[u8]) -> String {
    format!(
        "sha256:{}",
        Sha256::digest(b)
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect::<String>()
    )
}

fn version_item(h: &str) -> Value {
    json!({"id": "apv_1", "version": "1.4.0", "hash": h, "format": "yaml", "openapi": "3.1.0",
           "title": "Payments", "info_version": "1.4.0", "size_bytes": DOC.len(), "operation_count": 0,
           "pushed_by": "prn_1", "pushed_at": "2026-11-26T10:00:00Z", "message": null,
           "secret_override": false, "tags": []})
}

#[test]
fn push_a_yaml_document_with_a_message_and_a_tag() {
    let dir = TempDir::new("prego-apispec-push");
    std::fs::write(dir.join("api.yaml"), DOC).unwrap();
    let h = hash(DOC.as_bytes());
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(
            201,
            &json!({"created": true, "version": version_item(&h)}).to_string(),
        ),
    ]);
    let r = run(
        &server,
        &dir,
        &[
            "apispec",
            "push",
            "api.yaml",
            "acme/payments-api@1.4.0",
            "--message",
            "first",
            "--tag",
            "stable",
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stdout.contains(&format!(
            "acme/default/payments-api@1.4.0: published ({h}, OpenAPI 3.1.0, 0 operations)"
        )),
        "{}",
        r.stdout
    );
    assert!(
        r.stdout
            .contains("acme/default/payments-api: tag stable -> 1.4.0"),
        "{}",
        r.stdout
    );
    let reqs = server.requests();
    assert_eq!(reqs[1].method, "PUT");
    assert_eq!(
        reqs[1].target,
        "/v1/apispec/acme/default/payments-api/1.4.0?message=first&tag=stable"
    );
    assert_eq!(
        reqs[1].header("content-type").as_deref(),
        Some("application/yaml")
    );
    assert_eq!(reqs[1].body, DOC);
}

#[test]
fn push_refuses_swagger_and_bad_labels_before_any_request() {
    let dir = TempDir::new("prego-apispec-refuse");
    std::fs::write(dir.join("old.json"), r#"{"swagger":"2.0","info":{}}"#).unwrap();
    std::fs::write(dir.join("api.yaml"), DOC).unwrap();
    let server = MockServer::start(vec![]);
    let r = run(
        &server,
        &dir,
        &["apispec", "push", "old.json", "acme/payments-api@1.0.0"],
    );
    assert_eq!(r.code, 1);
    assert!(
        r.stderr.contains("/swagger: Swagger 2.0 is not supported"),
        "{}",
        r.stderr
    );
    assert!(r.stderr.contains("Nothing was sent."), "{}", r.stderr);
    let r = run(
        &server,
        &dir,
        &["apispec", "push", "api.yaml", "acme/payments-api@v1.0.0"],
    );
    assert_eq!(r.code, 1);
    assert!(
        r.stderr.contains("SemVer 2.0 with no leading v"),
        "{}",
        r.stderr
    );
    let r = run(
        &server,
        &dir,
        &["apispec", "push", "api.yaml", "acme/payments-api"],
    );
    assert_eq!(r.code, 1);
    assert!(server.requests().is_empty());
}

#[test]
fn push_of_the_same_bytes_is_no_change_and_a_hash_that_differs_is_an_error() {
    let dir = TempDir::new("prego-apispec-same");
    std::fs::write(dir.join("api.yaml"), DOC).unwrap();
    let h = hash(DOC.as_bytes());
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(
            200,
            &json!({"created": false, "version": version_item(&h)}).to_string(),
        ),
        sts_ok(),
        MockResponse::json(
            201,
            &json!({"created": true, "version": version_item("sha256:00")}).to_string(),
        ),
    ]);
    let r = run(
        &server,
        &dir,
        &["apispec", "push", "api.yaml", "acme/payments-api@1.4.0"],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stdout.contains("no change"), "{}", r.stdout);
    let r = run(
        &server,
        &dir,
        &["apispec", "push", "api.yaml", "acme/payments-api@1.4.0"],
    );
    assert_eq!(r.code, 1);
    assert!(
        r.stderr.contains("is not the hash of the document"),
        "{}",
        r.stderr
    );
}

#[test]
fn get_the_highest_version_and_check_the_hash() {
    let dir = TempDir::new("prego-apispec-get");
    let h = hash(DOC.as_bytes());
    let doc = |hash: &str| {
        MockResponse::bytes(200, "application/yaml", DOC.as_bytes().to_vec())
            .with_header("X-Prego-Apispec-Version", "1.4.0")
            .with_header("X-Prego-Apispec-Hash", hash)
    };
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(
            200,
            &json!({"name": "payments-api", "highest_version": "1.4.0", "tags": []}).to_string(),
        ),
        doc(&h),
        sts_ok(),
        doc("sha256:00"),
    ]);
    let r = run(
        &server,
        &dir,
        &["apispec", "get", "acme/payments-api", "--out", "api.yaml"],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(std::fs::read_to_string(dir.join("api.yaml")).unwrap(), DOC);
    assert!(
        r.stderr
            .contains(&format!("acme/default/payments-api@1.4.0 {h}")),
        "{}",
        r.stderr
    );
    let reqs = server.requests();
    assert_eq!(reqs[1].target, "/v1/apispec/acme/default/payments-api");
    assert_eq!(
        reqs[2].target,
        "/v1/apispec/acme/default/payments-api/1.4.0"
    );
    // Bytes that do not match the hash header.
    let r = run(
        &server,
        &dir,
        &["apispec", "get", "acme/payments-api@1.4.0"],
    );
    assert_eq!(r.code, 1);
    assert!(r.stderr.contains("not sha256:00"), "{}", r.stderr);
    assert!(r.stdout.is_empty());
}

#[test]
fn get_a_conversion_and_an_expect_that_fails() {
    let dir = TempDir::new("prego-apispec-format");
    let h = hash(DOC.as_bytes());
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::bytes(200, "application/json", br#"{"openapi":"3.1.0"}"#.to_vec())
            .with_header("X-Prego-Apispec-Version", "1.4.0")
            .with_header("X-Prego-Apispec-Hash", &h)
            .with_header("X-Prego-Apispec-Format", "converted"),
        sts_ok(),
        MockResponse::json(
            412,
            r#"{"error":{"code":"hash_mismatch","hash":"sha256:ab"}}"#,
        ),
    ]);
    let r = run(
        &server,
        &dir,
        &[
            "apispec",
            "get",
            "acme/payments-api@1.4.0",
            "--format",
            "json",
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.stdout, r#"{"openapi":"3.1.0"}"#);
    assert_eq!(
        server.requests()[1].target,
        "/v1/apispec/acme/default/payments-api/1.4.0?format=json"
    );
    let want = format!("sha256:{}", "c".repeat(64));
    let r = run(
        &server,
        &dir,
        &[
            "apispec",
            "get",
            "acme/payments-api@1.4.0",
            "--expect",
            &want,
        ],
    );
    assert_eq!(r.code, 3, "{}", r.stderr);
}

#[test]
fn diff_prints_the_registry_changes() {
    let dir = TempDir::new("prego-apispec-diff");
    let answer = json!({
        "from": {"version": "1.0.0", "hash": "sha256:a"}, "to": {"version": "1.1.0", "hash": "sha256:b"},
        "changes": [
            {"change": "added", "kind": "operation", "path": "/refunds", "method": "POST", "text": "operation POST /refunds added"},
            {"change": "changed", "kind": "schema", "name": "Payment", "text": "schema Payment changed"}
        ],
        "truncated": false
    });
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(200, &answer.to_string()),
        sts_ok(),
        MockResponse::json(200, &answer.to_string()),
    ]);
    let r = run(
        &server,
        &dir,
        &[
            "apispec",
            "diff",
            "acme/payments-api@1.0.0",
            "acme/payments-api@1.1.0",
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(
        r.stdout,
        "acme/default/payments-api 1.0.0 (sha256:a) -> 1.1.0 (sha256:b)\n\
         + operation POST /refunds added\n\
         ~ schema Payment changed\n"
    );
    assert_eq!(
        server.requests()[1].target,
        "/v1/apispec/acme/default/payments-api/diff?from=1.0.0&to=1.1.0"
    );
    let r = run(
        &server,
        &dir,
        &[
            "apispec",
            "diff",
            "acme/payments-api@1.0.0",
            "acme/payments-api@1.1.0",
            "--json",
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    let v: Value = serde_json::from_str(&r.stdout).unwrap();
    assert_eq!(v, answer);
    // Two specs, or no version: usage errors with no request.
    let r = run(
        &server,
        &dir,
        &["apispec", "diff", "acme/a@1.0.0", "acme/b@1.1.0"],
    );
    assert_eq!(r.code, 1);
    assert!(
        r.stderr.contains("both versions must be of one spec"),
        "{}",
        r.stderr
    );
    let r = run(
        &server,
        &dir,
        &["apispec", "diff", "acme/a", "acme/a@1.1.0"],
    );
    assert_eq!(r.code, 1);
    assert_eq!(server.requests().len(), 4);
}

const SDL_A: &str = "type Payment { id: ID! amount: Int! }\n";
const SDL_B: &str = "type Query { payment(id: ID!): Payment }\n";

fn sdl_item(h: &str) -> Value {
    json!({"id": "apv_2", "version": "1.0.0", "hash": h, "format": "graphql", "encoding": "sdl", "openapi": null,
           "title": null, "info_version": null, "size_bytes": 10, "operation_count": 1, "pushed_by": "prn_1",
           "pushed_at": "2026-11-26T10:00:00Z", "message": null, "secret_override": false, "tags": []})
}

#[test]
fn push_a_graphql_folder_joined_in_path_order() {
    let dir = TempDir::new("prego-apispec-sdl");
    std::fs::create_dir_all(dir.join("schema/b")).unwrap();
    std::fs::write(dir.join("schema/b/query.graphql"), SDL_B).unwrap();
    std::fs::write(dir.join("schema/a.gql"), SDL_A.trim_end()).unwrap();
    let joined = format!("{SDL_A}{SDL_B}");
    let h = hash(joined.as_bytes());
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(
            201,
            &json!({"created": true, "version": sdl_item(&h)}).to_string(),
        ),
    ]);
    let r = run(
        &server,
        &dir,
        &["apispec", "push", "schema", "acme/payments-graph@1.0.0"],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stdout.contains(&format!(
            "acme/default/payments-graph@1.0.0: published ({h}, GraphQL SDL, 1 root fields)"
        )),
        "{}",
        r.stdout
    );
    let reqs = server.requests();
    assert_eq!(
        reqs[1].header("content-type").as_deref(),
        Some("application/graphql")
    );
    assert_eq!(reqs[1].body, joined);
}

#[test]
fn graphql_with_a_query_is_refused_before_the_upload() {
    let dir = TempDir::new("prego-apispec-sdl-refuse");
    std::fs::write(
        dir.join("ops.graphql"),
        "type Query { a: Int }\nquery GetA { a }\n",
    )
    .unwrap();
    let server = MockServer::start(vec![]);
    let r = run(
        &server,
        &dir,
        &[
            "apispec",
            "push",
            "ops.graphql",
            "acme/payments-graph@1.0.0",
        ],
    );
    assert_eq!(r.code, 1);
    assert!(
        r.stderr
            .contains("ops.graphql: line 2, column 1: `query` starts an executable definition"),
        "{}",
        r.stderr
    );
    assert!(r.stderr.contains("Nothing was sent."), "{}", r.stderr);
    assert!(server.requests().is_empty());
}

#[test]
fn graphql_get_diff_and_a_format_mismatch() {
    let dir = TempDir::new("prego-apispec-sdl-get");
    let h = hash(SDL_A.as_bytes());
    let diff = json!({
        "from": {"version": "1.0.0", "hash": "sha256:a"}, "to": {"version": "1.1.0", "hash": "sha256:b"},
        "changes": [
            {"change": "added", "kind": "field", "name": "Payment.currency", "text": "field Payment.currency added"},
            {"change": "changed", "kind": "argument", "name": "Query.payment(id:)", "text": "argument Query.payment(id:) changed"}
        ],
        "truncated": false
    });
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::bytes(200, "application/graphql", SDL_A.as_bytes().to_vec())
            .with_header("X-Prego-Apispec-Version", "1.0.0")
            .with_header("X-Prego-Apispec-Hash", &h)
            .with_header("X-Prego-Apispec-Format", "published"),
        sts_ok(),
        MockResponse::json(200, &diff.to_string()),
        sts_ok(),
        MockResponse::json(
            400,
            r#"{"error":{"code":"format_mismatch","message":"the spec is graphql; this version is openapi","format":"graphql","sent":"openapi"}}"#,
        ),
    ]);
    let r = run(
        &server,
        &dir,
        &[
            "apispec",
            "get",
            "acme/payments-graph@1.0.0",
            "--format",
            "graphql",
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.stdout, SDL_A);
    assert_eq!(
        server.requests()[1].target,
        "/v1/apispec/acme/default/payments-graph/1.0.0?format=graphql"
    );
    let r = run(
        &server,
        &dir,
        &[
            "apispec",
            "diff",
            "acme/payments-graph@1.0.0",
            "acme/payments-graph@1.1.0",
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stdout
            .contains("+ field Payment.currency added\n~ argument Query.payment(id:) changed\n"),
        "{}",
        r.stdout
    );
    // An OpenAPI document to a GraphQL spec: the registry's message.
    std::fs::write(dir.join("api.yaml"), DOC).unwrap();
    let r = run(
        &server,
        &dir,
        &["apispec", "push", "api.yaml", "acme/payments-graph@1.1.0"],
    );
    assert_eq!(r.code, 1);
    assert!(r.stderr.contains("format_mismatch"), "{}", r.stderr);
}
