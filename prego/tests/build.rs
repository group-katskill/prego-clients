//! Runs `prego build` (ADR-0066) against a mock control host that serves the token exchange and the routes of
//! api.md section 16: the upload in parts, the lookup, the file downloads (direct and by a storage link), the
//! list and the promote.

use std::process::{Command, Stdio};

use prego_auth::testing::{MockResponse, MockServer, TempDir};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const BIN: &str = env!("CARGO_BIN_EXE_prego");
// Payload {"sub":"prn_1","tid":"ten_1","exp":4102444800} (2100-01-01).
const REG_TOKEN: &str =
    "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJwcm5fMSIsInRpZCI6InRlbl8xIiwiZXhwIjo0MTAyNDQ0ODAwfQ.c2ln";

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
        .env("PREGO_API_KEY", "prk_test_build_secret")
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

fn sha(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

const BASE: &str = "/v1/build/acme/ci/api-cli";

fn build(id: &str, label: Option<&str>, files: Value) -> Value {
    json!({"id": id, "level": "ci_source", "principal_id": "prn_1", "commit": "9f2c1ab3c4d5e6f708192a3b4c5d6e7f8091a2b3",
           "ref": "refs/tags/v1.4.0", "run": "456", "file_count": 2, "total_bytes": 12, "message": null,
           "release_url": null, "attestation_id": null, "promoted": label.is_some(), "label": label,
           "expires_at": if label.is_some() { Value::Null } else { json!("2026-12-26T10:00:00Z") },
           "created_at": "2026-11-26T10:00:00Z", "files": files})
}

#[test]
fn push_in_parts_with_promote_and_release_url() {
    let dir = TempDir::new("prego-build-push");
    std::fs::write(dir.join("api-cli.tar.gz"), b"hello world!").unwrap();
    std::fs::write(dir.join("EMPTY"), b"").unwrap();
    let open = json!({"upload_id": "bup_1", "expires_at": "2026-11-27T10:00:00Z",
                      "part_size_max": 4, "part_size_min": 1,
                      "files": [{"index": 0, "name": "api-cli.tar.gz", "size": 12}, {"index": 1, "name": "EMPTY", "size": 0}]});
    let part = |n: u64, done: bool| {
        MockResponse::json(
            200,
            &json!({"file": "api-cli.tar.gz", "part": n, "received": n * 4, "size": 12, "complete": done}).to_string(),
        )
    };
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(201, &open.to_string()),
        part(1, false),
        part(2, false),
        part(3, true),
        MockResponse::json(201, &build("bld_01", Some("v1.4.0"), json!([])).to_string()),
    ]);
    let r = run(
        &server,
        &dir,
        &[
            "build",
            "push",
            "acme/ci/api-cli",
            "api-cli.tar.gz",
            "EMPTY",
            "--promote",
            "v1.4.0",
            "--release-url",
            "https://github.com/acme/api/releases/tag/v1.4.0",
            "--expires-in",
            "7",
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.stdout, "bld_01\n");
    assert!(
        r.stderr
            .contains("acme/ci/api-cli: build bld_01, 2 files, promoted as v1.4.0"),
        "{}",
        r.stderr
    );
    let reqs = server.requests();
    assert_eq!(reqs[1].target, format!("{BASE}/uploads"));
    let body: Value = serde_json::from_str(&reqs[1].body).unwrap();
    assert_eq!(
        body,
        json!({"files": [{"name": "api-cli.tar.gz", "size": 12, "sha256": sha(b"hello world!")},
                         {"name": "EMPTY", "size": 0, "sha256": sha(b"")}],
               "expires_days": 7, "promote": "v1.4.0",
               "release_url": "https://github.com/acme/api/releases/tag/v1.4.0"})
    );
    // Parts of 4 bytes (the server's maximum here), in order; the empty file has no part.
    for (i, want) in ["hell", "o wo", "rld!"].iter().enumerate() {
        assert_eq!(reqs[2 + i].method, "PUT");
        assert_eq!(
            reqs[2 + i].target,
            format!("{BASE}/uploads/bup_1/files/0/parts/{}", i + 1)
        );
        assert_eq!(reqs[2 + i].body, *want);
    }
    assert_eq!(reqs[5].target, format!("{BASE}/uploads/bup_1/commit"));
    assert_eq!(reqs.len(), 6);
}

#[test]
fn a_digest_mismatch_cancels_the_upload() {
    let dir = TempDir::new("prego-build-mismatch");
    std::fs::write(dir.join("a.bin"), b"abc").unwrap();
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(
            201,
            &json!({"upload_id": "bup_2", "part_size_max": 99614720, "part_size_min": 5242880,
                    "files": [{"index": 0, "name": "a.bin", "size": 3}]})
            .to_string(),
        ),
        MockResponse::json(
            422,
            r#"{"error":{"code":"digest_mismatch","file":"a.bin"}}"#,
        ),
        MockResponse::bytes(204, "text/plain", vec![]),
    ]);
    let r = run(
        &server,
        &dir,
        &["build", "push", "acme/ci/api-cli", "a.bin"],
    );
    assert_eq!(r.code, 1);
    assert!(
        r.stderr.contains("Did the file change during the upload?"),
        "{}",
        r.stderr
    );
    assert!(
        r.stderr
            .contains("The upload was cancelled; nothing was stored."),
        "{}",
        r.stderr
    );
    let reqs = server.requests();
    assert_eq!(reqs[3].method, "DELETE");
    assert_eq!(reqs[3].target, format!("{BASE}/uploads/bup_2"));
}

#[test]
fn local_refusals_send_nothing() {
    let dir = TempDir::new("prego-build-refuse");
    std::fs::write(dir.join(".hidden"), b"x").unwrap();
    std::fs::write(dir.join("ok.bin"), b"x").unwrap();
    let server = MockServer::start(vec![]);
    for args in [
        vec!["build", "push", "acme/ci/api-cli", ".hidden"],
        vec![
            "build",
            "push",
            "acme/ci/api-cli",
            "ok.bin",
            "--release-url",
            "http://example.com/r",
        ],
        vec![
            "build",
            "push",
            "acme/ci/api-cli",
            "ok.bin",
            "--promote",
            "-x",
        ],
        vec![
            "build",
            "push",
            "acme/ci/api-cli",
            "ok.bin",
            "--expires-in",
            "2",
        ],
        vec!["build", "push", "acme/ci/api-cli", "missing.bin"],
        vec!["build", "get", "acme/ci/api-cli"],
        vec![
            "build",
            "get",
            "acme/ci/api-cli",
            "--run",
            "456",
            "--latest",
        ],
        vec![
            "build",
            "get",
            "acme/ci/api-cli",
            "--run",
            "456",
            "--ref",
            "main",
        ],
        vec!["build", "promote", "acme/ci/api-cli", "v1"],
    ] {
        let r = run(&server, &dir, &args);
        assert_eq!(r.code, 1, "{args:?}: {}", r.stderr);
    }
    assert!(server.requests().is_empty());
}

#[test]
fn get_latest_of_a_ref_through_a_storage_link_without_the_token() {
    let dir = TempDir::new("prego-build-get");
    let a = b"archive bytes".to_vec();
    let b = b"sums".to_vec();
    let files = json!([{"name": "api-cli.tar.gz", "size": a.len(), "sha256": sha(&a)},
                       {"name": "SHA256SUMS", "size": b.len(), "sha256": sha(&b)}]);
    let server = MockServer::start_with(|base| {
        vec![
            sts_ok(),
            MockResponse::json(200, &build("bld_07", None, files.clone()).to_string()),
            MockResponse::redirect(&format!("{base}/storage/bld_07/api-cli.tar.gz?sig=x")),
            MockResponse::bytes(200, "application/octet-stream", a.clone()),
            MockResponse::bytes(200, "application/octet-stream", b.clone())
                .with_header("X-Prego-Sha256", &sha(&b)),
        ]
    });
    let r = run(
        &server,
        &dir,
        &[
            "build",
            "get",
            "acme/ci/api-cli",
            "--latest",
            "--ref",
            "refs/heads/main",
            "--out",
            "dl",
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(std::fs::read(dir.join("dl/api-cli.tar.gz")).unwrap(), a);
    assert_eq!(std::fs::read(dir.join("dl/SHA256SUMS")).unwrap(), b);
    let reqs = server.requests();
    assert_eq!(
        reqs[1].target,
        format!("{BASE}/lookup?latest&ref=refs%2Fheads%2Fmain")
    );
    assert_eq!(
        reqs[2].target,
        format!("{BASE}/builds/bld_07/files/api-cli.tar.gz")
    );
    assert!(reqs[2].header("authorization").is_some());
    assert_eq!(reqs[3].target, "/storage/bld_07/api-cli.tar.gz?sig=x");
    assert_eq!(reqs[3].header("authorization"), None);
    assert_eq!(
        reqs[4].target,
        format!("{BASE}/builds/bld_07/files/SHA256SUMS")
    );
}

#[test]
fn get_with_a_wrong_sha256_leaves_no_file_and_never_replaces_one() {
    let dir = TempDir::new("prego-build-bad");
    let files = json!([{"name": "a.bin", "size": 3, "sha256": sha(b"abc")}]);
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(200, &build("bld_08", None, files.clone()).to_string()),
        MockResponse::bytes(200, "application/octet-stream", b"abd".to_vec()),
        sts_ok(),
        MockResponse::json(200, &build("bld_08", None, files.clone()).to_string()),
        MockResponse::bytes(200, "application/octet-stream", b"abd".to_vec()),
        sts_ok(),
        MockResponse::json(200, &build("bld_08", None, files).to_string()),
    ]);
    let r = run(
        &server,
        &dir,
        &["build", "get", "acme/ci/api-cli", "bld_08"],
    );
    assert_eq!(r.code, 1);
    assert!(r.stderr.contains("the sha256 is"), "{}", r.stderr);
    assert!(!dir.join("a.bin").exists());
    assert!(!dir.join(".a.bin.prego-tmp").exists());
    assert_eq!(
        server.requests()[1].target,
        format!("{BASE}/lookup?id=bld_08")
    );
    // --no-verify writes the bytes as they come.
    let r = run(
        &server,
        &dir,
        &["build", "get", "acme/ci/api-cli", "bld_08", "--no-verify"],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stderr.contains("not checked (--no-verify)"),
        "{}",
        r.stderr
    );
    // The file exists now: no download.
    let r = run(
        &server,
        &dir,
        &["build", "get", "acme/ci/api-cli", "bld_08"],
    );
    assert_eq!(r.code, 1);
    assert!(r.stderr.contains("does not replace files"), "{}", r.stderr);
    assert_eq!(server.requests().len(), 8);
}

#[test]
fn list_and_promote_by_commit() {
    let dir = TempDir::new("prego-build-list");
    let list = json!({"items": [build("bld_09", None, json!(null))], "next": null});
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(200, &list.to_string()),
        sts_ok(),
        MockResponse::json(200, &build("bld_09", None, json!([])).to_string()),
        MockResponse::json(200, &build("bld_09", Some("v1.4.0"), json!([])).to_string()),
    ]);
    let r = run(
        &server,
        &dir,
        &[
            "build",
            "list",
            "acme/ci/api-cli",
            "--commit",
            "9F2C1AB",
            "--promoted",
            "--limit",
            "5",
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stdout.starts_with(
            "bld_09  2026-11-26T10:00:00Z  ci_source  9f2c1ab3c4d5  refs/tags/v1.4.0  expires"
        ),
        "{}",
        r.stdout
    );
    let reqs = server.requests();
    assert_eq!(
        reqs[1].target,
        format!("{BASE}/builds?commit=9f2c1ab&promoted=true&limit=5")
    );
    let r = run(
        &server,
        &dir,
        &[
            "build",
            "promote",
            "acme/ci/api-cli",
            "v1.4.0",
            "--commit",
            "9f2c1ab",
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.stdout, "acme/ci/api-cli bld_09 promoted as v1.4.0\n");
    let reqs = server.requests();
    assert_eq!(reqs[3].target, format!("{BASE}/lookup?commit=9f2c1ab"));
    assert_eq!(reqs[4].target, format!("{BASE}/builds/bld_09/promote"));
    assert_eq!(
        serde_json::from_str::<Value>(&reqs[4].body).unwrap(),
        json!({"label": "v1.4.0"})
    );
}
