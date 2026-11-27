//! Runs `prego verify` (ADR-0065 section 7, wire contract of 2026-11-26) against a mock control host that serves
//! the token exchange, a Keys and Certificates version, the attestation route and the attestation keys. The
//! attestations are signed here with a test-only ES256 key, as the registry signs them (DSSE, DER signature,
//! `keyid` = RFC 7638 thumbprint).

use std::process::{Command, Stdio};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use prego_auth::testing::{MockResponse, MockServer, TempDir};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const BIN: &str = env!("CARGO_BIN_EXE_prego");
// Payload {"sub":"prn_1","tid":"ten_1","exp":4102444800} (2100-01-01).
const REG_TOKEN: &str =
    "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJwcm5fMSIsInRpZCI6InRlbl8xIiwiZXhwIjo0MTAyNDQ0ODAwfQ.c2ln";
const SHA: &str = "9f2c3e4d5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d";
const PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run(server: &MockServer, args: &[&str]) -> Run {
    let out = Command::new(BIN)
        .args(args)
        .env_clear()
        .env("PREGO_API_KEY", "prk_test_verify_secret")
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A test-only attestation key: the pair, its public JWK and its RFC 7638 thumbprint.
struct Signer {
    pair: EcdsaKeyPair,
    jwk: Value,
    kid: String,
}

impl Signer {
    fn new() -> Signer {
        let rng = SystemRandom::new();
        let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, doc.as_ref(), &rng).unwrap();
        let point = pair.public_key().as_ref().to_vec();
        let x = URL_SAFE_NO_PAD.encode(&point[1..33]);
        let y = URL_SAFE_NO_PAD.encode(&point[33..65]);
        let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
        let kid = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()));
        let jwk = json!({"kty": "EC", "crv": "P-256", "x": x, "y": y, "kid": kid, "alg": "ES256", "use": "sig"});
        Signer { pair, jwk, kid }
    }

    fn jwks(&self) -> String {
        json!({ "keys": [self.jwk] }).to_string()
    }

    /// A DSSE envelope over `statement`.
    fn envelope(&self, statement: &Value) -> String {
        let payload = statement.to_string();
        let pae = format!(
            "DSSEv1 {} {PAYLOAD_TYPE} {} {payload}",
            PAYLOAD_TYPE.len(),
            payload.len()
        );
        let sig = self
            .pair
            .sign(&SystemRandom::new(), pae.as_bytes())
            .unwrap();
        json!({
            "payloadType": PAYLOAD_TYPE,
            "payload": STANDARD.encode(payload),
            "signatures": [{ "keyid": self.kid, "sig": STANDARD.encode(sig.as_ref()) }],
        })
        .to_string()
    }
}

/// A publish statement for key `acme/default/release-keys` version `version` with subject `hex`.
fn statement(version: &str, subject_hex: &str, level: &str) -> Value {
    let identity = if level == "ci_source" {
        json!({
            "iss": "https://token.actions.githubusercontent.com",
            "repository": "acme/payments", "ref": "refs/tags/v1.4.0", "sha": SHA,
            "workflow_ref": "acme/payments/.github/workflows/release.yml@refs/tags/v1.4.0",
            "runner_environment": "github-hosted", "run_id": "456", "run_attempt": "1"
        })
    } else {
        json!({})
    };
    json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{ "name": "release-keys", "digest": { "sha256": subject_hex } }],
        "predicateType": "https://prego.k8skill.com/attestation/publish/v1",
        "predicate": {
            "tenant": "acme", "namespace": "default", "type": "key", "name": "release-keys",
            "version": version, "version_id": "ver_1", "published_at": "2026-11-26T10:00:00Z",
            "level": level, "principal_id": "prn_1", "identity": identity
        }
    })
}

/// One jwk entry, and the key version hash of it (ADR-0061 section 4a).
fn key_version() -> (Vec<u8>, String) {
    let entry =
        br#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#
            .to_vec();
    let canonical = format!(
        r#"{{"entries":[{{"sha256":"{}","type":"jwk"}}]}}"#,
        hex(&Sha256::digest(&entry))
    );
    (entry, hex(&Sha256::digest(canonical.as_bytes())))
}

/// The answers for the content step of `key:acme/default/release-keys`.
fn key_content(entry: &[u8], hash_hex: &str) -> Vec<MockResponse> {
    let version = json!({"number": 3, "hash": format!("sha256:{hash_hex}"), "tags": [],
                         "entries": [{"index": 0, "type": "jwk"}]});
    vec![
        sts_ok(),
        MockResponse::json(200, &version.to_string()),
        MockResponse::bytes(200, "application/octet-stream", entry.to_vec()),
    ]
}

fn attestation(envelope: String) -> MockResponse {
    MockResponse::bytes(
        200,
        "application/vnd.dsse.envelope.v1+json",
        envelope.into_bytes(),
    )
    .with_header("X-Prego-Attestation-Id", "att_01")
}

#[test]
fn key_version_verifies_with_policy_and_prints_the_facts() {
    let s = Signer::new();
    let (entry, h) = key_version();
    let mut answers = key_content(&entry, &h);
    answers.extend([
        sts_ok(),
        attestation(s.envelope(&statement("3", &h, "ci_source"))),
        MockResponse::json(200, &s.jwks()),
    ]);
    let server = MockServer::start(answers);
    let r = run(
        &server,
        &[
            "verify",
            "key:acme/default/release-keys",
            "--repository",
            "acme/payments",
            "--ref",
            "v1.4.0",
            "--sha",
            SHA,
            "--level",
            "ci_source",
            "--hosted-runner",
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    let line = |k: &str| {
        r.stdout
            .lines()
            .find(|l| l.split_whitespace().next() == Some(k))
            .map(|l| l.split_whitespace().nth(1).unwrap_or("").to_string())
    };
    assert_eq!(
        line("identity.repository").as_deref(),
        Some("acme/payments"),
        "{}",
        r.stdout
    );
    assert_eq!(line("level").as_deref(), Some("ci_source"), "{}", r.stdout);
    assert!(
        r.stderr.contains(&format!(
            "key:acme/default/release-keys@3: verified (signature, version, content digest, policy) with key {}",
            s.kid
        )),
        "{}",
        r.stderr
    );
    let reqs = server.requests();
    assert_eq!(
        reqs[1].target,
        "/v1/keys/acme/default/release-keys/v/current"
    );
    assert_eq!(
        reqs[4].target,
        "/v1/attestations/acme/default/key/release-keys/3"
    );
    assert_eq!(reqs[5].target, "/.well-known/prego-attestation-keys.json");
    // The public keys are read with no token.
    assert_eq!(reqs[5].header("authorization"), None);
}

#[test]
fn json_output() {
    let s = Signer::new();
    let (entry, h) = key_version();
    let mut answers = key_content(&entry, &h);
    answers.extend([
        sts_ok(),
        attestation(s.envelope(&statement("3", &h, "api_key"))),
        MockResponse::json(200, &s.jwks()),
    ]);
    let server = MockServer::start(answers);
    let r = run(
        &server,
        &["verify", "key:acme/default/release-keys@3", "--json"],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    let v: Value = serde_json::from_str(&r.stdout).unwrap();
    assert_eq!(v["verified"], true);
    assert_eq!(v["version"], "3");
    assert_eq!(v["attestation_id"], "att_01");
    assert_eq!(v["key_id"], s.kid);
    assert_eq!(v["content_checked"], true);
    assert_eq!(v["facts"]["level"], "api_key");
}

#[test]
fn a_wrong_digest_a_wrong_version_and_a_failed_policy_exit_1() {
    let s = Signer::new();
    let (entry, h) = key_version();
    // The attestation names another digest and another version.
    let mut answers = key_content(&entry, &h);
    answers.extend([
        sts_ok(),
        attestation(s.envelope(&statement("2", &"0".repeat(64), "api_key"))),
        MockResponse::json(200, &s.jwks()),
    ]);
    let server = MockServer::start(answers);
    let r = run(
        &server,
        &[
            "verify",
            "key:acme/default/release-keys",
            "--level",
            "ci_source",
        ],
    );
    assert_eq!(r.code, 1, "{}", r.stderr);
    assert!(
        r.stderr
            .contains("wrong_version: the attestation is for version `2`, not `3`"),
        "{}",
        r.stderr
    );
    assert!(r.stderr.contains("digest_mismatch"), "{}", r.stderr);
    assert!(
        r.stderr
            .contains("policy: --level ci_source: the level is api_key"),
        "{}",
        r.stderr
    );
    assert!(r.stderr.contains("NOT verified"), "{}", r.stderr);
}

#[test]
fn another_key_signed_it_exit_1() {
    let s = Signer::new();
    let other = Signer::new();
    let (entry, h) = key_version();
    let mut answers = key_content(&entry, &h);
    let mut env: Value =
        serde_json::from_str(&other.envelope(&statement("3", &h, "api_key"))).unwrap();
    // The other key, with the kid of the published key.
    env["signatures"][0]["keyid"] = s.kid.clone().into();
    answers.extend([
        sts_ok(),
        attestation(env.to_string()),
        MockResponse::json(200, &s.jwks()),
    ]);
    let server = MockServer::start(answers);
    let r = run(&server, &["verify", "key:acme/default/release-keys"]);
    assert_eq!(r.code, 1, "{}", r.stderr);
    assert!(r.stderr.contains("bad_signature"), "{}", r.stderr);
}

#[test]
fn no_attestation_exits_3() {
    let (entry, h) = key_version();
    let mut answers = key_content(&entry, &h);
    answers.extend([
        sts_ok(),
        MockResponse::json(
            404,
            r#"{"error":{"code":"no_attestation","message":"published before attestations"}}"#,
        ),
    ]);
    let server = MockServer::start(answers);
    let r = run(&server, &["verify", "key:acme/default/release-keys"]);
    assert_eq!(r.code, 3, "{}", r.stderr);
    assert!(
        r.stderr.contains("key:acme/default/release-keys@3: no attestation (published before attestations started)"),
        "{}",
        r.stderr
    );
}

#[test]
fn no_content_with_a_local_key_file() {
    let s = Signer::new();
    let dir = TempDir::new("prego-verify-keys");
    let keys = dir.join("keys.json");
    std::fs::write(&keys, s.jwks()).unwrap();
    let server = MockServer::start(vec![
        sts_ok(),
        attestation(s.envelope(&statement("3", &"a".repeat(64), "api_key"))),
    ]);
    let r = run(
        &server,
        &[
            "verify",
            "key:acme/default/release-keys@3",
            "--no-content",
            "--keys",
            keys.to_str().unwrap(),
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stderr.contains("content not checked: --no-content"),
        "{}",
        r.stderr
    );
    // Only the token exchange and the attestation: no content, no published keys.
    assert_eq!(server.requests().len(), 2);
}

#[test]
fn usage_and_network_errors_exit_2() {
    let server = MockServer::start(vec![]);
    for args in [
        vec!["verify", "release-keys"],
        vec!["verify", "zip:acme/default/x"],
        vec!["verify", "key:acme/default/k", "--no-content"],
        vec!["verify", "key:acme/default/k@1", "--level", "root"],
        vec!["verify", "key:acme/default/k@1", "--sha", "9f2c"],
        vec!["verify", "key:acme/default/k@1", "--bogus"],
        vec!["verify"],
    ] {
        let r = run(&server, &args);
        assert_eq!(r.code, 2, "{args:?}: {}", r.stderr);
    }
    // A missing grant (404 without no_attestation) is an error, not "no attestation".
    let (entry, h) = key_version();
    let mut answers = key_content(&entry, &h);
    answers.extend([
        sts_ok(),
        MockResponse::json(404, r#"{"error":{"code":"not_found"}}"#),
    ]);
    let server = MockServer::start(answers);
    let r = run(&server, &["verify", "key:acme/default/release-keys"]);
    assert_eq!(r.code, 2, "{}", r.stderr);
    assert!(
        r.stderr.contains("not found, or you have no grant for it"),
        "{}",
        r.stderr
    );
}

/// A statement for a package type with these subjects.
fn package_statement(typ: &str, name: &str, version: &str, subjects: Value) -> Value {
    json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects,
        "predicateType": "https://prego.k8skill.com/attestation/publish/v1",
        "predicate": {
            "tenant": "acme", "namespace": "default", "type": typ, "name": name,
            "version": version, "version_id": "ver_9", "published_at": "2026-11-26T10:00:00Z",
            "level": "workload", "principal_id": "prn_1", "identity": {"iss": "https://ci.example", "sub": "job"}
        }
    })
}

fn host(server: &MockServer) -> String {
    server.base_url().trim_start_matches("http://").to_string()
}

#[test]
fn npm_latest_tarball_both_digests() {
    let s = Signer::new();
    let tarball = b"npm tarball bytes".to_vec();
    let sha256 = hex(&Sha256::digest(&tarball));
    let sha512 = sha2::Sha512::digest(&tarball);
    let packument = |base: &str| {
        json!({
            "name": "@acme/hello",
            "dist-tags": {"latest": "1.2.0"},
            "versions": {
                "1.2.0": {"dist": {
                    "tarball": format!("{base}/t/acme/default/@acme/hello/-/hello-1.2.0.tgz"),
                    "integrity": format!("sha512-{}", STANDARD.encode(sha512)),
                }}
            }
        })
        .to_string()
    };
    let st = package_statement(
        "npm",
        "@acme/hello",
        "1.2.0",
        json!([{"name": "hello-1.2.0.tgz", "digest": {"sha256": sha256, "sha512": hex(&sha512)}}]),
    );
    // Two runs: the right digests, then a tarball that does not match the attestation.
    for (bytes, code) in [(tarball.clone(), 0), (b"other bytes".to_vec(), 2)] {
        let server = MockServer::start_with(|base| {
            let mut v = vec![
                sts_ok(),
                MockResponse::json(200, &packument(base)),
                MockResponse::bytes(200, "application/octet-stream", bytes.clone()),
            ];
            if code == 0 {
                v.extend([
                    sts_ok(),
                    attestation(s.envelope(&st)),
                    MockResponse::json(200, &s.jwks()),
                ]);
            }
            v
        });
        let r = run(
            &server,
            &[
                "verify",
                "npm:acme/default/@acme/hello",
                "--registry",
                &host(&server),
            ],
        );
        assert_eq!(r.code, code, "{}", r.stderr);
        let reqs = server.requests();
        assert_eq!(reqs[1].target, "/t/acme/default/@acme%2fhello");
        if code == 0 {
            assert_eq!(
                reqs[4].target,
                "/v1/attestations/acme/default/npm/%40acme%2Fhello/1.2.0"
            );
        } else {
            // The tarball does not match its integrity value: stopped before the attestation.
            assert!(
                r.stderr.contains("does not match its integrity value"),
                "{}",
                r.stderr
            );
        }
    }
}

#[test]
fn npm_tarball_behind_a_download_link_gets_no_token() {
    let s = Signer::new();
    let tarball = b"npm tarball bytes".to_vec();
    let sha512 = sha2::Sha512::digest(&tarball);
    let st = package_statement(
        "npm",
        "hello",
        "1.0.0",
        json!([{"name": "hello-1.0.0.tgz", "digest": {"sha256": hex(&Sha256::digest(&tarball)), "sha512": hex(&sha512)}}]),
    );
    let server = MockServer::start_with(|base| {
        vec![
            sts_ok(),
            MockResponse::json(
                200,
                &json!({"dist-tags": {"latest": "1.0.0"}, "versions": {"1.0.0": {"dist": {
                    "tarball": format!("{base}/t/acme/default/hello/-/hello-1.0.0.tgz"),
                    "integrity": format!("sha512-{}", STANDARD.encode(sha512))}}}})
                .to_string(),
            ),
            MockResponse::redirect(&format!("{base}/storage/hello-1.0.0.tgz?sig=x")),
            MockResponse::bytes(200, "application/octet-stream", tarball.clone()),
            sts_ok(),
            attestation(s.envelope(&st)),
            MockResponse::json(200, &s.jwks()),
        ]
    });
    let r = run(
        &server,
        &[
            "verify",
            "npm:acme/default/hello",
            "--registry",
            &host(&server),
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    let reqs = server.requests();
    assert!(reqs[2].header("authorization").is_some());
    assert_eq!(reqs[3].target, "/storage/hello-1.0.0.tgz?sig=x");
    assert_eq!(reqs[3].header("authorization"), None);
}

const WHL: &str = "acme_pay-1.0.0-py3-none-any.whl";
const SDIST: &str = "acme-pay-1.0.0.tar.gz";

/// The attestation of one Python file (wire contract item 14), with this uploader repository.
fn python_file_statement(file: &str, bytes: &[u8], repository: &str) -> Value {
    let mut st = package_statement(
        "python",
        "acme-pay",
        "1.0.0",
        json!([{"name": file, "digest": {"sha256": hex(&Sha256::digest(bytes))}}]),
    );
    st["predicate"]["identity"] = json!({"iss": "https://token.actions.githubusercontent.com",
                                         "repository": repository});
    st
}

#[test]
fn python_one_attestation_per_file() {
    let s = Signer::new();
    let whl = b"wheel bytes".to_vec();
    let sdist = b"sdist bytes".to_vec();
    let index = |base: &str| {
        json!({"files": [
            {"filename": WHL, "url": format!("{base}/files/a.whl"),
             "hashes": {"sha256": hex(&Sha256::digest(&whl))}},
            {"filename": "acme_pay-1.1.0-py3-none-any.whl", "url": format!("{base}/files/b.whl"),
             "hashes": {"sha256": "00"}},
            {"filename": SDIST, "url": format!("{base}/files/a.tar.gz"),
             "hashes": {"sha256": hex(&Sha256::digest(&sdist))}},
        ]})
        .to_string()
    };
    // The two files came from two jobs of different repositories.
    let server = MockServer::start_with(|base| {
        vec![
            sts_ok(),
            MockResponse::json(200, &index(base)),
            MockResponse::bytes(200, "application/octet-stream", whl.clone()),
            MockResponse::bytes(200, "application/octet-stream", sdist.clone()),
            sts_ok(),
            attestation(s.envelope(&python_file_statement(WHL, &whl, "acme/pay-wheels"))),
            MockResponse::json(200, &s.jwks()),
            attestation(s.envelope(&python_file_statement(SDIST, &sdist, "acme/pay"))),
        ]
    });
    let r = run(
        &server,
        &[
            "verify",
            "python:acme/default/Acme_Pay@1.0.0",
            "--registry",
            &host(&server),
            "--json",
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    let v: Value = serde_json::from_str(&r.stdout).unwrap();
    assert_eq!(v["verified"], true);
    assert_eq!(v["files"][0]["file"], WHL);
    assert_eq!(
        v["files"][0]["facts"]["identity.repository"],
        "acme/pay-wheels"
    );
    assert_eq!(v["files"][1]["file"], SDIST);
    assert_eq!(v["files"][1]["facts"]["identity.repository"], "acme/pay");
    let reqs = server.requests();
    assert_eq!(reqs[1].target, "/t/acme/default/simple/acme-pay/");
    assert!(reqs[1]
        .header("authorization")
        .unwrap()
        .starts_with("Basic "));
    assert_eq!(reqs[2].target, "/files/a.whl");
    assert_eq!(reqs[3].target, "/files/a.tar.gz");
    assert_eq!(
        reqs[5].target,
        format!(
            "/v1/attestations/acme/default/python/acme-pay/1.0.0?file={}",
            WHL
        )
    );
    assert_eq!(
        reqs[7].target,
        "/v1/attestations/acme/default/python/acme-pay/1.0.0?file=acme-pay-1.0.0.tar.gz"
    );
    // A policy that one file fails: exit 1, and the message names the file.
    let server = MockServer::start_with(|base| {
        vec![
            sts_ok(),
            MockResponse::json(200, &index(base)),
            MockResponse::bytes(200, "application/octet-stream", whl.clone()),
            MockResponse::bytes(200, "application/octet-stream", sdist.clone()),
            sts_ok(),
            attestation(s.envelope(&python_file_statement(WHL, &whl, "acme/pay-wheels"))),
            MockResponse::json(200, &s.jwks()),
            attestation(s.envelope(&python_file_statement(SDIST, &sdist, "acme/pay"))),
        ]
    });
    let r = run(
        &server,
        &[
            "verify",
            "python:acme/default/acme-pay@1.0.0",
            "--registry",
            &host(&server),
            "--repository",
            "acme/pay",
        ],
    );
    assert_eq!(r.code, 1, "{}", r.stderr);
    assert!(
        r.stderr.contains(&format!("python:acme/default/acme-pay@1.0.0 file {WHL}: policy: --repository acme/pay: the repository is acme/pay-wheels")),
        "{}",
        r.stderr
    );
    assert!(
        r.stderr.contains(&format!("file {SDIST}: verified")),
        "{}",
        r.stderr
    );
}

#[test]
fn python_no_content_reads_the_file_list_and_a_missing_attestation_exits_3() {
    let s = Signer::new();
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(
            400,
            &json!({"error": {"code": "bad_request", "message": "this release has 2 files; add ?file=<filename>",
                              "files": [WHL, SDIST]}})
            .to_string(),
        ),
        attestation(s.envelope(&python_file_statement(WHL, b"x", "acme/pay"))),
        MockResponse::json(200, &s.jwks()),
        MockResponse::json(404, r#"{"error":{"code":"no_attestation"}}"#),
    ]);
    let r = run(
        &server,
        &[
            "verify",
            "python:acme/default/acme-pay@1.0.0",
            "--no-content",
        ],
    );
    assert_eq!(r.code, 3, "{}", r.stderr);
    assert!(
        r.stdout.starts_with(&format!("file {WHL}\n")),
        "{}",
        r.stdout
    );
    assert!(
        r.stderr.contains(&format!(
            "file {WHL}: verified (signature, version (content not checked"
        )),
        "{}",
        r.stderr
    );
    assert!(
        r.stderr.contains(&format!("file {SDIST}: no attestation")),
        "{}",
        r.stderr
    );
    let reqs = server.requests();
    assert_eq!(
        reqs[1].target,
        "/v1/attestations/acme/default/python/acme-pay/1.0.0"
    );
    assert_eq!(
        reqs[2].target,
        format!("/v1/attestations/acme/default/python/acme-pay/1.0.0?file={WHL}")
    );
}

#[test]
fn cargo_crate_from_the_sparse_index() {
    let s = Signer::new();
    let krate = b"crate bytes".to_vec();
    let sha = hex(&Sha256::digest(&krate));
    let lines = format!(
        "{}\n{}\n",
        json!({"name": "payments", "vers": "1.4.0", "cksum": sha, "yanked": false}),
        json!({"name": "payments", "vers": "1.5.0", "cksum": "00", "yanked": true}),
    );
    let st = package_statement(
        "cargo",
        "payments",
        "1.4.0",
        json!([{"name": "payments-1.4.0.crate", "digest": {"sha256": sha}}]),
    );
    let server = MockServer::start_with(|base| {
        vec![
            sts_ok(),
            MockResponse::json(
                200,
                &json!({"dl": format!("{base}/t/acme/default/api/v1/crates")}).to_string(),
            ),
            MockResponse::bytes(200, "text/plain", lines.clone().into_bytes()),
            MockResponse::bytes(200, "application/octet-stream", krate.clone()),
            sts_ok(),
            attestation(s.envelope(&st)),
            MockResponse::json(200, &s.jwks()),
        ]
    });
    let r = run(
        &server,
        &[
            "verify",
            "cargo:acme/default/payments",
            "--registry",
            &host(&server),
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    let reqs = server.requests();
    // The token exchange names the index base as the resource.
    assert!(
        reqs[0].form()["resource"].ends_with("/t/acme/default/"),
        "{:?}",
        reqs[0].form()
    );
    assert_eq!(reqs[1].target, "/t/acme/default/index/config.json");
    assert_eq!(reqs[2].target, "/t/acme/default/index/pa/ym/payments");
    // The latest version that is not yanked.
    assert_eq!(
        reqs[3].target,
        "/t/acme/default/api/v1/crates/payments/1.4.0/download"
    );
    // Cargo sends the token with no scheme.
    assert_eq!(reqs[3].header("authorization").as_deref(), Some(REG_TOKEN));
}

mod support {
    pub mod mock_registry;
}

#[test]
fn oci_tag_resolves_to_the_manifest_digest() {
    use support::mock_registry::{sha256, MockRegistry};
    const KEY: &str = "prk_test_verify_secret";
    let s = Signer::new();
    let reg = MockRegistry::start(&format!("acme:{KEY}"), 1024 * 1024);
    let manifest = br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.empty.v1+json","digest":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","size":2},"layers":[]}"#.to_vec();
    let digest = sha256(&manifest);
    let hex_part = digest.trim_start_matches("sha256:").to_string();
    let st = json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "acme/default/api", "digest": {"sha256": hex_part}}],
        "predicateType": "https://prego.k8skill.com/attestation/publish/v1",
        "predicate": {"tenant": "acme", "namespace": "default", "type": "oci", "name": "api",
                      "version": digest, "level": "workload", "identity": {"spiffe_id": "spiffe://acme/ci"}}
    });
    reg.with(|state| {
        state.manifests.insert(
            ("acme/default/api".into(), digest.clone()),
            (
                "application/vnd.oci.image.manifest.v1+json".into(),
                manifest.clone(),
            ),
        );
        state
            .tags
            .insert(("acme/default/api".into(), "v1".into()), digest.clone());
        let json_h = vec![("Content-Type".to_string(), "application/json".to_string())];
        state.extra.insert(
            "/v1/sts/token/e/k7mq".into(),
            (
                200,
                json_h.clone(),
                json!({"access_token": REG_TOKEN, "token_type": "Bearer", "expires_in": 900})
                    .to_string()
                    .into_bytes(),
            ),
        );
        state.extra.insert(
            format!("/v1/attestations/acme/default/oci/api/{digest}"),
            (
                200,
                vec![("X-Prego-Attestation-Id".into(), "att_oci".into())],
                s.envelope(&st).into_bytes(),
            ),
        );
        state.extra.insert(
            "/.well-known/prego-attestation-keys.json".into(),
            (200, json_h, s.jwks().into_bytes()),
        );
    });
    let out = Command::new(BIN)
        .args([
            "verify",
            "oci:acme/default/api@v1",
            "--registry",
            &reg.host(),
            "--json",
        ])
        .args(["--sts-url", &reg.sts_url()])
        .env_clear()
        .env("PREGO_TENANT", "acme")
        .env("PREGO_API_KEY", KEY)
        .env("PREGO_OCI_HOSTS", reg.host())
        .env("HOME", "/nonexistent")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["version"], digest);
    assert_eq!(v["attestation_id"], "att_oci");
    assert_eq!(v["facts"]["identity.spiffe_id"], "spiffe://acme/ci");
}

/// A zip with stored entries (no compression), as a Go module zip.
fn stored_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    let crc = |d: &[u8]| crc32fast::hash(d);
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in files {
        let offset = out.len() as u32;
        let mut local = Vec::new();
        local.extend(0x0403_4b50u32.to_le_bytes());
        local.extend([20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        local.extend(crc(data).to_le_bytes());
        local.extend((data.len() as u32).to_le_bytes());
        local.extend((data.len() as u32).to_le_bytes());
        local.extend((name.len() as u16).to_le_bytes());
        local.extend(0u16.to_le_bytes());
        local.extend(name.as_bytes());
        out.extend(local);
        out.extend(*data);
        central.extend(0x0201_4b50u32.to_le_bytes());
        central.extend([20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        central.extend(crc(data).to_le_bytes());
        central.extend((data.len() as u32).to_le_bytes());
        central.extend((data.len() as u32).to_le_bytes());
        central.extend((name.len() as u16).to_le_bytes());
        central.extend([0u8; 12]);
        central.extend(offset.to_le_bytes());
        central.extend(name.as_bytes());
    }
    let cd_offset = out.len() as u32;
    let cd_len = central.len() as u32;
    out.extend(central);
    out.extend(0x0605_4b50u32.to_le_bytes());
    out.extend([0u8; 4]);
    out.extend((files.len() as u16).to_le_bytes());
    out.extend((files.len() as u16).to_le_bytes());
    out.extend(cd_len.to_le_bytes());
    out.extend(cd_offset.to_le_bytes());
    out.extend(0u16.to_le_bytes());
    out
}

/// `dirhash.Hash1`: the files sorted by name, then base64 of the SHA-256 of the lines `<sha256 hex>  <name>\n`.
fn hash1(files: &[(&str, &[u8])]) -> String {
    let mut sorted = files.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    let lines: String = sorted
        .iter()
        .map(|(n, d)| format!("{}  {n}\n", hex(&Sha256::digest(d))))
        .collect();
    format!("h1:{}", STANDARD.encode(Sha256::digest(lines.as_bytes())))
}

#[test]
fn go_latest_module_zip_and_h1() {
    let s = Signer::new();
    let files: [(&str, &[u8]); 2] = [
        (
            "go.acme.com/Core@v1.4.0/go.mod",
            b"module go.acme.com/Core\n",
        ),
        ("go.acme.com/Core@v1.4.0/core.go", b"package core\n"),
    ];
    let zip = stored_zip(&files);
    let h1 = hash1(&files);
    let mut st = package_statement(
        "go",
        "go.acme.com/Core",
        "v1.4.0",
        json!([{"name": "go.acme.com/Core@v1.4.0.zip", "digest": {"sha256": hex(&Sha256::digest(&zip))}}]),
    );
    st["predicate"]["go_h1"] = h1.clone().into();
    let mut wrong = st.clone();
    wrong["predicate"]["go_h1"] = "h1:AAAA".into();
    for (statement, code) in [(st, 0), (wrong, 1)] {
        let server = MockServer::start(vec![
            sts_ok(),
            MockResponse::json(200, r#"{"Version":"v1.4.0"}"#),
            MockResponse::bytes(200, "application/zip", zip.clone()),
            sts_ok(),
            attestation(s.envelope(&statement)),
            MockResponse::json(200, &s.jwks()),
        ]);
        let r = run(
            &server,
            &[
                "verify",
                "go:acme/default/go.acme.com/Core",
                "--registry",
                &host(&server),
            ],
        );
        assert_eq!(r.code, code, "{}", r.stderr);
        let reqs = server.requests();
        // Upper case is escaped as in the module proxy protocol.
        assert_eq!(reqs[1].target, "/t/acme/default/go.acme.com/!core/@latest");
        assert_eq!(
            reqs[2].target,
            "/t/acme/default/go.acme.com/!core/@v/v1.4.0.zip"
        );
        if code == 1 {
            assert!(
                r.stderr.contains(&format!("the h1 hash here is {h1}")),
                "{}",
                r.stderr
            );
        }
    }
}

#[test]
fn apispec_document_as_published() {
    let s = Signer::new();
    let doc = b"openapi: 3.1.0\ninfo:\n  title: Payments\n  version: 1.4.0\npaths: {}\n".to_vec();
    let h = hex(&Sha256::digest(&doc));
    let st = package_statement(
        "apispec",
        "payments-api",
        "1.4.0",
        json!([{"name": "payments-api", "digest": {"sha256": h}}]),
    );
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(
            200,
            &json!({"name": "payments-api", "highest_version": "1.4.0"}).to_string(),
        ),
        MockResponse::bytes(200, "application/yaml", doc.clone())
            .with_header("X-Prego-Apispec-Version", "1.4.0")
            .with_header("X-Prego-Apispec-Hash", &format!("sha256:{h}")),
        sts_ok(),
        attestation(s.envelope(&st)),
        MockResponse::json(200, &s.jwks()),
    ]);
    let r = run(&server, &["verify", "apispec:acme/default/payments-api"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stderr.contains("apispec:acme/default/payments-api@1.4.0: verified (signature, version, content digest)"),
        "{}",
        r.stderr
    );
    let reqs = server.requests();
    assert_eq!(reqs[1].target, "/v1/apispec/acme/default/payments-api");
    assert_eq!(
        reqs[2].target,
        "/v1/apispec/acme/default/payments-api/1.4.0"
    );
    assert_eq!(
        reqs[4].target,
        "/v1/attestations/acme/default/apispec/payments-api/1.4.0"
    );
}
