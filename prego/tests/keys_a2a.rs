//! Runs `prego keys` and `prego a2a` (ADR-0061, ADR-0062): the offline commands, the private-material stop
//! before any request, and the full flow `keys new` -> `a2a push --sign` -> `a2a get --verify` against mock
//! control hosts that serve the token exchange and `/v1/keys/*` and `/v1/a2a/*` in the shapes of the wire
//! contract (ADR-0061 section 4a, ADR-0062 section 3a). Data comes from the shared vectors where it can.

mod support {
    pub mod temp_dir;
}

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use prego_auth::testing::{MockResponse, MockServer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use support::temp_dir::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_prego");
// Payload {"sub":"prn_1","tid":"ten_1","exp":4102444800} (2100-01-01).
const REG_TOKEN: &str =
    "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJwcm5fMSIsInRpZCI6InRlbl8xIiwiZXhwIjo0MTAyNDQ0ODAwfQ.c2ln";

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run_in(dir: &Path, args: &[&str]) -> Run {
    let out = Command::new(BIN)
        .current_dir(dir)
        .args(args)
        .env_clear()
        .env("PREGO_API_KEY", "prk_test_keys_secret")
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

/// No identity at all: the offline commands must not need one.
fn run_offline(dir: &Path, args: &[&str]) -> Run {
    let out = Command::new(BIN)
        .current_dir(dir)
        .args(args)
        .env_clear()
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

fn temp_dir(name: &str) -> TempDir {
    TempDir::new(&format!("keys-a2a-{name}"))
}

fn vectors() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn sts_ok() -> MockResponse {
    MockResponse::json(
        200,
        &json!({ "access_token": REG_TOKEN, "token_type": "Bearer", "expires_in": 900 })
            .to_string(),
    )
}

fn sts(server: &MockServer) -> String {
    format!("{}/v1/sts/token/e/k7mq", server.base_url())
}

fn hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The key version hash of one jwk entry (ADR-0061 section 4a), written out by hand.
fn key_hash(entry: &[u8]) -> String {
    let canonical = format!(
        r#"{{"entries":[{{"sha256":"{}","type":"jwk"}}]}}"#,
        hex(entry)
    );
    format!("sha256:{}", hex(canonical.as_bytes()))
}

fn keys_case(name: &str) -> Value {
    let v: Value =
        serde_json::from_slice(&std::fs::read(vectors().join("keys/cases.json")).unwrap()).unwrap();
    for group in ["valid", "invalid", "private_material"] {
        if let Some(c) = v[group]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == name)
        {
            return c.clone();
        }
    }
    panic!("no keys case {name}");
}

fn unpack(body: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut plain = Vec::new();
    flate2::read::GzDecoder::new(body)
        .read_to_end(&mut plain)
        .unwrap();
    let mut a = tar::Archive::new(plain.as_slice());
    a.entries()
        .unwrap()
        .map(|e| {
            let mut e = e.unwrap();
            let path = String::from_utf8(e.path_bytes().into_owned()).unwrap();
            let mut data = Vec::new();
            e.read_to_end(&mut data).unwrap();
            (path, data)
        })
        .collect()
}

#[test]
fn keys_fingerprint_is_offline_and_matches_the_vectors() {
    let dir = temp_dir("fp");
    let c = keys_case("ssh-ed25519");
    std::fs::write(dir.join("id.pub"), c["content"].as_str().unwrap()).unwrap();
    let r = run_offline(&dir, &["keys", "fingerprint", "id.pub"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stdout
            .starts_with(c["entry"]["fingerprint"].as_str().unwrap()),
        "{}",
        r.stdout
    );
}

#[test]
fn keys_push_stops_at_a_private_key_before_any_request() {
    let dir = temp_dir("private");
    std::fs::write(
        dir.join("a.pub"),
        keys_case("ssh-ed25519")["content"].as_str().unwrap(),
    )
    .unwrap();
    std::fs::write(
        dir.join("id_ed25519"),
        keys_case("openssh-private-key")["content"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let server = MockServer::start(vec![]);
    let r = run_in(
        &dir,
        &[
            "keys",
            "push",
            "a.pub",
            "id_ed25519",
            "acme/deploy-keys",
            "--sts-url",
            &sts(&server),
        ],
    );
    assert_eq!(r.code, 1);
    assert!(
        r.stderr.contains(
            "Keys and Certificates holds public keys and certificates only. Entry 1 holds a private key \
             (OpenSSH private key). Upload the public key (`ssh-keygen -y -f <key>`) instead."
        ),
        "{}",
        r.stderr
    );
    assert!(r.stderr.contains("Nothing was sent"), "{}", r.stderr);
    assert!(server.requests().is_empty());
}

#[test]
fn keys_push_sends_the_entries_and_the_local_hash_matches() {
    let dir = temp_dir("push");
    let c = keys_case("jwk-ed25519");
    let content = c["content"].as_str().unwrap();
    std::fs::write(dir.join("signer.jwk"), content).unwrap();
    let hash = key_hash(content.as_bytes());
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(
            201,
            &json!({"created": true, "version": {"number": 1, "hash": hash}}).to_string(),
        ),
    ]);
    let r = run_in(
        &dir,
        &[
            "keys",
            "push",
            "signer.jwk",
            "acme/release-keys/signer",
            "--message",
            "first",
            "--sts-url",
            &sts(&server),
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(
        r.stdout,
        format!("acme/release-keys/signer: version 1 ({hash}), 1 entries\n")
    );
    assert!(!r.stderr.contains("warning"), "{}", r.stderr);
    let reqs = server.requests();
    assert_eq!(reqs[1].method, "PUT");
    assert_eq!(reqs[1].target, "/v1/keys/acme/release-keys/signer");
    let body: Value = serde_json::from_str(&reqs[1].body).unwrap();
    assert_eq!(
        body,
        json!({"entries": [{"type": "jwk", "content": content, "encoding": "text"}], "message": "first"})
    );
}

#[test]
fn a2a_upgrade_needs_no_account_and_gives_the_vector_output() {
    let dir = temp_dir("upgrade");
    let case = vectors().join("a2a/upgrade/full-03");
    std::fs::copy(case.join("agent.json"), dir.join("agent.json")).unwrap();
    let r = run_offline(&dir, &["a2a", "upgrade", "agent.json"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.stdout.trim(), "agent-card.json");
    let got: Value =
        serde_json::from_slice(&std::fs::read(dir.join("agent-card.json")).unwrap()).unwrap();
    let want: Value =
        serde_json::from_slice(&std::fs::read(case.join("agent-card.json")).unwrap()).unwrap();
    assert_eq!(got, want);
    // The output file is never replaced without --force.
    let r = run_offline(&dir, &["a2a", "upgrade", "agent.json"]);
    assert_eq!(r.code, 1);
    assert!(r.stderr.contains("--force"), "{}", r.stderr);
    // A 0.3 card in a push names the upgrade.
    let r = run_offline(&dir, &["a2a", "check", "agent.json"]);
    assert_eq!(r.code, 1);
    assert!(
        r.stderr.contains("Run `prego a2a upgrade agent.json`"),
        "{}",
        r.stderr
    );
    // The 1.0 output passes the check; it is not signed yet.
    let r = run_offline(&dir, &["a2a", "check", "agent-card.json"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stdout.contains("A2A 1.0 ok"), "{}", r.stdout);
}

#[test]
fn a2a_check_verifies_a_vector_card_with_a_local_public_key() {
    let dir = temp_dir("check");
    std::fs::copy(
        vectors().join("a2a/cards/signed-eddsa-with-source.json"),
        dir.join("acme.support-bot.json"),
    )
    .unwrap();
    std::fs::copy(
        vectors().join("a2a/keys/TEST-ONLY-ed25519.public.jwk.json"),
        dir.join("signer.jwk"),
    )
    .unwrap();
    let r = run_offline(
        &dir,
        &[
            "a2a",
            "check",
            "acme.support-bot.json",
            "--key-file",
            "signer.jwk",
        ],
    );
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    assert!(r.stdout.contains(": good (EdDSA by "), "{}", r.stdout);
    std::fs::copy(
        vectors().join("a2a/keys/TEST-ONLY-ed25519-other.public.jwk.json"),
        dir.join("other.jwk"),
    )
    .unwrap();
    let r = run_offline(
        &dir,
        &[
            "a2a",
            "check",
            "acme.support-bot.json",
            "--key-file",
            "other.jwk",
        ],
    );
    assert_eq!(r.code, 1, "{}", r.stdout);
}

const CARD: &str = r#"{
  "name": "Support Bot",
  "description": "Answers questions about orders.",
  "supportedInterfaces": [{"url": "https://support.example.com/a2a", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}],
  "version": "1.0.0",
  "capabilities": {"streaming": true},
  "defaultInputModes": ["text/plain"],
  "defaultOutputModes": ["text/plain"],
  "skills": [{"id": "orders", "name": "Orders", "description": "Order status", "tags": ["orders"]}]
}
"#;

/// The answers of the key item `acme/default/release-keys` with one jwk entry.
fn key_answers(public: &[u8], revoked: bool, not_after: Option<&str>) -> Vec<MockResponse> {
    let hash = key_hash(public);
    let item = json!({
        "name": "release-keys", "namespace": "default", "current": {"number": 1, "hash": hash},
        "version_count": 1, "tags": {}, "not_after": not_after,
        "revoked_at": if revoked { json!("2026-11-24T10:00:00Z") } else { Value::Null },
        "revoke_reason": if revoked { json!("key lost") } else { Value::Null },
    });
    let version =
        json!({"number": 1, "hash": hash, "tags": [], "entries": [{"index": 0, "type": "jwk"}]});
    vec![
        sts_ok(),
        MockResponse::json(200, &item.to_string()),
        MockResponse::json(200, &version.to_string()),
        MockResponse::bytes(200, "application/octet-stream", public.to_vec()),
    ]
}

#[test]
fn keys_new_then_signed_push_then_get_verify() {
    let dir = temp_dir("flow");
    // 1. keys new: no current version (404), then the push of the public JWK.
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(
            404,
            r#"{"error":{"code":"not_found","message":"not found"}}"#,
        ),
        MockResponse::json(201, r#"{"created": true, "version": {"number": 1}}"#),
    ]);
    let r = run_in(
        &dir,
        &[
            "keys",
            "new",
            "--alg",
            "ed25519",
            "acme/release-keys",
            "--sts-url",
            &sts(&server),
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    let key_file = dir.join("release-keys.private.pem");
    let public = std::fs::read(dir.join("release-keys.pub.jwk")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&key_file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let reqs = server.requests();
    assert_eq!(reqs[2].target, "/v1/keys/acme/default/release-keys");
    let body: Value = serde_json::from_str(&reqs[2].body).unwrap();
    assert_eq!(
        body["entries"][0]["content"].as_str().unwrap().as_bytes(),
        public.as_slice()
    );
    assert!(
        !reqs[2].body.contains("PRIVATE"),
        "the private key left the machine"
    );
    let kid = serde_json::from_slice::<Value>(&public).unwrap()["kid"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(r.stdout.contains(&kid), "{}", r.stdout);

    // 2. a2a push --sign: the key is checked in Keys and Certificates, then the signed tarball goes up.
    std::fs::create_dir_all(dir.join("cards")).unwrap();
    std::fs::write(dir.join("cards/acme.support-bot.json"), CARD).unwrap();
    let mut answers = key_answers(&public, false, None);
    answers.push(sts_ok());
    answers.push(MockResponse::json(
        201,
        r#"{"created": true, "version": {"number": 1}}"#,
    ));
    let server = MockServer::start(answers);
    let r = run_in(
        &dir,
        &[
            "a2a",
            "push",
            "cards",
            "acme/agents/support",
            "--sign",
            "release-keys.private.pem",
            "--key",
            "acme/release-keys",
            "--sts-url",
            &sts(&server),
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stdout.contains("acme/agents/support: version 1"),
        "{}",
        r.stdout
    );
    let reqs = server.requests();
    let put = reqs.iter().find(|q| q.method == "PUT").unwrap();
    assert_eq!(put.target, "/v1/a2a/acme/agents/support");
    let files = unpack(&put.raw);
    let names: Vec<&str> = files.iter().map(|(p, _)| p.as_str()).collect();
    assert_eq!(names, vec![".prego/set.jws.json", "acme.support-bot.json"]);
    let card: Value = serde_json::from_slice(&files[1].1).unwrap();
    assert_eq!(
        card["capabilities"]["extensions"][0],
        json!({"uri": "https://prego.k8skill.com/ext/a2a-source/v1", "params": {"tenant": "acme", "namespace": "agents", "set": "support"}})
    );
    assert_eq!(card["signatures"].as_array().unwrap().len(), 1);
    let card_bytes = files[1].1.clone();
    let set_sig = files[0].1.clone();

    // 3. a2a get --verify, from a registry that serves what was pushed.
    let entry = |p: &str, b: &[u8]| (p.to_string(), b.to_vec());
    let cards = [entry("acme.support-bot.json", &card_bytes)];
    let list = format!(
        r#"{{"files":[{{"mode":"0644","path":"acme.support-bot.json","sha256":"{}","size":{}}}]}}"#,
        hex(&card_bytes),
        card_bytes.len()
    );
    let version_hash = format!("sha256:{}", hex(list.as_bytes()));
    let signer = json!({"key": "acme/default/release-keys", "key_version": 1, "thumbprint": kid, "alg": "EdDSA"});
    let listing = json!({
        "number": 1, "hash": version_hash, "tags": [], "pushed_by": "prn_1", "pushed_at": "2026-11-24T10:00:00Z",
        "message": null, "signatures": [signer],
        "cards": [{"file": "acme.support-bot.json", "name": "Support Bot", "sha256": hex(&card_bytes),
                   "size": card_bytes.len(), "skills": ["Orders"], "signers": [signer],
                   "source": {"tenant": "acme", "namespace": "agents", "set": "support"}}],
    });
    let get_answers = |key: Vec<MockResponse>| {
        let mut a = vec![
            sts_ok(),
            MockResponse::json(200, &listing.to_string()),
            MockResponse::bytes(200, "application/json", cards[0].1.clone()),
            MockResponse::bytes(200, "application/json", set_sig.clone()),
        ];
        a.extend(key);
        a
    };
    let server = MockServer::start(get_answers(key_answers(
        &public,
        false,
        Some("2027-01-01T00:00:00Z"),
    )));
    let r = run_in(
        &dir,
        &[
            "a2a",
            "get",
            "acme/agents/support",
            "out",
            "--verify",
            "--sts-url",
            &sts(&server),
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stderr.contains("every card signature verify"),
        "{}",
        r.stderr
    );
    assert_eq!(
        std::fs::read(dir.join("out/acme.support-bot.json")).unwrap(),
        card_bytes
    );
    assert!(dir.join("out/.prego/set.jws.json").is_file());
    let reqs = server.requests();
    assert_eq!(reqs[1].target, "/v1/a2a/acme/agents/support/v/current");
    assert!(
        reqs.iter()
            .any(|q| q.target == "/v1/keys/acme/default/release-keys/v/1"),
        "{reqs:?}"
    );

    // 4. No read on the key item: --verify names the key grant.
    let server = MockServer::start(get_answers(vec![
        sts_ok(),
        MockResponse::json(
            404,
            r#"{"error":{"code":"not_found","message":"not found","request_id":"req_404"}}"#,
        ),
    ]));
    let r = run_in(
        &dir,
        &[
            "a2a",
            "get",
            "acme/agents/support",
            "out2",
            "--verify",
            "--sts-url",
            &sts(&server),
        ],
    );
    assert_eq!(r.code, 1);
    assert!(
        r.stderr.contains(
            "verify needs read on key acme/default/release-keys (type Keys and Certificates); ask an admin of acme \
             for a grant"
        ),
        "{}",
        r.stderr
    );
    assert!(!dir.join("out2").exists());

    // 5. A revoked key: --verify fails with the reason.
    let server = MockServer::start(get_answers(key_answers(&public, true, None)));
    let r = run_in(
        &dir,
        &[
            "a2a",
            "get",
            "acme/agents/support",
            "out3",
            "--verify",
            "--sts-url",
            &sts(&server),
        ],
    );
    assert_eq!(r.code, 1);
    assert!(
        r.stderr
            .contains("was revoked at 2026-11-24T10:00:00Z (key lost)"),
        "{}",
        r.stderr
    );

    // 6. The key ended (not_after) before the version was pushed: --verify fails. (Step 3 had a key that ends
    // after the push, which passes.)
    let server = MockServer::start(get_answers(key_answers(
        &public,
        false,
        Some("2026-11-01T00:00:00Z"),
    )));
    let r = run_in(
        &dir,
        &[
            "a2a",
            "get",
            "acme/agents/support",
            "out4",
            "--verify",
            "--sts-url",
            &sts(&server),
        ],
    );
    assert_eq!(r.code, 1);
    assert!(
        r.stderr
            .contains("ended at 2026-11-01T00:00:00Z (not_after), before this version was pushed"),
        "{}",
        r.stderr
    );
}

#[test]
fn a2a_get_without_a_grant_names_the_set_grant() {
    let dir = temp_dir("nogrant");
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(
            404,
            r#"{"error":{"code":"not_found","message":"not found","request_id":"req_404"}}"#,
        ),
    ]);
    let r = run_in(
        &dir,
        &[
            "a2a",
            "get",
            "acme/agents/support",
            "--sts-url",
            &sts(&server),
        ],
    );
    assert_eq!(r.code, 1);
    assert!(
        r.stderr.contains(
            "prego: read on a2a set acme/agents/support (type A2A Agent Cards) is missing; ask an admin of acme \
             for a grant ("
        ),
        "{}",
        r.stderr
    );
}

#[test]
fn a2a_push_without_signatures_says_how_to_sign() {
    let dir = temp_dir("unsigned");
    std::fs::create_dir_all(dir.join("cards")).unwrap();
    std::fs::write(dir.join("cards/acme.support-bot.json"), CARD).unwrap();
    let server = MockServer::start(vec![]);
    let r = run_in(
        &dir,
        &[
            "a2a",
            "push",
            "cards",
            "acme/agents/support",
            "--sts-url",
            &sts(&server),
        ],
    );
    assert_eq!(r.code, 1);
    assert!(
        r.stderr
            .contains("A2A Agent Cards must be signed. Sign with `prego a2a push --sign"),
        "{}",
        r.stderr
    );
    assert!(server.requests().is_empty());
}

/// Staging keys-e2e G: `keys get` by a principal without a grant. The registry 404 carries a request id; the
/// message names the missing grant first (ADR-0061 section 3.6).
#[test]
fn keys_get_without_a_grant_names_the_key_grant() {
    let dir = temp_dir("keys-nogrant");
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(
            404,
            r#"{"error":{"code":"not_found","message":"not found","request_id":"req_g"}}"#,
        ),
    ]);
    let r = run_in(
        &dir,
        &[
            "keys",
            "get",
            "acme/release-keys/signer",
            "--sts-url",
            &sts(&server),
        ],
    );
    assert_eq!(r.code, 1);
    assert!(
        r.stderr.starts_with(
            "prego: read on key acme/release-keys/signer (type Keys and Certificates) is missing; ask an admin of \
             acme for a grant ("
        ),
        "{}",
        r.stderr
    );
    assert!(r.stderr.contains("request req_g"), "{}", r.stderr);
}
