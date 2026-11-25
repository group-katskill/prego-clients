//! Runs `prego context` against a mock control host that serves the token exchange and `/v1/context/*`.
//! The checkpoint hashes come from the shared Snippets vectors (`tests/vectors/snippets/cases.json`): a
//! checkpoint uses the same file-list hash (ADR-0058 item 6).

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use prego_auth::testing::{MockResponse, MockServer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const BIN: &str = env!("CARGO_BIN_EXE_prego");
const API_KEY: &str = "prk_test_context_secret";
// Payload {"sub":"prn_1","tid":"ten_1","exp":4102444800} (2100-01-01).
const REG_TOKEN: &str =
    "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJwcm5fMSIsInRpZCI6InRlbl8xIiwiZXhwIjo0MTAyNDQ0ODAwfQ.c2ln";

struct Run {
    code: i32,
    stdout: Vec<u8>,
    stderr: String,
}

impl Run {
    fn out(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
}

fn run_in(dir: &Path, args: &[&str]) -> Run {
    let out = Command::new(BIN)
        .current_dir(dir)
        .args(args)
        .env_clear()
        .env("PREGO_API_KEY", API_KEY)
        .env("HOME", "/nonexistent")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run prego");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: out.stdout,
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// A temp directory, zeroed and removed when the test ends (also after a panic).
fn temp_dir(name: &str) -> prego_auth::testing::TempDir {
    prego_auth::testing::TempDir::new(&format!("prego-context-{name}"))
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

/// A secret-shaped string made at run time (an AWS access key ID shape), so the source has none.
fn aws_like() -> String {
    format!("AK{}", "IAQWERTYUIOPASDFGH")
}

/// One case of the shared vectors: its files (path, mode, bytes) and its hash.
struct Case {
    files: Vec<(String, u32, Vec<u8>)>,
    hash: String,
}

fn case(name: &str) -> Case {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/snippets");
    let v: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("cases.json")).unwrap()).unwrap();
    let c = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap();
    let root = dir.join(c["dir"].as_str().unwrap());
    let mut files: Vec<(String, u32, Vec<u8>)> = c["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            let p = f["path"].as_str().unwrap().to_string();
            let mode = u32::from_str_radix(f["mode"].as_str().unwrap(), 8).unwrap();
            let data = std::fs::read(root.join(&p)).unwrap();
            (p, mode, data)
        })
        .collect();
    files.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    Case {
        files,
        hash: c["hash"].as_str().unwrap().to_string(),
    }
}

fn write_case(c: &Case, dir: &Path) {
    for (p, mode, data) in &c.files {
        let target = dir.join(p);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(&target, data).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(*mode)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = mode;
    }
}

fn file_list(files: &[(String, u32, Vec<u8>)]) -> Value {
    json!(files
        .iter()
        .map(|(p, m, d)| json!({
            "path": p, "mode": format!("{m:04o}"), "size": d.len(), "sha256": hex(d)
        }))
        .collect::<Vec<_>>())
}

fn meta_answer(c: &Case, seq: u64) -> Value {
    json!({
        "seq": seq, "hash": c.hash, "session": "s1", "size": 100, "file_count": c.files.len(),
        "format": "tar.gz", "encryption": {"mode": "none"}, "files": file_list(&c.files)
    })
}

/// A `.tar.gz` of files, made here with the `tar` crate (not with the code under test).
fn tarball(files: &[(String, u32, Vec<u8>)]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    for (p, m, d) in files {
        let mut h = tar::Header::new_ustar();
        h.set_size(d.len() as u64);
        h.set_mode(*m);
        h.set_entry_type(tar::EntryType::Regular);
        // The name is written as bytes, so a test can make a bad path (`..`) that `set_path` refuses.
        h.as_old_mut().name[..p.len()].copy_from_slice(p.as_bytes());
        h.set_cksum();
        b.append(&h, d.as_slice()).unwrap();
    }
    let plain = b.into_inner().unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut gz, &plain).unwrap();
    gz.finish().unwrap()
}

/// Reads the files of a `.tar.gz` request body.
fn unpack(body: &[u8]) -> Vec<(String, u32, Vec<u8>)> {
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
            let mode = e.header().mode().unwrap();
            let mut data = Vec::new();
            e.read_to_end(&mut data).unwrap();
            (path, mode, data)
        })
        .collect()
}

fn kept(dir: &Path) -> Vec<PathBuf> {
    match std::fs::read_dir(dir.join(".prego-context")) {
        Ok(rd) => rd.map(|e| e.unwrap().path()).collect(),
        Err(_) => Vec::new(),
    }
}

#[cfg(unix)]
#[test]
fn hash_of_a_folder_is_the_shared_vector_hash() {
    for name in ["basic", "basic-mode", "order", "empty-file", "long-path"] {
        let c = case(name);
        let dir = temp_dir(&format!("hash-{name}"));
        write_case(&c, &dir);
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        std::fs::write(dir.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        for extra in [None, Some("--no-redact")] {
            let mut args = vec!["context", "hash", "."];
            args.extend(extra);
            let r = run_in(&dir, &args);
            assert_eq!(r.code, 0, "{name}: {}", r.stderr);
            assert_eq!(r.out().trim(), c.hash, "{name}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn hash_is_of_the_redacted_files_unless_no_redact() {
    let dir = temp_dir("hash-redact");
    std::fs::write(dir.join("notes.md"), format!("key {}\n", aws_like())).unwrap();
    let redacted = "key [REDACTED:aws_access_key_id]\n";
    let r = run_in(&dir, &["context", "hash", "."]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let want = |text: &str| {
        let list = format!(
            r#"{{"files":[{{"mode":"0644","path":"notes.md","sha256":"{}","size":{}}}]}}"#,
            hex(text.as_bytes()),
            text.len()
        );
        format!("sha256:{}", hex(list.as_bytes()))
    };
    assert_eq!(r.out().trim(), want(redacted));
    assert!(r
        .stderr
        .contains("redacted 1 secret-shaped string in 1 file"));
    assert!(!r.stderr.contains(&aws_like()));
    let r = run_in(&dir, &["context", "hash", ".", "--no-redact"]);
    assert_eq!(r.out().trim(), want(&format!("key {}\n", aws_like())));
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn save_redacts_and_sends_the_fixed_tarball_with_its_metadata() {
    let dir = temp_dir("save");
    let mem = dir.join("mem");
    std::fs::create_dir_all(mem.join("notes")).unwrap();
    std::fs::write(mem.join("MEMORY.md"), "# Memory\n").unwrap();
    let secret = aws_like();
    std::fs::write(
        mem.join("notes/today.md"),
        format!("AWS {secret}\nagain {secret}\n"),
    )
    .unwrap();
    let parent = format!("sha256:{}", "a".repeat(64));
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(
            201,
            &json!({"created": true, "seq": 7, "hash": "sha256:x", "file_count": 2, "size": 120,
                "session": "2026-11-20-a", "trigger": "compact", "dropped": {"seq": 2},
                "encryption": {"mode": "none"}})
            .to_string(),
        ),
    ]);
    let r = run_in(
        &dir,
        &[
            "context",
            "save",
            "mem",
            "acme/agents/billing-agent",
            "--sts-url",
            &sts(&server),
            "--session",
            "2026-11-20-a",
            "--trigger",
            "compact",
            "--parent",
            &parent,
            "--label",
            "ticket=OPS-412",
            "--label",
            "team=zoë",
            "--message",
            "Before compaction",
            "--tag",
            "handoff",
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stderr
            .contains("redacted 2 secret-shaped strings in 1 file"),
        "{}",
        r.stderr
    );
    assert!(!r.stderr.contains(&secret) && !r.out().contains(&secret));
    assert!(r.out().starts_with(
        "acme/agents/billing-agent: checkpoint 7 (sha256:x), 2 files, session 2026-11-20-a\n"
    ));
    assert!(r.out().contains("tag handoff -> checkpoint 7"));
    assert!(r.out().contains(
        "acme/agents/billing-agent: removed checkpoint 2, the oldest without a tag (on_full drop_oldest)\n"
    ));
    let reqs = server.requests();
    assert_eq!(reqs[1].method, "PUT");
    assert_eq!(
        reqs[1].target,
        format!(
            "/v1/context/acme/agents/billing-agent?session=2026-11-20-a&parent={}&trigger=compact&message=Before%20compaction&tag=handoff",
            parent.replace(':', "%3A")
        )
    );
    assert_eq!(reqs[1].header("content-type").unwrap(), "application/gzip");
    assert_eq!(
        reqs[1].header("x-prego-labels").unwrap(),
        "{\"ticket\":\"OPS-412\",\"team\":\"zo\\u00eb\"}"
    );
    let files = unpack(&reqs[1].raw);
    assert_eq!(
        files,
        [
            ("MEMORY.md".to_string(), 0o644, b"# Memory\n".to_vec()),
            (
                "notes/today.md".to_string(),
                0o644,
                b"AWS [REDACTED:aws_access_key_id]\nagain [REDACTED:aws_access_key_id]\n".to_vec()
            ),
        ]
    );
    assert!(kept(&dir).is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn save_of_the_same_files_is_a_no_op_and_no_redact_sends_them_as_they_are() {
    let dir = temp_dir("save-noop");
    std::fs::create_dir_all(dir.join("mem")).unwrap();
    std::fs::write(dir.join("mem/a.md"), format!("{}\n", aws_like())).unwrap();
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(
            200,
            &json!({"created": false, "checkpoint": {"seq": 3, "hash": "sha256:y"}}).to_string(),
        ),
    ]);
    let r = run_in(
        &dir,
        &[
            "context",
            "save",
            "mem",
            "acme/agent",
            "--sts-url",
            &sts(&server),
            "--no-redact",
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(
        r.out(),
        "acme/default/agent: no change, checkpoint 3 is the latest (sha256:y)\n"
    );
    assert!(!r.stderr.contains("redacted"));
    let reqs = server.requests();
    assert_eq!(
        reqs[1].target,
        "/v1/context/acme/default/agent?trigger=manual"
    );
    assert_eq!(reqs[1].header("x-prego-labels"), None);
    assert_eq!(
        unpack(&reqs[1].raw)[0].2,
        format!("{}\n", aws_like()).into_bytes()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_refused_save_keeps_the_checkpoint_and_exits_4() {
    let dir = temp_dir("save-refused");
    std::fs::create_dir_all(dir.join("mem")).unwrap();
    std::fs::write(dir.join("mem/notes.md"), "a line\nsecret-ish line\n").unwrap();
    let server = MockServer::start(vec![
        // The registry refuses the content.
        sts_ok(),
        MockResponse::json(
            422,
            r#"{"error":{"code":"looks_like_secret","message":"a file looks like it holds a secret","path":"notes.md","line":2,"secrets":[{"path":"notes.md","line":2},{"path":"notes.md","line":9}],"request_id":"r1"}}"#,
        ),
        // The plan is full.
        sts_ok(),
        MockResponse::json(
            403,
            r#"{"error":{"code":"plan_limit","message":"the checkpoint limit of the plan is reached"}}"#,
        ),
        // The token exchange fails.
        MockResponse::json(401, r#"{"error":"invalid_client"}"#),
    ]);
    let s = sts(&server);
    let mut bodies = Vec::new();
    for (i, want) in [
        "422 looks_like_secret: a file looks like it holds a secret (file: notes.md, line 2) (2 matches: notes.md:2, notes.md:9) (request r1)",
        "403 plan_limit: the checkpoint limit of the plan is reached",
        "401",
    ]
    .iter()
    .enumerate()
    {
        let r = run_in(
            &dir,
            &["context", "save", "mem", "acme/agents/a1", "--sts-url", &s],
        );
        assert_eq!(r.code, 4, "{i}: {}", r.stderr);
        assert!(r.stderr.contains(want), "{i}: {}", r.stderr);
        assert!(r.stderr.contains("the save was refused; the checkpoint (sha256:"));
        assert!(r.stderr.contains(".prego-context/a1-"), "{}", r.stderr);
        bodies.push(kept(&dir).len());
    }
    assert_eq!(bodies, [1, 2, 3]);
    // A kept file is the checkpoint as it was to be sent, and only the owner can read it.
    let reqs = server.requests();
    let mut files = kept(&dir);
    files.sort();
    let sent = &reqs[1].raw;
    assert!(files.iter().any(|f| std::fs::read(f).unwrap() == *sent));
    for f in &files {
        assert!(f.extension().unwrap() == "gz");
        assert_eq!(unpack(&std::fs::read(f).unwrap())[0].0, "notes.md");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(f).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn save_refuses_binary_files_before_any_request() {
    let dir = temp_dir("save-bad");
    std::fs::create_dir_all(dir.join("mem")).unwrap();
    std::fs::write(dir.join("mem/memory.sqlite"), [0u8, 1, 2]).unwrap();
    let r = run_in(
        &dir,
        &[
            "context",
            "save",
            "mem",
            "acme/a1",
            "--sts-url",
            "http://127.0.0.1:9/v1/sts/token/e/k7mq",
        ],
    );
    assert_eq!(r.code, 1, "{}", r.stderr);
    assert!(r.stderr.contains("memory.sqlite") && r.stderr.contains("NUL"));
    assert!(kept(&dir).is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn restore_writes_checked_files_with_their_modes() {
    let c = case("basic");
    let dir = temp_dir("restore");
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(200, &meta_answer(&c, 42).to_string())
            .with_header("X-Prego-Context-Seq", "42")
            .with_header("X-Prego-Context-Hash", &c.hash)
            .with_header("X-Prego-Encryption", "none"),
        MockResponse::bytes(200, "application/gzip", tarball(&c.files))
            .with_header("X-Prego-Encryption", "none"),
    ]);
    let r = run_in(
        &dir,
        &[
            "context",
            "restore",
            "acme/agents/billing-agent",
            "mem",
            "--sts-url",
            &sts(&server),
            "--session",
            "s1",
            "--expect",
            &c.hash,
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.out(), "mem\n");
    assert!(r.stderr.contains(&format!(
        "acme/agents/billing-agent@42 {} (2 files)",
        c.hash
    )));
    use std::os::unix::fs::PermissionsExt;
    for (p, mode, data) in &c.files {
        let target = dir.join("mem").join(p);
        assert_eq!(&std::fs::read(&target).unwrap(), data);
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777,
            *mode
        );
    }
    let reqs = server.requests();
    assert_eq!(
        reqs[1].target,
        format!(
            "/v1/context/acme/agents/billing-agent/at/latest?session=s1&expect={}",
            c.hash.replace(':', "%3A")
        )
    );
    // The content is read by the hash of the listed checkpoint.
    assert_eq!(
        reqs[2].target,
        format!(
            "/v1/context/acme/agents/billing-agent/at/{}/content",
            c.hash
        )
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn restore_with_another_expected_hash_exits_3_and_writes_nothing() {
    let c = case("basic");
    let dir = temp_dir("restore-expect");
    let other = format!("sha256:{}", "0".repeat(64));
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(200, &meta_answer(&c, 3).to_string()),
        sts_ok(),
        MockResponse::json(
            412,
            r#"{"error":{"code":"hash_mismatch","message":"the hash differs"}}"#,
        ),
    ]);
    for _ in 0..2 {
        let r = run_in(
            &dir,
            &[
                "context",
                "restore",
                "acme/x@handoff",
                "out",
                "--sts-url",
                &sts(&server),
                "--expect",
                &other,
            ],
        );
        assert_eq!(r.code, 3, "{}", r.stderr);
        assert!(r.stderr.contains("checkpoint hash"), "{}", r.stderr);
        assert!(!dir.join("out").exists());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn restore_refuses_a_path_that_leaves_the_folder_and_changed_content() {
    let c = case("basic");
    let dir = temp_dir("restore-bad");
    let mut bad = c.files.clone();
    bad[0].0 = "../escape.md".into();
    let bad_meta = json!({"checkpoint": {"seq": 1}, "files": file_list(&bad)});
    let mut changed = c.files.clone();
    changed[0].2 = b"changed\n".to_vec();
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(200, &bad_meta.to_string()),
        sts_ok(),
        MockResponse::json(200, &meta_answer(&c, 2).to_string()),
        MockResponse::bytes(200, "application/gzip", tarball(&changed)),
        sts_ok(),
        MockResponse::json(200, &meta_answer(&c, 2).to_string()),
        MockResponse::bytes(200, "application/gzip", tarball(&bad)),
    ]);
    let s = sts(&server);
    for want in ["..", "does not match the file list", "escape.md"] {
        let r = run_in(
            &dir,
            &["context", "restore", "acme/x", "out", "--sts-url", &s],
        );
        assert_eq!(r.code, 1, "{}", r.stderr);
        assert!(r.stderr.contains(want), "{want}: {}", r.stderr);
        assert!(!dir.join("out").exists());
        assert!(!dir.join("escape.md").exists());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn restore_needs_a_new_or_empty_folder_before_the_content_is_read() {
    let c = case("basic");
    let dir = temp_dir("restore-full");
    std::fs::create_dir_all(dir.join("out")).unwrap();
    std::fs::write(dir.join("out/keep.md"), "mine\n").unwrap();
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(200, &meta_answer(&c, 2).to_string()),
    ]);
    let r = run_in(
        &dir,
        &[
            "context",
            "restore",
            "acme/x",
            "out",
            "--sts-url",
            &sts(&server),
        ],
    );
    assert_eq!(r.code, 1, "{}", r.stderr);
    assert_eq!(server.requests().len(), 2);
    assert_eq!(std::fs::read(dir.join("out/keep.md")).unwrap(), b"mine\n");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_encryption_mode_other_than_none_exits_2_and_writes_nothing() {
    let c = case("basic");
    let dir = temp_dir("encryption");
    let mut sealed = meta_answer(&c, 3);
    sealed["encryption"] = json!({"mode": "envelope_v1"});
    // The older nested form: `checkpoint.enc_mode`.
    let mut enc_mode = meta_answer(&c, 3);
    enc_mode.as_object_mut().unwrap().remove("encryption");
    enc_mode["checkpoint"] = json!({"enc_mode": "envelope_v1"});
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(200, &sealed.to_string()),
        sts_ok(),
        MockResponse::json(200, &enc_mode.to_string()),
        sts_ok(),
        MockResponse::json(200, &meta_answer(&c, 3).to_string())
            .with_header("X-Prego-Encryption", "envelope_v1"),
        sts_ok(),
        MockResponse::json(200, &meta_answer(&c, 3).to_string())
            .with_header("X-Prego-Encryption", "none"),
        MockResponse::bytes(200, "application/gzip", tarball(&c.files))
            .with_header("X-Prego-Encryption", "envelope_v1"),
    ]);
    let s = sts(&server);
    for _ in 0..4 {
        let r = run_in(
            &dir,
            &["context", "restore", "acme/x", "out", "--sts-url", &s],
        );
        assert_eq!(r.code, 2, "{}", r.stderr);
        assert_eq!(
            r.stderr.trim(),
            "prego: this checkpoint uses encryption mode envelope_v1, which this prego version cannot read"
        );
        assert!(!dir.join("out").exists());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ls_log_tag_rm_and_set() {
    let dir = temp_dir("manage");
    let h = format!("sha256:{}", "1".repeat(64));
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(
            200,
            &json!({"items": [{"name": "billing-agent", "latest_seq": 9, "latest_hash": h,
                "checkpoint_count": 9, "updated_at": "2026-11-20T03:00:00Z"}], "next": null})
            .to_string(),
        ),
        sts_ok(),
        MockResponse::json(
            200,
            &json!({"items": [{"seq": 9, "hash": h, "latest": true, "created_at": "2026-11-20T03:00:00Z",
                "size": 2048, "file_count": 3, "trigger": "compact", "session": "s1",
                "agent": "prn_1", "tags": ["handoff"], "message": "before compaction"}], "next": "c2"})
            .to_string(),
        ),
        MockResponse::json(200, &json!({"items": [], "next": null}).to_string()),
        sts_ok(),
        MockResponse::json(201, &json!({"tag": "handoff", "seq": 9, "hash": h}).to_string()),
        sts_ok(),
        MockResponse::json(200, &json!({"deleted": 4}).to_string()),
        sts_ok(),
        MockResponse::json(204, ""),
        sts_ok(),
        MockResponse::json(200, &json!({"keep_days": 30, "on_full": "drop_oldest"}).to_string()),
    ]);
    let s = sts(&server);
    let run = |args: &[&str]| {
        let mut a = args.to_vec();
        a.extend(["--sts-url", &s]);
        let r = run_in(&dir, &a);
        assert_eq!(r.code, 0, "{a:?}: {}", r.stderr);
        r.out()
    };
    assert!(run(&["context", "ls", "acme/agents"]).starts_with("billing-agent"));
    let log = run(&[
        "context",
        "log",
        "acme/agents/billing-agent",
        "--session",
        "s1",
    ]);
    assert!(log.contains("*     9") && log.contains("[handoff]") && log.contains("session s1"));
    assert_eq!(
        run(&["context", "tag", "acme/agents/billing-agent@9", "handoff"]),
        format!("acme/agents/billing-agent: tag handoff -> checkpoint 9 ({h})\n")
    );
    assert_eq!(
        run(&[
            "context",
            "rm",
            "acme/agents/billing-agent",
            "--session",
            "s 1"
        ]),
        "acme/agents/billing-agent: removed session s 1 (4 checkpoints)\n"
    );
    assert_eq!(
        run(&["context", "rm", "acme/agents/billing-agent@9"]),
        "acme/agents/billing-agent: removed checkpoint 9\n"
    );
    assert_eq!(
        run(&[
            "context",
            "set",
            "acme/agents/billing-agent",
            "--keep-days",
            "30",
            "--on-full",
            "drop_oldest"
        ]),
        "acme/agents/billing-agent: keep_days 30, on_full drop_oldest\n"
    );
    let reqs = server.requests();
    let t: Vec<(&str, &str)> = reqs
        .iter()
        .filter(|r| !r.target.starts_with("/v1/sts/"))
        .map(|r| (r.method.as_str(), r.target.as_str()))
        .collect();
    assert_eq!(
        t,
        [
            ("GET", "/v1/context/acme/agents?limit=100"),
            (
                "GET",
                "/v1/context/acme/agents/billing-agent/checkpoints?session=s1&limit=100"
            ),
            (
                "GET",
                "/v1/context/acme/agents/billing-agent/checkpoints?session=s1&limit=100&after=c2"
            ),
            ("PUT", "/v1/context/acme/agents/billing-agent/tags/handoff"),
            (
                "DELETE",
                "/v1/context/acme/agents/billing-agent/sessions/s%201"
            ),
            ("DELETE", "/v1/context/acme/agents/billing-agent/at/9"),
            ("PATCH", "/v1/context/acme/agents/billing-agent"),
        ]
    );
    let body = |i: usize| -> Value {
        serde_json::from_slice(
            &reqs
                .iter()
                .filter(|r| !r.target.starts_with("/v1/sts/"))
                .nth(i)
                .unwrap()
                .raw,
        )
        .unwrap()
    };
    assert_eq!(body(3), json!({"checkpoint": 9}));
    assert_eq!(body(6), json!({"keep_days": 30, "on_full": "drop_oldest"}));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn not_found_says_no_grant_and_bad_arguments_stop_early() {
    let dir = temp_dir("notfound");
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(
            404,
            r#"{"error":{"code":"not_found","message":"not found"}}"#,
        ),
    ]);
    let r = run_in(
        &dir,
        &["context", "log", "acme/x", "--sts-url", &sts(&server)],
    );
    assert_eq!(r.code, 1);
    assert!(r
        .stderr
        .contains("the checkpoints of acme/default/x: not found, or you have no grant for it"));
    for (args, want) in [
        (
            vec!["context", "restore", "acme/x@4", "out", "--session", "s1"],
            "--session goes with the latest checkpoint only",
        ),
        (vec!["context", "rm", "acme/x"], "give one checkpoint"),
        (
            vec!["context", "rm", "acme/x@4", "--session", "s"],
            "give one checkpoint",
        ),
        (vec!["context", "set", "acme/x"], "--keep-days"),
        (
            vec!["context", "set", "acme/x", "--keep-days", "0"],
            "1 to 400",
        ),
        (
            vec!["context", "set", "acme/x", "--on-full", "drop"],
            "refuse or drop_oldest",
        ),
        (
            vec!["context", "save", "m", "acme/x", "--trigger", "later"],
            "compact, stop, manual or schedule",
        ),
        (
            vec!["context", "save", "m", "acme/x", "--label", "novalue"],
            "key=value",
        ),
        (vec!["context", "save", "m", "acme/x@3"], "without @"),
        (vec!["context", "tag", "acme/x", "t"], "give the checkpoint"),
        (vec!["context", "tag", "acme/x@3", "latest"], "kept"),
    ] {
        let r = run_in(&dir, &args);
        assert_ne!(r.code, 0, "{args:?}");
        assert!(r.stderr.contains(want), "{args:?}: {}", r.stderr);
    }
    let _ = std::fs::remove_dir_all(&dir);
}
