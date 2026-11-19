//! Runs `prego snippet` against a mock control host that serves the token exchange and `/v1/snippets/*`.
//! The version hashes come from the shared vectors (`tests/vectors/snippets/cases.json`), not from the code.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use prego_auth::testing::{MockResponse, MockServer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const BIN: &str = env!("CARGO_BIN_EXE_prego");
const API_KEY: &str = "prk_test_snippet_secret";
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

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("prego-snippet-{name}-{}", std::process::id()));
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

fn sts(server: &MockServer) -> String {
    format!("{}/v1/sts/token/e/k7mq", server.base_url())
}

fn hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/snippets")
}

/// One case of the shared vectors: its files (path, mode, bytes) and its hash.
struct Case {
    files: Vec<(String, u32, Vec<u8>)>,
    hash: String,
}

fn case(name: &str) -> Case {
    let dir = vectors_dir();
    let v: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("cases.json")).unwrap()).unwrap();
    let c = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap();
    let root = dir.join(c["dir"].as_str().unwrap());
    Case {
        files: c["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| {
                let p = f["path"].as_str().unwrap().to_string();
                let mode = u32::from_str_radix(f["mode"].as_str().unwrap(), 8).unwrap();
                let data = std::fs::read(root.join(&p)).unwrap();
                (p, mode, data)
            })
            .collect(),
        hash: c["hash"].as_str().unwrap().to_string(),
    }
}

/// Writes a case to a folder with its modes.
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

fn list_answer(c: &Case, number: u64) -> Value {
    json!({
        "version": number,
        "hash": c.hash,
        "files": c.files.iter().map(|(p, m, d)| json!({
            "path": p, "mode": format!("{m:04o}"), "size": d.len(), "sha256": hex(d)
        })).collect::<Vec<_>>()
    })
}

fn file_answers(c: &Case) -> Vec<MockResponse> {
    let mut sorted: Vec<&(String, u32, Vec<u8>)> = c.files.iter().collect();
    sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    sorted
        .iter()
        .map(|(_, _, d)| MockResponse::bytes(200, "text/plain; charset=utf-8", d.clone()))
        .collect()
}

/// Reads the files of a `.tar.gz` request body.
fn unpack(body: &[u8]) -> Vec<(String, u32, u64, Vec<u8>)> {
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
            let mtime = e.header().mtime().unwrap();
            let mut data = Vec::new();
            e.read_to_end(&mut data).unwrap();
            (path, mode, mtime, data)
        })
        .collect()
}

#[cfg(unix)]
#[test]
fn hash_of_a_folder_is_the_shared_vector_hash() {
    for name in ["basic", "basic-mode", "order", "empty-file", "long-path"] {
        let c = case(name);
        let dir = temp_dir(&format!("hash-{name}"));
        write_case(&c, &dir);
        // A .git folder is not part of the snippet.
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        std::fs::write(dir.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        let r = run_in(&dir, &["snippet", "hash", "."]);
        assert_eq!(r.code, 0, "{name}: {}", r.stderr);
        assert_eq!(r.out().trim(), c.hash, "{name}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(unix)]
#[test]
fn push_sends_the_fixed_tarball_and_prints_the_version() {
    let c = case("basic");
    let dir = temp_dir("push");
    write_case(&c, &dir.join("skill"));
    std::fs::create_dir_all(dir.join("skill/.git")).unwrap();
    std::fs::write(dir.join("skill/.git/index"), [0xffu8, 0, 1]).unwrap();
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(
            201,
            &json!({"created": true, "version": {"number": 4, "hash": c.hash, "file_count": 2}})
                .to_string(),
        ),
    ]);
    let r = run_in(
        &dir,
        &[
            "snippet",
            "push",
            "skill",
            "acme/agent-skill",
            "--sts-url",
            &sts(&server),
            "--tag",
            "v1",
            "--message",
            "first & best",
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(
        r.out(),
        format!(
            "acme/default/agent-skill: version 4 ({}), 2 files\nacme/default/agent-skill: tag v1 -> version 4\n",
            c.hash
        )
    );
    let reqs = server.requests();
    assert_eq!(reqs[0].form()["tenant"], "acme");
    assert_eq!(reqs[1].method, "PUT");
    assert_eq!(
        reqs[1].target,
        "/v1/snippets/acme/default/agent-skill?message=first%20%26%20best&tag=v1"
    );
    assert_eq!(reqs[1].header("content-type").unwrap(), "application/gzip");
    assert_eq!(
        reqs[1].header("authorization").unwrap(),
        format!("Bearer {REG_TOKEN}")
    );
    let files = unpack(&reqs[1].raw);
    let got: Vec<(&str, u32, u64)> = files
        .iter()
        .map(|(p, m, t, _)| (p.as_str(), *m, *t))
        .collect();
    assert_eq!(got, [("README.md", 0o644, 0), ("run.sh", 0o755, 0)]);
    assert!(!r.stderr.contains(REG_TOKEN));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn push_of_the_same_files_is_a_no_op_and_a_refused_push_names_the_file() {
    let dir = temp_dir("push-noop");
    std::fs::write(dir.join("prompt.md"), "Say hello.\n").unwrap();
    let hash_run = run_in(&dir, &["snippet", "hash", "prompt.md"]);
    let h = hash_run.out().trim().to_string();
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(
            200,
            &json!({"created": false, "version": {"number": 2, "hash": h}}).to_string(),
        ),
        sts_ok(),
        MockResponse::json(
            422,
            r#"{"error":{"code":"looks_like_secret","message":"a file looks like it holds a secret","path":"prompt.md","line":1}}"#,
        ),
    ]);
    let other = format!("sha256:{}", "e".repeat(64));
    let r = run_in(
        &dir,
        &[
            "snippet",
            "push",
            "prompt.md",
            "acme/tools/hello",
            "--sts-url",
            &sts(&server),
            "--if-current",
            &other,
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(
        r.out(),
        format!("acme/tools/hello: no change, version 2 is current ({h})\n")
    );
    let r = run_in(
        &dir,
        &[
            "snippet",
            "push",
            "prompt.md",
            "acme/tools/hello",
            "--sts-url",
            &sts(&server),
        ],
    );
    assert_eq!(r.code, 1);
    assert!(
        r.stderr.contains("(file: prompt.md, line 1)"),
        "{}",
        r.stderr
    );
    let reqs = server.requests();
    assert_eq!(
        reqs[1].target,
        format!(
            "/v1/snippets/acme/tools/hello?if_current={}",
            other.replace(':', "%3A")
        )
    );
    let files = unpack(&reqs[1].raw);
    assert_eq!(files[0].0, "prompt.md");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn push_refuses_binary_and_symlinks_before_any_request() {
    let dir = temp_dir("push-bad");
    std::fs::write(dir.join("blob.bin"), [0u8, 1, 2]).unwrap();
    let r = run_in(
        &dir,
        &[
            "snippet",
            "push",
            "blob.bin",
            "acme/x",
            "--sts-url",
            "http://127.0.0.1:9/v1/sts/token",
        ],
    );
    assert_eq!(r.code, 1);
    assert!(r.stderr.contains("NUL"), "{}", r.stderr);
    #[cfg(unix)]
    {
        std::fs::create_dir_all(dir.join("f")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", dir.join("f/link")).unwrap();
        let r = run_in(&dir, &["snippet", "hash", "f"]);
        assert_eq!(r.code, 1);
        assert!(r.stderr.contains("symlinks"), "{}", r.stderr);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn get_writes_checked_files_with_their_modes() {
    let c = case("basic");
    let dir = temp_dir("get");
    let mut answers = vec![
        sts_ok(),
        MockResponse::json(200, &list_answer(&c, 3).to_string())
            .with_header("X-Prego-Snippet-Version", "3")
            .with_header("X-Prego-Snippet-Hash", &c.hash),
    ];
    answers.extend(file_answers(&c));
    let server = MockServer::start(answers);
    let r = run_in(
        &dir,
        &[
            "snippet",
            "get",
            "acme/agent-skill@v1",
            "--sts-url",
            &sts(&server),
            "--expect",
            &c.hash,
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.out(), "agent-skill\n");
    assert!(r
        .stderr
        .contains(&format!("acme/default/agent-skill@3 {} (2 files)", c.hash)));
    use std::os::unix::fs::PermissionsExt;
    for (p, mode, data) in &c.files {
        let target = dir.join("agent-skill").join(p);
        assert_eq!(&std::fs::read(&target).unwrap(), data);
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777,
            *mode
        );
    }
    let reqs = server.requests();
    let enc = c.hash.clone();
    assert_eq!(
        reqs[1].target,
        format!(
            "/v1/snippets/acme/default/agent-skill/v/v1?expect={}",
            enc.replace(':', "%3A")
        )
    );
    // The files are read from the listed version by its hash.
    assert_eq!(
        reqs[2].target,
        format!(
            "/v1/snippets/acme/default/agent-skill/v/{}/files/README.md",
            c.hash
        )
    );
    assert_eq!(
        reqs[3].target,
        format!(
            "/v1/snippets/acme/default/agent-skill/v/{}/files/run.sh",
            c.hash
        )
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn get_with_another_expected_hash_exits_3_and_writes_nothing() {
    let c = case("basic");
    let dir = temp_dir("get-expect");
    let other = format!("sha256:{}", "0".repeat(64));
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(200, &list_answer(&c, 3).to_string()),
        sts_ok(),
        MockResponse::json(
            412,
            r#"{"error":{"code":"hash_mismatch","message":"the hash differs"}}"#,
        ),
    ]);
    // The answer has the expected hash in its body, but the files give another: the local hash counts.
    let r = run_in(
        &dir,
        &[
            "snippet",
            "get",
            "acme/x",
            "out",
            "--sts-url",
            &sts(&server),
            "--expect",
            &other,
        ],
    );
    assert_eq!(r.code, 3, "{}", r.stderr);
    assert!(
        r.stderr.contains(&c.hash) && r.stderr.contains(&other),
        "{}",
        r.stderr
    );
    assert!(!dir.join("out").exists());
    // The registry's 412 also exits with 3.
    let r = run_in(
        &dir,
        &[
            "snippet",
            "get",
            "acme/x",
            "out",
            "--sts-url",
            &sts(&server),
            "--expect",
            &other,
        ],
    );
    assert_eq!(r.code, 3, "{}", r.stderr);
    assert!(!dir.join("out").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn get_refuses_a_path_that_leaves_the_folder_and_a_changed_file() {
    let dir = temp_dir("get-bad");
    let data = b"x\n".to_vec();
    let bad_list = json!({"version": 1, "files": [
        {"path": "../escape.sh", "mode": "0755", "size": 2, "sha256": hex(&data)}
    ]});
    let c = case("basic");
    let mut answers = vec![
        sts_ok(),
        MockResponse::json(200, &bad_list.to_string()),
        sts_ok(),
        MockResponse::json(200, &list_answer(&c, 3).to_string()),
    ];
    // The second file is not the listed content.
    answers.push(file_answers(&c).remove(0));
    answers.push(MockResponse::bytes(
        200,
        "text/plain",
        b"echo changed\n".to_vec(),
    ));
    let server = MockServer::start(answers);
    let r = run_in(
        &dir,
        &[
            "snippet",
            "get",
            "acme/x",
            "out",
            "--sts-url",
            &sts(&server),
        ],
    );
    assert_eq!(r.code, 1);
    assert!(r.stderr.contains("`..` segment"), "{}", r.stderr);
    assert!(!dir.join("out").exists() && !dir.join("escape.sh").exists());
    let r = run_in(
        &dir,
        &[
            "snippet",
            "get",
            "acme/x",
            "out",
            "--sts-url",
            &sts(&server),
        ],
    );
    assert_eq!(r.code, 1);
    assert!(
        r.stderr.contains("does not match the file list"),
        "{}",
        r.stderr
    );
    assert!(!dir.join("out").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn get_file_prints_one_file_and_get_needs_an_empty_folder() {
    let c = case("basic");
    let dir = temp_dir("get-file");
    let readme = c
        .files
        .iter()
        .find(|f| f.0 == "README.md")
        .unwrap()
        .2
        .clone();
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(200, &list_answer(&c, 3).to_string()),
        MockResponse::bytes(200, "text/plain", readme.clone()),
    ]);
    let r = run_in(
        &dir,
        &[
            "snippet",
            "get",
            "acme/x",
            "--file",
            "README.md",
            "--sts-url",
            &sts(&server),
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.stdout, readme);
    std::fs::create_dir_all(dir.join("full")).unwrap();
    std::fs::write(dir.join("full/keep.txt"), "mine").unwrap();
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(200, &list_answer(&c, 3).to_string()),
    ]);
    let r = run_in(
        &dir,
        &[
            "snippet",
            "get",
            "acme/x",
            "full",
            "--sts-url",
            &sts(&server),
        ],
    );
    assert_eq!(r.code, 1);
    assert!(r.stderr.contains("not empty"), "{}", r.stderr);
    assert_eq!(
        std::fs::read_to_string(dir.join("full/keep.txt")).unwrap(),
        "mine"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn get_tar_checks_the_tarball_hash() {
    let c = case("basic");
    let dir = temp_dir("get-tar");
    write_case(&c, &dir.join("src"));
    // A tarball from the push of the same files (the fixed form).
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(
            201,
            &json!({"created": true, "version": {"number": 1, "hash": c.hash}}).to_string(),
        ),
    ]);
    let r = run_in(
        &dir,
        &[
            "snippet",
            "push",
            "src",
            "acme/x",
            "--sts-url",
            &sts(&server),
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    let tarball = server.requests()[1].raw.clone();
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::bytes(200, "application/gzip", tarball.clone())
            .with_header("X-Prego-Snippet-Hash", &c.hash)
            .with_header("X-Prego-Snippet-Version", "1"),
        sts_ok(),
        MockResponse::bytes(200, "application/gzip", tarball.clone()),
    ]);
    let r = run_in(
        &dir,
        &[
            "snippet",
            "get",
            "acme/x@1",
            "x.tar.gz",
            "--tar",
            "--expect",
            &c.hash,
            "--sts-url",
            &sts(&server),
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(std::fs::read(dir.join("x.tar.gz")).unwrap(), tarball);
    assert_eq!(
        server.requests()[1].target,
        format!(
            "/v1/snippets/acme/default/x/v/1.tar.gz?expect={}",
            c.hash.replace(':', "%3A")
        )
    );
    let other = format!("sha256:{}", "0".repeat(64));
    let r = run_in(
        &dir,
        &[
            "snippet",
            "get",
            "acme/x",
            "y.tar.gz",
            "--tar",
            "--expect",
            &other,
            "--sts-url",
            &sts(&server),
        ],
    );
    assert_eq!(r.code, 3, "{}", r.stderr);
    assert!(!dir.join("y.tar.gz").exists());
    // `hash --tar` and `push --tar` read the same tarball.
    let r = run_in(&dir, &["snippet", "hash", "x.tar.gz", "--tar"]);
    assert_eq!(r.out().trim(), c.hash);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn log_diff_tag_rollback_and_ls() {
    let dir = temp_dir("log");
    let h1 = format!("sha256:{}", "1".repeat(64));
    let h2 = format!("sha256:{}", "2".repeat(64));
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(200, &json!({"items": [
            {"number": 2, "hash": h2, "size_bytes": 41, "file_count": 2, "pushed_by": "prn_ci",
             "created_at": "2026-11-19T22:00:00Z", "message": "fix", "tags": ["prod"], "current": true}
        ], "next": "c2"}).to_string()),
        MockResponse::json(200, &json!({"items": [
            {"number": 1, "hash": h1, "size_bytes": 40, "file_count": 2, "pushed_by": "prn_ci",
             "created_at": "2026-11-19T21:00:00Z", "message": "", "tags": [], "current": false}
        ], "next": null}).to_string()),
        sts_ok(),
        MockResponse::json(200, &json!({
            "from": {"number": 1, "hash": h1}, "to": {"number": 2, "hash": h2},
            "added": [{"path": "new.md", "sha256": "a".repeat(64)}],
            "removed": [],
            "changed": [{"path": "run.sh", "old_sha256": "b".repeat(64), "new_sha256": "c".repeat(64),
                         "diff": "--- a/run.sh\n+++ b/run.sh\n@@ -1 +1 @@\n-echo a\n+echo b\n"}],
            "truncated": false
        }).to_string()),
        sts_ok(),
        MockResponse::json(201, &json!({"tag": "prod", "version": 2, "hash": h2}).to_string()),
        sts_ok(),
        MockResponse::json(200, &json!({"current_version": 1, "current_hash": h1}).to_string()),
        sts_ok(),
        MockResponse::json(200, &json!({"items": [
            {"name": "agent-skill", "current_version": 1, "current_hash": h1, "version_count": 2,
             "updated_at": "2026-11-19T22:10:00Z"}
        ], "next": null}).to_string()),
    ]);
    let s = sts(&server);
    let r = run_in(
        &dir,
        &["snippet", "log", "acme/agent-skill", "--sts-url", &s],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    let out = r.out();
    assert!(
        out.starts_with("acme/default/agent-skill\n*    2  "),
        "{out}"
    );
    assert!(out.contains("[prod]  fix") && out.contains(&h1), "{out}");
    let r = run_in(
        &dir,
        &[
            "snippet",
            "diff",
            "acme/agent-skill",
            "1",
            "prod",
            "--sts-url",
            &s,
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(
        r.out(),
        format!("acme/default/agent-skill from 1 ({h1}) to 2 ({h2})\n+ new.md\n~ run.sh\n\n--- a/run.sh\n+++ b/run.sh\n@@ -1 +1 @@\n-echo a\n+echo b\n")
    );
    let r = run_in(
        &dir,
        &[
            "snippet",
            "tag",
            "acme/agent-skill@2",
            "prod",
            "--sts-url",
            &s,
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(
        r.out(),
        format!("acme/default/agent-skill: tag prod -> version 2 ({h2})\n")
    );
    let r = run_in(
        &dir,
        &[
            "snippet",
            "rollback",
            "acme/agent-skill",
            "--to",
            "1",
            "--reason",
            "bad prompt",
            "--sts-url",
            &s,
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(
        r.out(),
        format!("acme/default/agent-skill: current version is now 1 ({h1})\n")
    );
    let r = run_in(&dir, &["snippet", "ls", "acme", "--sts-url", &s]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.out().starts_with("agent-skill "), "{}", r.out());

    let reqs = server.requests();
    let targets: Vec<(&str, &str)> = reqs
        .iter()
        .map(|q| (q.method.as_str(), q.target.as_str()))
        .collect();
    assert_eq!(
        targets[1],
        (
            "GET",
            "/v1/snippets/acme/default/agent-skill/versions?limit=100"
        )
    );
    assert_eq!(
        targets[2],
        (
            "GET",
            "/v1/snippets/acme/default/agent-skill/versions?limit=100&after=c2"
        )
    );
    assert_eq!(
        targets[4],
        (
            "GET",
            "/v1/snippets/acme/default/agent-skill/diff?from=1&to=prod"
        )
    );
    assert_eq!(
        targets[6],
        ("PUT", "/v1/snippets/acme/default/agent-skill/tags/prod")
    );
    assert_eq!(
        serde_json::from_str::<Value>(&reqs[6].body).unwrap(),
        json!({"version": 2})
    );
    assert_eq!(
        targets[8],
        ("POST", "/v1/snippets/acme/default/agent-skill/current")
    );
    assert_eq!(
        serde_json::from_str::<Value>(&reqs[8].body).unwrap(),
        json!({"version": 1, "reason": "bad prompt"})
    );
    assert_eq!(targets[10], ("GET", "/v1/snippets/acme/default?limit=100"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn not_found_says_no_grant() {
    let dir = temp_dir("404");
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(404, r#"{"error":{"code":"not_found"}}"#),
    ]);
    let r = run_in(
        &dir,
        &[
            "snippet",
            "log",
            "other/x",
            "--tenant",
            "acme",
            "--sts-url",
            &sts(&server),
        ],
    );
    assert_eq!(r.code, 1);
    assert_eq!(
        r.stderr.trim(),
        "prego: the history of other/default/x: not found, or you have no grant for it"
    );
    // A cross-tenant read: the token is for the configured tenant.
    assert_eq!(server.requests()[0].form()["tenant"], "acme");
    let _ = std::fs::remove_dir_all(&dir);
}
