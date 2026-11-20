//! Runs `prego sqlite` against a mock control host that serves the token exchange and `/v1/sqlite/*`.
//! The frame and snapshot hashes are computed here from the rule in ADR-0059 item 10 and the wire
//! decisions, not with the code under test.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use prego_auth::testing::{MockResponse, MockServer};
use rusqlite::Connection;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const BIN: &str = env!("CARGO_BIN_EXE_prego");
const API_KEY: &str = "prk_test_sqlite_secret";
// Payload {"sub":"prn_1","tid":"ten_1","exp":4102444800} (2100-01-01).
const REG_TOKEN: &str =
    "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJwcm5fMSIsInRpZCI6InRlbl8xIiwiZXhwIjo0MTAyNDQ0ODAwfQ.c2ln";
const FRAME: usize = 64 << 20;

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> Dir {
        let d = std::env::temp_dir().join(format!("prego-sqlite-t-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("tmp")).unwrap();
        Dir(d)
    }

    fn p(&self, rel: &str) -> PathBuf {
        self.0.join(rel)
    }

    fn run(&self, args: &[&str]) -> Run {
        let out = Command::new(BIN)
            .current_dir(&self.0)
            .args(args)
            .env_clear()
            .env("PREGO_API_KEY", API_KEY)
            .env("HOME", "/nonexistent")
            .env("TMPDIR", self.p("tmp"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("run prego");
        Run {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    /// The private copy folder in TMPDIR is removed at the end, also after a failure.
    fn assert_tmp_clean(&self) {
        let left: Vec<_> = std::fs::read_dir(self.p("tmp")).unwrap().collect();
        assert!(left.is_empty(), "left in TMPDIR: {left:?}");
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
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

/// The snapshot hash of a file: one line `sha256:<hex>\n` for each 64 MiB frame, then sha256 of the lines.
fn snapshot_hash(data: &[u8]) -> String {
    let lines: String = data
        .chunks(FRAME)
        .map(|c| format!("sha256:{}\n", hex(c)))
        .collect();
    format!("sha256:{}", hex(lines.as_bytes()))
}

fn gunzip(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    flate2::read::MultiGzDecoder::new(body)
        .read_to_end(&mut out)
        .unwrap();
    out
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(data).unwrap();
    gz.finish().unwrap()
}

fn make_db(path: &Path, rows: i64) {
    let c = Connection::open(path).unwrap();
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS lookup(id INTEGER PRIMARY KEY, v TEXT);
         PRAGMA user_version = 42;",
    )
    .unwrap();
    for i in 0..rows {
        c.execute("INSERT INTO lookup(v) VALUES (?1)", [format!("value {i}")])
            .unwrap();
    }
}

fn count(path: &Path) -> i64 {
    Connection::open(path)
        .unwrap()
        .query_row("SELECT count(*) FROM lookup", [], |r| r.get(0))
        .unwrap()
}

fn meta(data: &[u8], seq: u64) -> Value {
    json!({
        "seq": seq, "hash": snapshot_hash(data), "file_sha256": hex(data), "file_bytes": data.len(),
        "stored_bytes": 100, "page_count": data.len() / 4096, "user_version": 42,
        "encryption": {"mode": "none"}, "tags": [], "latest": true
    })
}

#[test]
fn save_one_frame_sends_a_checked_gzip_with_both_hashes() {
    let d = Dir::new("save");
    make_db(&d.p("app.db"), 500);
    // A program has the database open in WAL mode while the save runs.
    let live = Connection::open(d.p("app.db")).unwrap();
    live.query_row("PRAGMA journal_mode=WAL", [], |r| r.get::<_, String>(0))
        .unwrap();
    live.execute("INSERT INTO lookup(v) VALUES ('in the wal')", [])
        .unwrap();
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(
            201,
            &json!({"created": true, "seq": 3, "hash": "sha256:filled-below", "stored_bytes": 2048})
                .to_string(),
        ),
    ]);
    let r = d.run(&[
        "sqlite",
        "save",
        "app.db",
        "acme/fleet/lookup",
        "--sts-url",
        &sts(&server),
        "--label",
        "build=42",
        "--label",
        "note=café",
        "--message",
        "Daily build",
        "--tag",
        "2026-11-20",
    ]);
    // The answer hash is a placeholder, so the client warns; the request is what this test checks.
    assert_eq!(r.code, 0, "{}", r.stderr);
    let reqs = server.requests();
    assert_eq!(reqs.len(), 2);
    let put = &reqs[1];
    assert_eq!(put.method, "PUT");
    assert_eq!(
        put.target,
        "/v1/sqlite/acme/fleet/lookup?message=Daily%20build&tag=2026-11-20"
    );
    assert_eq!(put.header("content-type").unwrap(), "application/gzip");
    let data = gunzip(&put.raw);
    assert_eq!(&data[..16], b"SQLite format 3\0");
    assert_eq!(put.header("x-prego-file-sha256").unwrap(), hex(&data));
    let want = snapshot_hash(&data);
    assert_eq!(put.header("x-prego-snapshot-hash").unwrap(), want);
    assert_eq!(
        put.header("x-prego-labels").unwrap(),
        r#"{"build":"42","note":"caf\u00e9","prego.check":"quick_check:ok"}"#
    );
    // The snapshot has the row that was only in the WAL file: SQLite made the copy.
    std::fs::write(d.p("got.db"), &data).unwrap();
    assert_eq!(count(&d.p("got.db")), 501);
    assert!(
        r.stdout.contains("acme/fleet/lookup: snapshot 3 ("),
        "{}",
        r.stdout
    );
    assert!(r.stdout.contains("tag 2026-11-20 -> snapshot 3"));
    assert!(r.stderr.contains("1 frame, quick_check:ok"), "{}", r.stderr);
    d.assert_tmp_clean();

    // `hash` gives the same snapshot hash, offline.
    let h = d.run(&["sqlite", "hash", "app.db"]);
    assert_eq!(h.code, 0, "{}", h.stderr);
    assert_eq!(h.stdout.trim(), want);
    d.assert_tmp_clean();
    drop(live);
}

#[test]
fn save_compact_check_none_and_no_change() {
    let d = Dir::new("compact");
    make_db(&d.p("app.db"), 2000);
    Connection::open(d.p("app.db"))
        .unwrap()
        .execute("DELETE FROM lookup WHERE id > 100", [])
        .unwrap();
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(200, &json!({"created": false, "seq": 9}).to_string()),
    ]);
    let r = d.run(&[
        "sqlite",
        "save",
        "app.db",
        "acme/lookup",
        "--sts-url",
        &sts(&server),
        "--compact",
        "--check",
        "none",
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let put = &server.requests()[1];
    assert_eq!(put.target, "/v1/sqlite/acme/default/lookup");
    assert_eq!(
        put.header("x-prego-labels").unwrap(),
        r#"{"prego.check":"none"}"#
    );
    let data = gunzip(&put.raw);
    // VACUUM INTO leaves no free pages: the copy is smaller than the file.
    assert!(data.len() < std::fs::metadata(d.p("app.db")).unwrap().len() as usize);
    assert!(
        r.stdout.contains("no change, snapshot 9 is the latest"),
        "{}",
        r.stdout
    );
    let h = d.run(&["sqlite", "hash", "app.db", "--compact"]);
    assert_eq!(h.stdout.trim(), snapshot_hash(&data));
    let full = d.run(&["sqlite", "hash", "app.db"]);
    assert_ne!(full.stdout.trim(), h.stdout.trim());
}

#[test]
fn save_refused_exits_4_and_removes_the_copy() {
    let d = Dir::new("refused");
    make_db(&d.p("app.db"), 10);
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(
            403,
            &json!({"error": {"code": "plan_limit", "message": "storage pool is full"}})
                .to_string(),
        ),
    ]);
    let r = d.run(&[
        "sqlite",
        "save",
        "app.db",
        "acme/lookup",
        "--sts-url",
        &sts(&server),
    ]);
    assert_eq!(r.code, 4, "{}", r.stderr);
    assert!(
        r.stderr.contains("403 plan_limit: storage pool is full"),
        "{}",
        r.stderr
    );
    d.assert_tmp_clean();
}

#[test]
fn save_of_a_damaged_database_exits_5_and_sends_nothing() {
    let d = Dir::new("damaged");
    make_db(&d.p("app.db"), 3000);
    let mut b = std::fs::read(d.p("app.db")).unwrap();
    for x in &mut b[4096 + 8..4096 + 64] {
        *x = 0xff;
    }
    std::fs::write(d.p("app.db"), &b).unwrap();
    let server = MockServer::start(vec![sts_ok()]);
    let r = d.run(&[
        "sqlite",
        "save",
        "app.db",
        "acme/lookup",
        "--sts-url",
        &sts(&server),
    ]);
    assert_eq!(r.code, 5, "{}", r.stderr);
    assert!(
        r.stderr.contains("PRAGMA quick_check failed"),
        "{}",
        r.stderr
    );
    assert!(server.requests().is_empty());
    d.assert_tmp_clean();
}

#[test]
fn save_of_a_file_that_is_not_a_database_is_refused_locally() {
    let d = Dir::new("notdb");
    std::fs::write(d.p("x.db"), vec![0x42; 16384]).unwrap();
    let r = d.run(&["sqlite", "save", "x.db", "acme/lookup"]);
    assert_eq!(r.code, 1);
    assert!(r.stderr.contains("encrypted"), "{}", r.stderr);
    let r = d.run(&["sqlite", "save", "missing.db", "acme/lookup"]);
    assert_eq!(r.code, 1);
    // A missing file is not made by the save.
    assert!(!d.p("missing.db").exists());
    d.assert_tmp_clean();
}

#[test]
fn save_of_more_than_one_frame_uses_an_upload_session() {
    let d = Dir::new("session");
    {
        let c = Connection::open(d.p("big.db")).unwrap();
        c.execute_batch(
            "CREATE TABLE blobs(id INTEGER PRIMARY KEY, b BLOB);
             WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 70)
             INSERT INTO blobs(b) SELECT zeroblob(1048576) FROM n;",
        )
        .unwrap();
    }
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(201, &json!({"id": "squ_1", "expires_at": "x"}).to_string()),
        // The frame answers are written after the frames are known; the client compares them.
        MockResponse::json(200, &json!({"index": 0}).to_string()),
        MockResponse::json(503, &json!({"error": {"code": "unavailable"}}).to_string())
            .with_header("Retry-After", "0"),
        MockResponse::json(200, &json!({"index": 1}).to_string()),
        // A commit refused for the rate keeps the session open: it is sent again.
        MockResponse::json(429, &json!({"error": {"code": "rate_limited"}}).to_string())
            .with_header("Retry-After", "0"),
        MockResponse::json(
            201,
            &json!({"created": true, "seq": 21, "rotated": [1, 2]}).to_string(),
        ),
    ]);
    let r = d.run(&[
        "sqlite",
        "save",
        "big.db",
        "acme/fleet/big",
        "--sts-url",
        &sts(&server),
        "--message",
        "m",
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let reqs = server.requests();
    let open: Value = serde_json::from_slice(&reqs[1].raw).unwrap();
    assert_eq!(reqs[1].target, "/v1/sqlite/acme/fleet/big/uploads");
    assert_eq!(open["frames"], 2);
    assert_eq!(
        reqs[2].target,
        "/v1/sqlite/acme/fleet/big/uploads/squ_1/frames/0"
    );
    assert_eq!(
        reqs[3].target,
        "/v1/sqlite/acme/fleet/big/uploads/squ_1/frames/1"
    );
    // The 503 was tried again.
    assert_eq!(reqs[4].target, reqs[3].target);
    assert_eq!(
        reqs[5].target,
        "/v1/sqlite/acme/fleet/big/uploads/squ_1/commit"
    );
    assert_eq!(reqs[6].target, reqs[5].target);
    assert_eq!(reqs[6].raw, reqs[5].raw);
    assert!(
        r.stdout.contains(
            "acme/fleet/big: removed snapshots 1, 2, the oldest without a tag (keep_count)"
        ),
        "{}",
        r.stdout
    );
    let f0 = gunzip(&reqs[2].raw);
    let f1 = gunzip(&reqs[4].raw);
    assert_eq!(f0.len(), FRAME);
    let mut data = f0.clone();
    data.extend_from_slice(&f1);
    assert_eq!(open["snapshot_hash"], snapshot_hash(&data));
    assert_eq!(open["file_sha256"], hex(&data));
    // Each frame is one gzip member; together they are the file.
    let mut both = reqs[2].raw.clone();
    both.extend_from_slice(&reqs[4].raw);
    assert!(gunzip(&both) == data);
    let commit: Value = serde_json::from_slice(&reqs[5].raw).unwrap();
    assert_eq!(
        commit,
        json!({"labels": {"prego.check": "quick_check:ok"}, "message": "m"})
    );
    d.assert_tmp_clean();
}

#[test]
fn a_frame_failure_cancels_the_session_and_exits_4() {
    let d = Dir::new("session-fail");
    {
        let c = Connection::open(d.p("big.db")).unwrap();
        c.execute_batch(
            "CREATE TABLE blobs(id INTEGER PRIMARY KEY, b BLOB);
             WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 66)
             INSERT INTO blobs(b) SELECT zeroblob(1048576) FROM n;",
        )
        .unwrap();
    }
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(201, &json!({"id": "squ_2"}).to_string()),
        MockResponse::json(
            413,
            &json!({"error": {"code": "frame_too_large"}}).to_string(),
        ),
        MockResponse::json(200, "{}"),
    ]);
    let r = d.run(&[
        "sqlite",
        "save",
        "big.db",
        "acme/big",
        "--sts-url",
        &sts(&server),
    ]);
    assert_eq!(r.code, 4, "{}", r.stderr);
    assert!(r.stderr.contains("413 frame_too_large"), "{}", r.stderr);
    let reqs = server.requests();
    let last = reqs.last().unwrap();
    assert_eq!(last.method, "DELETE");
    assert_eq!(last.target, "/v1/sqlite/acme/default/big/uploads/squ_2");
    d.assert_tmp_clean();
}

fn restore_server(m: Value, gz: Vec<u8>) -> MockServer {
    let h = m["hash"].as_str().unwrap_or("").to_string();
    MockServer::start(vec![
        sts_ok(),
        MockResponse::json(200, &m.to_string()).with_header("ETag", &format!("\"{h}\"")),
        MockResponse::bytes(200, "application/gzip", gz).with_header("X-Prego-Encryption", "none"),
    ])
}

fn source_bytes(d: &Dir, rows: i64) -> Vec<u8> {
    make_db(&d.p("src.db"), rows);
    std::fs::read(d.p("src.db")).unwrap()
}

#[test]
fn restore_writes_a_checked_file_and_renames_it() {
    let d = Dir::new("restore");
    let data = source_bytes(&d, 300);
    // Two gzip members, as a restore of two frames streams them.
    let mut gz = gzip(&data[..4096]);
    gz.extend(gzip(&data[4096..]));
    let server = restore_server(meta(&data, 7), gz);
    std::fs::create_dir_all(d.p("data")).unwrap();
    make_db(&d.p("data/lookup.db"), 1);
    let want = snapshot_hash(&data);
    let r = d.run(&[
        "sqlite",
        "restore",
        "acme/fleet/lookup@2026-11-20",
        "data/lookup.db",
        "--sts-url",
        &sts(&server),
        "--expect",
        &want,
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let reqs = server.requests();
    assert_eq!(
        reqs[1].target,
        format!(
            "/v1/sqlite/acme/fleet/lookup/at/2026-11-20?expect={}",
            want.replace(':', "%3A")
        )
    );
    assert_eq!(
        reqs[2].target,
        format!("/v1/sqlite/acme/fleet/lookup/at/{want}.db.gz")
    );
    assert!(std::fs::read(d.p("data/lookup.db")).unwrap() == data);
    assert_eq!(count(&d.p("data/lookup.db")), 300);
    assert!(!d.p("data/lookup.db.prego-tmp").exists());
    assert!(!d.p("data/lookup.db-wal").exists());
    assert_eq!(r.stdout.trim(), "data/lookup.db");
    assert!(r.stderr.contains("acme/fleet/lookup@7 "), "{}", r.stderr);
}

/// Restores each accepted file of the shared vectors, with the metadata (hashes, size and frames) that
/// Prego-registry computed for it: the restored file is the vector file.
#[test]
fn restore_of_the_shared_vectors() {
    let vdir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/sqlite");
    let v: Value =
        serde_json::from_str(&std::fs::read_to_string(vdir.join("cases.json")).unwrap()).unwrap();
    let d = Dir::new("vectors");
    let mut n = 0;
    for f in v["files"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["expect"] == "accept")
    {
        let name = f["file"].as_str().unwrap();
        let data = std::fs::read(vdir.join(name)).unwrap();
        let frames: Vec<Value> = f["frame_hashes"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(i, h)| json!({"index": i, "hash": h, "bytes": data.len(), "stored": 1}))
            .collect();
        let m = json!({
            "seq": 1, "hash": f["snapshot_hash"], "file_sha256": f["file_sha256"],
            "file_bytes": f["file_bytes"], "frame_count": frames.len(), "frames": frames,
            "encryption": {"mode": "none"}
        });
        let h = f["snapshot_hash"].as_str().unwrap();
        let server = MockServer::start(vec![
            sts_ok(),
            MockResponse::json(200, &m.to_string())
                .with_header("ETag", &format!("\"{h}\""))
                .with_header("X-Prego-Sqlite-Hash", h),
            MockResponse::bytes(200, "application/gzip", gzip(&data))
                .with_header("X-Prego-Sqlite-Hash", h)
                .with_header("X-Prego-File-Sha256", f["file_sha256"].as_str().unwrap())
                .with_header("X-Prego-Encryption", "none"),
        ]);
        let out = format!("{name}.restored");
        let r = d.run(&[
            "sqlite",
            "restore",
            "acme/vectors",
            &out,
            "--sts-url",
            &sts(&server),
            "--expect",
            h,
        ]);
        assert_eq!(r.code, 0, "{name}: {}", r.stderr);
        assert!(std::fs::read(d.p(&out)).unwrap() == data, "{name}");
        n += 1;
    }
    assert_eq!(n, 7);
}

#[test]
fn save_of_a_refused_vector_sends_nothing() {
    let vdir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/sqlite");
    let d = Dir::new("refused-vectors");
    for name in [
        "random.bin",
        "encrypted-like.db",
        "empty-file.bin",
        "duckdb-like.db",
        "bad-fractions.db",
        "bad-page-size.db",
        "bad-page-count.db",
        "index-page-one.db",
    ] {
        let server = MockServer::start(vec![sts_ok()]);
        let src = vdir.join(name);
        let r = d.run(&[
            "sqlite",
            "save",
            src.to_str().unwrap(),
            "acme/x",
            "--sts-url",
            &sts(&server),
        ]);
        assert_eq!(r.code, 1, "{name}: {}", r.stderr);
        assert!(server.requests().is_empty(), "{name}");
        d.assert_tmp_clean();
    }
}

#[test]
fn restore_expect_mismatch_exits_3_and_writes_nothing() {
    let d = Dir::new("expect");
    let data = source_bytes(&d, 5);
    let server = restore_server(meta(&data, 1), gzip(&data));
    let other = format!("sha256:{}", "0".repeat(64));
    let r = d.run(&[
        "sqlite",
        "restore",
        "acme/lookup",
        "out.db",
        "--sts-url",
        &sts(&server),
        "--expect",
        &other,
    ]);
    assert_eq!(r.code, 3, "{}", r.stderr);
    assert!(!d.p("out.db").exists() && !d.p("out.db.prego-tmp").exists());
    // The server answer 412 also exits 3.
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(
            412,
            &json!({"error": {"code": "hash_mismatch", "hash": "sha256:x"}}).to_string(),
        ),
    ]);
    let r = d.run(&[
        "sqlite",
        "restore",
        "acme/lookup",
        "out.db",
        "--sts-url",
        &sts(&server),
        "--expect",
        &other,
    ]);
    assert_eq!(r.code, 3, "{}", r.stderr);
    assert!(!d.p("out.db").exists());
}

#[test]
fn restore_of_an_unknown_encryption_mode_exits_2() {
    let d = Dir::new("enc");
    let data = source_bytes(&d, 5);
    let mut m = meta(&data, 1);
    m["encryption"] = json!({"mode": "envelope_v1"});
    let server = restore_server(m, gzip(&data));
    let r = d.run(&[
        "sqlite",
        "restore",
        "acme/lookup",
        "out.db",
        "--sts-url",
        &sts(&server),
    ]);
    assert_eq!(r.code, 2, "{}", r.stderr);
    assert!(!d.p("out.db").exists() && !d.p("out.db.prego-tmp").exists());
    assert_eq!(server.requests().len(), 2);
}

#[test]
fn restore_refuses_wrong_content_and_keeps_the_target() {
    let d = Dir::new("wrong");
    let data = source_bytes(&d, 50);
    make_db(&d.p("out.db"), 2);
    let before = std::fs::read(d.p("out.db")).unwrap();
    let mut changed = data.clone();
    let n = changed.len();
    changed[n - 10] ^= 1;
    let server = restore_server(meta(&data, 1), gzip(&changed));
    let r = d.run(&[
        "sqlite",
        "restore",
        "acme/lookup",
        "out.db",
        "--sts-url",
        &sts(&server),
    ]);
    assert_eq!(r.code, 1, "{}", r.stderr);
    assert!(
        r.stderr.contains("the content has the snapshot hash"),
        "{}",
        r.stderr
    );
    assert!(std::fs::read(d.p("out.db")).unwrap() == before);
    assert!(!d.p("out.db.prego-tmp").exists());
}

#[test]
fn restore_of_a_damaged_snapshot_exits_5_and_keeps_the_target() {
    let d = Dir::new("damaged-restore");
    make_db(&d.p("src.db"), 3000);
    let mut data = std::fs::read(d.p("src.db")).unwrap();
    for x in &mut data[4096 + 8..4096 + 64] {
        *x = 0xff;
    }
    make_db(&d.p("out.db"), 2);
    let before = std::fs::read(d.p("out.db")).unwrap();
    // The hashes match the damaged bytes: only quick_check finds the damage.
    let server = restore_server(meta(&data, 1), gzip(&data));
    let r = d.run(&[
        "sqlite",
        "restore",
        "acme/lookup",
        "out.db",
        "--sts-url",
        &sts(&server),
    ]);
    assert_eq!(r.code, 5, "{}", r.stderr);
    assert!(std::fs::read(d.p("out.db")).unwrap() == before);
    assert!(!d.p("out.db.prego-tmp").exists());
}

#[test]
fn restore_refuses_a_database_with_a_wal_file_unless_force() {
    let d = Dir::new("wal");
    let data = source_bytes(&d, 20);
    make_db(&d.p("out.db"), 2);
    std::fs::write(d.p("out.db-wal"), b"old wal").unwrap();
    std::fs::write(d.p("out.db-shm"), b"old shm").unwrap();
    let server = MockServer::start(vec![sts_ok()]);
    let r = d.run(&[
        "sqlite",
        "restore",
        "acme/lookup",
        "out.db",
        "--sts-url",
        &sts(&server),
    ]);
    assert_eq!(r.code, 1);
    assert!(r.stderr.contains("out.db-wal"), "{}", r.stderr);
    assert!(server.requests().is_empty());
    let server = restore_server(meta(&data, 1), gzip(&data));
    let r = d.run(&[
        "sqlite",
        "restore",
        "acme/lookup",
        "out.db",
        "--sts-url",
        &sts(&server),
        "--force",
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(std::fs::read(d.p("out.db")).unwrap() == data);
    assert!(!d.p("out.db-wal").exists() && !d.p("out.db-shm").exists());
}

#[test]
fn prune_lists_asks_and_removes_untagged_old_snapshots() {
    let d = Dir::new("prune");
    let snaps = json!({"items": [
        {"seq": 4, "hash": "sha256:d", "created_at": "2026-11-20T00:00:00Z", "tags": [], "latest": true},
        {"seq": 3, "hash": "sha256:c", "created_at": "2026-11-19T00:00:00Z", "tags": ["keep"]},
        {"seq": 2, "hash": "sha256:b", "created_at": "2026-11-18T00:00:00Z", "tags": [], "stored_bytes": 10},
        {"seq": 1, "hash": "sha256:a", "created_at": "2026-11-17T00:00:00Z", "tags": [], "stored_bytes": 5}
    ], "next": null});
    // Without a terminal and without --yes, nothing is removed.
    let server = MockServer::start(vec![sts_ok(), MockResponse::json(200, &snaps.to_string())]);
    let r = d.run(&[
        "sqlite",
        "prune",
        "acme/lookup",
        "--keep",
        "1",
        "--sts-url",
        &sts(&server),
    ]);
    assert_eq!(r.code, 1);
    assert!(r.stderr.contains("give --yes"), "{}", r.stderr);
    assert!(server.requests().iter().all(|q| q.method != "DELETE"));
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(200, &snaps.to_string()),
        MockResponse::json(200, "{}"),
        MockResponse::json(200, "{}"),
    ]);
    let r = d.run(&[
        "sqlite",
        "prune",
        "acme/lookup",
        "--keep",
        "1",
        "--yes",
        "--sts-url",
        &sts(&server),
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let reqs = server.requests();
    assert_eq!(
        reqs[1].target,
        "/v1/sqlite/acme/default/lookup/snapshots?limit=1000"
    );
    let deletes: Vec<_> = reqs
        .iter()
        .filter(|q| q.method == "DELETE")
        .map(|q| q.target.clone())
        .collect();
    assert_eq!(
        deletes,
        [
            "/v1/sqlite/acme/default/lookup/at/2",
            "/v1/sqlite/acme/default/lookup/at/1"
        ]
    );
    assert!(
        r.stdout
            .contains("acme/default/lookup: removed 2 snapshots"),
        "{}",
        r.stdout
    );
}

#[test]
fn rm_of_a_database_needs_yes_without_a_terminal() {
    let d = Dir::new("rm");
    let server = MockServer::start(vec![sts_ok()]);
    let r = d.run(&["sqlite", "rm", "acme/lookup", "--sts-url", &sts(&server)]);
    assert_eq!(r.code, 1);
    assert!(server.requests().iter().all(|q| q.method != "DELETE"));
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(
            200,
            &json!({"ok": true, "purge_after": "2026-12-20"}).to_string(),
        ),
    ]);
    let r = d.run(&[
        "sqlite",
        "rm",
        "acme/lookup",
        "--yes",
        "--sts-url",
        &sts(&server),
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let reqs = server.requests();
    assert_eq!(reqs[1].method, "DELETE");
    assert_eq!(reqs[1].target, "/v1/sqlite/acme/default/lookup");
    assert!(r.stdout.contains("until 2026-12-20"));
    // One snapshot needs no --yes.
    let server = MockServer::start(vec![sts_ok(), MockResponse::json(200, "{}")]);
    let r = d.run(&["sqlite", "rm", "acme/lookup@5", "--sts-url", &sts(&server)]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(
        server.requests()[1].target,
        "/v1/sqlite/acme/default/lookup/at/5"
    );
}

#[test]
fn tag_set_log_and_ls() {
    let d = Dir::new("misc");
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(201, &json!({"seq": 42, "hash": "sha256:h"}).to_string()),
    ]);
    let r = d.run(&[
        "sqlite",
        "tag",
        "acme/fleet/lookup@42",
        "2026-11-20",
        "--sts-url",
        &sts(&server),
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let reqs = server.requests();
    assert_eq!(
        reqs[1].target,
        "/v1/sqlite/acme/fleet/lookup/tags/2026-11-20"
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&reqs[1].raw).unwrap(),
        json!({"snapshot": 42})
    );
    assert!(r
        .stdout
        .contains("tag 2026-11-20 -> snapshot 42 (sha256:h)"));

    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(200, &json!({"keep_count": 10, "keep_days": 14}).to_string()),
    ]);
    let r = d.run(&[
        "sqlite",
        "set",
        "acme/lookup",
        "--keep-count",
        "10",
        "--keep-days",
        "14",
        "--sts-url",
        &sts(&server),
    ]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let reqs = server.requests();
    assert_eq!(reqs[1].method, "PATCH");
    assert_eq!(
        serde_json::from_slice::<Value>(&reqs[1].raw).unwrap(),
        json!({"keep_count": 10, "keep_days": 14})
    );

    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(
            200,
            &json!({"items": [{"seq": 2, "hash": "sha256:h2", "latest": true, "file_bytes": 8192,
                "page_count": 2, "user_version": 42, "client_check": "quick_check:ok",
                "agent": "prn_1", "tags": ["v1"], "message": "m", "encryption": {"mode": "none"}}],
                "next": null})
            .to_string(),
        ),
    ]);
    let r = d.run(&["sqlite", "log", "acme/lookup", "--sts-url", &sts(&server)]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stdout.contains("*     2  sha256:h2"), "{}", r.stdout);
    assert!(r.stdout.contains("quick_check:ok") && r.stdout.contains("[v1]"));

    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(200, &json!({"items": [], "next": null}).to_string()),
    ]);
    let r = d.run(&["sqlite", "ls", "acme/fleet", "--sts-url", &sts(&server)]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(
        server.requests()[1].target,
        "/v1/sqlite/acme/fleet?limit=1000"
    );
    assert!(r.stderr.contains("no SQLite databases in acme/fleet"));
}
