//! Tests for `prego go publish`, `prego go-auth`, `prego setup go` and `prego exec`.
//!
//! The h1 values in `GO_SUMS` were recorded with Go 1.26.8 (`go mod download -json`, `Sum` and
//! `GoModSum`) from the same fixture repository that `fixture_repo` makes, fetched with `GOPROXY=direct`.
//! Set `PREGO_TEST_GO=/path/to/go` to run the live check against real Go as well.

mod support {
    pub mod mock_go;
}

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{json, Value};
use support::mock_go::{check_zip, MockGo};

const BIN: &str = env!("CARGO_BIN_EXE_prego");
const API_KEY: &str = "prk_test_go_secret";

/// (module dir, tag, module, version, Sum, GoModSum) from Go 1.26.8.
const GO_SUMS: [(&str, &str, &str, &str, &str, &str); 4] = [
    (
        ".",
        "v1.0.0",
        "example.com/repo.git",
        "v1.0.0",
        "h1:3JK+4beCMKukZOKbx09IG5kiJ8QWrxUK7zrk9QzE0Qs=",
        "h1:QjdhFINz2WzVAI3dCEO9LvNJZWWj5Y60L5Wv7N6UKdc=",
    ),
    (
        ".",
        "v1.1.0",
        "example.com/repo.git",
        "v1.1.0",
        "h1:wX6QFwi4wHJrWzfXqTZ4edlO04K+pv8KS0pHJTx+bG8=",
        "h1:QjdhFINz2WzVAI3dCEO9LvNJZWWj5Y60L5Wv7N6UKdc=",
    ),
    (
        "sub",
        "sub/v1.0.0",
        "example.com/repo.git/sub",
        "v1.0.0",
        "h1:PxR7k7T+8LsRw8mxtWZAU0gSImdQzhRs5Z9OiX+1FAQ=",
        "h1:Zz0lmwBCWLxnCFPeD/VjAApwn8+xhJMoHbAX1neHjhc=",
    ),
    (
        "v2",
        "v2.0.0",
        "example.com/repo.git/v2",
        "v2.0.0",
        "h1:XOxDwafHYgEXmMmUHijggTdpsd0YPG7aRDLavUYfvr0=",
        "h1:shpcQdt646uLzfsOO3/QN6+rfca1mm2oj0/VteoGBFU=",
    ),
];

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run_in(dir: &Path, args: &[&str], env: &[(&str, &str)], stdin: Option<&str>) -> Run {
    let mut cmd = Command::new(BIN);
    cmd.current_dir(dir).args(args).env_clear();
    cmd.env("PATH", std::env::var("PATH").unwrap_or_default());
    cmd.env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1");
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("run prego");
    if let Some(s) = stdin {
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
    let dir = std::env::temp_dir().join(format!("prego-go-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn git(dir: &Path, args: &[&str]) {
    let ok = Command::new("git")
        .current_dir(dir)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.test")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.test")
        .stdout(Stdio::null())
        .status()
        .unwrap()
        .success();
    assert!(ok, "git {args:?}");
}

fn write(dir: &Path, path: &str, content: &[u8]) {
    let p = dir.join(path);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, content).unwrap();
}

/// The fixture repository: a root module (vendor files, a nested module, a symlink, CRLF files, git
/// attributes that Go ignores), a module in `sub/`, and a `/v2` module in `v2/`.
fn fixture_repo(dir: &Path) {
    git(dir, &["init", "-q", "-b", "main"]);
    write(dir, "go.mod", b"module example.com/repo.git\n\ngo 1.22\n");
    write(dir, "a.go", b"package repo\n\nfunc A() int { return 1 }\n");
    write(dir, "LICENSE", b"MIT\r\nline2\r\n");
    write(dir, "vendor/modules.txt", b"v\n");
    write(dir, "vendor/x/x.go", b"package x\n");
    write(
        dir,
        "nested/go.mod",
        b"module example.com/repo.git/nested\n",
    );
    write(dir, "nested/n.go", b"package n\n");
    write(
        dir,
        "sub/go.mod",
        b"module example.com/repo.git/sub\n\ngo 1.22\n",
    );
    write(dir, "sub/s.go", b"package sub\n");
    write(dir, "crlf.txt", b"crlf\r\n");
    std::os::unix::fs::symlink("a.go", dir.join("link.go")).unwrap();
    write(dir, ".gitattributes", b"ignored.txt export-ignore\n");
    write(dir, "ignored.txt", b"ign\n");
    write(
        dir,
        "v2/go.mod",
        b"module example.com/repo.git/v2\n\ngo 1.22\n",
    );
    write(dir, "v2/v.go", b"package v2\n");
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "-q", "--no-gpg-sign", "-m", "one"]);
    for t in ["v1.0.0", "sub/v1.0.0", "v2.0.0"] {
        git(dir, &["tag", t]);
    }
    write(
        dir,
        ".gitattributes",
        b"ignored.txt export-ignore\nsubst.txt export-subst\n",
    );
    write(dir, "subst.txt", b"id $Format:%H$\n");
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "-q", "--no-gpg-sign", "-m", "two"]);
    git(dir, &["tag", "v1.1.0"]);
}

fn json_line(r: &Run) -> Value {
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    serde_json::from_str(r.stdout.trim()).unwrap_or_else(|_| panic!("not JSON: {}", r.stdout))
}

#[test]
fn dry_run_h1_matches_go() {
    let repo = temp_dir("fixture");
    fixture_repo(&repo);
    // A dirty working tree must not change the zip.
    write(&repo, "a.go", b"package repo // changed, not committed\n");
    write(&repo, ".env", b"SECRET=1\n");
    for (dir, tag, module, version, sum, mod_sum) in GO_SUMS {
        let r = run_in(
            &repo,
            &["go", "publish", "--dry-run", "--json", dir, tag],
            &[],
            None,
        );
        let v = json_line(&r);
        assert_eq!(v["module"], module);
        assert_eq!(v["version"], version);
        assert_eq!(v["h1"], sum, "{dir} {tag}");
        assert_eq!(v["mod_h1"], mod_sum, "{dir} {tag}");
        let files: Vec<&str> = v["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["path"].as_str().unwrap())
            .collect();
        assert!(!files.contains(&".env"));
        assert!(!files
            .iter()
            .any(|f| f.starts_with("vendor/x") || f.starts_with("nested/")));
        assert!(!files.contains(&"link.go"));
        if dir == "sub" {
            assert_eq!(v["origin"]["Subdir"], "sub");
            assert!(files.contains(&"LICENSE"), "root LICENSE is added");
        } else {
            assert!(v["origin"].get("Subdir").is_none());
        }
        assert_eq!(v["origin"]["Ref"], format!("refs/tags/{tag}"));
    }
    // The text form lists the files and says nothing was sent.
    let r = run_in(
        &repo,
        &["go", "publish", "--dry-run", ".", "v1.0.0"],
        &[],
        None,
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r
        .stdout
        .contains("left out    vendor/x/x.go (vendored package)"));
    assert!(r.stdout.contains("nothing was sent"));
    std::fs::remove_dir_all(&repo).unwrap();
}

#[test]
fn tag_rules() {
    let repo = temp_dir("tags");
    fixture_repo(&repo);
    let r = |args: &[&str]| run_in(&repo, args, &[], None);
    // HEAD has v1.1.0 only.
    let v = json_line(&r(&["go", "publish", "--dry-run", "--json"]));
    assert_eq!(v["version"], "v1.1.0");
    for (args, want) in [
        (
            vec!["go", "publish", "--dry-run", "sub", "v1.0.0"],
            "sub/vX.Y.Z",
        ),
        (
            vec!["go", "publish", "--dry-run", "v2", "v1.0.0"],
            "must be v2.x.y, not v1.0.0",
        ),
        (
            vec!["go", "publish", "--dry-run", ".", "v9.9.9"],
            "not in this repository",
        ),
        (vec!["go", "publish", "--dry-run", "sub"], "HEAD has no tag"),
        (
            vec!["go", "publish", "--dry-run", "nope"],
            "not a directory",
        ),
    ] {
        let out = r(&args);
        assert_eq!(out.code, 1, "{args:?}");
        assert!(out.stderr.contains(want), "{args:?}: {}", out.stderr);
    }
    git(&repo, &["tag", "v1.2.0-0.20261104010203-abcdefabcdef"]);
    let out = r(&[
        "go",
        "publish",
        "--dry-run",
        ".",
        "v1.2.0-0.20261104010203-abcdefabcdef",
    ]);
    assert!(out.stderr.contains("pseudo-version"), "{}", out.stderr);
    std::fs::remove_dir_all(&repo).unwrap();
}

fn small_repo(dir: &Path, module: &str, tag: &str) {
    git(dir, &["init", "-q", "-b", "main"]);
    write(
        dir,
        "go.mod",
        format!("module {module}\n\ngo 1.22\n").as_bytes(),
    );
    write(dir, "core.go", b"package core\n");
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "-q", "--no-gpg-sign", "-m", "c"]);
    git(dir, &["tag", tag]);
}

fn go_env(m: &MockGo) -> Vec<(&'static str, String)> {
    vec![
        ("PREGO_TENANT", "acme".into()),
        ("PREGO_STS_URL", m.sts_url()),
        ("PREGO_GO_HOSTS", m.host()),
        ("PREGO_API_KEY", API_KEY.into()),
    ]
}

fn refs<'a>(env: &'a [(&'static str, String)]) -> Vec<(&'static str, &'a str)> {
    env.iter().map(|(k, v)| (*k, v.as_str())).collect()
}

#[test]
fn publish_single_put() {
    let m = MockGo::start();
    let repo = temp_dir("single");
    small_repo(&repo, "go.acme.com/Core", "v1.2.0");
    let env = go_env(&m);
    let r = run_in(&repo, &["go", "publish", "--json"], &refs(&env), None);
    let v = json_line(&r);
    assert_eq!(v["module"], "go.acme.com/Core");
    assert!(!r.stderr.contains("regtok") && !r.stderr.contains(API_KEY));

    let put = m
        .requests()
        .into_iter()
        .find(|q| q.method == "PUT")
        .unwrap();
    assert_eq!(
        put.target,
        "/t/acme/default/-/publish/go.acme.com/!core/@v/v1.2.0.zip"
    );
    assert_eq!(put.headers["authorization"], "Bearer regtok-1");
    assert_eq!(put.headers["content-length"], put.body_len.to_string());
    assert_eq!(put.headers["x-prego-go-h1"], v["h1"].as_str().unwrap());
    let origin: Value = serde_json::from_str(&put.headers["x-prego-go-origin"]).unwrap();
    assert_eq!(origin["VCS"], "git");
    assert_eq!(origin["Ref"], "refs/tags/v1.2.0");
    assert_eq!(origin["Hash"].as_str().unwrap().len(), 40);
    assert!(origin.get("URL").is_none());

    // The mock read the zip and computed the same hashes.
    let zip = m.with(|s| s.zips[&("go.acme.com/Core".to_string(), "v1.2.0".to_string())].clone());
    let (h1, mod_h1) = check_zip(&zip, "go.acme.com/Core", "v1.2.0").unwrap();
    assert_eq!(v["h1"], h1);
    assert_eq!(v["mod_h1"], mod_h1);

    // A second publish of the same version: the registry text is shown, and the exit code is 1.
    let r = run_in(&repo, &["go", "publish"], &refs(&env), None);
    assert_eq!(r.code, 1);
    assert!(
        r.stderr.contains("HTTP 409: version was already published"),
        "{}",
        r.stderr
    );
    std::fs::remove_dir_all(&repo).unwrap();
}

#[test]
fn publish_refuses_a_zip_above_300_mib_before_any_upload() {
    let m = MockGo::start();
    let repo = temp_dir("cap");
    small_repo(&repo, "go.acme.com/big", "v1.0.0");
    // A blob of 300 MiB + 1 byte, made from stdin: no file of that size is written to the work tree.
    let mut child = Command::new("git")
        .current_dir(&repo)
        .args(["hash-object", "-w", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        let block = vec![0u8; 1 << 20];
        for _ in 0..300 {
            stdin.write_all(&block).unwrap();
        }
        stdin.write_all(&[0]).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let blob = String::from_utf8(out.stdout).unwrap();
    let info = format!("100644,{},big.bin", blob.trim());
    git(&repo, &["update-index", "--add", "--cacheinfo", &info]);
    git(&repo, &["commit", "-q", "--no-gpg-sign", "-m", "big"]);
    git(&repo, &["tag", "v1.1.0"]);

    let env = go_env(&m);
    let r = run_in(&repo, &["go", "publish", ".", "v1.1.0"], &refs(&env), None);
    assert_eq!(r.code, 1, "{}", r.stderr);
    assert!(r.stderr.contains("at most 300 MiB"), "{}", r.stderr);
    assert!(r.stderr.contains("Nothing was sent"), "{}", r.stderr);
    // Refused before any token exchange or upload.
    assert!(m.requests().is_empty(), "{:?}", m.requests().len());
    assert_eq!(m.sts_count(), 0);
    std::fs::remove_dir_all(&repo).unwrap();
}

#[test]
fn publish_errors_and_retoken() {
    let m = MockGo::start();
    let repo = temp_dir("errors");
    small_repo(&repo, "go.acme.com/core", "v1.0.0");
    let env = go_env(&m);
    let prefix = "module path go.acme.com/core is not under a registered Go module path prefix of tenant acme";
    m.with(|s| s.fail_next.insert("PUT".into(), vec![(400, prefix.into())]));
    let r = run_in(&repo, &["go", "publish"], &refs(&env), None);
    assert_eq!(r.code, 1);
    assert!(r.stderr.contains(prefix), "{}", r.stderr);
    assert!(!r.stderr.contains("regtok"));

    // A 401 gets one new token, then the publish goes on.
    m.with(|s| {
        s.fail_next
            .insert("PUT".into(), vec![(401, "expired".into())])
    });
    let before = m.sts_count();
    let r = run_in(&repo, &["go", "publish", "--json"], &refs(&env), None);
    json_line(&r);
    assert_eq!(m.sts_count() - before, 2);

    // The registry's h1 differs from the local one: an error.
    let repo2 = temp_dir("errors2");
    small_repo(&repo2, "go.acme.com/other", "v1.0.0");
    m.with(|s| s.wrong_h1 = true);
    let r = run_in(&repo2, &["go", "publish"], &refs(&env), None);
    assert_eq!(r.code, 1);
    assert!(
        r.stderr.contains("the registry computed h1"),
        "{}",
        r.stderr
    );
    std::fs::remove_dir_all(&repo).unwrap();
    std::fs::remove_dir_all(&repo2).unwrap();
}

/// Incompressible bytes, so the zip is as large as the file.
fn noise(len: usize) -> Vec<u8> {
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut v = Vec::with_capacity(len);
    while v.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        v.extend_from_slice(&x.to_le_bytes());
    }
    v.truncate(len);
    v
}

#[test]
fn publish_chunked_with_faults() {
    let m = MockGo::start();
    let repo = temp_dir("chunked");
    git(&repo, &["init", "-q", "-b", "main"]);
    write(&repo, "go.mod", b"module go.acme.com/big\n\ngo 1.22\n");
    write(&repo, "data.bin", &noise(97 << 20));
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-q", "--no-gpg-sign", "-m", "big"]);
    git(&repo, &["tag", "v1.0.0"]);
    // Part 1 is stored but its answer is lost; part 2 gets a 503 one time.
    m.with(|s| {
        s.drop_after_part = Some(1);
        s.fail_part_once = Some(2);
    });
    let env = go_env(&m);
    let r = run_in(&repo, &["go", "publish", "--json"], &refs(&env), None);
    let v = json_line(&r);
    let zip = m.with(|s| s.zips[&("go.acme.com/big".to_string(), "v1.0.0".to_string())].clone());
    assert!(zip.len() > 95 << 20);
    let (h1, _) = check_zip(&zip, "go.acme.com/big", "v1.0.0").unwrap();
    assert_eq!(v["h1"], h1);

    let reqs = m.requests();
    assert!(reqs
        .iter()
        .any(|q| q.method == "POST" && q.target.ends_with("/@v/v1.0.0/uploads")));
    let patches: Vec<&str> = reqs
        .iter()
        .filter(|q| q.method == "PATCH")
        .map(|q| q.target.as_str())
        .collect();
    // Part 1 twice (the lost answer, then 409), part 2 twice (503, then stored), then part 3.
    let u = "/t/acme/default/-/uploads/gup_1?part=";
    assert_eq!(patches, [1, 1, 2, 2, 3].map(|n| format!("{u}{n}")));
    assert!(reqs
        .iter()
        .any(|q| q.method == "PUT" && q.target == "/t/acme/default/-/uploads/gup_1"));
    assert!(!reqs
        .iter()
        .any(|q| q.method == "PUT" && q.target.contains("/-/publish/")));
    std::fs::remove_dir_all(&repo).unwrap();
}

#[test]
fn publish_chunked_gets_a_new_token_before_the_old_one_expires() {
    let m = MockGo::start();
    let repo = temp_dir("short-tokens");
    git(&repo, &["init", "-q", "-b", "main"]);
    write(&repo, "go.mod", b"module go.acme.com/big\n\ngo 1.22\n");
    write(&repo, "data.bin", &noise(97 << 20));
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-q", "--no-gpg-sign", "-m", "big"]);
    git(&repo, &["tag", "v1.0.0"]);
    // Tokens of 2 s that the mock refuses when older, and 1.1 s for each part: the client must get new
    // tokens between the parts, before the registry refuses the old one.
    m.with(|s| {
        s.expires_in = Some(2);
        s.patch_delay = Some(std::time::Duration::from_millis(1100));
    });
    let env = go_env(&m);
    let r = run_in(&repo, &["go", "publish", "--json"], &refs(&env), None);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let v = json_line(&r);
    assert_eq!(v["module"], "go.acme.com/big");
    assert_eq!(
        m.with(|s| s.too_old),
        0,
        "a request used a token that was too old"
    );
    assert!(m.sts_count() >= 2, "{}", m.sts_count());
    let base = format!("http://{}/t/acme/default", m.host());
    for f in m.with(|s| s.sts.clone()) {
        assert_eq!(f["resource"], base);
    }
    std::fs::remove_dir_all(&repo).unwrap();
}

fn private_dir(name: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let d = temp_dir(name);
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

#[test]
fn go_auth_blocks_cache_and_refresh() {
    let m = MockGo::start();
    let run_dir = private_dir("xdg");
    let proxy = format!(
        "http://{}/t/acme/default,https://proxy.golang.org,direct",
        m.host()
    );
    let mut env = go_env(&m);
    env.push(("GOPROXY", proxy));
    env.push(("XDG_RUNTIME_DIR", run_dir.to_str().unwrap().to_string()));
    let here = std::env::temp_dir();
    let block = |n: usize| {
        format!(
            "http://{}/t/acme/\n\nAuthorization: Bearer regtok-{n}\n\n",
            m.host()
        )
    };

    let r = run_in(&here, &["go-auth"], &refs(&env), None);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.stdout, block(1));
    assert!(r.stderr.is_empty());

    // First call again: the cached token, no STS call.
    let r = run_in(&here, &["go-auth"], &refs(&env), None);
    assert_eq!(r.stdout, block(1));
    assert_eq!(m.sts_count(), 1);

    // A 404 from Prego (a public module): the cached token, no STS call.
    let url = format!(
        "http://{}/t/acme/default/golang.org/x/text/@v/list",
        m.host()
    );
    let r = run_in(
        &here,
        &["go-auth", &url],
        &refs(&env),
        Some("HTTP/1.1 404 Not Found\r\n\r\n"),
    );
    assert_eq!(r.stdout, block(1));
    assert_eq!(m.sts_count(), 1);

    // A 4xx from another host: no STS call, and only the Prego prefix is printed.
    let r = run_in(
        &here,
        &["go-auth", "https://proxy.golang.org/x/@v/list"],
        &refs(&env),
        Some("HTTP/1.1 401 Unauthorized\r\n\r\n"),
    );
    assert_eq!(r.stdout, block(1));
    assert_eq!(m.sts_count(), 1);

    // A 401 from Prego: a new token.
    let r = run_in(
        &here,
        &["go-auth", &url],
        &refs(&env),
        Some("HTTP/1.1 401 Unauthorized\r\n\r\n"),
    );
    assert_eq!(r.stdout, block(2));
    assert_eq!(m.sts_count(), 2);

    // The cache file holds the token with mode 0600, in a 0700 directory.
    use std::os::unix::fs::PermissionsExt;
    let dir = run_dir.join("prego");
    assert_eq!(
        std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(files.len(), 1, "{files:?}");
    assert_eq!(
        std::fs::metadata(&files[0]).unwrap().permissions().mode() & 0o777,
        0o600
    );

    // No Prego entry in GOPROXY: no output, no STS call.
    let mut env2 = go_env(&m);
    env2.push(("GOPROXY", "https://proxy.golang.org,direct".into()));
    let r = run_in(&here, &["go-auth"], &refs(&env2), None);
    assert_eq!((r.code, r.stdout.as_str()), (0, ""));
    assert_eq!(m.sts_count(), 2);

    // A refused identity: an error that shows no secret.
    let mut env3 = go_env(&m);
    env3.retain(|(k, _)| *k != "PREGO_API_KEY");
    env3.push(("GOPROXY", format!("http://{}/t/acme/default", m.host())));
    env3.push(("XDG_RUNTIME_DIR", run_dir.to_str().unwrap().to_string()));
    let r = run_in(&here, &["go-auth"], &refs(&env3), None);
    assert_eq!(r.code, 1);
    assert!(r.stdout.is_empty());
    assert!(!r.stderr.contains("regtok"));
    std::fs::remove_dir_all(&run_dir).unwrap();
}

#[test]
fn go_auth_one_minute_token_and_cache_margin() {
    let m = MockGo::start();
    m.with(|s| s.expires_in = Some(60));
    let run_dir = private_dir("xdg-short");
    let base = format!("http://{}/t/acme/default", m.host());
    let mut env = go_env(&m);
    env.push(("GOPROXY", format!("{base},https://proxy.golang.org,direct")));
    env.push(("XDG_RUNTIME_DIR", run_dir.to_str().unwrap().to_string()));
    let here = std::env::temp_dir();

    let r = run_in(&here, &["go-auth"], &refs(&env), None);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stdout.contains("Bearer regtok-1"));
    assert_eq!(m.with(|s| s.sts[0]["resource"].clone()), base);

    let dir = run_dir.join("prego");
    let file = std::fs::read_dir(&dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    assert_eq!(v["lifetime"], 60);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let left = v["expires_at"].as_i64().unwrap() - now;
    assert!((58..=60).contains(&left), "{left}");

    // The margin of a 1-minute token is 15 s. With 20 s left: the cached token.
    let set_left = |secs: i64| {
        let body = json!({"token": "regtok-1", "expires_at": now + secs, "lifetime": 60});
        std::fs::write(&file, body.to_string()).unwrap();
    };
    set_left(20);
    let r = run_in(&here, &["go-auth"], &refs(&env), None);
    assert!(r.stdout.contains("Bearer regtok-1"));
    assert_eq!(m.sts_count(), 1);
    // With 10 s left: not given out again; a new token.
    set_left(10);
    let r = run_in(&here, &["go-auth"], &refs(&env), None);
    assert!(r.stdout.contains("Bearer regtok-2"), "{}", r.stdout);
    assert_eq!(m.sts_count(), 2);
    std::fs::remove_dir_all(&run_dir).unwrap();
}

#[test]
fn go_auth_tenant_from_goproxy_and_unsafe_cache() {
    let m = MockGo::start();
    let open_dir = temp_dir("xdg-open");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(open_dir.join("prego")).unwrap();
        std::fs::set_permissions(
            open_dir.join("prego"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }
    let mut env = go_env(&m);
    env.retain(|(k, _)| *k != "PREGO_TENANT");
    env.push(("GOPROXY", format!("http://{}/t/acme/default", m.host())));
    env.push(("XDG_RUNTIME_DIR", open_dir.to_str().unwrap().to_string()));
    let here = std::env::temp_dir();
    for n in 1..=2 {
        let r = run_in(&here, &["go-auth"], &refs(&env), None);
        assert_eq!(r.code, 0, "{}", r.stderr);
        assert!(r.stdout.contains(&format!("Bearer regtok-{n}")));
    }
    // The tenant came from GOPROXY; a 0755 cache directory is not used, so each call is an exchange.
    assert_eq!(m.sts_count(), 2);
    assert_eq!(m.with(|s| s.sts[0]["tenant"].clone()), "acme");
    assert_eq!(
        std::fs::read_dir(open_dir.join("prego")).unwrap().count(),
        0
    );
    std::fs::remove_dir_all(&open_dir).unwrap();
}

#[test]
fn setup_go_lines() {
    let m = MockGo::start();
    let home = temp_dir("setup-home");
    let env = go_env(&m);
    let mut e = refs(&env);
    let home_s = home.to_str().unwrap().to_string();
    e.push(("HOME", &home_s));
    // No go on PATH: GOAUTH gets only the helper.
    e.retain(|(k, _)| *k != "PATH");
    let host = m.host();

    let r = run_in(
        &home,
        &[
            "setup",
            "go",
            "--prefix",
            "go.acme.com",
            "--prefix",
            "github.com/acme",
        ],
        &e,
        None,
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(
        r.stdout,
        format!(
            "go env -w GOPROXY='http://{host}/t/acme/default,https://proxy.golang.org,direct'\n\
             go env -w GONOSUMDB='go.acme.com,github.com/acme'\n\
             go env -w GOAUTH='prego go-auth'\n"
        )
    );

    // From the admin API, when the identity has admin:read.
    m.with(|s| s.admin_ok = true);
    let r = run_in(
        &home,
        &["setup", "go", "--print", "--namespace", "rel"],
        &e,
        None,
    );
    assert!(r.stdout.contains("/t/acme/rel,"), "{}", r.stdout);
    assert!(
        r.stdout.contains("GONOSUMDB='go.acme.com,github.com/acme'"),
        "{}",
        r.stdout
    );
    let admin = m.with(|s| s.sts.last().cloned().unwrap());
    assert_eq!(admin["audience"], "prego-admin");
    assert_eq!(admin["scope"], "admin:read");

    // Refused: a placeholder and a note, and no error.
    m.with(|s| s.admin_ok = false);
    let r = run_in(&home, &["setup", "go"], &e, None);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stdout.contains("GONOSUMDB='<your module path prefixes"),
        "{}",
        r.stdout
    );
    assert!(r.stdout.contains("--prefix"));

    // From the settings file.
    write(
        &home,
        ".config/prego/config.toml",
        b"go_prefixes = [\"go.example.test\"]\n",
    );
    let r = run_in(&home, &["setup", "go"], &e, None);
    assert!(
        r.stdout.contains("GONOSUMDB='go.example.test'"),
        "{}",
        r.stdout
    );

    // --write runs `go env -w`. A fake go records the arguments and reports an old GOAUTH of netrc.
    let bin = home.join("bin");
    let log = home.join("go-args");
    write(
        &bin,
        "go",
        format!(
            "#!/bin/sh\nif [ \"$2\" = -changed ]; then echo '{{\"GOAUTH\":\"netrc\"}}'; exit 0; fi\nprintf '%s\\n' \"$@\" > {}\n",
            log.display()
        )
        .as_bytes(),
    );
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(bin.join("go"), std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let path = format!("{}:/usr/bin:/bin", bin.display());
    let mut w = e.clone();
    w.push(("PATH", &path));
    let r = run_in(
        &home,
        &["setup", "go", "--write", "--prefix", "go.acme.com"],
        &w,
        None,
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    let args = std::fs::read_to_string(&log).unwrap();
    let args: Vec<&str> = args.lines().collect();
    assert_eq!(args[..2], ["env", "-w"]);
    assert!(args.contains(&"GOAUTH=netrc;prego go-auth"), "{args:?}");
    assert!(args.contains(&"GONOSUMDB=go.acme.com"), "{args:?}");
    assert!(!args.iter().any(|a| a.contains("command ")), "{args:?}");

    // A bad prefix is refused.
    let r = run_in(&home, &["setup", "go", "--prefix", "a,b.c"], &e, None);
    assert_eq!(r.code, 1);
    std::fs::remove_dir_all(&home).unwrap();
}

#[test]
fn exec_writes_a_private_netrc_and_deletes_it() {
    let m = MockGo::start();
    let run_dir = private_dir("exec");
    let mut env = go_env(&m);
    env.push(("XDG_RUNTIME_DIR", run_dir.to_str().unwrap().to_string()));
    let script = "cat \"$NETRC\"; stat -c %a \"$NETRC\" 2>/dev/null || stat -f %Lp \"$NETRC\"; echo \"$NETRC\"; exit 7";
    let r = run_in(
        &std::env::temp_dir(),
        &["exec", "--", "sh", "-c", script],
        &refs(&env),
        None,
    );
    assert_eq!(r.code, 7, "{}", r.stderr);
    let lines: Vec<&str> = r.stdout.lines().collect();
    assert_eq!(lines[0], "machine 127.0.0.1 login acme password regtok-1");
    assert_eq!(lines[1], "600");
    assert!(lines[2].starts_with(run_dir.to_str().unwrap()));
    assert!(!Path::new(lines[2]).exists(), "the netrc file is deleted");

    assert!(
        r.stderr.contains("prego exec: token valid for 15 min"),
        "{}",
        r.stderr
    );

    let r = run_in(&std::env::temp_dir(), &["exec"], &refs(&env), None);
    assert_eq!(r.code, 1);
    assert!(r.stderr.contains("usage"));

    // A 1-minute token: a warning with the lifetime, and the resource of the single Prego GOPROXY entry.
    m.with(|s| s.expires_in = Some(60));
    let base = format!("http://{}/t/acme/default", m.host());
    env.push(("GOPROXY", format!("{base},https://proxy.golang.org,direct")));
    let r = run_in(
        &std::env::temp_dir(),
        &["exec", "--", "true"],
        &refs(&env),
        None,
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stderr.contains(
            "prego exec: warning: token valid for 1 min; long builds need GOAUTH, see prego setup go."
        ),
        "{}",
        r.stderr
    );
    assert_eq!(m.with(|s| s.sts.last().unwrap()["resource"].clone()), base);
    std::fs::remove_dir_all(&run_dir).unwrap();
}

/// With `PREGO_TEST_GO` set to a Go 1.24+ binary: Go fetches the fixture with `GOPROXY=direct` and gets
/// the same Sum and GoModSum, and Go accepts the zip that prego uploads (served from a file:// proxy).
#[test]
fn live_go() {
    let Ok(go) = std::env::var("PREGO_TEST_GO") else {
        eprintln!("PREGO_TEST_GO is not set: live Go check skipped");
        return;
    };
    let work = temp_dir("live");
    let repo = work.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    fixture_repo(&repo);
    let gitconfig = work.join("gitconfig");
    std::fs::write(
        &gitconfig,
        format!(
            "[url \"file://{}\"]\n\tinsteadOf = https://example.com/repo\n[protocol \"file\"]\n\tallow = always\n",
            repo.display()
        ),
    )
    .unwrap();
    let go_cmd = |proxy: &str, module: &str| -> Value {
        let out = Command::new(&go)
            .current_dir(&work)
            .args(["mod", "download", "-json", module])
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", &work)
            .env("GOPATH", work.join("gopath"))
            .env("GOMODCACHE", work.join(format!("modcache-{}", proxy.len())))
            .env("GOCACHE", work.join("gocache"))
            .env("GIT_CONFIG_GLOBAL", &gitconfig)
            .env("GIT_SSH_COMMAND", "false")
            .env("GOPROXY", proxy)
            .env("GONOSUMDB", "example.com,go.acme.com")
            .env("GOFLAGS", "-modcacherw")
            .env("GOTOOLCHAIN", "local")
            .env("GOVCS", "*:all")
            .output()
            .unwrap();
        serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&out.stderr)))
    };
    for (_, _, module, version, sum, mod_sum) in GO_SUMS {
        let v = go_cmd("direct", &format!("{module}@{version}"));
        assert_eq!(v["Sum"], sum, "{module}");
        assert_eq!(v["GoModSum"], mod_sum, "{module}");
    }

    // Upload with prego to the mock, then let Go read that zip from a file:// proxy.
    let m = MockGo::start();
    let small = work.join("small");
    std::fs::create_dir_all(&small).unwrap();
    small_repo(&small, "go.acme.com/Core", "v1.2.0");
    let env = go_env(&m);
    let v = json_line(&run_in(
        &small,
        &["go", "publish", "--json"],
        &refs(&env),
        None,
    ));
    let zip = m.with(|s| s.zips[&("go.acme.com/Core".to_string(), "v1.2.0".to_string())].clone());
    let dir = work.join("proxy/go.acme.com/!core/@v");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("v1.2.0.zip"), &zip).unwrap();
    std::fs::write(
        dir.join("v1.2.0.mod"),
        "module go.acme.com/Core\n\ngo 1.22\n",
    )
    .unwrap();
    std::fs::write(dir.join("v1.2.0.info"), r#"{"Version":"v1.2.0"}"#).unwrap();
    std::fs::write(dir.join("list"), "v1.2.0\n").unwrap();
    let proxy = format!("file://{}", work.join("proxy").display());
    let g = go_cmd(&proxy, "go.acme.com/Core@v1.2.0");
    assert_eq!(g["Sum"], v["h1"]);
    assert_eq!(g["GoModSum"], v["mod_h1"]);
    std::fs::remove_dir_all(&work).unwrap();
}
