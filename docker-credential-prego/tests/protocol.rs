//! Spawns the binary, speaks the Docker credential helper protocol, and checks the answers.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use prego_auth::testing::{MockResponse, MockServer};
use serde_json::{json, Value};

const BIN: &str = env!("CARGO_BIN_EXE_docker-credential-prego");
const JWT: &str = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln";
const API_KEY: &str = "prk_test_secret_value";
const HOST: &str = "oci.prego.k8skill.com";

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Run {
    fn json(&self) -> Value {
        serde_json::from_str(&self.stdout).expect("stdout is JSON")
    }
}

fn run(args: &[&str], input: &str, env: &[(&str, &str)]) -> Run {
    let mut cmd = Command::new(BIN);
    cmd.args(args)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn binary");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// A new, empty directory for one test.
fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "docker-credential-prego-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(dir: &Path, name: &str, content: &str) -> String {
    let path = dir.join(name);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, content).unwrap();
    path.to_string_lossy().into_owned()
}

/// Checks a successful `get` answer and that stderr is empty.
fn assert_get(r: &Run, server_url: &str, secret: &str) {
    assert_eq!(r.code, 0, "stdout: {} stderr: {}", r.stdout, r.stderr);
    assert_eq!(
        r.json(),
        json!({ "ServerURL": server_url, "Username": "acme", "Secret": secret })
    );
    assert!(r.stderr.is_empty(), "stderr: {}", r.stderr);
}

#[test]
fn get_with_api_key() {
    let r = run(
        &["get"],
        HOST,
        &[("PREGO_TENANT", "acme"), ("PREGO_API_KEY", API_KEY)],
    );
    assert_get(&r, HOST, API_KEY);
}

#[test]
fn get_accepts_url_forms() {
    for url in [
        "https://oci.prego.k8skill.com",
        "https://oci.prego.k8skill.com/v2/\n",
    ] {
        let r = run(
            &["get"],
            url,
            &[("PREGO_TENANT", "acme"), ("PREGO_API_KEY", API_KEY)],
        );
        assert_get(&r, url.trim(), API_KEY);
    }
}

#[test]
fn get_with_gitlab_id_token() {
    let r = run(
        &["get"],
        HOST,
        &[("PREGO_TENANT", "acme"), ("PREGO_ID_TOKEN", JWT)],
    );
    assert_get(&r, HOST, JWT);
}

#[test]
fn get_with_svid_file_and_token_file() {
    let dir = temp_dir("files");
    let path = write(&dir, "svid.jwt", &format!("{JWT}\n"));
    let r = run(
        &["get"],
        HOST,
        &[("PREGO_TENANT", "acme"), ("PREGO_SVID_FILE", &path)],
    );
    assert_get(&r, HOST, JWT);
    let r = run(
        &["get"],
        HOST,
        &[("PREGO_TENANT", "acme"), ("PREGO_TOKEN_FILE", &path)],
    );
    assert_get(&r, HOST, JWT);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn get_with_github_actions() {
    let server = MockServer::start(vec![MockResponse::json(
        200,
        &json!({ "count": 1, "value": JWT }).to_string(),
    )]);
    let url = format!("{}/token?api-version=2.0", server.base_url());
    let r = run(
        &["get"],
        HOST,
        &[
            ("PREGO_TENANT", "acme"),
            ("ACTIONS_ID_TOKEN_REQUEST_URL", &url),
            ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "request-token"),
        ],
    );
    assert_get(&r, HOST, JWT);
    let reqs = server.requests();
    assert_eq!(reqs.len(), 1);
    assert_eq!(
        reqs[0].target,
        "/token?api-version=2.0&audience=prego.k8skill.com"
    );
}

#[test]
fn spiffe_failure_does_not_fall_through() {
    let r = run(
        &["get"],
        HOST,
        &[
            ("PREGO_TENANT", "acme"),
            (
                "SPIFFE_ENDPOINT_SOCKET",
                "unix:///nonexistent/prego/agent.sock",
            ),
            ("PREGO_API_KEY", API_KEY),
        ],
    );
    assert_eq!(r.code, 1);
    assert!(r.stdout.contains("`spiffe` failed"), "{}", r.stdout);
    assert!(!r.stdout.contains(API_KEY));
    assert!(!r.stderr.contains(API_KEY));
}

#[test]
fn other_host_is_not_found_and_reads_no_source() {
    let server = MockServer::start(vec![]);
    let url = format!("{}/token", server.base_url());
    for host in [
        "registry-1.docker.io",
        "https://ghcr.io",
        "oci.prego.k8skill.com.evil.test",
    ] {
        let r = run(
            &["get"],
            host,
            &[
                ("PREGO_TENANT", "acme"),
                ("PREGO_API_KEY", API_KEY),
                ("ACTIONS_ID_TOKEN_REQUEST_URL", &url),
                ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "t"),
            ],
        );
        assert_eq!(r.code, 1, "{host}");
        assert_eq!(r.stdout, "credentials not found in native keychain\n");
        assert!(!r.stderr.contains(API_KEY));
    }
    assert!(server.requests().is_empty());
}

#[test]
fn not_found_needs_no_tenant() {
    let r = run(&["get"], "registry-1.docker.io", &[]);
    assert_eq!(r.code, 1);
    assert_eq!(r.stdout, "credentials not found in native keychain\n");
}

#[test]
fn missing_tenant_is_a_clear_error() {
    let r = run(&["get"], HOST, &[("PREGO_API_KEY", API_KEY)]);
    assert_eq!(r.code, 1);
    assert!(r.stdout.contains("tenant is not set"), "{}", r.stdout);
    assert!(!r.stdout.contains(API_KEY));
}

#[test]
fn no_source_is_a_clear_error() {
    let r = run(&["get"], HOST, &[("PREGO_TENANT", "acme")]);
    assert_eq!(r.code, 1);
    assert!(
        r.stdout.contains("no identity source found"),
        "{}",
        r.stdout
    );
}

#[test]
fn tenant_flag_wins() {
    let r = run(
        &["--tenant", "acme", "get"],
        HOST,
        &[("PREGO_TENANT", "other"), ("PREGO_API_KEY", API_KEY)],
    );
    assert_get(&r, HOST, API_KEY);
}

#[test]
fn settings_file_gives_tenant_and_extra_hosts() {
    let home = temp_dir("home");
    write(
        &home,
        ".config/prego/config.toml",
        "tenant = \"acme\"\noci_hosts = [\"oci.example.test\"]\n",
    );
    let home_s = home.to_string_lossy().into_owned();
    let env = [("HOME", home_s.as_str()), ("PREGO_API_KEY", API_KEY)];

    let r = run(&["get"], "oci.example.test", &env);
    assert_get(&r, "oci.example.test", API_KEY);

    let r = run(&["list"], "", &env);
    assert_eq!(r.code, 0);
    assert_eq!(
        r.json(),
        json!({ "https://oci.prego.k8skill.com": "acme", "https://oci.example.test": "acme" })
    );
    std::fs::remove_dir_all(&home).unwrap();
}

#[test]
fn settings_file_with_a_secret_is_refused() {
    let home = temp_dir("secret");
    write(
        &home,
        ".config/prego/config.toml",
        &format!("tenant = \"acme\"\napi_key = \"{API_KEY}\"\n"),
    );
    let home_s = home.to_string_lossy().into_owned();
    let r = run(&["get"], HOST, &[("HOME", home_s.as_str())]);
    assert_eq!(r.code, 1);
    assert!(r.stdout.contains("must not hold a secret"), "{}", r.stdout);
    assert!(!r.stdout.contains(API_KEY));
    assert!(!r.stderr.contains(API_KEY));
    std::fs::remove_dir_all(&home).unwrap();
}

#[test]
fn list_with_env_hosts_and_without_tenant() {
    let r = run(
        &["list"],
        "",
        &[
            ("PREGO_TENANT", "acme"),
            ("PREGO_OCI_HOSTS", "oci.two.test"),
        ],
    );
    assert_eq!(
        r.json(),
        json!({ "https://oci.prego.k8skill.com": "acme", "https://oci.two.test": "acme" })
    );
    let r = run(&["list"], "", &[]);
    assert_eq!(r.code, 0);
    assert_eq!(r.json(), json!({}));
}

#[test]
fn store_and_erase_are_no_ops() {
    let store = json!({ "ServerURL": HOST, "Username": "acme", "Secret": API_KEY }).to_string();
    let r = run(&["store"], &store, &[]);
    assert_eq!((r.code, r.stdout.as_str(), r.stderr.as_str()), (0, "", ""));
    let r = run(&["erase"], HOST, &[]);
    assert_eq!((r.code, r.stdout.as_str(), r.stderr.as_str()), (0, "", ""));
}

#[test]
fn version_and_unknown_action() {
    let r = run(&["--version"], "", &[]);
    assert_eq!(r.code, 0);
    assert!(r.stdout.starts_with(concat!(
        "docker-credential-prego ",
        env!("CARGO_PKG_VERSION"),
        " ("
    )));
    let r = run(&["bogus"], "", &[]);
    assert_eq!(r.code, 1);
    assert!(r.stdout.contains("unknown action"));
}
