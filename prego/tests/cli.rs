//! Runs the `prego` binary against a mock STS and checks its output.

use std::path::PathBuf;
use std::process::Command;

use prego_auth::testing::{MockResponse, MockServer};
use serde_json::{json, Value};

const BIN: &str = env!("CARGO_BIN_EXE_prego");
const API_KEY: &str = "prk_test_secret_value";
// Payload {"sub":"prn_1","tid":"ten_1","exp":4102444800} (2100-01-01).
const REG_TOKEN: &str =
    "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJwcm5fMSIsInRpZCI6InRlbl8xIiwiZXhwIjo0MTAyNDQ0ODAwfQ.c2ln";

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str], env: &[(&str, &str)]) -> Run {
    let mut cmd = Command::new(BIN);
    cmd.args(args).env_clear();
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("run prego");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("prego-cli-{name}-{}", std::process::id()));
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

#[test]
fn token_prints_only_the_registry_token() {
    let server = MockServer::start(vec![sts_ok()]);
    let sts = format!("{}/v1/sts/token/e/k7mq", server.base_url());
    let r = run(
        &["token", "--tenant", "acme", "--sts-url", &sts],
        &[("PREGO_API_KEY", API_KEY)],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.stdout, format!("{REG_TOKEN}\n"));
    assert!(r.stderr.is_empty());
    let form = server.requests()[0].form();
    assert_eq!(form["subject_token"], API_KEY);
    assert_eq!(form["tenant"], "acme");
}

#[test]
fn token_with_scope_uses_the_oci_realm() {
    let server = MockServer::start(vec![MockResponse::json(
        200,
        &json!({ "token": REG_TOKEN, "access_token": REG_TOKEN, "expires_in": 900 }).to_string(),
    )]);
    let sts = format!("{}/v1/sts/token/e/k7mq", server.base_url());
    let r = run(
        &[
            "token",
            "--scope",
            "repository:acme/default/api:pull",
            "--sts-url",
            &sts,
        ],
        &[("PREGO_TENANT", "acme"), ("PREGO_API_KEY", API_KEY)],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.stdout, format!("{REG_TOKEN}\n"));
    let req = &server.requests()[0];
    assert_eq!(req.method, "GET");
    assert!(
        req.target
            .starts_with("/v1/oci/token/e/k7mq?service=oci.prego.k8skill.com&scope="),
        "{}",
        req.target
    );
    assert!(req.header("authorization").unwrap().starts_with("Basic "));
}

#[test]
fn refused_identity_shows_no_secret() {
    let server = MockServer::start(vec![MockResponse::json(
        400,
        r#"{"error":"invalid_grant"}"#,
    )]);
    let sts = format!("{}/v1/sts/token/e/k7mq", server.base_url());
    let r = run(
        &["token", "--tenant", "acme", "--sts-url", &sts],
        &[("PREGO_API_KEY", API_KEY)],
    );
    assert_eq!(r.code, 1);
    assert!(r.stdout.is_empty());
    assert!(
        r.stderr.contains("refused this identity for tenant acme"),
        "{}",
        r.stderr
    );
    assert!(!r.stderr.contains(API_KEY));
}

#[test]
fn whoami_shows_the_principal_but_not_the_token() {
    let server = MockServer::start(vec![sts_ok()]);
    let sts = format!("{}/v1/sts/token/e/k7mq", server.base_url());
    let r = run(
        &["whoami", "--sts-url", &sts, "--namespace", "rel"],
        &[("PREGO_TENANT", "acme"), ("PREGO_API_KEY", API_KEY)],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stdout.contains("tenant:     acme"), "{}", r.stdout);
    assert!(r.stdout.contains("source:     api-key"));
    assert!(r.stdout.contains("principal:  prn_1 (not verified)"));
    assert!(r.stdout.contains("tenant id:  ten_1 (not verified)"));
    assert!(r
        .stdout
        .contains("sparse+https://cargo.prego.k8skill.com/t/acme/rel/index/"));
    assert!(r.stdout.contains("oci.prego.k8skill.com/acme/rel/<repo>"));
    assert!(r
        .stdout
        .contains("npm:        https://npm.prego.k8skill.com/t/acme/rel/ (scoped packages)"));
    assert!(r
        .stdout
        .contains("token:      lifetime 15 min for all your grants (not shown"));
    assert!(!r.stdout.contains(REG_TOKEN));
    assert!(!r.stdout.contains(API_KEY));
    assert!(!server.requests()[0].form().contains_key("resource"));
}

#[test]
fn resource_sets_the_lifetime_scope() {
    let five = MockResponse::json(
        200,
        &json!({ "access_token": REG_TOKEN, "token_type": "Bearer", "expires_in": 300 })
            .to_string(),
    );
    let server = MockServer::start(vec![five, sts_ok()]);
    let sts = format!("{}/v1/sts/token/e/k7mq", server.base_url());
    let res = "https://cargo.prego.k8skill.com/t/acme/rel/";
    let env = [("PREGO_TENANT", "acme"), ("PREGO_API_KEY", API_KEY)];
    let r = run(&["whoami", "--sts-url", &sts, "--resource", res], &env);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stdout
            .contains(&format!("token:      lifetime 5 min for {res} (not shown")),
        "{}",
        r.stdout
    );
    let r = run(&["token", "--sts-url", &sts, "--resource", res], &env);
    assert_eq!(r.stdout, format!("{REG_TOKEN}\n"));
    let reqs = server.requests();
    assert_eq!(reqs[0].form()["resource"], res);
    assert_eq!(reqs[1].form()["resource"], res);

    // A value that is not a registry base URL: an error, and no request.
    let r = run(
        &["token", "--sts-url", &sts, "--resource", "https://x.test/"],
        &env,
    );
    assert_eq!(r.code, 1);
    assert!(r.stderr.contains("bad --resource"), "{}", r.stderr);
    assert_eq!(server.requests().len(), 2);
}

#[test]
fn setup_cargo_prints_the_snippet() {
    let r = run(
        &["setup", "cargo", "--namespace", "rel"],
        &[("PREGO_TENANT", "acme")],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stdout.contains("[registries.acme]\n"));
    assert!(r
        .stdout
        .contains("index = \"sparse+https://cargo.prego.k8skill.com/t/acme/rel/index/\"\n"));
    assert!(r
        .stdout
        .contains("credential-provider = [\"cargo-credential-prego\", \"--tenant\", \"acme\"]\n"));
}

#[test]
fn setup_cargo_tenant_from_settings_file() {
    let home = temp_dir("cargo");
    std::fs::create_dir_all(home.join(".config/prego")).unwrap();
    std::fs::write(
        home.join(".config/prego/config.toml"),
        "tenant = \"fileco\"\n",
    )
    .unwrap();
    let r = run(&["setup", "cargo"], &[("HOME", &home.to_string_lossy())]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stdout.contains("[registries.fileco]"));
    std::fs::remove_dir_all(&home).unwrap();
}

#[test]
fn setup_docker_prints_without_writing() {
    let home = temp_dir("print");
    let r = run(
        &["setup", "docker"],
        &[
            ("HOME", &home.to_string_lossy()),
            ("PREGO_OCI_HOSTS", "oci.example.test"),
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stdout.contains("\"oci.prego.k8skill.com\": \"prego\""));
    assert!(r.stdout.contains("\"oci.example.test\": \"prego\""));
    assert!(r.stdout.contains("set the tenant"));
    assert!(r.stdout.contains("not on PATH"));
    assert!(!home.join(".docker").exists());
    std::fs::remove_dir_all(&home).unwrap();
}

#[test]
fn setup_docker_write_keeps_other_keys() {
    let home = temp_dir("write");
    let docker = home.join(".docker");
    std::fs::create_dir_all(&docker).unwrap();
    let old = r#"{"auths":{"ghcr.io":{}},"credsStore":"desktop"}"#;
    std::fs::write(docker.join("config.json"), old).unwrap();

    let env = [
        ("HOME", home.to_string_lossy().into_owned()),
        ("PREGO_TENANT", "acme".into()),
    ];
    let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let r = run(&["setup", "docker", "--write"], &env);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stdout.contains("Backup:"), "{}", r.stdout);
    assert!(!r.stdout.contains("set the tenant"));

    let v: Value =
        serde_json::from_str(&std::fs::read_to_string(docker.join("config.json")).unwrap())
            .unwrap();
    assert_eq!(
        v,
        json!({
            "auths": { "ghcr.io": {} },
            "credsStore": "desktop",
            "credHelpers": { "oci.prego.k8skill.com": "prego" }
        })
    );

    let r = run(&["setup", "docker", "--write"], &env);
    assert_eq!(r.code, 0);
    assert!(r.stdout.contains("already uses prego"), "{}", r.stdout);
    std::fs::remove_dir_all(&home).unwrap();
}

#[test]
fn setup_docker_honors_docker_config() {
    let dir = temp_dir("dockerconfig");
    let r = run(
        &["setup", "docker", "--write"],
        &[("DOCKER_CONFIG", &dir.to_string_lossy())],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(dir.join("config.json").is_file());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn usage_errors() {
    let r = run(&["setup", "cargo", "--write"], &[]);
    assert_eq!(r.code, 1);
    assert!(r.stderr.contains("--write"));
    let r = run(&["bogus"], &[]);
    assert_eq!(r.code, 1);
    assert!(r.stderr.contains("unknown command"));
    let r = run(&["--version"], &[]);
    assert!(r
        .stdout
        .starts_with(concat!("prego ", env!("CARGO_PKG_VERSION"), " (")));
}
