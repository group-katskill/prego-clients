//! Tests for `prego setup npm`, `prego npm-env`, and `prego token` and `prego exec` with npm and pnpm.
//!
//! The live tests run the real `npm` and `pnpm` against the mock registry. They are skipped when a tool is
//! not on `PATH`, unless `PREGO_TEST_NPM` is set (CI sets it): then a missing tool is a failure.

mod support {
    pub mod mock_go;
}

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use support::mock_go::{add_npm, MockGo};

const BIN: &str = env!("CARGO_BIN_EXE_prego");
const API_KEY: &str = "prk_test_npm_secret";

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run_cmd(program: &str, dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Run {
    let mut cmd = Command::new(program);
    cmd.current_dir(dir).args(args).env_clear();
    cmd.env("PATH", std::env::var("PATH").unwrap_or_default());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("run {program}: {e}"));
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn prego(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Run {
    run_cmd(BIN, dir, args, env)
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("prego-npm-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The environment for the mock: tenant, STS, npm host, API key, and a private HOME.
fn npm_env(m: &MockGo, home: &Path) -> Vec<(&'static str, String)> {
    vec![
        ("PREGO_TENANT", "acme".into()),
        ("PREGO_STS_URL", m.sts_url()),
        ("PREGO_NPM_HOST", m.host()),
        ("PREGO_API_KEY", API_KEY.into()),
        ("HOME", home.to_str().unwrap().into()),
        ("XDG_RUNTIME_DIR", home.to_str().unwrap().into()),
    ]
}

fn refs<'a>(env: &'a [(&'static str, String)]) -> Vec<(&'static str, &'a str)> {
    env.iter().map(|(k, v)| (*k, v.as_str())).collect()
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap()
}

#[test]
fn setup_npm_writes_the_npmrc_with_a_variable_only() {
    let m = MockGo::start();
    let dir = temp_dir("setup");
    let env = npm_env(&m, &dir);
    let url = format!("http://{}/t/acme/default/", m.host());
    std::fs::write(
        dir.join(".npmrc"),
        format!(
            "save-exact=true\n//{}/t/acme/default/:_authToken=eyJ.pasted.token\n",
            m.host()
        ),
    )
    .unwrap();

    let r = prego(&dir, &["setup", "npm", "--scope", "@acme"], &refs(&env));
    assert_eq!(r.code, 0, "{}", r.stderr);
    let text = read(&dir.join(".npmrc"));
    assert_eq!(
        text,
        format!(
            "save-exact=true\n//{}/t/acme/default/:_authToken=${{PREGO_NPM_TOKEN}}\n@acme:registry={url}\n",
            m.host()
        )
    );
    assert!(r.stdout.contains("Replaced a token value"), "{}", r.stdout);
    assert!(
        r.stdout.contains("prego exec -- npm install"),
        "{}",
        r.stdout
    );
    assert!(
        r.stdout
            .contains(&format!("prego exec -- npm whoami --registry {url}")),
        "{}",
        r.stdout
    );
    assert!(r.stdout.contains("organization @acme on npmjs.com"));
    assert!(!r.stdout.contains("pasted"));
    assert_eq!(m.sts_count(), 0, "setup with --scope needs no token");

    // A second run changes nothing.
    let r = prego(&dir, &["setup", "npm", "--scope", "acme"], &refs(&env));
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stdout.contains("already sends @acme"), "{}", r.stdout);
    assert_eq!(read(&dir.join(".npmrc")), text);

    // --print writes nothing.
    let other = temp_dir("setup-print");
    let r = prego(
        &other,
        &[
            "setup",
            "npm",
            "--scope",
            "@acme",
            "--namespace",
            "rel",
            "--print",
        ],
        &refs(&env),
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r
        .stdout
        .contains(&format!("@acme:registry=http://{}/t/acme/rel/", m.host())));
    assert!(r.stdout.contains(&format!(
        "//{}/t/acme/rel/:_authToken=${{PREGO_NPM_TOKEN}}",
        m.host()
    )));
    assert!(!other.join(".npmrc").exists());

    // --user writes ~/.npmrc.
    let home = temp_dir("setup-home");
    let mut henv = npm_env(&m, &home);
    henv.retain(|(k, _)| *k != "PREGO_NPM_HOST");
    let r = prego(
        &other,
        &["setup", "npm", "--scope", "@acme", "--user"],
        &refs(&henv),
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(
        read(&home.join(".npmrc")),
        "@acme:registry=https://npm.prego.k8skill.com/t/acme/default/\n\
         //npm.prego.k8skill.com/t/acme/default/:_authToken=${PREGO_NPM_TOKEN}\n"
    );
    assert!(!other.join(".npmrc").exists());

    // Bad input.
    for bad in [
        &["setup", "npm", "--scope", "@Acme"][..],
        &["setup", "npm", "--scope", "@acme", "--namespace", "a/b"],
        &[
            "setup", "npm", "--scope", "@acme", "--client", "yarn", "--user",
        ],
    ] {
        let r = prego(&other, bad, &refs(&env));
        assert_eq!(r.code, 1, "{bad:?}: {}", r.stdout);
    }
    for d in [dir, other, home] {
        std::fs::remove_dir_all(d).unwrap();
    }
}

#[test]
fn setup_npm_takes_the_only_scope_from_the_admin_api() {
    let m = MockGo::start();
    let dir = temp_dir("scopes");
    let env = npm_env(&m, &dir);

    // The identity cannot read the admin API.
    let r = prego(&dir, &["setup", "npm"], &refs(&env));
    assert_eq!(r.code, 1);
    assert!(
        r.stderr.contains("give the npm scope with --scope"),
        "{}",
        r.stderr
    );

    m.with(|s| s.admin_ok = true);
    let r = prego(&dir, &["setup", "npm"], &refs(&env));
    assert_eq!(r.code, 1);
    assert!(r.stderr.contains("has no npm scope yet"), "{}", r.stderr);

    m.with(|s| s.npm_scopes = vec!["@acme".into(), "@acme-labs".into()]);
    let r = prego(&dir, &["setup", "npm"], &refs(&env));
    assert_eq!(r.code, 1);
    assert!(r.stderr.contains("more than one npm scope"), "{}", r.stderr);
    assert!(!dir.join(".npmrc").exists());

    // One scope, with or without the `@`.
    for scope in ["@acme", "acme"] {
        m.with(|s| s.npm_scopes = vec![scope.into()]);
        let r = prego(&dir, &["setup", "npm", "--client", "pnpm"], &refs(&env));
        assert_eq!(r.code, 0, "{}", r.stderr);
        assert!(read(&dir.join(".npmrc")).starts_with("@acme:registry="));
        assert!(
            r.stdout.contains("prego exec -- pnpm install"),
            "{}",
            r.stdout
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn setup_npm_for_yarn_and_bun_never_rewrites_their_files() {
    let m = MockGo::start();
    let dir = temp_dir("yarn-bun");
    let env = npm_env(&m, &dir);
    let url = format!("http://{}/t/acme/default/", m.host());

    std::fs::write(dir.join(".yarnrc.yml"), "nodeLinker: node-modules\n").unwrap();
    let r = prego(
        &dir,
        &["setup", "npm", "--scope", "@acme", "--client", "yarn"],
        &refs(&env),
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(
        read(&dir.join(".yarnrc.yml")),
        format!(
            "nodeLinker: node-modules\n\nnpmScopes:\n  acme:\n    npmRegistryServer: \"{url}\"\n    \
             npmAuthToken: \"${{PREGO_NPM_TOKEN}}\"\n"
        )
    );
    let r = prego(
        &dir,
        &["setup", "npm", "--scope", "@acme", "--client", "yarn"],
        &refs(&env),
    );
    assert!(r.stdout.contains("already sends @acme"), "{}", r.stdout);

    let r = prego(
        &dir,
        &["setup", "npm", "--scope", "@acme", "--client", "bun"],
        &refs(&env),
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(
        read(&dir.join("bunfig.toml")),
        format!(
            "[install.scopes]\n\"@acme\" = {{ url = \"{url}\", token = \"$PREGO_NPM_TOKEN\" }}\n"
        )
    );

    // A file with a scopes section stays as it is; the lines are printed.
    let old = "[install.scopes]\n\"@other\" = \"https://other.example.test/\"\n";
    std::fs::write(dir.join("bunfig.toml"), old).unwrap();
    let r = prego(
        &dir,
        &["setup", "npm", "--scope", "@acme", "--client", "bun"],
        &refs(&env),
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(read(&dir.join("bunfig.toml")), old);
    assert!(r.stdout.contains("by hand"), "{}", r.stdout);
    assert!(r.stdout.contains("\"@acme\" = {"), "{}", r.stdout);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn npm_env_and_exec_give_the_token_in_variables() {
    let m = MockGo::start();
    let dir = temp_dir("env");
    let env = npm_env(&m, &dir);

    let r = prego(&dir, &["npm-env"], &refs(&env));
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.stdout, "export PREGO_NPM_TOKEN='regtok-1'\n");
    assert!(r.stderr.contains("token valid for 15 min"), "{}", r.stderr);
    assert!(!m.with(|s| s.sts[0].contains_key("resource")));

    let r = prego(
        &dir,
        &[
            "exec",
            "--",
            "sh",
            "-c",
            "echo \"$PREGO_NPM_TOKEN $PREGO_TOKEN\"",
        ],
        &refs(&env),
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.stdout, "regtok-2 regtok-2\n");
    std::fs::remove_dir_all(dir).unwrap();
}

/// The path of a tool, or `None` (the live test is skipped). With `PREGO_TEST_NPM` set, a missing tool
/// fails the test.
fn tool(name: &str) -> Option<String> {
    let path = std::env::var("PATH").unwrap_or_default();
    let found = std::env::split_paths(&path)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
        .map(|p| p.to_string_lossy().into_owned());
    if found.is_none() {
        assert!(
            std::env::var_os("PREGO_TEST_NPM").is_none(),
            "PREGO_TEST_NPM is set, but {name} is not on PATH"
        );
        eprintln!("{name} is not on PATH: live check skipped");
    }
    found
}

/// A project that depends on `@acme/hello`, with the `.npmrc` from `prego setup npm`.
fn project(m: &MockGo, env: &[(&str, &str)], name: &str) -> PathBuf {
    let dir = temp_dir(name);
    std::fs::write(
        dir.join("package.json"),
        r#"{"name": "app", "version": "1.0.0", "private": true, "dependencies": {"@acme/hello": "1.0.0"}}"#,
    )
    .unwrap();
    let r = prego(&dir, &["setup", "npm", "--scope", "@acme"], env);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(read(&dir.join(".npmrc")).contains(&m.host()));
    dir
}

/// The npm settings that keep the live tests off the network and out of the real home directory.
/// A `pnpm` that is a corepack shim uses the corepack cache of the real home directory, and never
/// downloads.
fn npm_quiet(dir: &Path) -> Vec<(&'static str, String)> {
    let mut v = vec![
        (
            "npm_config_cache",
            dir.join(".cache").to_str().unwrap().into(),
        ),
        ("npm_config_update_notifier", "false".into()),
        ("npm_config_audit", "false".into()),
        ("npm_config_fund", "false".into()),
        ("npm_config_ignore_scripts", "true".into()),
        ("COREPACK_ENABLE_NETWORK", "0".into()),
    ];
    let corepack = std::env::var("COREPACK_HOME").ok().or_else(|| {
        std::env::var("HOME")
            .ok()
            .map(|h| format!("{h}/.cache/node/corepack"))
    });
    if let Some(c) = corepack {
        v.push(("COREPACK_HOME", c));
    }
    v
}

fn installed(dir: &Path) -> String {
    read(&dir.join("node_modules/@acme/hello/index.js"))
}

#[test]
fn live_npm_install_and_publish() {
    let Some(npm) = tool("npm") else { return };
    let m = MockGo::start();
    m.with(|s| add_npm(s, "@acme/hello", "1.0.0"));
    let home = temp_dir("npm-home");
    let mut env = npm_env(&m, &home);
    let dir = project(&m, &refs(&env), "npm-app");
    env.extend(npm_quiet(&dir));

    // prego exec.
    let r = prego(&dir, &["exec", "--", &npm, "install"], &refs(&env));
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    assert_eq!(installed(&dir), "module.exports = \"@acme/hello@1.0.0\";\n");
    let auth: Vec<String> = m
        .requests()
        .iter()
        .filter(|q| q.target.starts_with("/t/acme/default/@acme"))
        .map(|q| q.headers.get("authorization").cloned().unwrap_or_default())
        .collect();
    assert!(auth.len() >= 2, "packument and tarball: {auth:?}");
    assert!(auth.iter().all(|a| a == "Bearer regtok-1"), "{auth:?}");

    // prego token, as in CI: PREGO_NPM_TOKEN=$(prego token).
    std::fs::remove_dir_all(dir.join("node_modules")).unwrap();
    std::fs::remove_file(dir.join("package-lock.json")).unwrap();
    let t = prego(&dir, &["token"], &refs(&env));
    assert_eq!(t.code, 0, "{}", t.stderr);
    let mut with_token = env.clone();
    with_token.push(("PREGO_NPM_TOKEN", t.stdout.trim().into()));
    let r = run_cmd(&npm, &dir, &["install"], &refs(&with_token));
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    assert_eq!(installed(&dir), "module.exports = \"@acme/hello@1.0.0\";\n");

    // npm publish through prego exec; the package can then be installed.
    let lib = temp_dir("npm-lib");
    std::fs::write(
        lib.join("package.json"),
        r#"{"name": "@acme/lib", "version": "2.0.0", "main": "index.js"}"#,
    )
    .unwrap();
    std::fs::write(lib.join("index.js"), "module.exports = 2;\n").unwrap();
    let r = prego(&lib, &["setup", "npm", "--scope", "@acme"], &refs(&env));
    assert_eq!(r.code, 0, "{}", r.stderr);
    let r = prego(&lib, &["exec", "--", &npm, "publish"], &refs(&env));
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    assert!(m.with(|s| s
        .npm
        .get("@acme/lib")
        .is_some_and(|p| p.contains_key("2.0.0"))));
    let r = prego(
        &dir,
        &["exec", "--", &npm, "install", "@acme/lib@2.0.0"],
        &refs(&env),
    );
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    assert_eq!(
        read(&dir.join("node_modules/@acme/lib/index.js")),
        "module.exports = 2;\n"
    );
    // A second publish of the same version is refused (npm checks the package document first, or the
    // registry answers 403).
    let r = prego(&lib, &["exec", "--", &npm, "publish"], &refs(&env));
    assert_ne!(r.code, 0);
    assert!(
        r.stderr.contains("publish over") && r.stderr.contains("2.0.0"),
        "{}",
        r.stderr
    );

    // Without a token, npm cannot read the package.
    let mut bad = env.clone();
    bad.push(("PREGO_NPM_TOKEN", "not-a-prego-token".into()));
    std::fs::remove_dir_all(dir.join("node_modules")).unwrap();
    std::fs::remove_file(dir.join("package-lock.json")).unwrap();
    std::fs::remove_dir_all(dir.join(".cache")).unwrap();
    let r = run_cmd(&npm, &dir, &["install"], &refs(&bad));
    assert_ne!(r.code, 0);
    assert!(r.stderr.contains("401"), "{}", r.stderr);
    for d in [dir, lib, home] {
        std::fs::remove_dir_all(d).unwrap();
    }
}

#[test]
fn live_pnpm_install() {
    let Some(pnpm) = tool("pnpm") else { return };
    let m = MockGo::start();
    m.with(|s| add_npm(s, "@acme/hello", "1.0.0"));
    let home = temp_dir("pnpm-home");
    let mut env = npm_env(&m, &home);
    let dir = project(&m, &refs(&env), "pnpm-app");
    env.extend(npm_quiet(&dir));
    let store = dir.join(".store");
    let store = store.to_str().unwrap();

    let r = prego(
        &dir,
        &["exec", "--", &pnpm, "install", "--store-dir", store],
        &refs(&env),
    );
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    assert_eq!(installed(&dir), "module.exports = \"@acme/hello@1.0.0\";\n");

    // prego token.
    std::fs::remove_dir_all(dir.join("node_modules")).unwrap();
    std::fs::remove_dir_all(dir.join(".store")).unwrap();
    std::fs::remove_file(dir.join("pnpm-lock.yaml")).unwrap();
    let t = prego(&dir, &["token"], &refs(&env));
    assert_eq!(t.code, 0, "{}", t.stderr);
    let mut with_token = env.clone();
    with_token.push(("PREGO_NPM_TOKEN", t.stdout.trim().into()));
    let r = run_cmd(
        &pnpm,
        &dir,
        &["install", "--store-dir", store],
        &refs(&with_token),
    );
    assert_eq!(r.code, 0, "{}\n{}", r.stdout, r.stderr);
    assert_eq!(installed(&dir), "module.exports = \"@acme/hello@1.0.0\";\n");
    let regs: Vec<String> = m
        .requests()
        .iter()
        .filter(|q| q.target.starts_with("/t/acme/default/@acme"))
        .map(|q| q.headers.get("authorization").cloned().unwrap_or_default())
        .collect();
    assert!(
        regs.iter().all(|a| a.starts_with("Bearer regtok-")),
        "{regs:?}"
    );
    for d in [dir, home] {
        std::fs::remove_dir_all(d).unwrap();
    }
}
