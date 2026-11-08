//! Runs the Python commands of `prego` against a mock server that is the STS and the Python host.

use std::path::{Path, PathBuf};
use std::process::Command;

use prego_auth::testing::{MockResponse, MockServer};
use serde_json::json;

const BIN: &str = env!("CARGO_BIN_EXE_prego");
const API_KEY: &str = "prk_test_python_secret";
// Payload {"sub":"prn_1","tid":"ten_1","exp":4102444800} (2100-01-01).
const REG_TOKEN: &str =
    "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJwcm5fMSIsInRpZCI6InRlbl8xIiwiZXhwIjo0MTAyNDQ0ODAwfQ.c2ln";

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("prego-py-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    dir
}

/// Runs prego with the mock server as the STS and the Python host, and `dir` as the working directory and
/// the runtime directory (token cache).
fn run(server: &MockServer, dir: &Path, args: &[&str]) -> Run {
    let sts = format!("{}/v1/sts/token/e/k7mq", server.base_url());
    let host = server.base_url().trim_start_matches("http://").to_string();
    let out = Command::new(BIN)
        .args(args)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("PREGO_API_KEY", API_KEY)
        .env("PREGO_STS_URL", sts)
        .env("PREGO_PYPI_HOST", host)
        .env("HOME", "/nonexistent")
        .env("XDG_RUNTIME_DIR", dir)
        .current_dir(dir)
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
        &json!({ "access_token": REG_TOKEN, "token_type": "Bearer", "expires_in": 1800 })
            .to_string(),
    )
}

fn host_of(server: &MockServer) -> String {
    server.base_url().trim_start_matches("http://").to_string()
}

#[test]
fn token_uses_the_python_resource_and_the_cache() {
    let server = MockServer::start(vec![sts_ok()]);
    let dir = temp_dir("token");
    let r = run(&server, &dir, &["--tenant", "acme", "token", "--python"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.stdout, format!("{REG_TOKEN}\n"));
    // The second call reads the cache: no new request (the mock has no more answers).
    let r = run(&server, &dir, &["--tenant", "acme", "token", "--python"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.stdout, format!("{REG_TOKEN}\n"));
    let reqs = server.requests();
    assert_eq!(reqs.len(), 1);
    let form = reqs[0].form();
    assert_eq!(form["tenant"], "acme");
    assert_eq!(
        form["resource"],
        format!("{}/t/acme/default/", server.base_url())
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let files: Vec<_> = std::fs::read_dir(dir.join("prego"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(files.len(), 1, "{files:?}");
        let mode = std::fs::metadata(&files[0]).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(files[0]
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("python-"));
    }
}

#[test]
fn token_url_names_the_tenant_and_namespace() {
    let server = MockServer::start(vec![sts_ok()]);
    let dir = temp_dir("url");
    let url = format!("{}/t/beta/rel/simple/beta-core/", server.base_url());
    // No tenant is set: the tenant of the URL is used.
    let r = run(&server, &dir, &["token", "--python", "--url", &url]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let form = server.requests()[0].form();
    assert_eq!(form["tenant"], "beta");
    assert_eq!(
        form["resource"],
        format!("{}/t/beta/rel/", server.base_url())
    );

    // A URL on another host gets no token, and no request is sent.
    let other = MockServer::start(vec![]);
    let r = run(
        &other,
        &dir,
        &[
            "--tenant",
            "acme",
            "token",
            "--python",
            "--url",
            "https://pypi.org/simple/",
        ],
    );
    assert_eq!(r.code, 1);
    assert!(
        r.stderr.contains("is not a Prego Python URL"),
        "{}",
        r.stderr
    );
    assert!(r.stdout.is_empty());
    assert!(other.requests().is_empty());
}

#[test]
fn exec_python_mode_sets_the_variables_and_prints_nothing() {
    let server = MockServer::start(vec![sts_ok()]);
    let dir = temp_dir("exec");
    let script = "printf '%s\\n' \"$UV_INDEX_PREGO_USERNAME\" \"$UV_INDEX_PREGO_PASSWORD\" \
                  \"$TWINE_REPOSITORY_URL\" \"$UV_PUBLISH_URL\" \"$POETRY_HTTP_BASIC_PREGO_PASSWORD\" \
                  \"$PIP_EXTRA_INDEX_URL\" \"${PREGO_NPM_TOKEN:-none}\"";
    let r = run(
        &server,
        &dir,
        &[
            "--tenant",
            "acme",
            "exec",
            "--pip",
            "--namespace",
            "rel",
            "--",
            "sh",
            "-c",
            script,
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.stderr, "");
    let base = server.base_url();
    let host = host_of(&server);
    assert_eq!(
        r.stdout,
        format!(
            "__token__\n{REG_TOKEN}\n{base}/t/acme/rel/legacy/\n{base}/t/acme/rel/legacy/\n{REG_TOKEN}\n\
             http://__token__:{REG_TOKEN}@{host}/t/acme/rel/simple/\nnone\n"
        )
    );
    assert_eq!(
        server.requests()[0].form()["resource"],
        format!("{base}/t/acme/rel/")
    );
}

fn write(dir: &Path, name: &str, body: &[u8]) -> String {
    let p = dir.join(name);
    std::fs::write(&p, body).unwrap();
    p.to_string_lossy().into_owned()
}

#[test]
fn publish_streams_each_file_with_the_upload_fields() {
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(200, "OK"),
        MockResponse::json(200, "OK"),
    ]);
    let dir = temp_dir("publish");
    let wheel = write(&dir, "acme_core-1.2.0-py3-none-any.whl", b"wheel bytes");
    let sdist = write(&dir, "acme_core-1.2.0.tar.gz", b"sdist bytes");
    let r = run(
        &server,
        &dir,
        &["--tenant", "acme", "python", "publish", &wheel, &sdist],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r
        .stdout
        .contains("Published acme_core-1.2.0-py3-none-any.whl (sha256 "));
    assert!(r.stdout.contains("Published acme_core-1.2.0.tar.gz"));
    assert!(
        r.stdout.contains("acme-core = { index = \"prego\" }"),
        "{}",
        r.stdout
    );
    assert!(!r.stdout.contains(REG_TOKEN) && !r.stderr.contains(REG_TOKEN));

    let reqs = server.requests();
    assert_eq!(reqs.len(), 3);
    let up = &reqs[1];
    assert_eq!(up.method, "POST");
    assert_eq!(up.target, "/t/acme/default/legacy/");
    use base64::Engine;
    let basic = base64::engine::general_purpose::STANDARD.encode(format!("__token__:{REG_TOKEN}"));
    assert_eq!(
        up.header("authorization").unwrap(),
        format!("Basic {basic}")
    );
    assert!(up
        .header("content-type")
        .unwrap()
        .starts_with("multipart/form-data; boundary="));
    for field in [
        "name=\":action\"\r\n\r\nfile_upload\r\n",
        "name=\"protocol_version\"\r\n\r\n1\r\n",
        "name=\"name\"\r\n\r\nacme_core\r\n",
        "name=\"version\"\r\n\r\n1.2.0\r\n",
        "name=\"filetype\"\r\n\r\nbdist_wheel\r\n",
        "name=\"pyversion\"\r\n\r\npy3\r\n",
        "filename=\"acme_core-1.2.0-py3-none-any.whl\"",
        "\r\n\r\nwheel bytes\r\n",
    ] {
        assert!(up.body.contains(field), "{field:?} in {:?}", up.body);
    }
    assert!(reqs[2].body.contains("name=\"filetype\"\r\n\r\nsdist\r\n"));
    assert!(reqs[2]
        .body
        .contains("name=\"pyversion\"\r\n\r\nsource\r\n"));
}

#[test]
fn publish_refuses_before_any_request() {
    let server = MockServer::start(vec![]);
    let dir = temp_dir("refuse");
    let big = dir.join("acme_core-9.9.9-py3-none-any.whl");
    std::fs::File::create(&big)
        .unwrap()
        .set_len(90 * 1024 * 1024 + 1)
        .unwrap();
    let small = write(&dir, "acme_core-1.0-py3-none-any.whl", b"x");
    let r = run(
        &server,
        &dir,
        &[
            "--tenant",
            "acme",
            "python",
            "publish",
            &small,
            big.to_str().unwrap(),
        ],
    );
    assert_eq!(r.code, 1);
    assert!(r.stderr.contains("is larger than 90 MiB"), "{}", r.stderr);
    let egg = write(&dir, "acme-1.0.zip", b"x");
    let r = run(
        &server,
        &dir,
        &["--tenant", "acme", "python", "publish", &egg],
    );
    assert_eq!(r.code, 1);
    assert!(
        r.stderr.contains("only wheels (.whl) and sdists (.tar.gz)"),
        "{}",
        r.stderr
    );
    assert!(server.requests().is_empty());
}

#[test]
fn publish_shows_the_registry_line_and_stops() {
    let server = MockServer::start(vec![
        sts_ok(),
        MockResponse::json(400, "File already exists.\n"),
    ]);
    let dir = temp_dir("dup");
    let a = write(&dir, "acme_core-1.0-py3-none-any.whl", b"a");
    let b = write(&dir, "acme_core-1.0.tar.gz", b"b");
    let r = run(
        &server,
        &dir,
        &["--tenant", "acme", "python", "publish", &a, &b],
    );
    assert_eq!(r.code, 1);
    assert!(
        r.stderr
            .contains("upload of acme_core-1.0-py3-none-any.whl refused: 400 File already exists."),
        "{}",
        r.stderr
    );
    assert_eq!(server.requests().len(), 2);
}

#[test]
fn setup_python_writes_the_projects_from_the_index() {
    let index = json!({
        "meta": { "api-version": "1.1" },
        "projects": [ { "name": "acme-core" }, { "name": "acme-db" }, { "name": "bad name" } ]
    });
    let server = MockServer::start(vec![sts_ok(), MockResponse::json(200, &index.to_string())]);
    let dir = temp_dir("setup");
    std::fs::write(dir.join("pyproject.toml"), "[project]\nname = \"app\"\n").unwrap();
    let r = run(&server, &dir, &["--tenant", "acme", "setup", "python"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let text = std::fs::read_to_string(dir.join("pyproject.toml")).unwrap();
    let base = server.base_url();
    assert_eq!(
        text,
        format!(
            "[project]\nname = \"app\"\n\n[[tool.uv.index]]\nname = \"prego\"\n\
             url = \"{base}/t/acme/default/simple/\"\nexplicit = true\nauthenticate = \"always\"\n\n\
             [tool.uv.sources]\nacme-core = {{ index = \"prego\" }}\nacme-db = {{ index = \"prego\" }}\n"
        )
    );
    assert!(!text.contains(REG_TOKEN));
    let reqs = server.requests();
    assert_eq!(reqs[1].target, "/t/acme/default/simple/");
    assert_eq!(
        reqs[1].header("accept").unwrap(),
        "application/vnd.pypi.simple.v1+json"
    );
}

#[test]
fn setup_python_with_projects_poetry_and_pip() {
    let server = MockServer::start(vec![]);
    let dir = temp_dir("setup2");
    // --project: no index request, no token.
    let r = run(
        &server,
        &dir,
        &[
            "--tenant",
            "acme",
            "setup",
            "python",
            "--project",
            "acme-core",
            "--print",
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stdout.contains("acme-core = { index = \"prego\" }"),
        "{}",
        r.stdout
    );
    assert!(!dir.join("pyproject.toml").exists());

    let r = run(&server, &dir, &["--tenant", "acme", "setup", "python"]);
    assert_eq!(r.code, 1);
    assert!(r.stderr.contains("no pyproject.toml"), "{}", r.stderr);

    std::fs::write(dir.join("pyproject.toml"), "[project]\nname = \"app\"\n").unwrap();
    let r = run(
        &server,
        &dir,
        &["--tenant", "acme", "setup", "python", "--tool", "poetry"],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    let text = std::fs::read_to_string(dir.join("pyproject.toml")).unwrap();
    assert!(
        text.contains("[[tool.poetry.source]]\nname = \"prego\""),
        "{text}"
    );
    assert!(text.contains("priority = \"explicit\""));

    let r = run(
        &server,
        &dir,
        &["--tenant", "acme", "setup", "python", "--tool", "pip"],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stdout.contains("dependency confusion"));
    assert!(r.stdout.contains("prego exec --pip -- pip install"));
    assert!(server.requests().is_empty());
}
