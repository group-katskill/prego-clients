//! Go modules: `prego go publish`, `prego go-auth`, `prego setup go` and `prego exec`.

pub mod auth;
pub mod git;
pub mod module;
pub mod publish;
pub mod zip;

use std::io::Write;
use std::process::Command;

use prego_auth::http::Http;
use prego_auth::sources::find_subject_token;
use prego_auth::{go, sts, Config, Env, FileConfig};

/// The public proxy and `direct` after the Prego entry.
const PUBLIC_TAIL: &str = "https://proxy.golang.org,direct";
/// The GOAUTH entry of the helper. Go runs an entry that is not `off`, `netrc` or `git <dir>` as a command
/// line, so the entry is the command itself (the word "command" in `go help goauth` is only the name of
/// the method).
pub const GOAUTH_COMMAND: &str = "prego go-auth";
/// A wrong entry from early drafts; Go would try to run a program named `command`.
const WRONG_GOAUTH: &str = "command prego go-auth";

/// Runs `go env <name>` and returns the value. `None` if `go` cannot run.
pub fn go_env(env: &dyn Env, name: &str) -> Option<String> {
    let mut cmd = Command::new("go");
    cmd.args(["env", name]);
    if let Some(p) = env.var("PATH") {
        cmd.env("PATH", p);
    }
    let out = cmd.output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// The value of `GOAUTH` if the user set it (environment or `go env -w`), else `None` (Go's default).
fn changed_goauth(env: &dyn Env) -> Option<String> {
    if let Some(v) = env.var("GOAUTH").filter(|v| !v.is_empty()) {
        return Some(v);
    }
    let mut cmd = Command::new("go");
    cmd.args(["env", "-changed", "-json", "GOAUTH"]);
    if let Some(p) = env.var("PATH") {
        cmd.env("PATH", p);
    }
    let out = cmd.output().ok()?;
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    v["GOAUTH"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// The new `GOAUTH`: the helper alone, or the old value with the helper added at the end.
pub fn goauth_value(old: Option<&str>) -> String {
    let mut entries: Vec<&str> = old
        .unwrap_or("")
        .split(';')
        .map(str::trim)
        .filter(|e| !e.is_empty() && *e != WRONG_GOAUTH)
        .collect();
    if !entries.contains(&GOAUTH_COMMAND) {
        entries.push(GOAUTH_COMMAND);
    }
    entries.join(";")
}

/// Checks a module path prefix for `GONOSUMDB`: a module path, without glob characters or commas.
fn check_prefix(p: &str) -> Result<(), String> {
    if p.contains([',', '*', '?', '[', ' ']) {
        return Err(format!("prego: bad module path prefix `{p}`"));
    }
    module::check_path(p).map_err(|e| format!("prego: bad module path prefix: {e}"))
}

/// The tenant's prefixes from the admin API, if the identity may read them (`admin:read`). Any refusal
/// gives `None`, with no error.
fn admin_prefixes(config: &Config, env: &dyn Env) -> Option<Vec<String>> {
    let http = Http::with_ca_file(crate::USER_AGENT, config.ca_file.as_deref()).ok()?;
    let subject = find_subject_token(config, env, &http).ok()?;
    let fields = [
        ("grant_type", sts::GRANT_TYPE),
        ("subject_token", subject.value.expose()),
        ("subject_token_type", subject.token_type.urn()),
        ("tenant", config.tenant.as_str()),
        ("audience", "prego-admin"),
        ("scope", "admin:read"),
    ];
    let res = http.post_form(&config.sts_url, &fields).ok()?;
    if res.status != 200 {
        return None;
    }
    let token: serde_json::Value = serde_json::from_str(&res.body).ok()?;
    let token = token["access_token"].as_str()?.to_string();
    let base = config.sts_url.strip_suffix("/v1/sts/token")?;
    let url = format!("{base}/v1/admin/tenants/{}/go/prefixes", config.tenant);
    let auth = format!("Bearer {token}");
    let res = http
        .send(
            "GET",
            &url,
            &[("Authorization", &auth), ("Accept", "application/json")],
            prego_auth::http::Body::Empty,
        )
        .ok()?;
    if res.status != 200 {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(&res.body).ok()?;
    let list: Vec<String> = v["items"]
        .as_array()?
        .iter()
        .filter_map(|i| i["prefix"].as_str().map(str::to_string))
        .filter(|p| check_prefix(p).is_ok())
        .collect();
    Some(list)
}

/// `prego setup go`: prints the three `go env -w` lines, or runs them with `write`.
pub fn setup(
    globals: &[&str],
    namespace: &str,
    prefixes: &[String],
    write: bool,
    env: &dyn Env,
) -> Result<(), String> {
    crate::setup::check_slug("namespace", namespace)?;
    let file = FileConfig::load(env).map_err(|e| e.to_string())?;
    let config = Config::from_parts(globals, env, &file).map_err(|e| e.to_string())?;
    let host = go::go_hosts(&file, env)
        .into_iter()
        .next()
        .unwrap_or_else(|| go::DEFAULT_GO_HOST.into());
    let proxy = format!(
        "{}://{host}/t/{}/{namespace},{PUBLIC_TAIL}",
        go::scheme(&host),
        config.tenant
    );

    let mut list: Vec<String> = if !prefixes.is_empty() {
        prefixes.to_vec()
    } else if !file.go_prefixes.is_empty() {
        file.go_prefixes.clone()
    } else {
        admin_prefixes(&config, env).unwrap_or_default()
    };
    for p in &list {
        check_prefix(p)?;
    }
    list.dedup();
    let nosumdb = (!list.is_empty()).then(|| list.join(","));
    let goauth = goauth_value(changed_goauth(env).as_deref());

    if write {
        let mut args = vec![
            "env".to_string(),
            "-w".into(),
            format!("GOPROXY={proxy}"),
            format!("GOAUTH={goauth}"),
        ];
        if let Some(n) = &nosumdb {
            args.push(format!("GONOSUMDB={n}"));
        }
        let mut cmd = Command::new("go");
        cmd.args(&args);
        let status = cmd
            .status()
            .map_err(|e| format!("prego: cannot run go: {e}. Install Go 1.24 or later."))?;
        if !status.success() {
            return Err("prego: `go env -w` failed".into());
        }
        println!("Set GOPROXY={proxy}");
        println!("Set GOAUTH={goauth}");
        match &nosumdb {
            Some(n) => println!("Set GONOSUMDB={n}"),
            None => println!("{}", no_prefix_note()),
        }
        return Ok(());
    }

    println!("go env -w GOPROXY='{proxy}'");
    match &nosumdb {
        Some(n) => println!("go env -w GONOSUMDB='{n}'"),
        None => {
            println!("go env -w GONOSUMDB='<your module path prefixes, for example go.acme.com,github.com/acme>'");
            println!("{}", no_prefix_note());
        }
    }
    println!("go env -w GOAUTH='{goauth}'");
    Ok(())
}

fn no_prefix_note() -> &'static str {
    "# GONOSUMDB: give your tenant's module path prefixes with --prefix, or go_prefixes in \
     ~/.config/prego/config.toml. The console Settings page shows them. Do not use GOPRIVATE: it also \
     turns off the checksum database for nothing more."
}

/// `prego exec -- <command>`: runs the command with `NETRC` set to a temporary file that holds a registry
/// token for the Prego Go host. The file has mode 0600 and is deleted when the command ends.
pub fn exec(globals: &[&str], command: &[String], env: &dyn Env) -> Result<i32, String> {
    let (program, rest) = command
        .split_first()
        .ok_or("prego: usage: prego exec -- <command> [args]")?;
    let file = FileConfig::load(env).map_err(|e| e.to_string())?;
    let config = Config::from_parts(globals, env, &file).map_err(|e| e.to_string())?;
    let host = go::go_hosts(&file, env)
        .into_iter()
        .next()
        .unwrap_or_else(|| go::DEFAULT_GO_HOST.into());
    // A netrc machine name has no port.
    let machine = host.split(':').next().unwrap_or(&host).to_string();
    let hosts = go::go_hosts(&file, env);
    let resource = auth::prego_resource(&auth::goproxy(env), &hosts);
    let token = auth::exchange(&config, env, resource.as_deref())?;
    eprintln!("{}", lifetime_note(token.lifetime));

    let dir = private_tmp(env).unwrap_or_else(std::env::temp_dir);
    let mut netrc = publish::TempFile::create(&dir, ".prego-netrc")?;
    netrc
        .file
        .write_all(
            format!(
                "machine {machine} login {} password {}\n",
                config.tenant,
                token.token.expose()
            )
            .as_bytes(),
        )
        .and_then(|()| netrc.file.sync_all())
        .map_err(|e| format!("prego: cannot write the netrc file: {e}"))?;
    let status = Command::new(program)
        .args(rest)
        .env("NETRC", &netrc.path)
        .status()
        .map_err(|e| format!("prego: cannot run `{program}`: {e}"))?;
    drop(netrc);
    Ok(status.code().unwrap_or(1))
}

/// Below this lifetime, `prego exec` warns.
const SHORT_LIFETIME_SECONDS: i64 = 10 * 60;

/// The line that `prego exec` prints on stderr: the token lifetime, with a warning when it is short. The
/// netrc file cannot get a new token, because Go reads it once.
fn lifetime_note(lifetime: i64) -> String {
    let min = lifetime / 60;
    let secs = lifetime % 60;
    let len = if secs == 0 {
        format!("{min} min")
    } else {
        format!("{min} min {secs} s")
    };
    if lifetime < SHORT_LIFETIME_SECONDS {
        format!(
            "prego exec: warning: token valid for {len}; long builds need GOAUTH, see prego setup go. \
             The netrc file cannot get a new token."
        )
    } else {
        format!("prego exec: token valid for {len}")
    }
}

/// The private cache directory, for the netrc file of `prego exec`.
fn private_tmp(env: &dyn Env) -> Option<std::path::PathBuf> {
    auth::Cache::open(env, "netrc").map(|c| c.dir().to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn goauth_values() {
        assert_eq!(goauth_value(None), "prego go-auth");
        assert_eq!(goauth_value(Some("netrc")), "netrc;prego go-auth");
        assert_eq!(
            goauth_value(Some("netrc;prego go-auth")),
            "netrc;prego go-auth"
        );
        assert_eq!(goauth_value(Some("git /src;")), "git /src;prego go-auth");
        // The wrong draft value is replaced.
        assert_eq!(goauth_value(Some("command prego go-auth")), "prego go-auth");
        assert_eq!(
            goauth_value(Some("netrc;command prego go-auth")),
            "netrc;prego go-auth"
        );
    }

    #[test]
    fn lifetime_notes() {
        assert_eq!(lifetime_note(900), "prego exec: token valid for 15 min");
        assert_eq!(lifetime_note(600), "prego exec: token valid for 10 min");
        let w = lifetime_note(300);
        assert!(
            w.starts_with("prego exec: warning: token valid for 5 min; long builds need GOAUTH, see prego setup go."),
            "{w}"
        );
        assert!(lifetime_note(60).contains("token valid for 1 min;"));
        assert!(lifetime_note(90).contains("token valid for 1 min 30 s;"));
    }

    #[test]
    fn prefixes() {
        check_prefix("go.acme.com").unwrap();
        check_prefix("github.com/acme").unwrap();
        assert!(check_prefix("go.acme.com,evil.test").is_err());
        assert!(check_prefix("*.acme.com").is_err());
        assert!(check_prefix("acme").is_err());
    }
}
