//! `prego login`, `prego logout` and `prego status`: the device session for people on a laptop.

use prego_auth::http::Http;
use prego_auth::session::{self, Access, DeviceHandle, Logout, SessionInfo};
use prego_auth::sources::env_source;
use prego_auth::{Config, Env, FileConfig};

fn config(globals: &[&str], env: &dyn Env) -> Result<Config, String> {
    let file = FileConfig::load(env).map_err(|e| e.to_string())?;
    Config::from_parts(globals, env, &file).map_err(|e| e.to_string())
}

fn http(config: &Config) -> Result<Http, String> {
    Http::with_ca_file(crate::USER_AGENT, config.ca_file.as_deref())
        .map_err(|e| format!("prego: PREGO_CA_FILE: {e}"))
}

/// The note when another identity source is set: the tools use it before the session.
fn other_source_note(config: &Config, env: &dyn Env) -> Option<String> {
    env_source(config, env).map(|k| {
        format!(
            "Note: {} is set. The Prego tools use it before the login session.",
            k.trigger()
        )
    })
}

/// `prego login`.
pub fn login(
    globals: &[&str],
    publish: bool,
    no_browser: bool,
    env: &dyn Env,
) -> Result<(), String> {
    let config = config(globals, env)?;
    // Stop before the request if there is no secure storage.
    let device = DeviceHandle::open(env).map_err(|e| e.to_string())?;
    let http = http(&config)?;
    let sleep = std::thread::sleep;
    let code = session::start(
        &http,
        &config,
        crate::USER_AGENT.replace("prego/", "prego-cli/").as_str(),
        &Access::request(publish),
        &sleep,
    )
    .map_err(|e| e.to_string())?;

    eprintln!("To log in to tenant {}, open this page:", config.tenant);
    eprintln!();
    eprintln!("  {}", code.verification_uri);
    eprintln!();
    eprintln!("and confirm this code: {}", code.user_code);
    eprintln!();
    eprintln!("Approve only if you ran prego login yourself just now.");
    let page = code
        .verification_uri_complete
        .as_deref()
        .unwrap_or(&code.verification_uri);
    if !no_browser && open_browser(page, env) {
        eprintln!("The page is open in your browser.");
    }
    eprintln!("Waiting for the approval...");

    let info = session::wait_for_approval(
        &http,
        &config,
        device.store.as_ref(),
        &code,
        &prego_auth::now_unix,
        &sleep,
    )
    .map_err(|e| e.to_string())?;
    eprintln!();
    eprintln!("Logged in to tenant {}.", config.tenant);
    print_session(&info, device.store.name());
    if let Some(n) = other_source_note(&config, env) {
        eprintln!("{n}");
    }
    Ok(())
}

/// `prego logout`.
pub fn logout(globals: &[&str], env: &dyn Env) -> Result<(), String> {
    let config = config(globals, env)?;
    let device = DeviceHandle::open(env).map_err(|e| e.to_string())?;
    let http = http(&config)?;
    let out = session::logout(&http, &config, device.store.as_ref(), &std::thread::sleep)
        .map_err(|e| e.to_string())?;
    match out {
        Logout::NoSession => eprintln!("You are not logged in to tenant {}.", config.tenant),
        Logout::Revoked => eprintln!(
            "Logged out of tenant {}. The session is ended, and it is deleted from this computer.",
            config.tenant
        ),
        Logout::LocalOnly(e) => eprintln!(
            "The session is deleted from this computer, but Prego did not confirm that it is ended ({e}). \
             Revoke it in the console: Settings, Your sessions."
        ),
    }
    Ok(())
}

/// `prego status`. It never shows a token.
pub fn status(globals: &[&str], env: &dyn Env) -> Result<(), String> {
    let config = config(globals, env)?;
    let device = DeviceHandle::open(env).map_err(|e| e.to_string())?;
    match session::status(&config, device.store.as_ref()).map_err(|e| e.to_string())? {
        Some(info) => {
            println!("Tenant:    {}", config.tenant);
            print_session_to(&info, device.store.name(), &mut |l| println!("{l}"));
            if let Some(n) = other_source_note(&config, env) {
                println!("{n}");
            }
            Ok(())
        }
        None => Err(format!(
            "prego: you are not logged in to tenant {}. Run prego login.",
            config.tenant
        )),
    }
}

fn print_session(info: &SessionInfo, storage: &str) {
    print_session_to(info, storage, &mut |l| eprintln!("{l}"));
}

fn print_session_to(info: &SessionInfo, storage: &str, out: &mut dyn FnMut(String)) {
    let name = info.name.as_deref().unwrap_or("(no name)");
    out(format!("Session:   {name} ({})", info.id));
    out(format!("Access:    {}", access_text(&info.access)));
    out(format!(
        "Ends:      {} if not used, at the latest {}",
        utc(info.idle_expires_at),
        utc(info.expires_at)
    ));
    out(format!("Stored in: {storage}"));
}

/// `read, publish (any, default)`.
pub fn access_text(access: &[Access]) -> String {
    if access.is_empty() {
        return "(not known)".into();
    }
    access
        .iter()
        .map(|a| {
            format!(
                "{} ({}, {})",
                a.actions.join(", "),
                a.ecosystem,
                a.namespace.as_deref().unwrap_or("default")
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// A Unix time as `2026-11-06 14:05 UTC`.
pub fn utc(t: i64) -> String {
    let days = t.div_euclid(86_400);
    let secs = t.rem_euclid(86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02} UTC",
        secs / 3600,
        secs % 3600 / 60
    )
}

/// Opens `url` in a browser if this looks like a desktop session. Returns true if a browser was started.
/// Only `https://` URLs are opened.
fn open_browser(url: &str, env: &dyn Env) -> bool {
    if !url.starts_with("https://") || url.chars().any(|c| c.is_whitespace() || c == '"') {
        return false;
    }
    if env.var("SSH_CONNECTION").is_some() || env.var("SSH_TTY").is_some() {
        return false;
    }
    let mut cmd = if cfg!(target_os = "macos") {
        let mut c = std::process::Command::new("open");
        c.arg(url);
        c
    } else if cfg!(windows) {
        let mut c = std::process::Command::new("rundll32");
        c.arg("url.dll,FileProtocolHandler").arg(url);
        c
    } else {
        if env.var("DISPLAY").is_none() && env.var("WAYLAND_DISPLAY").is_none() {
            return false;
        }
        let mut c = std::process::Command::new("xdg-open");
        c.arg(url);
        c
    };
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_dates() {
        assert_eq!(utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(utc(1_793_973_900), "2026-11-06 14:05 UTC");
        assert_eq!(utc(951_782_400), "2000-02-29 00:00 UTC");
    }

    #[test]
    fn access_lines() {
        let a = vec![Access {
            ecosystem: "any".into(),
            namespace: None,
            actions: vec!["read".into(), "publish".into()],
        }];
        assert_eq!(access_text(&a), "read, publish (any, default)");
        assert_eq!(access_text(&[]), "(not known)");
    }

    #[test]
    fn browser_is_not_opened_over_ssh_or_for_other_urls() {
        let env = prego_auth::MapEnv::new().with("SSH_CONNECTION", "1 2 3 4");
        assert!(!open_browser("https://console.example.test/device", &env));
        let env = prego_auth::MapEnv::new();
        assert!(!open_browser("http://console.example.test/device", &env));
        assert!(!open_browser("https://x.test/a b", &env));
    }
}
