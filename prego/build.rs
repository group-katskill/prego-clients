//! Puts the git commit in `PREGO_GIT_COMMIT` for `--version`.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=PREGO_GIT_COMMIT");
    // Watch HEAD only in a git checkout. A missing path makes Cargo rerun this script on every build.
    if std::path::Path::new("../.git/HEAD").exists() {
        println!("cargo:rerun-if-changed=../.git/HEAD");
    }
    let commit = std::env::var("PREGO_GIT_COMMIT")
        .ok()
        .filter(|c| !c.is_empty())
        .or_else(|| {
            Command::new("git")
                .args(["rev-parse", "--short=12", "HEAD"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=PREGO_GIT_COMMIT={commit}");
}
