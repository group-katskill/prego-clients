//! `prego setup cargo` and `prego setup docker`.

use prego_auth::{oci, Config, Env, FileConfig};

use crate::docker_config::{self, Change};

/// Checks a namespace or registry name: letters, digits, `-` and `_`, 1 to 64 characters.
pub fn check_slug(what: &str, value: &str) -> Result<(), String> {
    let ok = !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if ok {
        Ok(())
    } else {
        Err(format!("prego: bad {what} `{value}`"))
    }
}

/// The Cargo snippet for one tenant and namespace.
pub fn cargo_snippet(tenant: &str, namespace: &str, registry: &str) -> String {
    format!(
        "[registries.{registry}]\n\
         index = \"sparse+https://cargo.prego.k8skill.com/t/{tenant}/{namespace}/index/\"\n\
         credential-provider = [\"cargo-credential-prego\", \"--tenant\", \"{tenant}\"]\n"
    )
}

/// `prego setup cargo`: prints the snippet. It writes no file.
pub fn cargo(
    globals: &[&str],
    namespace: &str,
    registry: Option<&str>,
    env: &dyn Env,
) -> Result<(), String> {
    check_slug("namespace", namespace)?;
    let config = Config::from_args(globals, env).map_err(|e| e.to_string())?;
    let registry = registry.unwrap_or(&config.tenant);
    check_slug("registry name", registry)?;
    println!("# Add this to ~/.cargo/config.toml, or to .cargo/config.toml in a project:");
    print!("{}", cargo_snippet(&config.tenant, namespace, registry));
    println!("# Then use: acme-core = {{ version = \"1\", registry = \"{registry}\" }}");
    Ok(())
}

/// `prego setup docker`: prints the snippet, and with `write` adds it to the Docker config file.
pub fn docker(write: bool, env: &dyn Env) -> Result<(), String> {
    let file = FileConfig::load(env).map_err(|e| e.to_string())?;
    let hosts = oci::oci_hosts(&file, env);
    let path = docker_config::path(env)
        .ok_or("prego: cannot find the Docker config. Set HOME or DOCKER_CONFIG.")?;

    if write {
        match docker_config::add_cred_helpers(&path, &hosts)? {
            Change::None => println!(
                "{} already uses prego for the Prego OCI hosts.",
                path.display()
            ),
            Change::Written { backup, replaced } => {
                for (host, old) in replaced {
                    println!("Replaced credential helper `{old}` with `prego` for {host}.");
                }
                match backup {
                    Some(b) => println!("Updated {}. Backup: {}", path.display(), b.display()),
                    None => println!("Wrote {}.", path.display()),
                }
            }
        }
    } else {
        println!(
            "# Add this to {} (or run `prego setup docker --write`):",
            path.display()
        );
        println!("{}", docker_config::snippet(&hosts));
    }

    // docker-credential-prego gets no arguments from Docker, so it needs the tenant from the
    // environment or the settings file.
    if env.var("PREGO_TENANT").is_none() && file.tenant.is_none() {
        let cfg = FileConfig::path(env)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "~/.config/prego/config.toml".into());
        println!("# Also set the tenant for docker-credential-prego: tenant = \"<slug>\" in {cfg}");
    }
    if !on_path("docker-credential-prego", env) {
        println!("# docker-credential-prego is not on PATH. Install it first.");
    }
    Ok(())
}

fn on_path(program: &str, env: &dyn Env) -> bool {
    let Some(path) = env.var("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| dir.join(program).is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_snippet_text() {
        assert_eq!(
            cargo_snippet("acme", "default", "acme"),
            "[registries.acme]\n\
             index = \"sparse+https://cargo.prego.k8skill.com/t/acme/default/index/\"\n\
             credential-provider = [\"cargo-credential-prego\", \"--tenant\", \"acme\"]\n"
        );
    }

    #[test]
    fn slugs() {
        check_slug("namespace", "release_1-a").unwrap();
        for bad in ["", "a b", "a/b", "a\"b", &"x".repeat(65)] {
            assert!(check_slug("namespace", bad).is_err(), "{bad}");
        }
    }
}
