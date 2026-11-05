//! The shared settings file `prego/config.toml`.
//!
//! All Prego client tools read the same file. It holds settings only, never a secret. The location is
//! `$XDG_CONFIG_HOME/prego/config.toml`, or `$HOME/.config/prego/config.toml` if `XDG_CONFIG_HOME` is not set.
//! A missing file is not an error. A file that does not parse is an error.
//!
//! ```toml
//! tenant = "acme"
//! sts_url = "https://sts.prego.k8skill.com/v1/sts/token"
//! audience = "prego.k8skill.com"
//! source = "auto"
//! oci_hosts = ["oci.example.internal"]
//! go_hosts = ["go.example.internal"]
//! go_prefixes = ["go.acme.com", "github.com/acme"]
//! npm_host = "npm.example.internal"
//! ```

use std::path::PathBuf;

use crate::env::Env;
use crate::error::Error;

/// Largest settings file that the client reads.
const MAX_FILE_BYTES: u64 = 64 * 1024;

/// Keys that look like a secret. The file is refused if it has one of them.
const SECRET_KEYS: [&str; 9] = [
    "api_key",
    "apikey",
    "key",
    "token",
    "secret",
    "password",
    "subject_token",
    "id_token",
    "access_token",
];

/// Settings from `prego/config.toml`. Each field is `None` if the file does not set it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileConfig {
    /// Tenant slug.
    pub tenant: Option<String>,
    /// STS endpoint URL.
    pub sts_url: Option<String>,
    /// Audience for SVIDs and CI tokens.
    pub audience: Option<String>,
    /// Identity source name (`auto`, `spiffe`, ...).
    pub source: Option<String>,
    /// More OCI registry hosts, added to `oci.prego.k8skill.com`.
    pub oci_hosts: Vec<String>,
    /// Go hosts. The first one is used for publish; all are allowed for `prego go-auth`.
    pub go_hosts: Vec<String>,
    /// The Go module path prefixes of the tenant, for `GONOSUMDB`.
    pub go_prefixes: Vec<String>,
    /// The npm host, in place of `npm.prego.k8skill.com`.
    pub npm_host: Option<String>,
}

impl FileConfig {
    /// The path of the settings file, or `None` if neither `XDG_CONFIG_HOME` nor `HOME` is set.
    pub fn path(env: &dyn Env) -> Option<PathBuf> {
        if let Some(xdg) = env.var("XDG_CONFIG_HOME") {
            return Some(PathBuf::from(xdg).join("prego").join("config.toml"));
        }
        env.var("HOME").map(|home| {
            PathBuf::from(home)
                .join(".config")
                .join("prego")
                .join("config.toml")
        })
    }

    /// Reads the settings file. Returns empty settings if the file does not exist.
    pub fn load(env: &dyn Env) -> Result<FileConfig, Error> {
        let Some(path) = Self::path(env) else {
            return Ok(FileConfig::default());
        };
        let shown = path.display().to_string();
        let file = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(FileConfig::default()),
            Err(e) => return Err(Error::Config(format!("cannot open `{shown}`: {e}"))),
        };
        let mut text = String::new();
        use std::io::Read;
        file.take(MAX_FILE_BYTES + 1)
            .read_to_string(&mut text)
            .map_err(|e| Error::Config(format!("cannot read `{shown}`: {e}")))?;
        if text.len() as u64 > MAX_FILE_BYTES {
            return Err(Error::Config(format!(
                "`{shown}` is larger than {MAX_FILE_BYTES} bytes"
            )));
        }
        Self::parse(&text).map_err(|m| Error::Config(format!("`{shown}`: {m}")))
    }

    /// Parses the text of a settings file.
    pub fn parse(text: &str) -> Result<FileConfig, String> {
        // The parse error from `toml` can quote the line. Do not show it: the line may hold a secret.
        let table: toml::Table = text.parse().map_err(|_| "is not valid TOML".to_string())?;
        let mut out = FileConfig::default();
        for (key, value) in &table {
            if SECRET_KEYS.contains(&key.to_ascii_lowercase().as_str()) {
                return Err(format!(
                    "key `{key}` is not allowed. This file must not hold a secret. \
                     Put the token in a file and set PREGO_TOKEN_FILE or PREGO_SVID_FILE, \
                     or set PREGO_API_KEY in the environment."
                ));
            }
            let string = |slot: &mut Option<String>| -> Result<(), String> {
                match value.as_str() {
                    Some(s) => {
                        *slot = Some(s.to_string());
                        Ok(())
                    }
                    None => Err(format!("key `{key}` must be a string")),
                }
            };
            let list = |slot: &mut Vec<String>| -> Result<(), String> {
                let bad = || format!("key `{key}` must be a list of strings");
                for item in value.as_array().ok_or_else(bad)? {
                    slot.push(item.as_str().ok_or_else(bad)?.to_string());
                }
                Ok(())
            };
            match key.as_str() {
                "tenant" => string(&mut out.tenant)?,
                "sts_url" => string(&mut out.sts_url)?,
                "audience" => string(&mut out.audience)?,
                "source" => string(&mut out.source)?,
                "oci_hosts" => list(&mut out.oci_hosts)?,
                "go_hosts" => list(&mut out.go_hosts)?,
                "go_prefixes" => list(&mut out.go_prefixes)?,
                "npm_host" => string(&mut out.npm_host)?,
                other => {
                    return Err(format!(
                        "unknown key `{other}`. Known keys: tenant, sts_url, audience, source, oci_hosts, \
                         go_hosts, go_prefixes, npm_host."
                    ))
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::MapEnv;

    #[test]
    fn parses_all_keys() {
        let c = FileConfig::parse(
            r#"
tenant = "acme"
sts_url = "https://sts.example.test/v1/sts/token"
audience = "example.test"
source = "api-key"
oci_hosts = ["oci.example.test", "oci2.example.test"]
"#,
        )
        .unwrap();
        assert_eq!(c.tenant.as_deref(), Some("acme"));
        assert_eq!(
            c.sts_url.as_deref(),
            Some("https://sts.example.test/v1/sts/token")
        );
        assert_eq!(c.audience.as_deref(), Some("example.test"));
        assert_eq!(c.source.as_deref(), Some("api-key"));
        assert_eq!(c.oci_hosts, vec!["oci.example.test", "oci2.example.test"]);
    }

    #[test]
    fn refuses_secret_keys_without_showing_the_value() {
        for key in ["api_key", "token", "Password", "secret"] {
            let e = FileConfig::parse(&format!("{key} = \"prk_do_not_show\"")).unwrap_err();
            assert!(e.contains("must not hold a secret"), "{e}");
            assert!(e.contains("PREGO_TOKEN_FILE"), "{e}");
            assert!(!e.contains("prk_do_not_show"), "{e}");
        }
    }

    #[test]
    fn bad_toml_does_not_quote_the_line() {
        let e = FileConfig::parse("tenant = \"prk_do_not_show").unwrap_err();
        assert!(!e.contains("prk_do_not_show"), "{e}");
    }

    #[test]
    fn refuses_unknown_keys_and_wrong_types() {
        assert!(FileConfig::parse("tenent = \"acme\"")
            .unwrap_err()
            .contains("unknown key"));
        assert!(FileConfig::parse("tenant = 1")
            .unwrap_err()
            .contains("must be a string"));
        assert!(FileConfig::parse("oci_hosts = \"x\"")
            .unwrap_err()
            .contains("list of strings"));
    }

    #[test]
    fn path_prefers_xdg() {
        let env = MapEnv::new().with("HOME", "/home/u");
        assert_eq!(
            FileConfig::path(&env).unwrap(),
            PathBuf::from("/home/u/.config/prego/config.toml")
        );
        let env = env.with("XDG_CONFIG_HOME", "/cfg");
        assert_eq!(
            FileConfig::path(&env).unwrap(),
            PathBuf::from("/cfg/prego/config.toml")
        );
        assert_eq!(FileConfig::path(&MapEnv::new()), None);
    }

    #[test]
    fn missing_file_is_empty_settings() {
        let dir =
            std::env::temp_dir().join(format!("prego-auth-cfg-missing-{}", std::process::id()));
        let env = MapEnv::new().with("XDG_CONFIG_HOME", &dir.to_string_lossy());
        assert_eq!(FileConfig::load(&env).unwrap(), FileConfig::default());
    }

    #[test]
    fn load_reads_the_file() {
        let dir = std::env::temp_dir().join(format!("prego-auth-cfg-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("prego")).unwrap();
        std::fs::write(dir.join("prego/config.toml"), "tenant = \"acme\"\n").unwrap();
        let env = MapEnv::new().with("XDG_CONFIG_HOME", &dir.to_string_lossy());
        assert_eq!(
            FileConfig::load(&env).unwrap().tenant.as_deref(),
            Some("acme")
        );
        std::fs::write(dir.join("prego/config.toml"), "token = \"x\"\n").unwrap();
        let e = FileConfig::load(&env).unwrap_err().to_string();
        assert!(e.contains("config.toml"), "{e}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
