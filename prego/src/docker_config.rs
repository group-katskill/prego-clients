//! Reads and changes the Docker client config file (`~/.docker/config.json`).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use prego_auth::Env;
use serde_json::{Map, Value};

/// The helper name in `credHelpers`. Docker runs `docker-credential-<name>`.
pub const HELPER: &str = "prego";
/// Largest config file that `prego` reads.
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// What [`add_cred_helpers`] did.
#[derive(Debug, PartialEq, Eq)]
pub enum Change {
    /// The file already had the entries. Nothing was written.
    None,
    /// The file was written.
    Written {
        /// The backup copy of the old file, if there was one.
        backup: Option<PathBuf>,
        /// Hosts that had another helper before, with that helper.
        replaced: Vec<(String, String)>,
    },
}

/// `$DOCKER_CONFIG/config.json`, else `$HOME/.docker/config.json`.
pub fn path(env: &dyn Env) -> Option<PathBuf> {
    if let Some(dir) = env.var("DOCKER_CONFIG") {
        return Some(PathBuf::from(dir).join("config.json"));
    }
    env.var("HOME")
        .map(|h| PathBuf::from(h).join(".docker").join("config.json"))
}

/// The `credHelpers` snippet for `hosts`.
pub fn snippet(hosts: &[String]) -> String {
    let helpers: Map<String, Value> = hosts
        .iter()
        .map(|h| (h.clone(), Value::String(HELPER.into())))
        .collect();
    let mut root = Map::new();
    root.insert("credHelpers".into(), Value::Object(helpers));
    serde_json::to_string_pretty(&Value::Object(root)).expect("JSON value serializes")
}

/// Sets `credHelpers.<host> = "prego"` for each host. Keeps all other keys and their order.
///
/// Before it changes an existing file, it copies the file to `config.json.prego-backup-<unix time>`. It
/// writes a temporary file in the same directory and renames it, so a failure never leaves half a file.
/// If the file is not a JSON object, nothing is changed.
pub fn add_cred_helpers(path: &Path, hosts: &[String]) -> Result<Change, String> {
    let shown = path.display();
    let old_text = match fs::metadata(path) {
        Ok(m) if m.len() > MAX_FILE_BYTES => {
            return Err(format!(
                "prego: {shown} is larger than {MAX_FILE_BYTES} bytes"
            ))
        }
        Ok(_) => {
            Some(fs::read_to_string(path).map_err(|e| format!("prego: cannot read {shown}: {e}"))?)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(format!("prego: cannot read {shown}: {e}")),
    };

    let mut root = match old_text.as_deref().map(str::trim) {
        None | Some("") => Map::new(),
        Some(text) => match serde_json::from_str::<Value>(text) {
            Ok(Value::Object(m)) => m,
            _ => {
                return Err(format!(
                    "prego: {shown} is not a JSON object. Fix it, or add the snippet from \
                     `prego setup docker` by hand. The file is not changed."
                ))
            }
        },
    };

    let helpers = root
        .entry("credHelpers")
        .or_insert_with(|| Value::Object(Map::new()));
    let Value::Object(helpers) = helpers else {
        return Err(format!(
            "prego: `credHelpers` in {shown} is not a JSON object. The file is not changed."
        ));
    };
    let mut replaced = Vec::new();
    let mut changed = false;
    for host in hosts {
        match helpers.get(host) {
            Some(Value::String(h)) if h == HELPER => {}
            other => {
                if let Some(old) = other {
                    let old = old
                        .as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| old.to_string());
                    replaced.push((host.clone(), old));
                }
                helpers.insert(host.clone(), Value::String(HELPER.into()));
                changed = true;
            }
        }
    }
    if !changed {
        return Ok(Change::None);
    }

    let dir = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(dir).map_err(|e| format!("prego: cannot create {}: {e}", dir.display()))?;
    let backup = match old_text {
        Some(_) => Some(backup_copy(path)?),
        None => None,
    };

    let mut text =
        serde_json::to_string_pretty(&Value::Object(root)).expect("JSON value serializes");
    text.push('\n');
    let tmp = dir.join(format!(
        ".{}.prego-tmp-{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("config.json"),
        std::process::id()
    ));
    let result = write_new(&tmp, path, text.as_bytes()).and_then(|()| {
        fs::rename(&tmp, path).map_err(|e| format!("prego: cannot replace {shown}: {e}"))
    });
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result?;
    Ok(Change::Written { backup, replaced })
}

/// Copies `path` to a new `<name>.prego-backup-<unix time>[-n]` file. `fs::copy` keeps the permissions.
fn backup_copy(path: &Path) -> Result<PathBuf, String> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("config.json");
    let stamp = prego_auth::now_unix();
    for n in 0..100 {
        let suffix = if n == 0 {
            format!("{stamp}")
        } else {
            format!("{stamp}-{n}")
        };
        let backup = path.with_file_name(format!("{name}.prego-backup-{suffix}"));
        if backup.exists() {
            continue;
        }
        fs::copy(path, &backup)
            .map_err(|e| format!("prego: cannot make a backup of {}: {e}", path.display()))?;
        return Ok(backup);
    }
    Err(format!(
        "prego: cannot find a free backup name for {}",
        path.display()
    ))
}

/// Writes `bytes` to the new file `tmp`, with the permissions of `like` (or 0600 if `like` does not exist).
fn write_new(tmp: &Path, like: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(tmp)
        .map_err(|e| format!("prego: cannot write {}: {e}", tmp.display()))?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|e| format!("prego: cannot write {}: {e}", tmp.display()))?;
    if let Ok(m) = fs::metadata(like) {
        fs::set_permissions(tmp, m.permissions())
            .map_err(|e| format!("prego: cannot set permissions on {}: {e}", tmp.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use prego_auth::MapEnv;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("prego-docker-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn hosts() -> Vec<String> {
        vec!["oci.prego.k8skill.com".into()]
    }

    #[test]
    fn path_prefers_docker_config() {
        let env = MapEnv::new().with("HOME", "/h");
        assert_eq!(path(&env).unwrap(), PathBuf::from("/h/.docker/config.json"));
        let env = env.with("DOCKER_CONFIG", "/d");
        assert_eq!(path(&env).unwrap(), PathBuf::from("/d/config.json"));
    }

    #[test]
    fn new_file() {
        let d = dir("new");
        let p = d.join("sub/config.json");
        assert_eq!(
            add_cred_helpers(&p, &hosts()).unwrap(),
            Change::Written {
                backup: None,
                replaced: vec![]
            }
        );
        let v: Value = serde_json::from_str(&fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(v["credHelpers"]["oci.prego.k8skill.com"], "prego");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn existing_file_keeps_keys_and_order_and_makes_a_backup() {
        let d = dir("existing");
        let p = d.join("config.json");
        let old = r#"{"auths":{"ghcr.io":{}},"credsStore":"desktop","credHelpers":{"gcr.io":"gcloud","oci.prego.k8skill.com":"old"},"zzz":1}"#;
        fs::write(&p, old).unwrap();
        let Change::Written { backup, replaced } = add_cred_helpers(&p, &hosts()).unwrap() else {
            panic!("not written");
        };
        assert_eq!(fs::read_to_string(backup.unwrap()).unwrap(), old);
        assert_eq!(
            replaced,
            vec![("oci.prego.k8skill.com".to_string(), "old".to_string())]
        );
        let text = fs::read_to_string(&p).unwrap();
        let v: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["credsStore"], "desktop");
        assert_eq!(v["credHelpers"]["gcr.io"], "gcloud");
        assert_eq!(v["credHelpers"]["oci.prego.k8skill.com"], "prego");
        let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["auths", "credsStore", "credHelpers", "zzz"]);

        // A second run changes nothing and makes no second backup.
        assert_eq!(add_cred_helpers(&p, &hosts()).unwrap(), Change::None);
        let backups = fs::read_dir(&d)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains("prego-backup")
            })
            .count();
        assert_eq!(backups, 1);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn bad_file_is_not_changed() {
        let d = dir("bad");
        let p = d.join("config.json");
        for bad in ["{not json", "[1,2]", r#"{"credHelpers":"x"}"#] {
            fs::write(&p, bad).unwrap();
            assert!(add_cred_helpers(&p, &hosts()).is_err(), "{bad}");
            assert_eq!(fs::read_to_string(&p).unwrap(), bad);
        }
        assert_eq!(fs::read_dir(&d).unwrap().count(), 1);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn snippet_text() {
        assert_eq!(
            snippet(&hosts()),
            "{\n  \"credHelpers\": {\n    \"oci.prego.k8skill.com\": \"prego\"\n  }\n}"
        );
    }
}
