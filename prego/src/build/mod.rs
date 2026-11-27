//! `prego build` (ADR-0066, build artifacts): the parts that do not depend on the wire contract yet. The file
//! set of a build and the sha256 of each file, the part plan of an upload, the `--release-url` check, the
//! expiry window, the promote label and the selectors of `get`.
//!
//! The commands (`push`, `get`, `list`, `promote`) are in [`commands`], on the routes of api.md section 16.

pub mod commands;

use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};

/// One to 32 files in a build (ADR-0066 section 1).
pub const MAX_FILES: usize = 32;
/// A `release_url` is at most 2,048 characters (ADR-0066 section 7).
pub const MAX_RELEASE_URL: usize = 2048;
/// The expiry window: 3 to 360 days (ADR-0066 section 5).
pub const MIN_EXPIRY_DAYS: u32 = 3;
pub const MAX_EXPIRY_DAYS: u32 = 360;
/// Parts of an upload: at most 95 MiB, as `prego oci push` (ADR-0066 section 4).
pub const MAX_PART: u64 = 95 * 1024 * 1024;
pub const DEFAULT_PART: u64 = 64 * 1024 * 1024;
/// The largest file of any plan (Publisher, 5 GiB; api.md section 16.1).
pub const MAX_FILE_BYTES: u64 = 5 * 1024 * 1024 * 1024;

/// One file of a build: the name in the build, the path on disk, the size and the sha256 (hex).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildFile {
    pub name: String,
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

/// The name of a file in a build (api.md section 16.1): one path segment, `[A-Za-z0-9._+-]`, 1 to 128
/// characters, not starting with `.`.
pub fn check_file_name(name: &str) -> Result<(), String> {
    let ok = !name.is_empty()
        && name.len() <= 128
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(format!(
            "the file name `{}` is not allowed in a build: 1 to 128 characters from A-Z, a-z, 0-9, `.`, `_`, \
             `+` and `-`, not starting with `.`. Rename the file or put it in an archive",
            name.escape_debug()
        ))
    }
}

/// The sha256 (hex) and size of a reader, streamed.
pub fn hash_reader(r: &mut dyn Read) -> std::io::Result<(String, u64)> {
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut size = 0u64;
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        size += n as u64;
    }
    Ok((
        h.finalize().iter().map(|b| format!("{b:02x}")).collect(),
        size,
    ))
}

/// The files of a build, in the order given, each hashed. Only regular files (a symbolic link is refused, not
/// followed); two files with the same name are refused; 1 to 32 files.
pub fn collect(paths: &[String]) -> Result<Vec<BuildFile>, String> {
    if paths.is_empty() {
        return Err("a build has 1 to 32 files; give at least one".into());
    }
    if paths.len() > MAX_FILES {
        return Err(format!(
            "a build has at most {MAX_FILES} files; {} were given. Put them in an archive",
            paths.len()
        ));
    }
    let mut out: Vec<BuildFile> = Vec::with_capacity(paths.len());
    for p in paths {
        let meta = std::fs::symlink_metadata(p).map_err(|e| format!("{p}: {e}"))?;
        if meta.file_type().is_symlink() {
            return Err(format!("{p}: a symbolic link; give the file it points to"));
        }
        if !meta.is_file() {
            return Err(format!("{p}: not a regular file"));
        }
        let name = Path::new(p)
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| format!("{p}: the file name is not UTF-8"))?
            .to_string();
        check_file_name(&name).map_err(|e| format!("{p}: {e}"))?;
        if let Some(other) = out.iter().find(|f| f.name == name) {
            return Err(format!(
                "{p} and {} have the same name `{name}` in the build",
                other.path
            ));
        }
        let mut f = std::fs::File::open(p).map_err(|e| format!("{p}: {e}"))?;
        let (sha256, size) = hash_reader(&mut f).map_err(|e| format!("{p}: {e}"))?;
        if size != meta.len() {
            return Err(format!("{p}: the file changed while prego read it"));
        }
        out.push(BuildFile {
            name,
            path: p.clone(),
            size,
            sha256,
        });
    }
    Ok(out)
}

/// The part plan of one file: `(offset, length)` pairs. Every part has `part` bytes except the last. An empty
/// file has one empty part.
pub fn parts(size: u64, part: u64) -> Vec<(u64, u64)> {
    let part = part.clamp(1, MAX_PART);
    if size == 0 {
        return vec![(0, 0)];
    }
    let mut out = Vec::new();
    let mut at = 0;
    while at < size {
        let n = part.min(size - at);
        out.push((at, n));
        at += n;
    }
    out
}

/// `--release-url`: an `https://` URL with a host, at most 2,048 characters, no spaces or control characters.
/// Prego does not fetch it (ADR-0066 section 7).
pub fn check_release_url(u: &str) -> Result<(), String> {
    let bad = |why: &str| format!("--release-url `{u}`: {why}");
    if u.len() > MAX_RELEASE_URL {
        return Err(bad("longer than 2,048 characters"));
    }
    let rest = u
        .strip_prefix("https://")
        .ok_or_else(|| bad("use an https:// URL"))?;
    if u.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(bad("it has a space or a control character"));
    }
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.rsplit('@').next().unwrap_or(host);
    if host.is_empty()
        || rest
            .split(['/', '?', '#'])
            .next()
            .unwrap_or("")
            .contains('@')
    {
        return Err(bad("give a host, with no user name or password"));
    }
    Ok(())
}

/// `--expires-in <days>`: a window of 3 to 360 days. The registry also refuses a window longer than the
/// namespace setting.
pub fn parse_expiry_days(s: &str) -> Result<u32, String> {
    let d: u32 = s
        .trim_end_matches('d')
        .parse()
        .map_err(|_| format!("--expires-in `{s}` is not a number of days"))?;
    if !(MIN_EXPIRY_DAYS..=MAX_EXPIRY_DAYS).contains(&d) {
        return Err(format!(
            "--expires-in {d}: the expiry window is {MIN_EXPIRY_DAYS} to {MAX_EXPIRY_DAYS} days"
        ));
    }
    Ok(d)
}

/// A promote label: SemVer or a free label (ADR-0066 section 1), with the tag characters
/// (`A-Za-z0-9._+-`, 1 to 128, starting with a letter or a digit).
pub fn check_label(s: &str) -> Result<(), String> {
    crate::snippet::reference::check_tag(s).map_err(|_| {
        format!(
            "bad label `{s}`: 1 to 128 characters from A-Z, a-z, 0-9, `.`, `_`, `+` and `-`, starting with a \
             letter or a digit (for example 1.4.0 or v1.4.0)"
        )
    })
}

/// A commit for `--commit`: 7 to 64 hex characters (a short or a full SHA-1 or SHA-256 commit).
pub fn check_commit(s: &str) -> Result<(), String> {
    if (7..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(format!(
            "--commit `{s}`: give 7 to 64 hex characters of the commit"
        ))
    }
}

/// How `get` and `promote` choose a build (ADR-0066 sections 2 and 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selector {
    Id(String),
    Commit(String),
    Run(String),
    Version(String),
    Latest { git_ref: Option<String> },
}

impl Selector {
    /// Exactly one of: a build ID (`bld_...`), `--commit`, `--run`, `--version`, `--latest` (with an optional
    /// `--ref`). `--ref` goes with `--latest` only.
    pub fn from_parts(
        id: Option<&str>,
        commit: Option<&str>,
        run: Option<&str>,
        version: Option<&str>,
        latest: bool,
        git_ref: Option<&str>,
    ) -> Result<Selector, String> {
        let given = [
            id.is_some(),
            commit.is_some(),
            run.is_some(),
            version.is_some(),
            latest,
        ]
        .iter()
        .filter(|b| **b)
        .count();
        if given != 1 {
            return Err(
                "choose one build: <build-id>, --commit <sha>, --run <id>, --label <label> or --latest".into(),
            );
        }
        if git_ref.is_some() && !latest {
            return Err("--ref goes with --latest".into());
        }
        if let Some(i) = id {
            if !(i.starts_with("bld_")
                && i.len() > 4
                && i[4..].bytes().all(|b| b.is_ascii_alphanumeric()))
            {
                return Err(format!("`{i}` is not a build ID (bld_...)"));
            }
            return Ok(Selector::Id(i.to_string()));
        }
        if let Some(c) = commit {
            check_commit(c)?;
            return Ok(Selector::Commit(c.to_ascii_lowercase()));
        }
        if let Some(r) = run {
            if r.is_empty() || r.len() > 20 || !r.bytes().all(|b| b.is_ascii_digit()) {
                return Err(format!("--run `{r}`: give the run or pipeline ID (digits)"));
            }
            return Ok(Selector::Run(r.to_string()));
        }
        if let Some(v) = version {
            check_label(v)?;
            return Ok(Selector::Version(v.to_string()));
        }
        Ok(Selector::Latest {
            git_ref: git_ref.map(str::to_string),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prego_auth::testing::TempDir;

    #[test]
    fn collect_hashes_and_refuses() {
        let d = TempDir::new("prego-build-collect");
        std::fs::write(d.join("app.tar.gz"), b"archive").unwrap();
        std::fs::create_dir_all(d.join("sub")).unwrap();
        std::fs::write(d.join("sub/app.tar.gz"), b"other").unwrap();
        std::fs::write(d.join("empty.txt"), b"").unwrap();
        let p = |n: &str| d.join(n).to_string_lossy().into_owned();
        let files = collect(&[p("app.tar.gz"), p("empty.txt")]).unwrap();
        assert_eq!(files[0].name, "app.tar.gz");
        assert_eq!(files[0].size, 7);
        assert_eq!(
            files[0].sha256,
            hash_reader(&mut &b"archive"[..]).unwrap().0
        );
        assert_eq!(
            files[1].sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert!(collect(&[p("app.tar.gz"), p("sub/app.tar.gz")])
            .unwrap_err()
            .contains("the same name `app.tar.gz`"));
        assert!(collect(&[p("sub")])
            .unwrap_err()
            .contains("not a regular file"));
        assert!(collect(&[]).is_err());
        assert!(collect(&vec![p("empty.txt"); 33])
            .unwrap_err()
            .contains("at most 32"));
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(d.join("app.tar.gz"), d.join("link")).unwrap();
            assert!(collect(&[p("link")]).unwrap_err().contains("symbolic link"));
        }
    }

    #[test]
    fn known_sha256() {
        let (h, n) = hash_reader(&mut &b"abc"[..]).unwrap();
        assert_eq!(n, 3);
        assert_eq!(
            h,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn part_plans() {
        assert_eq!(parts(0, 10), vec![(0, 0)]);
        assert_eq!(parts(25, 10), vec![(0, 10), (10, 10), (20, 5)]);
        assert_eq!(parts(10, 10), vec![(0, 10)]);
        // Never larger than 95 MiB.
        assert_eq!(
            parts(MAX_PART + 1, u64::MAX),
            vec![(0, MAX_PART), (MAX_PART, 1)]
        );
    }

    #[test]
    fn release_urls() {
        check_release_url("https://github.com/acme/api/releases/tag/v1.4.0").unwrap();
        check_release_url("https://gitlab.example.com/acme/api/-/releases/v1.4.0").unwrap();
        for bad in [
            "http://github.com/x",
            "https://",
            "https://user:pw@github.com/x",
            "https://github.com/a b",
            "ftp://x",
        ] {
            assert!(check_release_url(bad).is_err(), "{bad}");
        }
        let long = format!("https://example.com/{}", "a".repeat(MAX_RELEASE_URL));
        assert!(check_release_url(&long).unwrap_err().contains("2,048"));
    }

    #[test]
    fn expiry_and_labels_and_commits() {
        assert_eq!(parse_expiry_days("3").unwrap(), 3);
        assert_eq!(parse_expiry_days("30d").unwrap(), 30);
        assert!(parse_expiry_days("2").is_err());
        assert!(parse_expiry_days("361").is_err());
        assert!(parse_expiry_days("x").is_err());
        check_label("1.4.0").unwrap();
        check_label("v1.4.0").unwrap();
        check_label("nightly-2026-11-26").unwrap();
        assert!(check_label("-x").is_err());
        assert!(check_label("a b").is_err());
        check_commit("9f2c3e4").unwrap();
        assert!(check_commit("9f2c").is_err());
        assert!(check_commit("zzzzzzz").is_err());
    }

    #[test]
    fn selectors() {
        assert_eq!(
            Selector::from_parts(Some("bld_01ABC"), None, None, None, false, None).unwrap(),
            Selector::Id("bld_01ABC".into())
        );
        assert_eq!(
            Selector::from_parts(None, Some("9F2C3E4D"), None, None, false, None).unwrap(),
            Selector::Commit("9f2c3e4d".into())
        );
        assert_eq!(
            Selector::from_parts(None, None, None, None, true, Some("refs/heads/main")).unwrap(),
            Selector::Latest {
                git_ref: Some("refs/heads/main".into())
            }
        );
        assert!(Selector::from_parts(None, None, None, None, false, None).is_err());
        assert!(
            Selector::from_parts(Some("bld_1"), Some("9f2c3e4"), None, None, false, None).is_err()
        );
        assert!(Selector::from_parts(None, None, Some("456"), None, false, Some("main")).is_err());
        assert!(Selector::from_parts(Some("build1"), None, None, None, false, None).is_err());
        assert!(Selector::from_parts(None, None, Some("a b"), None, false, None).is_err());
        assert!(Selector::from_parts(None, None, Some("run-1"), None, false, None).is_err());
        assert_eq!(
            Selector::from_parts(None, None, None, Some("1.4.0"), false, None).unwrap(),
            Selector::Version("1.4.0".into())
        );
    }
}
