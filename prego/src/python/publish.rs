//! `prego python publish`: uploads wheels and sdists with the upload API that twine uses
//! (`POST <base>legacy/`, `multipart/form-data`). The file is streamed, never read into memory.

use std::fs::File;
use std::io::{Cursor, Read};
use std::path::Path;

use base64::Engine;
use prego_auth::http::{Body, Http};
use sha2::{Digest, Sha256};

use super::{python_token, target, USERNAME};

/// The largest file the registry takes (`pyMaxFileBytes`). Larger files are refused before the upload.
pub const MAX_FILE_BYTES: u64 = 90 * 1024 * 1024;

const BOUNDARY: &str = "----prego-python-publish-7f3a9c1e5b";

/// What the filename says about a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dist {
    pub filename: String,
    pub name: String,
    pub version: String,
    /// `bdist_wheel` or `sdist`.
    pub filetype: &'static str,
    /// The Python tag of a wheel (`py3`), or `source`.
    pub pyversion: String,
}

/// Reads the name, version and type from a filename: a wheel
/// `{name}-{version}(-{build})?-{python}-{abi}-{platform}.whl` or an sdist `{name}-{version}.tar.gz`.
pub fn parse_filename(filename: &str) -> Result<Dist, String> {
    let bad = |why: &str| format!("prego: `{filename}`: {why}");
    let safe = !filename.is_empty()
        && filename
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'+' | b'!'));
    if !safe {
        return Err(bad(
            "the filename has characters that a Python package file cannot have",
        ));
    }
    if let Some(stem) = filename.strip_suffix(".whl") {
        let parts: Vec<&str> = stem.split('-').collect();
        let (name, version, py) = match parts.as_slice() {
            [n, v, py, _abi, _plat] | [n, v, _, py, _abi, _plat] => (*n, *v, *py),
            _ => {
                return Err(bad(
                    "not a wheel filename ({name}-{version}-{python}-{abi}-{platform}.whl)",
                ))
            }
        };
        if name.is_empty() || version.is_empty() || py.is_empty() {
            return Err(bad("not a wheel filename"));
        }
        return Ok(Dist {
            filename: filename.into(),
            name: name.into(),
            version: version.into(),
            filetype: "bdist_wheel",
            pyversion: py.into(),
        });
    }
    if let Some(stem) = filename.strip_suffix(".tar.gz") {
        let (name, version) = stem
            .rsplit_once('-')
            .filter(|(n, v)| !n.is_empty() && !v.is_empty())
            .ok_or_else(|| bad("not an sdist filename ({name}-{version}.tar.gz)"))?;
        return Ok(Dist {
            filename: filename.into(),
            name: name.into(),
            version: version.into(),
            filetype: "sdist",
            pyversion: "source".into(),
        });
    }
    Err(bad(
        "only wheels (.whl) and sdists (.tar.gz) can be published",
    ))
}

/// The multipart text before the file bytes, and the text after them.
pub fn multipart_parts(d: &Dist, sha256: &str) -> (String, String) {
    let mut head = String::new();
    let fields = [
        (":action", "file_upload"),
        ("protocol_version", "1"),
        ("name", d.name.as_str()),
        ("version", d.version.as_str()),
        ("filetype", d.filetype),
        ("pyversion", d.pyversion.as_str()),
        ("sha256_digest", sha256),
    ];
    for (k, v) in fields {
        head.push_str(&format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n"
        ));
    }
    head.push_str(&format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"content\"; filename=\"{}\"\r\n\
         Content-Type: application/octet-stream\r\n\r\n",
        d.filename
    ));
    (head, format!("\r\n--{BOUNDARY}--\r\n"))
}

fn sha256_of(path: &Path) -> Result<String, String> {
    let mut f =
        File::open(path).map_err(|e| format!("prego: cannot read {}: {e}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f
            .read(&mut buf)
            .map_err(|e| format!("prego: cannot read {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// The first line of an error answer, as pypi.org and Prego send one line of text.
fn answer_line(body: &str) -> String {
    let line = body
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("");
    line.chars().take(300).collect()
}

/// `prego python publish <file>...`.
pub fn publish(
    globals: &[&str],
    files: &[String],
    namespace: &str,
    env: &dyn prego_auth::Env,
) -> Result<(), String> {
    if files.is_empty() {
        return Err("prego: usage: prego python publish [--namespace <ns>] <file>...".into());
    }
    // Check every file before the first upload.
    let mut dists = Vec::new();
    for f in files {
        let path = Path::new(f);
        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| format!("prego: `{f}` is not a file"))?;
        let d = parse_filename(filename)?;
        let meta = std::fs::metadata(path).map_err(|e| format!("prego: {f}: {e}"))?;
        if !meta.is_file() {
            return Err(format!("prego: `{f}` is not a file"));
        }
        if meta.len() > MAX_FILE_BYTES {
            return Err(format!(
                "prego: {filename} is larger than 90 MiB ({} bytes). The registry refuses it. Make the wheel \
                 smaller, or split the package.",
                meta.len()
            ));
        }
        dists.push((path, d, meta.len()));
    }

    let (config, t) = target(globals, None, namespace, env)?;
    let token = python_token(&config, &t, env)?;
    let basic =
        base64::engine::general_purpose::STANDARD.encode(format!("{USERNAME}:{}", token.expose()));
    let auth = format!("Basic {basic}");
    let content_type = format!("multipart/form-data; boundary={BOUNDARY}");
    let http = Http::for_transfers(crate::USER_AGENT, config.ca_file.as_deref())
        .map_err(|e| format!("prego: PREGO_CA_FILE: {e}"))?;
    let url = t.upload();

    let mut names: Vec<String> = Vec::new();
    for (path, d, len) in &dists {
        let sha = sha256_of(path)?;
        let (head, tail) = multipart_parts(d, &sha);
        let file = File::open(path).map_err(|e| format!("prego: {}: {e}", path.display()))?;
        let total = head.len() as u64 + len + tail.len() as u64;
        let mut body = Cursor::new(head.into_bytes())
            .chain(file.take(*len))
            .chain(Cursor::new(tail.into_bytes()));
        let res = http
            .send(
                "POST",
                &url,
                &[("Content-Type", &content_type), ("Authorization", &auth)],
                Body::Reader(&mut body, total),
            )
            .map_err(|e| format!("prego: upload of {} failed: {e}", d.filename))?;
        match res.status {
            200 | 201 => println!("Published {} (sha256 {sha})", d.filename),
            s => {
                let line = answer_line(&res.body);
                let hint = match s {
                    401 => " (no valid token: check the identity with prego whoami)",
                    403 => {
                        " (no publish grant for this project, or the plan has no Python packages)"
                    }
                    404 => " (unknown tenant or namespace, or no grant)",
                    _ => "",
                };
                return Err(format!(
                    "prego: upload of {} refused: {s} {line}{hint}",
                    d.filename
                ));
            }
        }
        let normalized = normalize(&d.name);
        if !names.contains(&normalized) {
            names.push(normalized);
        }
    }

    println!("# To install with uv, add this to pyproject.toml (or run prego setup python):");
    print!(
        "{}",
        super::setup::merge_uv("", &t.index(), &names).map(|(t, _)| t)?
    );
    Ok(())
}

/// The normalized project name (PEP 503): lowercase, runs of `-`, `_` and `.` become one `-`.
pub fn normalize(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut sep = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            sep = true;
        } else {
            if sep && !out.is_empty() {
                out.push('-');
            }
            sep = false;
            out.push(c.to_ascii_lowercase());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filenames() {
        let w = parse_filename("acme_core-1.2.0-py3-none-any.whl").unwrap();
        assert_eq!(
            (
                w.name.as_str(),
                w.version.as_str(),
                w.filetype,
                w.pyversion.as_str()
            ),
            ("acme_core", "1.2.0", "bdist_wheel", "py3")
        );
        let w = parse_filename("acme_core-1.2.0-1-cp312-cp312-manylinux_2_17_x86_64.whl").unwrap();
        assert_eq!(
            (w.version.as_str(), w.pyversion.as_str()),
            ("1.2.0", "cp312")
        );
        let s = parse_filename("acme_core-1.2.0rc1.tar.gz").unwrap();
        assert_eq!(
            (
                s.name.as_str(),
                s.version.as_str(),
                s.filetype,
                s.pyversion.as_str()
            ),
            ("acme_core", "1.2.0rc1", "sdist", "source")
        );
        let s = parse_filename("acme-core-1.0.tar.gz").unwrap();
        assert_eq!((s.name.as_str(), s.version.as_str()), ("acme-core", "1.0"));
        for bad in [
            "acme-1.0.zip",
            "acme-1.0.egg",
            "acme.whl",
            "acme-1.0-py3.whl",
            "acme.tar.gz",
            "a\"b-1.0.tar.gz",
            "a b-1.0.tar.gz",
            "",
        ] {
            assert!(parse_filename(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn multipart_text() {
        let d = parse_filename("acme_core-1.0-py3-none-any.whl").unwrap();
        let (head, tail) = multipart_parts(&d, "ab12");
        assert!(head.starts_with(&format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\":action\"\r\n\r\nfile_upload\r\n"
        )));
        assert!(head.contains("name=\"sha256_digest\"\r\n\r\nab12\r\n"));
        assert!(head.contains("name=\"filetype\"\r\n\r\nbdist_wheel\r\n"));
        assert!(head.ends_with(
            "name=\"content\"; filename=\"acme_core-1.0-py3-none-any.whl\"\r\n\
             Content-Type: application/octet-stream\r\n\r\n"
        ));
        assert_eq!(tail, format!("\r\n--{BOUNDARY}--\r\n"));
    }

    #[test]
    fn normalized_names() {
        assert_eq!(normalize("Acme_Core.Lib"), "acme-core-lib");
        assert_eq!(normalize("a--_b"), "a-b");
        assert_eq!(
            answer_line("\n  400 File already exists.\nmore"),
            "400 File already exists."
        );
    }
}
