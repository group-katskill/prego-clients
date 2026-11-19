//! The content of a snippet version: the file rules, the version hash, the fixed tar form, and the safe
//! write of `prego snippet get`. Written from the ADR-0057 text (items 4, 5 and 6).
//!
//! - A version is at most 100 files, each at most 1 MiB, together at most 8 MiB. Every file is UTF-8 with no
//!   NUL byte. A path is relative, `/` separated, at most 255 bytes, with no empty, `.` or `..` segment.
//!   The mode is `0644` or `0755`.
//! - The version hash is `sha256:` of the RFC 8785 canonical JSON of
//!   `{"files":[{"path","mode","size","sha256"}]}`, sorted by the bytes of the path.
//! - The fixed tar form: paths sorted, ustar headers, mtime 0, uid and gid 0, no user names, regular files
//!   only, a pax `path` record only for a path that does not fit the ustar name and prefix fields.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::env::jcs;

pub const MAX_FILES: usize = 100;
pub const MAX_FILE_BYTES: u64 = 1024 * 1024;
pub const MAX_VERSION_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_UPLOAD_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_PATH_BYTES: usize = 255;

/// The two kept modes.
pub const MODE_FILE: u32 = 0o644;
pub const MODE_EXEC: u32 = 0o755;

/// One file of a version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct File {
    pub path: String,
    pub mode: u32,
    pub data: Vec<u8>,
}

/// One entry of a version's file list, without the content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub path: String,
    pub mode: u32,
    pub size: u64,
    /// 64 lowercase hex characters.
    pub sha256: String,
}

impl Entry {
    pub fn of(f: &File) -> Entry {
        Entry {
            path: f.path.clone(),
            mode: f.mode,
            size: f.data.len() as u64,
            sha256: hex_sha256(&f.data),
        }
    }
}

pub fn hex_sha256(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for b in Sha256::digest(bytes) {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// The text form of a kept mode: `0644` or `0755`.
pub fn mode_text(mode: u32) -> String {
    format!("{mode:04o}")
}

/// Reads a mode from a file list answer: the text `0644`/`644`, or the number 420/493.
pub fn mode_from(v: &Value) -> Option<u32> {
    let m = match v {
        Value::String(s) => u32::from_str_radix(s, 8).ok()?,
        Value::Number(n) => u32::try_from(n.as_u64()?).ok()?,
        _ => return None,
    };
    matches!(m, MODE_FILE | MODE_EXEC).then_some(m)
}

/// Reads a file hash from an answer: `sha256:<hex>` or bare hex. Returns the bare hex.
pub fn sha_from(v: &Value) -> Option<String> {
    let s = v.as_str()?;
    let hex = s.strip_prefix("sha256:").unwrap_or(s);
    (hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    .then(|| hex.to_string())
}

/// The canonical file list that the version hash covers.
///
/// `mode` is the text `0644` or `0755` and `sha256` is the bare hex of the file (Prego-QB, 2026-11-19).
/// The shared test vectors of the registry check it.
pub fn file_list(entries: &[Entry]) -> Value {
    let mut sorted: Vec<&Entry> = entries.iter().collect();
    sorted.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    let files: Vec<Value> = sorted
        .iter()
        .map(|e| {
            json!({
                "path": e.path,
                "mode": mode_text(e.mode),
                "size": e.size,
                "sha256": e.sha256,
            })
        })
        .collect();
    json!({ "files": files })
}

/// The version hash: `sha256:<hex>` of the canonical file list.
pub fn version_hash(entries: &[Entry]) -> Result<String, String> {
    jcs::hash(&file_list(entries))
}

/// Checks one path against item 4. The error says why.
pub fn check_path(path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("the path is empty".into());
    }
    if path.len() > MAX_PATH_BYTES {
        return Err(format!("the path is longer than {MAX_PATH_BYTES} bytes"));
    }
    if path.starts_with('/') {
        return Err("the path starts with /".into());
    }
    if path.bytes().any(|b| b == 0) {
        return Err("the path has a NUL byte".into());
    }
    if path.contains('\\') {
        return Err("the path has a `\\` (use `/`)".into());
    }
    if let Some(c) = path
        .chars()
        .find(|c| c.is_ascii_control() || is_c1(*c) || is_bidi_control(*c))
    {
        return Err(format!(
            "the path has the control character U+{:04X} (C0, C1 and bidi controls are refused)",
            u32::from(c)
        ));
    }
    for seg in path.split('/') {
        match seg {
            "" => return Err("the path has an empty segment".into()),
            "." | ".." => return Err(format!("the path has a `{seg}` segment")),
            _ => {}
        }
    }
    Ok(())
}

/// C1 control characters, U+0080 to U+009F.
fn is_c1(c: char) -> bool {
    ('\u{80}'..='\u{9f}').contains(&c)
}

/// Bidi embedding, override and isolate controls: U+202A to U+202E and U+2066 to U+2069.
fn is_bidi_control(c: char) -> bool {
    ('\u{202a}'..='\u{202e}').contains(&c) || ('\u{2066}'..='\u{2069}').contains(&c)
}

/// The key under which two paths are the same: Unicode NFC, then lowercase.
pub fn fold(path: &str) -> String {
    icu_normalizer::ComposingNormalizerBorrowed::new_nfc()
        .normalize(path)
        .to_lowercase()
}

/// No two paths are the same after NFC and lowercase, and no path is also a folder of another path
/// (`a` and `a/b`, also `A` and `a/b`). Both checks use the folded key, as a case-folding file system would.
fn check_clashes(files: &[File]) -> Result<(), String> {
    let mut folded: std::collections::BTreeMap<String, &str> = std::collections::BTreeMap::new();
    for f in files {
        if let Some(other) = folded.insert(fold(&f.path), &f.path) {
            return Err(format!(
                "the paths {other} and {} are the same after Unicode NFC and lowercase",
                f.path
            ));
        }
    }
    // `/` is not changed by NFC or lowercase, so the folder prefixes of a folded path are the folded folders.
    for (key, path) in &folded {
        for (i, b) in key.bytes().enumerate() {
            if b != b'/' {
                continue;
            }
            if let Some(file) = folded.get(&key[..i]) {
                return Err(format!("{file} is a file and also a folder of {path}"));
            }
        }
    }
    Ok(())
}

/// On Windows a `:` in a segment would change where the file goes. Other systems write it as it is.
fn check_local_path(path: &str) -> Result<(), String> {
    if cfg!(windows) && path.contains(':') {
        return Err("the path has a `:`, which this system cannot write as a name".into());
    }
    Ok(())
}

/// Checks a whole version against item 4: the file count, the sizes, the paths (unique), UTF-8 and NUL.
pub fn check_files(files: &[File]) -> Result<(), String> {
    if files.is_empty() {
        return Err("there are no files".into());
    }
    if files.len() > MAX_FILES {
        return Err(format!(
            "{} files: a version has at most {MAX_FILES} files",
            files.len()
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut total = 0u64;
    for f in files {
        check_path(&f.path).map_err(|e| format!("{}: {e}", f.path))?;
        if !seen.insert(f.path.as_str()) {
            return Err(format!("{}: the path is there two times", f.path));
        }
        if !matches!(f.mode, MODE_FILE | MODE_EXEC) {
            return Err(format!(
                "{}: the mode {:o} is not 0644 or 0755",
                f.path, f.mode
            ));
        }
        let size = f.data.len() as u64;
        if size > MAX_FILE_BYTES {
            return Err(format!(
                "{}: {size} bytes: a file is at most 1 MiB ({MAX_FILE_BYTES} bytes)",
                f.path
            ));
        }
        total += size;
        check_text(&f.data).map_err(|e| format!("{}: {e}", f.path))?;
    }
    check_clashes(files)?;
    if total > MAX_VERSION_BYTES {
        return Err(format!(
            "{total} bytes: the files of a version are at most 8 MiB ({MAX_VERSION_BYTES} bytes) together"
        ));
    }
    Ok(())
}

/// UTF-8 with no NUL byte.
pub fn check_text(data: &[u8]) -> Result<(), String> {
    if let Some(i) = data.iter().position(|b| *b == 0) {
        return Err(format!("a NUL byte at offset {i}: a snippet file is text"));
    }
    std::str::from_utf8(data)
        .map(|_| ())
        .map_err(|e| format!("not UTF-8 text ({e})"))
}

/// Reads the files of a push or a hash: every regular file under a folder, or one file (its name is its path).
/// A folder named `.git` is skipped; other dotfiles are kept. Symlinks and other special files are refused,
/// not followed. Empty folders give nothing.
pub fn collect(source: &Path) -> Result<Vec<File>, String> {
    let meta =
        std::fs::symlink_metadata(source).map_err(|e| format!("{}: {e}", source.display()))?;
    let mut files = Vec::new();
    if meta.is_dir() {
        walk(source, "", &mut files)?;
    } else if meta.is_file() {
        let name = source
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| format!("{}: the file name is not UTF-8", source.display()))?;
        files.push(read_file(source, name, &meta)?);
    } else {
        return Err(format!(
            "{}: not a folder or a regular file (symlinks are refused)",
            source.display()
        ));
    }
    files.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    Ok(files)
}

fn walk(dir: &Path, prefix: &str, files: &mut Vec<File>) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("{}: {e}", dir.display()))?;
        let full = entry.path();
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| format!("{}: the name is not UTF-8", full.display()))?;
        let rel = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let meta =
            std::fs::symlink_metadata(&full).map_err(|e| format!("{}: {e}", full.display()))?;
        if meta.is_dir() {
            if rel.rsplit('/').next() == Some(".git") {
                continue;
            }
            walk(&full, &rel, files)?;
        } else if meta.is_file() {
            if files.len() >= MAX_FILES {
                return Err(format!(
                    "more than {MAX_FILES} files: a version has at most {MAX_FILES} files"
                ));
            }
            files.push(read_file(&full, &rel, &meta)?);
        } else {
            return Err(format!(
                "{rel}: not a regular file (symlinks, devices and sockets are refused)"
            ));
        }
    }
    Ok(())
}

fn read_file(full: &Path, rel: &str, meta: &std::fs::Metadata) -> Result<File, String> {
    if meta.len() > MAX_FILE_BYTES {
        return Err(format!(
            "{rel}: {} bytes: a file is at most 1 MiB ({MAX_FILE_BYTES} bytes)",
            meta.len()
        ));
    }
    let mut data = Vec::with_capacity(meta.len() as usize);
    std::fs::File::open(full)
        .and_then(|f| f.take(MAX_FILE_BYTES + 1).read_to_end(&mut data))
        .map_err(|e| format!("{rel}: {e}"))?;
    Ok(File {
        path: rel.to_string(),
        mode: local_mode(meta),
        data,
    })
}

/// The owner's execute bit gives `0755`; every other file is `0644`.
#[cfg(unix)]
fn local_mode(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    if meta.permissions().mode() & 0o100 != 0 {
        MODE_EXEC
    } else {
        MODE_FILE
    }
}

#[cfg(not(unix))]
fn local_mode(_meta: &std::fs::Metadata) -> u32 {
    MODE_FILE
}

// ---- The fixed tar form ----

const BLOCK: usize = 512;

/// The uncompressed tar of a version in the fixed form.
pub fn tar(files: &[File]) -> Vec<u8> {
    let mut sorted: Vec<&File> = files.iter().collect();
    sorted.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    let mut out = Vec::new();
    for f in sorted {
        let (name, prefix) = match ustar_split(&f.path) {
            Some(np) => np,
            None => {
                let record = pax_record("path", &f.path);
                let pax_name = "PaxHeaders/entry";
                out.extend_from_slice(&header(pax_name, "", 0o644, record.len() as u64, b'x'));
                write_padded(&mut out, record.as_bytes());
                (truncate_name(&f.path), String::new())
            }
        };
        out.extend_from_slice(&header(&name, &prefix, f.mode, f.data.len() as u64, b'0'));
        write_padded(&mut out, &f.data);
    }
    out.extend_from_slice(&[0u8; BLOCK * 2]);
    out
}

/// The `.tar.gz` of a version: the fixed tar, gzip level 6, no file name and mtime 0 in the gzip header.
/// Only the uncompressed tar is the same as the registry's; the version hash is on the file list.
pub fn tar_gz(files: &[File]) -> Vec<u8> {
    let mut gz = flate2::GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), flate2::Compression::new(6));
    gz.write_all(&tar(files))
        .expect("writing to memory does not fail");
    gz.finish().expect("writing to memory does not fail")
}

/// Splits a path into the ustar `name` (at most 100 bytes) and `prefix` (at most 155 bytes) at a `/`.
fn ustar_split(path: &str) -> Option<(String, String)> {
    if path.len() <= 100 {
        return Some((path.to_string(), String::new()));
    }
    // The longest prefix that fits, so that the name is as short as possible.
    for (i, b) in path.bytes().enumerate().rev() {
        if b == b'/' && i <= 155 && path.len() - i - 1 <= 100 && i > 0 {
            return Some((path[i + 1..].to_string(), path[..i].to_string()));
        }
    }
    None
}

/// The last 100 bytes of the path, cut at a character boundary, for the header that follows a pax record.
fn truncate_name(path: &str) -> String {
    let mut start = path.len().saturating_sub(100);
    while !path.is_char_boundary(start) {
        start += 1;
    }
    path[start..].to_string()
}

/// One pax record `"<len> <key>=<value>\n"`, where `<len>` counts the whole record with its own digits.
fn pax_record(key: &str, value: &str) -> String {
    let body = format!(" {key}={value}\n");
    let mut len = body.len() + 1;
    loop {
        let total = body.len() + len.to_string().len();
        if total == len {
            return format!("{len}{body}");
        }
        len = total;
    }
}

fn header(name: &str, prefix: &str, mode: u32, size: u64, kind: u8) -> [u8; BLOCK] {
    let mut h = [0u8; BLOCK];
    h[..name.len()].copy_from_slice(name.as_bytes());
    octal(&mut h[100..108], u64::from(mode));
    octal(&mut h[108..116], 0); // uid
    octal(&mut h[116..124], 0); // gid
    octal(&mut h[124..136], size);
    octal(&mut h[136..148], 0); // mtime
    h[148..156].fill(b' ');
    h[156] = kind;
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    octal(&mut h[329..337], 0); // devmajor
    octal(&mut h[337..345], 0); // devminor
    h[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
    let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
    let text = format!("{sum:06o}\0 ");
    h[148..156].copy_from_slice(text.as_bytes());
    h
}

/// Zero-padded octal digits and a NUL in the whole field.
fn octal(field: &mut [u8], value: u64) {
    let digits = field.len() - 1;
    let text = format!("{value:0digits$o}");
    field[..digits].copy_from_slice(text.as_bytes());
    field[digits] = 0;
}

fn write_padded(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(data);
    let pad = (BLOCK - data.len() % BLOCK) % BLOCK;
    out.extend(std::iter::repeat_n(0u8, pad));
}

/// Reads a `.tar.gz` or `.tar` of a version: for `prego snippet push --tar` and the check of
/// `prego snippet get --tar`. Only regular files are accepted (directory entries are skipped); the mode is
/// mapped by the owner's execute bit; every file is checked with [`check_files`].
pub fn untar(bytes: &[u8]) -> Result<Vec<File>, String> {
    // The unpacked tar is the content plus headers: content 8 MiB, at most 100 files of 3 blocks each.
    const MAX_UNPACKED: u64 = MAX_VERSION_BYTES + (MAX_FILES as u64 + 1) * 3 * BLOCK as u64 + 2048;
    let gz = bytes.starts_with(&[0x1f, 0x8b]);
    let reader: Box<dyn Read + '_> = if gz {
        Box::new(flate2::read::GzDecoder::new(bytes))
    } else {
        Box::new(bytes)
    };
    let mut plain = Vec::new();
    reader
        .take(MAX_UNPACKED + 1)
        .read_to_end(&mut plain)
        .map_err(|e| format!("the tarball cannot be read: {e}"))?;
    if plain.len() as u64 > MAX_UNPACKED {
        return Err("the unpacked tarball is larger than a version can be".into());
    }
    let mut archive = tar::Archive::new(plain.as_slice());
    let mut files = Vec::new();
    for entry in archive
        .entries()
        .map_err(|e| format!("the tarball cannot be read: {e}"))?
    {
        let mut entry = entry.map_err(|e| format!("the tarball cannot be read: {e}"))?;
        let kind = entry.header().entry_type();
        let mut path = String::from_utf8(entry.path_bytes().into_owned())
            .map_err(|_| "a path in the tarball is not UTF-8".to_string())?;
        // A tar entry `./a` is the file `a`, as the registry reads it.
        if let Some(rest) = path.strip_prefix("./") {
            path = rest.to_string();
        }
        if kind.is_dir() {
            continue;
        }
        if !kind.is_file() {
            return Err(format!("{path}: not a regular file in the tarball"));
        }
        // The owner's execute bit gives 0755, every other mode 0644, as the registry does.
        let mode = if entry.header().mode().map_err(|e| format!("{path}: {e}"))? & 0o100 != 0 {
            MODE_EXEC
        } else {
            MODE_FILE
        };
        if files.len() >= MAX_FILES {
            return Err(format!("more than {MAX_FILES} files in the tarball"));
        }
        let mut data = Vec::new();
        (&mut entry)
            .take(MAX_FILE_BYTES + 1)
            .read_to_end(&mut data)
            .map_err(|e| format!("{path}: {e}"))?;
        files.push(File { path, mode, data });
    }
    check_files(&files)?;
    files.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    Ok(files)
}

// ---- The safe write of `prego snippet get` ----

/// Creates the folder, or checks that it is empty. Returns true if it was created.
pub fn prepare_folder(dir: &Path) -> Result<bool, String> {
    match std::fs::symlink_metadata(dir) {
        Ok(meta) if meta.file_type().is_symlink() => Err(format!(
            "the folder {} is a symlink. Give a new or empty folder",
            dir.display()
        )),
        Ok(meta) if !meta.is_dir() => Err(format!("{} is not a folder", dir.display())),
        Ok(_) => {
            let mut entries =
                std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            if entries.next().is_some() {
                return Err(format!(
                    "the folder {} is not empty. Give a new or empty folder",
                    dir.display()
                ));
            }
            Ok(false)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(dir)
                .map_err(|e| format!("cannot make the folder {}: {e}", dir.display()))?;
            Ok(true)
        }
        Err(e) => Err(format!("cannot read the folder {}: {e}", dir.display())),
    }
}

/// Writes the checked files under `root`, which [`prepare_folder`] made new or empty. Every path is checked
/// again here: it must stay in `root`. Files get mode `0644` or `0755` only. On an error, the files and
/// folders written here are removed again.
pub fn write_all(root: &Path, files: &[File]) -> Result<(), String> {
    let mut made: Vec<PathBuf> = Vec::new();
    let result = write_inner(root, files, &mut made);
    if result.is_err() {
        for p in made.iter().rev() {
            let _ = std::fs::remove_file(p).or_else(|_| std::fs::remove_dir(p));
        }
    }
    result
}

fn write_inner(root: &Path, files: &[File], made: &mut Vec<PathBuf>) -> Result<(), String> {
    let root_real = std::fs::canonicalize(root).map_err(|e| format!("{}: {e}", root.display()))?;
    for f in files {
        check_path(&f.path).map_err(|e| format!("{}: {e}", f.path))?;
        check_local_path(&f.path).map_err(|e| format!("{}: {e}", f.path))?;
        if !matches!(f.mode, MODE_FILE | MODE_EXEC) {
            return Err(format!(
                "{}: the mode {:o} is not 0644 or 0755",
                f.path, f.mode
            ));
        }
        let segments: Vec<&str> = f.path.split('/').collect();
        let (file_name, dirs) = segments.split_last().expect("a checked path has a segment");
        let mut dir = root.to_path_buf();
        for seg in dirs {
            dir.push(seg);
            match std::fs::symlink_metadata(&dir) {
                Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {}
                Ok(_) => {
                    return Err(format!(
                        "{}: {} is there and is not a folder",
                        f.path,
                        dir.display()
                    ))
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    std::fs::create_dir(&dir)
                        .map_err(|e| format!("cannot make {}: {e}", dir.display()))?;
                    made.push(dir.clone());
                }
                Err(e) => return Err(format!("{}: {e}", dir.display())),
            }
        }
        // The folder of the file must be inside the root, also after the links are resolved.
        let dir_real =
            std::fs::canonicalize(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        if !dir_real.starts_with(&root_real) {
            return Err(format!(
                "{}: the path leaves the folder {}",
                f.path,
                root.display()
            ));
        }
        let target = dir.join(file_name);
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)
            .map_err(|e| format!("cannot write {}: {e}", target.display()))?;
        made.push(target.clone());
        out.write_all(&f.data)
            .and_then(|_| out.flush())
            .map_err(|e| format!("cannot write {}: {e}", target.display()))?;
        drop(out);
        set_mode(&target, f.mode)?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("cannot set the mode of {}: {e}", path.display()))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(path: &str, mode: u32, data: &str) -> File {
        File {
            path: path.into(),
            mode,
            data: data.as_bytes().to_vec(),
        }
    }

    fn temp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("prego-snip-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn the_hash_does_not_depend_on_the_order() {
        let a = [
            f("b.sh", MODE_EXEC, "echo b\n"),
            f("a.md", MODE_FILE, "# a\n"),
        ];
        let b = [
            f("a.md", MODE_FILE, "# a\n"),
            f("b.sh", MODE_EXEC, "echo b\n"),
        ];
        let ea: Vec<Entry> = a.iter().map(Entry::of).collect();
        let eb: Vec<Entry> = b.iter().map(Entry::of).collect();
        assert_eq!(version_hash(&ea).unwrap(), version_hash(&eb).unwrap());
        // A changed mode is a changed version.
        let c = [
            f("a.md", MODE_FILE, "# a\n"),
            f("b.sh", MODE_FILE, "echo b\n"),
        ];
        let ec: Vec<Entry> = c.iter().map(Entry::of).collect();
        assert_ne!(version_hash(&ea).unwrap(), version_hash(&ec).unwrap());
    }

    #[test]
    fn the_file_list_is_canonical_json_sorted_by_path_bytes() {
        let files = [
            f("b", MODE_FILE, ""),
            f("B", MODE_EXEC, "x"),
            f("a/z", MODE_FILE, ""),
        ];
        let entries: Vec<Entry> = files.iter().map(Entry::of).collect();
        let text = jcs::canonical(&file_list(&entries)).unwrap();
        let empty = hex_sha256(b"");
        let x = hex_sha256(b"x");
        assert_eq!(
            text,
            format!(
                "{{\"files\":[\
                 {{\"mode\":\"0755\",\"path\":\"B\",\"sha256\":\"{x}\",\"size\":1}},\
                 {{\"mode\":\"0644\",\"path\":\"a/z\",\"sha256\":\"{empty}\",\"size\":0}},\
                 {{\"mode\":\"0644\",\"path\":\"b\",\"sha256\":\"{empty}\",\"size\":0}}]}}"
            )
        );
        assert_eq!(
            version_hash(&entries).unwrap(),
            jcs::hash_bytes(text.as_bytes())
        );
    }

    #[test]
    fn path_rules() {
        for ok in ["a", "a/b.txt", "x/.hidden", "a..b", &"a".repeat(255)] {
            assert!(check_path(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "/a",
            "a//b",
            "a/",
            "./a",
            "a/../b",
            "..",
            "a\0b",
            "a\\b",
            &"a".repeat(256),
        ] {
            assert!(check_path(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn control_characters_in_paths() {
        for bad in [
            "a\u{85}b",
            "x/\u{9f}",
            "evil\u{202e}txt.sh",
            "a\u{2066}b",
            "a\u{2069}",
        ] {
            assert!(
                check_path(bad).unwrap_err().contains("control character"),
                "{bad:?}"
            );
        }
        for bad in [
            "a\u{1}b",
            "tab\there",
            "new\nline",
            "esc\u{1b}[31m",
            "del\u{7f}",
        ] {
            assert!(
                check_path(bad).unwrap_err().contains("control character"),
                "{bad:?}"
            );
        }
        for ok in [
            "caf\u{e9}.md",
            "a\u{a0}b",
            "a\u{2065}b",
            "a\u{202f}b",
            "a b~!",
        ] {
            assert!(check_path(ok).is_ok(), "{ok:?}");
        }
    }

    #[test]
    fn clashing_paths() {
        let clash = |paths: &[&str]| {
            let files: Vec<File> = paths.iter().map(|p| f(p, MODE_FILE, "x")).collect();
            check_files(&files)
        };
        assert!(clash(&["a", "a/b"]).unwrap_err().contains("also a folder"));
        assert!(clash(&["x/a", "x/a/b/c"])
            .unwrap_err()
            .contains("also a folder"));
        assert!(clash(&["README.md", "readme.md"])
            .unwrap_err()
            .contains("NFC and lowercase"));
        // U+00E9 and U+0065 U+0301 are the same after NFC.
        assert!(clash(&["caf\u{e9}.md", "cafe\u{301}.md"])
            .unwrap_err()
            .contains("NFC"));
        assert!(clash(&["A", "a/b"])
            .unwrap_err()
            .contains("A is a file and also a folder of a/b"));
        assert!(clash(&["x/Caf\u{e9}", "x/cafe\u{301}/y"])
            .unwrap_err()
            .contains("also a folder"));
        assert!(clash(&["D/x", "d/y"]).is_ok());
        assert!(clash(&["a", "ab/c", "a.b/c"]).is_ok());
        assert_eq!(fold("Caf\u{e9}/X"), fold("cafe\u{301}/x"));
    }

    #[test]
    fn untar_refuses_a_name_that_is_not_utf8() {
        let mut raw = tar(&[f("ok", MODE_FILE, "x")]);
        raw[0] = 0xff;
        let mut h = [0u8; BLOCK];
        h.copy_from_slice(&raw[..BLOCK]);
        h[148..156].fill(b' ');
        let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
        raw[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        assert!(untar(&raw).unwrap_err().contains("not UTF-8"));
    }

    #[test]
    fn content_rules() {
        assert!(check_files(&[f("a", MODE_FILE, "ok")]).is_ok());
        assert!(check_files(&[]).is_err());
        assert!(
            check_files(&[f("a", MODE_FILE, "x"), f("a", MODE_FILE, "y")])
                .unwrap_err()
                .contains("two times")
        );
        assert!(check_files(&[f("a", 0o600, "x")])
            .unwrap_err()
            .contains("0644"));
        assert!(check_files(&[f("a", MODE_FILE, "a\0b")])
            .unwrap_err()
            .contains("NUL"));
        let bin = File {
            path: "a".into(),
            mode: MODE_FILE,
            data: vec![0xff, 0xfe],
        };
        assert!(check_files(&[bin]).unwrap_err().contains("UTF-8"));
        let big = File {
            path: "a".into(),
            mode: MODE_FILE,
            data: vec![b'a'; MAX_FILE_BYTES as usize + 1],
        };
        assert!(check_files(&[big]).unwrap_err().contains("1 MiB"));
        let many: Vec<File> = (0..=MAX_FILES)
            .map(|i| f(&format!("f{i}"), MODE_FILE, ""))
            .collect();
        assert!(check_files(&many).unwrap_err().contains("at most 100"));
        let nine: Vec<File> = (0..9)
            .map(|i| File {
                path: format!("f{i}"),
                mode: MODE_FILE,
                data: vec![b'a'; MAX_FILE_BYTES as usize],
            })
            .collect();
        assert!(check_files(&nine).unwrap_err().contains("8 MiB"));
    }

    #[test]
    fn the_tar_is_fixed_and_reads_back() {
        let long_dir = format!("{}/{}", "d".repeat(120), "e".repeat(30));
        let long_path = format!("{long_dir}/file.txt");
        let no_split = "n".repeat(200);
        let files = vec![
            f("run.sh", MODE_EXEC, "#!/bin/sh\necho hi\n"),
            f("a/b/prompt.md", MODE_FILE, "Say hello, ünïcode.\n"),
            f(&long_path, MODE_FILE, "deep\n"),
            f(&no_split, MODE_FILE, "pax\n"),
        ];
        let mut shuffled = files.clone();
        shuffled.reverse();
        assert_eq!(tar(&files), tar(&shuffled));
        assert_eq!(tar_gz(&files), tar_gz(&shuffled));
        let back = untar(&tar_gz(&files)).unwrap();
        let mut want = files.clone();
        want.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
        assert_eq!(back, want);
        assert_eq!(untar(&tar(&files)).unwrap(), want);
        // The headers: mtime 0, uid and gid 0, no user names, ustar magic.
        let t = tar(&[f("x", MODE_FILE, "1")]);
        assert_eq!(&t[136..147], b"00000000000");
        assert_eq!(&t[108..115], b"0000000");
        assert_eq!(&t[116..123], b"0000000");
        assert_eq!(&t[100..107], b"0000644");
        assert!(t[265..329].iter().all(|b| *b == 0));
        assert_eq!(&t[257..263], b"ustar\0");
        assert_eq!(t.len(), BLOCK * 4);
    }

    #[test]
    fn pax_record_length_counts_itself() {
        let r = pax_record("path", "abc");
        assert_eq!(r, "12 path=abc\n");
        assert_eq!(r.len(), 12);
        let long = "x".repeat(95);
        let r = pax_record("path", &long);
        assert_eq!(r.len().to_string(), r.split(' ').next().unwrap());
    }

    #[test]
    fn untar_refuses_bad_entries() {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_ustar();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        h.set_mode(0o777);
        b.append_link(&mut h, "link", "/etc/passwd").unwrap();
        let bytes = b.into_inner().unwrap();
        assert!(untar(&bytes).unwrap_err().contains("not a regular file"));

        let mut raw = tar(&[f("ok", MODE_FILE, "x")]);
        // Make the name `../ok`: the header checksum must be fixed too.
        let mut h = [0u8; BLOCK];
        h.copy_from_slice(&raw[..BLOCK]);
        let mut name = [0u8; 100];
        name[..5].copy_from_slice(b"../ok");
        h[..100].copy_from_slice(&name);
        h[148..156].fill(b' ');
        let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        raw[..BLOCK].copy_from_slice(&h);
        assert!(untar(&raw).unwrap_err().contains(".."));
    }

    #[test]
    fn collect_reads_a_folder_and_a_file() {
        let d = temp("collect");
        std::fs::create_dir_all(d.join("sub")).unwrap();
        std::fs::write(d.join("sub/b.md"), "b\n").unwrap();
        std::fs::write(d.join("a.sh"), "a\n").unwrap();
        std::fs::write(d.join(".env.example"), "A=1\n").unwrap();
        std::fs::create_dir_all(d.join(".git/objects")).unwrap();
        std::fs::write(d.join(".git/objects/x"), [0xffu8, 0]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(d.join("a.sh"), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let files = collect(&d).unwrap();
        let paths: Vec<&str> = files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, [".env.example", "a.sh", "sub/b.md"]);
        if cfg!(unix) {
            assert_eq!(files[1].mode, MODE_EXEC);
        }
        assert_eq!(files[2].mode, MODE_FILE);
        let one = collect(&d.join("sub/b.md")).unwrap();
        assert_eq!(one[0].path, "b.md");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/etc/passwd", d.join("link")).unwrap();
            assert!(collect(&d).unwrap_err().contains("symlinks"));
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn write_all_keeps_files_in_the_folder() {
        let d = temp("write");
        assert!(prepare_folder(&d).unwrap());
        let files = vec![
            f("run.sh", MODE_EXEC, "echo\n"),
            f("deep/er/x.md", MODE_FILE, "x\n"),
        ];
        write_all(&d, &files).unwrap();
        assert_eq!(
            std::fs::read_to_string(d.join("deep/er/x.md")).unwrap(),
            "x\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = |p: &str| std::fs::metadata(d.join(p)).unwrap().permissions().mode() & 0o7777;
            assert_eq!(m("run.sh"), 0o755);
            assert_eq!(m("deep/er/x.md"), 0o644);
        }
        // Not empty now.
        assert!(prepare_folder(&d).unwrap_err().contains("not empty"));

        let d2 = temp("write-bad");
        prepare_folder(&d2).unwrap();
        let bad = vec![
            f("ok.md", MODE_FILE, "x"),
            f("../escape.md", MODE_FILE, "x"),
        ];
        assert!(write_all(&d2, &bad).unwrap_err().contains(".."));
        // The file written before the error is removed again.
        assert!(std::fs::read_dir(&d2).unwrap().next().is_none());
        assert!(!d2.parent().unwrap().join("escape.md").exists());
        let abs = vec![f("/etc/x", MODE_FILE, "x")];
        assert!(write_all(&d2, &abs).is_err());
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&d2);
    }

    fn vectors() -> (PathBuf, Value) {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/snippets");
        let cases = std::fs::read_to_string(dir.join("cases.json")).unwrap();
        (dir, serde_json::from_str(&cases).unwrap())
    }

    /// The shared vectors of the registry (apps/registry/test/vectors/snippets, data only): the canonical
    /// text and the hash of each case, with the modes from cases.json.
    #[test]
    fn shared_vectors_hash() {
        let (dir, v) = vectors();
        let cases = v["cases"].as_array().unwrap();
        assert!(cases.len() >= 5);
        for case in cases {
            let root = dir.join(case["dir"].as_str().unwrap());
            let entries: Vec<Entry> = case["files"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| {
                    let path = f["path"].as_str().unwrap();
                    let data = std::fs::read(root.join(path)).unwrap();
                    Entry::of(&File {
                        path: path.into(),
                        mode: mode_from(&f["mode"]).unwrap(),
                        data,
                    })
                })
                .collect();
            let name = case["name"].as_str().unwrap();
            assert_eq!(
                jcs::canonical(&file_list(&entries)).unwrap(),
                case["canonical"].as_str().unwrap(),
                "{name}"
            );
            assert_eq!(
                version_hash(&entries).unwrap(),
                case["hash"].as_str().unwrap(),
                "{name}"
            );
            // The tar form reads back to the same hash.
            let files: Vec<File> = entries
                .iter()
                .map(|e| File {
                    path: e.path.clone(),
                    mode: e.mode,
                    data: std::fs::read(root.join(&e.path)).unwrap(),
                })
                .collect();
            let back: Vec<Entry> = untar(&tar_gz(&files))
                .unwrap()
                .iter()
                .map(Entry::of)
                .collect();
            assert_eq!(
                version_hash(&back).unwrap(),
                case["hash"].as_str().unwrap(),
                "{name}"
            );
        }
    }

    #[test]
    fn shared_vectors_invalid_paths_and_tar_modes() {
        let (_, v) = vectors();
        for p in v["invalid_paths"].as_array().unwrap() {
            let path = p["path"].as_str().unwrap();
            assert!(check_path(path).is_err(), "{path:?} ({})", p["reason"]);
        }
        for m in v["tar_modes"].as_array().unwrap() {
            let tar_mode = u32::from_str_radix(m["tar_mode"].as_str().unwrap(), 8).unwrap();
            let want = mode_from(&m["mode"]).unwrap();
            let mut b = tar::Builder::new(Vec::new());
            let mut h = tar::Header::new_ustar();
            h.set_size(1);
            h.set_mode(tar_mode);
            h.set_entry_type(tar::EntryType::Regular);
            b.append_data(&mut h, "./x.sh", &b"x"[..]).unwrap();
            let mut d = tar::Header::new_ustar();
            d.set_size(0);
            d.set_mode(0o755);
            d.set_entry_type(tar::EntryType::Directory);
            b.append_data(&mut d, "dir/", &b""[..]).unwrap();
            let files = untar(&b.into_inner().unwrap()).unwrap();
            assert_eq!(files.len(), 1);
            assert_eq!(files[0].path, "x.sh");
            assert_eq!(files[0].mode, want, "tar mode {tar_mode:o}");
        }
    }

    #[test]
    fn modes_and_hashes_from_answers() {
        assert_eq!(mode_from(&json!("0755")), Some(MODE_EXEC));
        assert_eq!(mode_from(&json!("644")), Some(MODE_FILE));
        assert_eq!(mode_from(&json!(420)), Some(MODE_FILE));
        assert_eq!(mode_from(&json!("0777")), None);
        let h = "a".repeat(64);
        assert_eq!(sha_from(&json!(format!("sha256:{h}"))), Some(h.clone()));
        assert_eq!(sha_from(&json!(h.clone())), Some(h));
        assert_eq!(sha_from(&json!("sha256:xyz")), None);
    }
}
