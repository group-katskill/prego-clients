//! Module zip files and `h1` hashes, as `golang.org/x/mod/zip` and `golang.org/x/mod/sumdb/dirhash` make them.

use std::collections::HashMap;
#[cfg(test)]
use std::io::Read;
use std::io::{Seek, SeekFrom, Write};

use base64::Engine;
use sha2::{Digest, Sha256};

use super::module;

/// Largest module zip that Prego takes, compressed and uncompressed: 300 MiB. The registry has the same cap.
/// Go's own limit (`x/mod/zip` `MaxZipFile`) is 500 MiB.
pub const MAX_ZIP_BYTES: u64 = 300 << 20;

/// The refusal text for a module that is larger than [`MAX_ZIP_BYTES`].
fn too_large(what: &str, size: u64) -> String {
    format!(
        "{what} is {size} bytes ({:.1} MiB); Prego takes a module zip of at most 300 MiB ({MAX_ZIP_BYTES} bytes), \
         compressed and uncompressed. Nothing was sent",
        size as f64 / (1u64 << 20) as f64
    )
}

/// Refuses a zip size above [`MAX_ZIP_BYTES`].
pub fn check_zip_size(size: u64) -> Result<(), String> {
    if size > MAX_ZIP_BYTES {
        return Err(too_large("the zip", size));
    }
    Ok(())
}
/// Largest `go.mod` that Prego takes (Go allows 16 MiB).
pub const MAX_GO_MOD_BYTES: u64 = 1 << 20;
/// Largest `LICENSE` (`x/mod/zip` `MaxLICENSE`).
pub const MAX_LICENSE_BYTES: u64 = 16 << 20;
/// Largest number of entries (no zip64).
pub const MAX_ENTRIES: usize = 65535;

/// The kind of a file in the git tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Regular,
    Symlink,
}

/// A file of the module, with its path relative to the module directory.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub path: String,
    pub mode: Mode,
    pub size: u64,
    /// Where the content comes from (a git object ID).
    pub object: String,
}

/// Why a file is not in the zip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Omit {
    Vendored,
    Submodule,
    HgArchival,
    NotRegular,
}

/// The result of [`select`]: the files for the zip, and the files that were left out.
#[derive(Debug, Default)]
pub struct Selection {
    pub files: Vec<Candidate>,
    pub omitted: Vec<(String, Omit)>,
}

/// Applies the file rules of `x/mod/zip` `Create` to `candidates`, in their order. Invalid files are errors:
/// Go would refuse the whole module.
pub fn select(candidates: Vec<Candidate>) -> Result<Selection, String> {
    // A directory with a regular go.mod (other than the root) is a nested module.
    let mut have_go_mod: Vec<String> = Vec::new();
    for c in &candidates {
        let (dir, base) = split(&c.path);
        if base.eq_ignore_ascii_case("go.mod") && c.mode == Mode::Regular {
            have_go_mod.push(dir.to_string());
        }
    }
    let in_submodule = |p: &str| -> bool {
        let mut p = p;
        loop {
            let (dir, _) = split(p);
            if dir.is_empty() {
                return false;
            }
            if have_go_mod.iter().any(|d| d == dir) {
                return true;
            }
            p = &dir[..dir.len() - 1];
        }
    };

    let mut out = Selection::default();
    let mut collisions = Collisions::default();
    let mut total: u64 = 0;
    let mut errors = Vec::new();
    for c in candidates {
        let p = c.path.as_str();
        if is_vendored_package(p) {
            out.omitted.push((c.path, Omit::Vendored));
            continue;
        }
        if in_submodule(p) {
            out.omitted.push((c.path, Omit::Submodule));
            continue;
        }
        if p == ".hg_archival.txt" {
            out.omitted.push((c.path, Omit::HgArchival));
            continue;
        }
        if let Err(e) = module::check_file_path(p) {
            errors.push(e);
            continue;
        }
        if let Err(e) = collisions.check(p) {
            errors.push(e);
            continue;
        }
        if c.mode != Mode::Regular {
            out.omitted.push((c.path, Omit::NotRegular));
            continue;
        }
        total = total.saturating_add(c.size);
        if p == "go.mod" && c.size > MAX_GO_MOD_BYTES {
            errors.push(format!(
                "go.mod is {} bytes; Prego takes at most {MAX_GO_MOD_BYTES}",
                c.size
            ));
        }
        if p == "LICENSE" && c.size > MAX_LICENSE_BYTES {
            errors.push(format!("LICENSE is larger than {MAX_LICENSE_BYTES} bytes"));
        }
        out.files.push(c);
    }
    if total > MAX_ZIP_BYTES {
        errors.push(too_large("the total of the module files", total));
    }
    if out.files.len() > MAX_ENTRIES {
        errors.push(format!(
            "the module has {} files; a module zip can hold at most {MAX_ENTRIES}",
            out.files.len()
        ));
    }
    if !out.files.iter().any(|f| f.path == "go.mod") {
        errors.push("the module has no go.mod at the tag".into());
    }
    if !errors.is_empty() {
        errors.truncate(20);
        return Err(format!(
            "the module cannot be zipped:\n  {}",
            errors.join("\n  ")
        ));
    }
    Ok(out)
}

fn split(p: &str) -> (&str, &str) {
    match p.rfind('/') {
        Some(i) => (&p[..=i], &p[i + 1..]),
        None => ("", p),
    }
}

/// `x/mod/zip` `isVendoredPackage`, with its offset quirk kept: Go cannot change it without changing the
/// checksums of published modules.
fn is_vendored_package(name: &str) -> bool {
    let i = if name.starts_with("vendor/") {
        "vendor/".len()
    } else if name.contains("/vendor/") {
        "/vendor/".len()
    } else {
        return false;
    };
    name.get(i..).is_some_and(|rest| rest.contains('/'))
}

/// File names that differ only in case (also with the directories above them).
#[derive(Default)]
struct Collisions(HashMap<String, (String, bool)>);

impl Collisions {
    fn check(&mut self, p: &str) -> Result<(), String> {
        self.check_one(p, false)
    }

    fn check_one(&mut self, p: &str, is_dir: bool) -> Result<(), String> {
        let lower = p.to_lowercase();
        if let Some((other, other_dir)) = self.0.get(&lower) {
            if other != p {
                return Err(format!(
                    "case-insensitive file name collision: `{other}` and `{p}`"
                ));
            }
            if *other_dir != is_dir {
                return Err(format!("entry `{p}` is both a file and a directory"));
            }
            if is_dir {
                return Ok(());
            }
        }
        self.0.insert(lower, (p.to_string(), is_dir));
        if let Some((dir, _)) = p.rsplit_once('/') {
            self.check_one(dir, true)?;
        }
        Ok(())
    }
}

/// Builds the `h1:` hash of a set of files, like `dirhash.Hash1`. `files` holds (name, SHA-256 of the content).
pub fn hash1(files: &[(String, [u8; 32])]) -> Result<String, String> {
    let mut sorted: Vec<&(String, [u8; 32])> = files.iter().collect();
    sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let mut summary = Sha256::new();
    for (name, digest) in sorted {
        if name.contains('\n') {
            return Err("file names with a new line are not allowed".into());
        }
        summary.update(format!("{}  {name}\n", hex(digest)));
    }
    Ok(format!(
        "h1:{}",
        base64::engine::general_purpose::STANDARD.encode(summary.finalize())
    ))
}

/// The `h1:` of a `go.mod` file (the `/go.mod` line of `go.sum`).
pub fn mod_hash1(go_mod: &[u8]) -> String {
    hash1(&[("go.mod".to_string(), Sha256::digest(go_mod).into())])
        .expect("the name go.mod is valid")
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Writes a module zip: one deflate entry per file, named `<module>@<version>/<path>`, with no directory
/// entries and no zip64. It returns the zip h1.
pub struct ZipWriter<W: Write + Seek> {
    out: W,
    prefix: String,
    central: Vec<u8>,
    entries: usize,
    hashes: Vec<(String, [u8; 32])>,
}

impl<W: Write + Seek> ZipWriter<W> {
    pub fn new(out: W, module: &str, version: &str) -> Self {
        ZipWriter {
            out,
            prefix: format!("{module}@{version}/"),
            central: Vec::new(),
            entries: 0,
            hashes: Vec::new(),
        }
    }

    /// Adds one file. `content` is read to the end.
    pub fn add(&mut self, path: &str, content: &[u8]) -> Result<(), String> {
        let name = format!("{}{path}", self.prefix);
        let crc = crc32fast::hash(content);
        let mut enc =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(content).map_err(|e| e.to_string())?;
        let packed = enc.finish().map_err(|e| e.to_string())?;
        let offset = self.out.stream_position().map_err(|e| e.to_string())?;
        let too_big = |n: u64| n > u32::MAX as u64 - 1;
        if too_big(offset) || too_big(packed.len() as u64) || too_big(content.len() as u64) {
            return Err("the zip is too large for a zip without zip64".into());
        }
        let utf8 = if name.is_ascii() { 0 } else { 0x0800u16 };
        let name_bytes = name.as_bytes();

        let mut local = Vec::with_capacity(30 + name_bytes.len());
        local.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        local.extend_from_slice(&20u16.to_le_bytes()); // version needed
        local.extend_from_slice(&utf8.to_le_bytes()); // flags
        local.extend_from_slice(&8u16.to_le_bytes()); // deflate
        local.extend_from_slice(&0u16.to_le_bytes()); // time
        local.extend_from_slice(&0x0021u16.to_le_bytes()); // date 1980-01-01
        local.extend_from_slice(&crc.to_le_bytes());
        local.extend_from_slice(&(packed.len() as u32).to_le_bytes());
        local.extend_from_slice(&(content.len() as u32).to_le_bytes());
        local.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes()); // extra
        local.extend_from_slice(name_bytes);
        self.out.write_all(&local).map_err(|e| e.to_string())?;
        self.out.write_all(&packed).map_err(|e| e.to_string())?;

        let c = &mut self.central;
        c.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        c.extend_from_slice(&20u16.to_le_bytes()); // made by
        c.extend_from_slice(&20u16.to_le_bytes()); // version needed
        c.extend_from_slice(&utf8.to_le_bytes());
        c.extend_from_slice(&8u16.to_le_bytes());
        c.extend_from_slice(&0u16.to_le_bytes());
        c.extend_from_slice(&0x0021u16.to_le_bytes());
        c.extend_from_slice(&crc.to_le_bytes());
        c.extend_from_slice(&(packed.len() as u32).to_le_bytes());
        c.extend_from_slice(&(content.len() as u32).to_le_bytes());
        c.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        c.extend_from_slice(&0u16.to_le_bytes()); // extra
        c.extend_from_slice(&0u16.to_le_bytes()); // comment
        c.extend_from_slice(&0u16.to_le_bytes()); // disk
        c.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
        c.extend_from_slice(&0u32.to_le_bytes()); // external attributes
        c.extend_from_slice(&(offset as u32).to_le_bytes());
        c.extend_from_slice(name_bytes);

        self.entries += 1;
        self.hashes.push((name, Sha256::digest(content).into()));
        Ok(())
    }

    /// Writes the central directory. Returns the writer, the zip size and the zip h1.
    pub fn finish(mut self) -> Result<(W, u64, String), String> {
        if self.entries > MAX_ENTRIES {
            return Err(format!("more than {MAX_ENTRIES} files"));
        }
        let start = self.out.stream_position().map_err(|e| e.to_string())?;
        self.out
            .write_all(&self.central)
            .map_err(|e| e.to_string())?;
        let mut end = Vec::with_capacity(22);
        end.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        end.extend_from_slice(&0u16.to_le_bytes());
        end.extend_from_slice(&0u16.to_le_bytes());
        end.extend_from_slice(&(self.entries as u16).to_le_bytes());
        end.extend_from_slice(&(self.entries as u16).to_le_bytes());
        end.extend_from_slice(&(self.central.len() as u32).to_le_bytes());
        end.extend_from_slice(&(start as u32).to_le_bytes());
        end.extend_from_slice(&0u16.to_le_bytes());
        self.out.write_all(&end).map_err(|e| e.to_string())?;
        self.out.flush().map_err(|e| e.to_string())?;
        let size = self.out.stream_position().map_err(|e| e.to_string())?;
        check_zip_size(size)?;
        let h1 = hash1(&self.hashes)?;
        self.out
            .seek(SeekFrom::Start(0))
            .map_err(|e| e.to_string())?;
        Ok((self.out, size, h1))
    }
}

#[cfg(test)]
/// Computes the h1 of an existing module zip (for tests and checks): the SHA-256 of each entry, by name.
pub fn zip_hash1(mut zip: impl Read) -> Result<String, String> {
    let mut data = Vec::new();
    zip.read_to_end(&mut data).map_err(|e| e.to_string())?;
    let mut files = Vec::new();
    for (name, content) in read_entries(&data)? {
        files.push((name, Sha256::digest(&content).into()));
    }
    hash1(&files)
}

#[cfg(test)]
/// Reads the entries of a zip (store or deflate, no zip64) from its central directory.
pub fn read_entries(data: &[u8]) -> Result<Vec<(String, Vec<u8>)>, String> {
    let u16_at = |i: usize| -> Result<u16, String> {
        data.get(i..i + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .ok_or_else(|| "truncated zip".to_string())
    };
    let u32_at = |i: usize| -> Result<u32, String> {
        data.get(i..i + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .ok_or_else(|| "truncated zip".to_string())
    };
    let eocd = (0..data.len().saturating_sub(21))
        .rev()
        .find(|&i| u32_at(i) == Ok(0x0605_4b50))
        .ok_or("no end of central directory")?;
    let count = u16_at(eocd + 10)? as usize;
    let mut at = u32_at(eocd + 16)? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        if u32_at(at)? != 0x0201_4b50 {
            return Err("bad central directory".into());
        }
        let method = u16_at(at + 10)?;
        let packed = u32_at(at + 20)? as usize;
        let name_len = u16_at(at + 28)? as usize;
        let extra = u16_at(at + 30)? as usize;
        let comment = u16_at(at + 32)? as usize;
        let local = u32_at(at + 42)? as usize;
        let name = String::from_utf8(
            data.get(at + 46..at + 46 + name_len)
                .ok_or("truncated zip")?
                .to_vec(),
        )
        .map_err(|_| "a zip name is not UTF-8".to_string())?;
        at += 46 + name_len + extra + comment;
        let l_name = u16_at(local + 26)? as usize;
        let l_extra = u16_at(local + 28)? as usize;
        let start = local + 30 + l_name + l_extra;
        let raw = data.get(start..start + packed).ok_or("truncated zip")?;
        let content = match method {
            0 => raw.to_vec(),
            8 => {
                let mut v = Vec::new();
                flate2::read::DeflateDecoder::new(raw)
                    .read_to_end(&mut v)
                    .map_err(|e| e.to_string())?;
                v
            }
            m => return Err(format!("zip method {m} is not supported")),
        };
        out.push((name, content));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn cand(path: &str, mode: Mode) -> Candidate {
        Candidate {
            path: path.into(),
            mode,
            size: 1,
            object: String::new(),
        }
    }

    #[test]
    fn selection_rules() {
        let s = select(vec![
            cand("go.mod", Mode::Regular),
            cand("a.go", Mode::Regular),
            cand("vendor/modules.txt", Mode::Regular),
            cand("vendor/x/x.go", Mode::Regular),
            cand("pkg/vendor/y/y.go", Mode::Regular),
            cand("nested/go.mod", Mode::Regular),
            cand("nested/deep/n.go", Mode::Regular),
            cand("link.go", Mode::Symlink),
            cand("linkmod/GO.MOD", Mode::Symlink),
            cand("linkmod/l.go", Mode::Regular),
            cand(".hg_archival.txt", Mode::Regular),
            cand("sub/.hg_archival.txt", Mode::Regular),
        ])
        .unwrap();
        let names: Vec<&str> = s.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(
            names,
            [
                "go.mod",
                "a.go",
                "vendor/modules.txt",
                "linkmod/l.go",
                "sub/.hg_archival.txt"
            ]
        );
        assert!(s
            .omitted
            .contains(&("vendor/x/x.go".into(), Omit::Vendored)));
        assert!(s
            .omitted
            .contains(&("pkg/vendor/y/y.go".into(), Omit::Vendored)));
        assert!(s
            .omitted
            .contains(&("nested/go.mod".into(), Omit::Submodule)));
        assert!(s.omitted.contains(&("link.go".into(), Omit::NotRegular)));
    }

    #[test]
    fn size_cap_300_mib() {
        const MIB: u64 = 1 << 20;
        assert_eq!(MAX_ZIP_BYTES, 300 * MIB);
        let sized = |size| Candidate {
            size,
            ..cand("big.bin", Mode::Regular)
        };
        // go.mod is 1 byte, so 300 MiB minus 1 byte of other files is exactly at the cap.
        select(vec![cand("go.mod", Mode::Regular), sized(300 * MIB - 1)]).unwrap();
        let err = select(vec![cand("go.mod", Mode::Regular), sized(300 * MIB)]).unwrap_err();
        assert!(err.contains("314572801 bytes"), "{err}");
        assert!(err.contains("at most 300 MiB"), "{err}");

        check_zip_size(300 * MIB).unwrap();
        let err = check_zip_size(300 * MIB + 1).unwrap_err();
        assert!(err.contains("the zip is 314572801 bytes"), "{err}");
        assert!(err.contains("Nothing was sent"), "{err}");
    }

    #[test]
    fn vendored_quirk() {
        assert!(is_vendored_package("vendor/a/b.go"));
        assert!(!is_vendored_package("vendor/modules.txt"));
        // The offset quirk: the rest after 8 bytes of "a/vendor/b.go" is "/b.go", which has a slash.
        assert!(is_vendored_package("a/vendor/b.go"));
        assert!(!is_vendored_package("abcdefgh/vendor"));
    }

    #[test]
    fn invalid_files_are_errors() {
        let e = select(vec![
            cand("go.mod", Mode::Regular),
            cand("a.go", Mode::Regular),
            cand("A.go", Mode::Regular),
        ])
        .unwrap_err();
        assert!(e.contains("collision"), "{e}");
        let e = select(vec![
            cand("go.mod", Mode::Regular),
            cand("x/aux.c", Mode::Regular),
        ])
        .unwrap_err();
        assert!(e.contains("Windows"), "{e}");
        let e = select(vec![cand("a.go", Mode::Regular)]).unwrap_err();
        assert!(e.contains("no go.mod"), "{e}");
        let mut big = cand("go.mod", Mode::Regular);
        big.size = MAX_GO_MOD_BYTES + 1;
        assert!(select(vec![big]).is_err());
    }

    #[test]
    fn zip_round_trip_and_h1() {
        let mut w = ZipWriter::new(Cursor::new(Vec::new()), "go.acme.com/x", "v1.0.0");
        w.add("go.mod", b"module go.acme.com/x\n").unwrap();
        w.add("a.go", b"package x\n").unwrap();
        let (cur, size, h1) = w.finish().unwrap();
        let data = cur.into_inner();
        assert_eq!(size as usize, data.len());
        let entries = read_entries(&data).unwrap();
        assert_eq!(entries[0].0, "go.acme.com/x@v1.0.0/go.mod");
        assert_eq!(entries[1].1, b"package x\n");
        assert_eq!(zip_hash1(&data[..]).unwrap(), h1);
    }

    #[test]
    fn known_hashes() {
        // dirhash test vector: Hash1 of a single empty file named "xyz".
        let empty: [u8; 32] = Sha256::digest(b"").into();
        let h = hash1(&[("xyz".into(), empty)]).unwrap();
        let line = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  xyz\n";
        let want = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(line));
        assert_eq!(h, format!("h1:{want}"));
        assert!(hash1(&[("a\nb".into(), empty)]).is_err());
    }
}
