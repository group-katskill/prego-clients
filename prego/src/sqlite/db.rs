//! The SQLite side of `prego sqlite` (ADR-0059 items 7 and 17): a consistent copy with the online backup API
//! or `VACUUM INTO`, and `PRAGMA quick_check` or `integrity_check`. The source file bytes are never read
//! directly.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rusqlite::backup::{Backup, StepResult};
use rusqlite::{Connection, OpenFlags};

/// How long a copy waits for a lock that another program holds.
const BUSY: Duration = Duration::from_secs(60);

/// The check on a copy or a restored file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    Quick,
    Full,
    None,
}

impl Check {
    pub fn parse(s: &str) -> Result<Check, String> {
        match s {
            "quick" => Ok(Check::Quick),
            "full" => Ok(Check::Full),
            "none" => Ok(Check::None),
            _ => Err(format!("bad --check `{s}`: use quick, full or none")),
        }
    }

    /// The value of the reserved label `prego.check` after a check that passed.
    pub fn label(self) -> &'static str {
        match self {
            Check::Quick => "quick_check:ok",
            Check::Full => "integrity_check:ok",
            Check::None => "none",
        }
    }

    fn pragma(self) -> Option<&'static str> {
        match self {
            Check::Quick => Some("quick_check"),
            Check::Full => Some("integrity_check"),
            Check::None => None,
        }
    }
}

/// A private folder for the copy, removed when it is dropped.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new() -> Result<TempDir, String> {
        let base = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        for n in 0..100u32 {
            let p = base.join(format!(
                "prego-sqlite-{}-{nanos:08x}-{n}",
                std::process::id()
            ));
            let mut b = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                b.mode(0o700);
            }
            match b.create(&p) {
                Ok(()) => return Ok(TempDir(p)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(format!("{}: {e}", p.display())),
            }
        }
        Err(format!("{}: no free folder name", base.display()))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A `file:` URI that opens `path` read-only as immutable: SQLite makes no `-wal`, `-shm` or `-journal`
/// file next to it and takes no locks.
fn immutable_uri(path: &Path) -> Result<String, String> {
    let abs = std::path::absolute(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let s = abs
        .to_str()
        .ok_or_else(|| format!("{}: the path is not UTF-8", abs.display()))?;
    let mut out = String::from("file:");
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                out.push(b as char)
            }
            #[cfg(windows)]
            b'\\' => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out.push_str("?mode=ro&immutable=1");
    Ok(out)
}

fn open_immutable(path: &Path) -> Result<Connection, String> {
    Connection::open_with_flags(
        immutable_uri(path)?,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| format!("{}: {e}", path.display()))
}

/// The error text for a source that SQLite cannot read. An encrypted file looks like "not a database".
fn source_error(path: &Path, e: rusqlite::Error) -> String {
    let text = e.to_string();
    if text.contains("not a database") {
        format!(
            "{}: {text}. It is not a SQLite database, or it is encrypted (Prego does not accept encrypted \
             databases)",
            path.display()
        )
    } else {
        format!("{}: {text}", path.display())
    }
}

/// The flags that open the source: read-only, except for a WAL database that no program has open (no `-wal`
/// and no `-shm` file). A read-only connection cannot remove the `-wal` and `-shm` files that it makes, and a
/// `-wal` file left next to the database stops a later `prego sqlite restore` to that path. Opened read-write
/// (never created), the connection writes nothing, and SQLite removes the two files when it closes the
/// database as the last connection. Only the 100-byte header is read here, to find the journal mode.
fn source_flags(source: &Path) -> OpenFlags {
    use std::io::Read;
    let ro = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let mut h = [0u8; 20];
    let wal = File::open(source)
        .and_then(|mut f| f.read_exact(&mut h))
        .is_ok()
        && &h[..16] == b"SQLite format 3\0"
        && h[18] == 2
        && h[19] == 2;
    let side = |s: &str| {
        let mut p = source.as_os_str().to_owned();
        p.push(s);
        std::fs::symlink_metadata(PathBuf::from(p)).is_ok()
    };
    if wal && !side("-wal") && !side("-shm") {
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX
    } else {
        ro
    }
}

/// Copies the database `source` to the new file `dest` with the online backup API (the page layout stays),
/// or with `VACUUM INTO` when `compact` is true (no free pages). The copy is consistent: one read
/// transaction, so a program can keep using the source.
pub fn copy(source: &Path, dest: &Path, compact: bool) -> Result<(), String> {
    let meta = std::fs::metadata(source).map_err(|e| format!("{}: {e}", source.display()))?;
    if !meta.is_file() {
        return Err(format!("{}: not a file", source.display()));
    }
    // SQLite opens a file of 0 bytes as an empty database; Prego refuses it as not a database.
    if meta.len() == 0 {
        return Err(format!(
            "{}: the file is empty (0 bytes): it is not a SQLite database",
            source.display()
        ));
    }
    let src = Connection::open_with_flags(source, source_flags(source))
        .map_err(|e| source_error(source, e))?;
    src.busy_timeout(BUSY)
        .map_err(|e| source_error(source, e))?;
    // Reads the schema, so a file that is not a database fails here with a clear message.
    src.query_row("SELECT count(*) FROM sqlite_schema", [], |r| {
        r.get::<_, i64>(0)
    })
    .map_err(|e| source_error(source, e))?;
    if compact {
        let d = dest
            .to_str()
            .ok_or_else(|| format!("{}: the path is not UTF-8", dest.display()))?;
        src.execute("VACUUM INTO ?1", [d])
            .map_err(|e| source_error(source, e))?;
        return Ok(());
    }
    let mut dst = Connection::open(dest).map_err(|e| format!("{}: {e}", dest.display()))?;
    {
        let b = Backup::new(&src, &mut dst).map_err(|e| source_error(source, e))?;
        let start = Instant::now();
        loop {
            // -1: all pages in one step, in one read transaction on the source.
            match b.step(-1).map_err(|e| source_error(source, e))? {
                StepResult::Done => break,
                StepResult::More => {}
                StepResult::Busy | StepResult::Locked => {
                    if start.elapsed() > BUSY {
                        return Err(format!(
                            "{}: the database stayed locked for {} s",
                            source.display(),
                            BUSY.as_secs()
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                _ => {}
            }
        }
    }
    dst.close()
        .map_err(|(_, e)| format!("{}: {e}", dest.display()))?;
    Ok(())
}

/// Runs the check on `path`, opened read-only as immutable. `Ok(None)`: passed or not run.
/// `Ok(Some(lines))`: the check found problems (the first lines of its answer).
pub fn check(path: &Path, check: Check) -> Result<Option<Vec<String>>, String> {
    let Some(pragma) = check.pragma() else {
        return Ok(None);
    };
    let c = match open_immutable(path) {
        Ok(c) => c,
        Err(e) => return Ok(Some(vec![e])),
    };
    let run = || -> rusqlite::Result<Vec<String>> {
        let mut st = c.prepare(&format!("PRAGMA {pragma}(100)"))?;
        let rows = st.query_map([], |r| r.get::<_, String>(0))?;
        rows.collect()
    };
    match run() {
        Ok(lines) if lines.len() == 1 && lines[0] == "ok" => Ok(None),
        Ok(lines) => Ok(Some(lines)),
        Err(e) => Ok(Some(vec![e.to_string()])),
    }
}

/// The values from the header of a SQLite file that `prego sqlite` shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub page_size: u32,
    pub page_count: u32,
    pub text_encoding: u32,
    pub user_version: u32,
    pub application_id: u32,
}

/// Reads the 100-byte header of a SQLite file (a copy that this program made).
pub fn header(path: &Path) -> Result<Header, String> {
    use std::io::Read;
    let mut h = [0u8; 100];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut h))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if &h[..16] != b"SQLite format 3\0" {
        return Err(format!("{}: not a SQLite database", path.display()));
    }
    let be = |o: usize| u32::from_be_bytes([h[o], h[o + 1], h[o + 2], h[o + 3]]);
    let raw = u16::from_be_bytes([h[16], h[17]]);
    Ok(Header {
        page_size: if raw == 1 { 65_536 } else { u32::from(raw) },
        page_count: be(28),
        text_encoding: be(56),
        user_version: be(60),
        application_id: be(68),
    })
}

/// The `-wal` and `-journal` files next to `target` that exist.
pub fn side_files(target: &Path) -> Vec<PathBuf> {
    ["-wal", "-journal"]
        .iter()
        .map(|s| {
            let mut p = target.as_os_str().to_owned();
            p.push(s);
            PathBuf::from(p)
        })
        .filter(|p| std::fs::symlink_metadata(p).is_ok())
        .collect()
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// Makes a small database at `path` with `rows` rows.
    pub fn make_db(path: &Path, rows: i64, wal: bool) {
        let c = Connection::open(path).unwrap();
        if wal {
            c.query_row("PRAGMA journal_mode=WAL", [], |r| r.get::<_, String>(0))
                .unwrap();
        }
        c.execute_batch(
            "CREATE TABLE IF NOT EXISTS t(id INTEGER PRIMARY KEY, v TEXT);
             PRAGMA user_version = 7;",
        )
        .unwrap();
        for i in 0..rows {
            c.execute(
                "INSERT INTO t(v) VALUES (?1)",
                [format!("row {i} {}", "x".repeat((i % 97) as usize))],
            )
            .unwrap();
        }
    }

    fn bytes(p: &Path) -> Vec<u8> {
        std::fs::read(p).unwrap()
    }

    #[test]
    fn copies_are_the_same_bytes() {
        let t = TempDir::new().unwrap();
        for wal in [false, true] {
            let src = t.path().join(format!("src-{wal}.db"));
            make_db(&src, 2000, wal);
            // Free pages, so that the compact copy is different.
            Connection::open(&src)
                .unwrap()
                .execute("DELETE FROM t WHERE id % 2 = 0", [])
                .unwrap();
            let (a, b) = (
                t.path().join(format!("a-{wal}")),
                t.path().join(format!("b-{wal}")),
            );
            copy(&src, &a, false).unwrap();
            copy(&src, &b, false).unwrap();
            assert!(bytes(&a) == bytes(&b), "backup copies differ (wal {wal})");
            let (c1, c2) = (
                t.path().join(format!("c1-{wal}")),
                t.path().join(format!("c2-{wal}")),
            );
            copy(&src, &c1, true).unwrap();
            copy(&src, &c2, true).unwrap();
            assert!(
                bytes(&c1) == bytes(&c2),
                "VACUUM INTO copies differ (wal {wal})"
            );
            assert!(bytes(&c1).len() < bytes(&a).len());
            for p in [&a, &c1] {
                assert_eq!(check(p, Check::Quick).unwrap(), None);
                assert_eq!(check(p, Check::Full).unwrap(), None);
                assert_eq!(header(p).unwrap().user_version, 7);
            }
            // The checks make no side files.
            assert!(side_files(&a).is_empty());
            assert!(std::fs::symlink_metadata(format!("{}-shm", a.display())).is_err());
        }
    }

    /// A save of a WAL database that no program has open leaves no -wal or -shm file next to it, so that a
    /// later restore to the same path is not refused.
    #[test]
    fn a_closed_wal_database_gets_no_side_files() {
        let t = TempDir::new().unwrap();
        let src = t.path().join("w.db");
        make_db(&src, 50, true);
        // make_db closed the database: SQLite removed its -wal and -shm files.
        assert!(side_files(&src).is_empty());
        for compact in [false, true] {
            let dest = t.path().join(format!("copy-{compact}"));
            copy(&src, &dest, compact).unwrap();
            assert!(side_files(&src).is_empty(), "compact {compact}");
            assert!(std::fs::symlink_metadata(format!("{}-shm", src.display())).is_err());
            assert_eq!(check(&dest, Check::Quick).unwrap(), None);
        }
    }

    #[test]
    fn refuses_a_file_that_is_not_a_database() {
        let t = TempDir::new().unwrap();
        let p = t.path().join("x.db");
        std::fs::write(&p, vec![0x5a; 8192]).unwrap();
        let e = copy(&p, &t.path().join("y"), false).unwrap_err();
        assert!(e.contains("encrypted"), "{e}");
        assert!(check(&p, Check::Quick).unwrap().is_some());
    }

    #[test]
    fn finds_damage() {
        let t = TempDir::new().unwrap();
        let p = t.path().join("d.db");
        make_db(&p, 3000, false);
        let mut b = bytes(&p);
        let ps = header(&p).unwrap().page_size as usize;
        // Damage the second page (a b-tree page of table t).
        for x in &mut b[ps + 8..ps + 64] {
            *x = 0xff;
        }
        std::fs::write(&p, &b).unwrap();
        assert!(check(&p, Check::Quick).unwrap().is_some());
        assert_eq!(check(&p, Check::None).unwrap(), None);
    }

    /// The shared vectors: the header values of the accepted files, and what a save does with the refused
    /// files. SQLite refuses most of them when it opens them. It reads `truncated.db` and `padded.db` as
    /// valid databases, so the copy that a save sends is a valid file, not the refused bytes.
    #[test]
    fn shared_vectors() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/sqlite");
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("cases.json")).unwrap())
                .unwrap();
        let t = TempDir::new().unwrap();
        for f in v["files"].as_array().unwrap() {
            let name = f["file"].as_str().unwrap();
            // A copy of the vector: SQLite makes -wal and -shm files next to a WAL database that it opens.
            let path = t.path().join(name);
            std::fs::copy(dir.join(name), &path).unwrap();
            let dest = t.path().join(format!("{name}.copy"));
            let u = |k: &str| f[k].as_u64().unwrap() as u32;
            if f["expect"] == "accept" {
                let h = header(&path).unwrap();
                assert_eq!(
                    (
                        h.page_size,
                        h.page_count,
                        h.text_encoding,
                        h.user_version,
                        h.application_id
                    ),
                    (
                        u("page_size"),
                        u("page_count"),
                        u("text_encoding"),
                        u("user_version"),
                        u("application_id")
                    ),
                    "{name}"
                );
                assert_eq!(check(&path, Check::Quick).unwrap(), None, "{name}");
                copy_is_valid(&path, &dest, name);
                continue;
            }
            match name {
                "truncated.db" | "padded.db" => copy_is_valid(&path, &dest, name),
                _ => assert!(copy(&path, &dest, false).is_err(), "{name} was copied"),
            }
        }
    }

    /// A copy (as a save makes it) that the server checks of ADR-0059 item 5 accept: the length is the header
    /// page count times the page size, and quick_check passes.
    fn copy_is_valid(path: &Path, dest: &Path, name: &str) {
        copy(path, dest, false).unwrap_or_else(|e| panic!("{name}: {e}"));
        let h = header(dest).unwrap();
        let len = std::fs::metadata(dest).unwrap().len();
        assert_eq!(
            len,
            u64::from(h.page_count) * u64::from(h.page_size),
            "{name}"
        );
        assert_eq!(check(dest, Check::Quick).unwrap(), None, "{name}");
    }

    #[test]
    fn uri_escapes() {
        let u = immutable_uri(Path::new("/tmp/a b?c#d%e.db")).unwrap();
        assert_eq!(u, "file:/tmp/a%20b%3Fc%23d%25e.db?mode=ro&immutable=1");
    }
}
