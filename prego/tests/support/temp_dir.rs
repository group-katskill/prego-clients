//! A temp directory for the integration tests. It is removed when it goes out of scope, also when the test
//! panics. Before the removal, each file in it is overwritten with zeros and synced, because tests put key files,
//! tokens and session files in it.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

pub struct TempDir(PathBuf);

impl TempDir {
    /// Makes an empty directory `prego-<name>-<pid>` in the system temp directory.
    pub fn new(name: &str) -> TempDir {
        let dir = std::env::temp_dir().join(format!("prego-{name}-{}", std::process::id()));
        scrub(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
}

impl std::ops::Deref for TempDir {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for TempDir {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        scrub(&self.0);
    }
}

/// Overwrites each regular file under `dir` with zeros, then removes `dir`. Symbolic links are removed, not
/// followed. Errors are ignored: this is cleanup.
pub fn scrub(dir: &Path) {
    zero_files(dir);
    let _ = std::fs::remove_dir_all(dir);
}

fn zero_files(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let Ok(t) = e.file_type() else { continue };
        if t.is_dir() {
            zero_files(&e.path());
        } else if t.is_file() {
            if let (Ok(m), Ok(mut f)) = (
                e.metadata(),
                std::fs::OpenOptions::new().write(true).open(e.path()),
            ) {
                use std::io::Write as _;
                let _ = f.write_all(&vec![0u8; m.len() as usize]);
                let _ = f.sync_all();
            }
        }
    }
}
