//! A temporary test directory that is removed when it goes out of scope, also when the test panics. Before the
//! removal, each file in it is overwritten with zeros and synced, because tests put private key files in it.

use std::path::{Path, PathBuf};

pub struct ScrubDir(PathBuf);

impl ScrubDir {
    /// Makes an empty directory `prego-<name>-<pid>` in the system temp directory.
    pub fn new(name: &str) -> ScrubDir {
        let dir = std::env::temp_dir().join(format!("prego-{name}-{}", std::process::id()));
        scrub(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        ScrubDir(dir)
    }
}

impl std::ops::Deref for ScrubDir {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScrubDir {
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
        let p = e.path();
        if t.is_dir() {
            zero_files(&p);
        } else if t.is_file() {
            if let Ok(m) = e.metadata() {
                if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&p) {
                    use std::io::Write as _;
                    let _ = f.write_all(&vec![0u8; m.len() as usize]);
                    let _ = f.sync_all();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removed_on_drop_and_on_panic() {
        let path = {
            let d = ScrubDir::new("scrub-drop");
            std::fs::create_dir_all(d.join("sub")).unwrap();
            std::fs::write(d.join("sub/k.pem"), "secret").unwrap();
            d.to_path_buf()
        };
        assert!(!path.exists());
        let r = std::panic::catch_unwind(|| {
            let d = ScrubDir::new("scrub-panic");
            std::fs::write(d.join("k.pem"), "secret").unwrap();
            panic!("test panic");
        });
        assert!(r.is_err());
        assert!(!std::env::temp_dir()
            .join(format!("prego-scrub-panic-{}", std::process::id()))
            .exists());
    }
}
