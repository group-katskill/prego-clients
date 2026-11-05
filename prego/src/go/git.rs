//! Reads a module from the git tree of a tag. It never reads the working directory.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use super::zip::{Candidate, Mode};

/// Runs git in `dir` and returns stdout. Git's stderr is shown on failure.
fn git(dir: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("prego: cannot run git: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "prego: git {} failed: {}",
            args.first().unwrap_or(&""),
            err.trim()
        ));
    }
    Ok(out.stdout)
}

fn git_line(dir: &Path, args: &[&str]) -> Result<String, String> {
    let out = git(dir, args)?;
    Ok(String::from_utf8_lossy(&out).trim().to_string())
}

/// Where the module is in its repository.
#[derive(Debug, Clone)]
pub struct Location {
    /// The repository root.
    pub root: std::path::PathBuf,
    /// The module directory relative to the root, with `/`, or empty for the root.
    pub subdir: String,
}

/// Finds the repository of `dir` and the path of `dir` in it.
pub fn locate(dir: &Path) -> Result<Location, String> {
    if !dir.is_dir() {
        return Err(format!("prego: `{}` is not a directory", dir.display()));
    }
    let root = git_line(dir, &["rev-parse", "--show-toplevel"])
        .map_err(|_| format!("prego: `{}` is not in a git repository", dir.display()))?;
    let prefix = git_line(dir, &["rev-parse", "--show-prefix"])?;
    Ok(Location {
        root: root.into(),
        subdir: prefix.trim_end_matches('/').to_string(),
    })
}

/// The tags that point at `HEAD`.
pub fn tags_at_head(loc: &Location) -> Result<Vec<String>, String> {
    let out = git_line(&loc.root, &["tag", "--points-at", "HEAD"])?;
    Ok(out.lines().map(str::to_string).collect())
}

/// The full commit hash of a tag.
pub fn tag_commit(loc: &Location, tag: &str) -> Result<String, String> {
    if tag.starts_with('-') || tag.contains("..") {
        return Err(format!("prego: bad tag `{tag}`"));
    }
    let r = format!("refs/tags/{tag}^{{commit}}");
    git_line(&loc.root, &["rev-parse", "--verify", "--quiet", &r])
        .ok()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| format!("prego: tag `{tag}` is not in this repository"))
}

/// One entry of `git ls-tree`.
#[derive(Debug, Clone)]
pub struct TreeEntry {
    /// Path from the repository root.
    pub path: String,
    pub mode: String,
    pub object: String,
    pub size: u64,
}

/// Lists all blobs of `commit` (recursively), with their sizes.
pub fn ls_tree(loc: &Location, commit: &str) -> Result<Vec<TreeEntry>, String> {
    let out = git(
        &loc.root,
        &["ls-tree", "-r", "-l", "-z", "--full-tree", commit],
    )?;
    let mut entries = Vec::new();
    for rec in out.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        let tab = rec
            .iter()
            .position(|b| *b == b'\t')
            .ok_or("prego: unexpected git ls-tree output")?;
        let meta = String::from_utf8_lossy(&rec[..tab]);
        let path = String::from_utf8(rec[tab + 1..].to_vec())
            .map_err(|_| "prego: a file name in the tag is not UTF-8".to_string())?;
        let mut f = meta.split_whitespace();
        let (Some(mode), Some(kind), Some(object), Some(size)) =
            (f.next(), f.next(), f.next(), f.next())
        else {
            return Err("prego: unexpected git ls-tree output".into());
        };
        // Submodules (commits) have no content in this repository.
        if kind != "blob" {
            continue;
        }
        entries.push(TreeEntry {
            path,
            mode: mode.to_string(),
            object: object.to_string(),
            size: size.parse().unwrap_or(0),
        });
    }
    Ok(entries)
}

/// The module files under `dir` (a path from the root, or empty), with paths relative to `dir`. Like the go
/// command, it adds the root `LICENSE` when the module is in a subdirectory and has no `LICENSE` of its own.
pub fn module_files(entries: &[TreeEntry], dir: &str) -> Vec<Candidate> {
    let prefix = if dir.is_empty() {
        String::new()
    } else {
        format!("{dir}/")
    };
    let mut files = Vec::new();
    let mut have_license = false;
    for e in entries {
        let Some(rel) = e.path.strip_prefix(&prefix) else {
            continue;
        };
        if rel.is_empty() {
            continue;
        }
        if rel == "LICENSE" {
            have_license = true;
        }
        files.push(Candidate {
            path: rel.to_string(),
            mode: if e.mode == "120000" {
                Mode::Symlink
            } else {
                Mode::Regular
            },
            size: e.size,
            object: e.object.clone(),
        });
    }
    if !have_license && !dir.is_empty() {
        if let Some(e) = entries.iter().find(|e| e.path == "LICENSE") {
            // The go command reads it with `git cat-file blob`, so a symlink gives its target text.
            files.push(Candidate {
                path: "LICENSE".into(),
                mode: Mode::Regular,
                size: e.size,
                object: e.object.clone(),
            });
        }
    }
    files
}

/// Reads blobs with one `git cat-file --batch` process.
pub struct Blobs {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Blobs {
    pub fn open(loc: &Location) -> Result<Blobs, String> {
        let mut child = Command::new("git")
            .arg("-C")
            .arg(&loc.root)
            .args(["cat-file", "--batch"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("prego: cannot run git: {e}"))?;
        let stdin = child
            .stdin
            .take()
            .ok_or("prego: git cat-file has no stdin")?;
        let stdout = BufReader::new(
            child
                .stdout
                .take()
                .ok_or("prego: git cat-file has no stdout")?,
        );
        Ok(Blobs {
            child,
            stdin,
            stdout,
        })
    }

    /// The content of one blob.
    pub fn read(&mut self, object: &str) -> Result<Vec<u8>, String> {
        let io = |e: std::io::Error| format!("prego: git cat-file: {e}");
        writeln!(self.stdin, "{object}").map_err(io)?;
        self.stdin.flush().map_err(io)?;
        let mut header = String::new();
        self.stdout.read_line(&mut header).map_err(io)?;
        let mut f = header.split_whitespace();
        let (Some(_), Some(kind), Some(size)) = (f.next(), f.next(), f.next()) else {
            return Err(format!("prego: git cat-file: object {object} is missing"));
        };
        if kind != "blob" {
            return Err(format!(
                "prego: git cat-file: {object} is a {kind}, not a blob"
            ));
        }
        let size: usize = size
            .parse()
            .map_err(|_| "prego: git cat-file: bad size".to_string())?;
        let mut data = vec![0u8; size];
        self.stdout.read_exact(&mut data).map_err(io)?;
        let mut nl = [0u8; 1];
        self.stdout.read_exact(&mut nl).map_err(io)?;
        Ok(data)
    }
}

impl Drop for Blobs {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(path: &str, mode: &str) -> TreeEntry {
        TreeEntry {
            path: path.into(),
            mode: mode.into(),
            object: format!("obj-{path}"),
            size: 3,
        }
    }

    #[test]
    fn subdir_files_and_root_license() {
        let entries = [
            e("LICENSE", "100644"),
            e("go.mod", "100644"),
            e("sub/go.mod", "100644"),
            e("sub/a.go", "100755"),
            e("sub/l.go", "120000"),
            e("subx/b.go", "100644"),
        ];
        let f = module_files(&entries, "sub");
        let names: Vec<&str> = f.iter().map(|c| c.path.as_str()).collect();
        assert_eq!(names, ["go.mod", "a.go", "l.go", "LICENSE"]);
        assert_eq!(f[2].mode, Mode::Symlink);
        assert_eq!(f[3].object, "obj-LICENSE");
        // At the root, no extra LICENSE.
        assert_eq!(module_files(&entries, "").len(), 6);
    }
}
