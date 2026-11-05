//! Reads an image to push from an OCI image layout directory or a `docker save` tar file.
//!
//! The result is a list of blobs (byte ranges in local files, never read into memory) and a list of
//! manifests in push order: child manifests first, the top manifest last.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Largest manifest that the registry accepts.
pub const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
/// Largest blob that the registry accepts.
pub const MAX_BLOB_BYTES: u64 = 10 * 1024 * 1024 * 1024;
/// Largest JSON file read from the input (index.json, manifest.json, oci-layout).
const MAX_JSON_BYTES: u64 = 4 * 1024 * 1024;

pub const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
pub const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
pub const DOCKER_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
pub const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
const OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
const OCI_LAYER_TAR: &str = "application/vnd.oci.image.layer.v1.tar";
const OCI_LAYER_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";

/// A byte range of a local file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub path: PathBuf,
    pub offset: u64,
    pub size: u64,
}

impl Source {
    /// A reader for `len` bytes from `start` (relative to this source).
    pub fn reader(&self, start: u64, len: u64) -> io::Result<io::Take<File>> {
        let mut f = File::open(&self.path)?;
        f.seek(SeekFrom::Start(self.offset + start))?;
        Ok(f.take(len))
    }

    fn read_all(&self, max: u64, what: &str) -> Result<Vec<u8>, String> {
        if self.size > max {
            return Err(format!("{what} is larger than {max} bytes"));
        }
        let mut buf = Vec::with_capacity(self.size as usize);
        self.reader(0, self.size)
            .and_then(|mut r| r.read_to_end(&mut buf))
            .map_err(|e| format!("cannot read {what}: {e}"))?;
        if buf.len() as u64 != self.size {
            return Err(format!("{what} is shorter than expected"));
        }
        Ok(buf)
    }

    /// The `sha256:<hex>` digest of the content.
    pub fn sha256(&self) -> Result<String, String> {
        let mut r = self
            .reader(0, self.size)
            .map_err(|e| format!("cannot read {}: {e}", self.path.display()))?;
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 1024 * 1024];
        let mut total = 0u64;
        loop {
            let n = r
                .read(&mut buf)
                .map_err(|e| format!("cannot read {}: {e}", self.path.display()))?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
            total += n as u64;
        }
        if total != self.size {
            return Err(format!("{} is shorter than expected", self.path.display()));
        }
        Ok(format!("sha256:{}", hex(&h.finalize())))
    }

    fn starts_with_gzip(&self) -> bool {
        let mut magic = [0u8; 2];
        self.size >= 2
            && self
                .reader(0, 2)
                .and_then(|mut r| r.read_exact(&mut magic))
                .is_ok()
            && magic == [0x1f, 0x8b]
    }
}

/// One blob to push.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blob {
    pub digest: String,
    pub size: u64,
    pub source: Source,
    /// True if the digest was computed from the content. Else it comes from a descriptor, and the content
    /// must be checked before the upload.
    pub verified: bool,
}

/// One manifest to push.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub digest: String,
    pub media_type: String,
    pub bytes: Vec<u8>,
}

/// An image to push.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    /// Unique blobs, in the order of first use.
    pub blobs: Vec<Blob>,
    /// Manifests in push order. The last one is the top manifest, pushed with the tag.
    pub manifests: Vec<Manifest>,
}

/// Where the content of an input is.
enum Store {
    /// An OCI image layout directory.
    Dir(PathBuf),
    /// Regular files of a tar file, by normalized path.
    Tar(PathBuf, HashMap<String, (u64, u64)>),
}

impl Store {
    fn file(&self, rel: &str) -> Option<Source> {
        match self {
            Store::Dir(root) => {
                let path = root.join(rel);
                let meta = std::fs::metadata(&path).ok()?;
                meta.is_file().then_some(Source {
                    path,
                    offset: 0,
                    size: meta.len(),
                })
            }
            Store::Tar(path, files) => files.get(rel).map(|&(offset, size)| Source {
                path: path.clone(),
                offset,
                size,
            }),
        }
    }

    fn blob(&self, digest: &str) -> Option<Source> {
        let hex = digest.strip_prefix("sha256:")?;
        self.file(&format!("blobs/sha256/{hex}"))
    }

    fn json(&self, rel: &str) -> Result<Option<Value>, String> {
        let Some(src) = self.file(rel) else {
            return Ok(None);
        };
        let bytes = src.read_all(MAX_JSON_BYTES, rel)?;
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| format!("{rel} in the input is not valid JSON"))
    }
}

/// Reads the image for `tag` from `input`.
pub fn load(input: &Path, tag: &str) -> Result<Image, String> {
    let store = if input.is_dir() {
        Store::Dir(input.to_path_buf())
    } else if input.is_file() {
        let files = index_tar(input)?;
        Store::Tar(input.to_path_buf(), files)
    } else {
        return Err(format!("input `{}` does not exist", input.display()));
    };

    let layout = store.json("oci-layout")?;
    let index = store.json("index.json")?;
    match (layout, index) {
        (Some(layout), Some(index)) => {
            if layout.get("imageLayoutVersion").and_then(Value::as_str) != Some("1.0.0") {
                return Err("oci-layout: imageLayoutVersion is not 1.0.0".into());
            }
            let top = select_top(&index, tag)?;
            let mut walk = Walk::new(&store);
            walk.descriptor(&top, 0)?;
            Ok(walk.finish())
        }
        _ => match (&store, store.json("manifest.json")?) {
            (Store::Tar(..), Some(m)) => docker_legacy(&store, &m, tag),
            _ => Err(format!(
                "`{}` is not an OCI image layout (oci-layout and index.json) or a docker save tar file",
                input.display()
            )),
        },
    }
}

/// Picks the top descriptor of `index.json`: the only one, or the one whose
/// `org.opencontainers.image.ref.name` is the tag.
fn select_top(index: &Value, tag: &str) -> Result<Value, String> {
    let list = index
        .get("manifests")
        .and_then(Value::as_array)
        .ok_or("index.json has no manifests")?;
    match list.as_slice() {
        [] => Err("index.json has no manifests".into()),
        [one] => Ok(one.clone()),
        many => {
            let name = |d: &Value| {
                d.pointer("/annotations/org.opencontainers.image.ref.name")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            };
            let hits: Vec<&Value> = many
                .iter()
                .filter(|d| name(d).as_deref() == Some(tag))
                .collect();
            match hits.as_slice() {
                [one] => Ok((*one).clone()),
                _ => {
                    let names: Vec<String> = many.iter().filter_map(name).collect();
                    Err(format!(
                        "index.json has {} images and none has the ref name `{tag}`. Ref names: {}",
                        many.len(),
                        if names.is_empty() {
                            "none".to_string()
                        } else {
                            names.join(", ")
                        }
                    ))
                }
            }
        }
    }
}

struct Walk<'a> {
    store: &'a Store,
    blobs: Vec<Blob>,
    seen_blobs: HashSet<String>,
    manifests: Vec<Manifest>,
    seen_manifests: HashSet<String>,
}

impl<'a> Walk<'a> {
    fn new(store: &'a Store) -> Self {
        Walk {
            store,
            blobs: Vec::new(),
            seen_blobs: HashSet::new(),
            manifests: Vec::new(),
            seen_manifests: HashSet::new(),
        }
    }

    fn finish(self) -> Image {
        Image {
            blobs: self.blobs,
            manifests: self.manifests,
        }
    }

    /// Adds a manifest (and, first, everything it points to).
    fn descriptor(&mut self, d: &Value, depth: usize) -> Result<(), String> {
        if depth > 4 {
            return Err("the image indexes are nested too deep".into());
        }
        let (digest, size, desc_type) = parse_descriptor(d)?;
        if self.seen_manifests.contains(&digest) {
            return Ok(());
        }
        let Some(src) = self.store.blob(&digest) else {
            let platform = d
                .get("platform")
                .map(|p| {
                    format!(
                        " (platform {}/{})",
                        p.get("os").and_then(Value::as_str).unwrap_or("?"),
                        p.get("architecture").and_then(Value::as_str).unwrap_or("?")
                    )
                })
                .unwrap_or_default();
            return Err(format!(
                "manifest {digest}{platform} is not in the input. Save all platforms of the image, or save one platform \
                 (docker save --platform)"
            ));
        };
        let what = format!("manifest {digest}");
        let bytes = src.read_all(MAX_MANIFEST_BYTES, &what)?;
        let actual = format!("sha256:{}", hex(&Sha256::digest(&bytes)));
        if actual != digest || bytes.len() as u64 != size {
            return Err(format!(
                "{what} in the input does not match its digest or size"
            ));
        }
        let body: Value =
            serde_json::from_slice(&bytes).map_err(|_| format!("{what} is not valid JSON"))?;
        let media_type = body
            .get("mediaType")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or(desc_type)
            .ok_or_else(|| format!("{what} has no mediaType"))?;

        match media_type.as_str() {
            OCI_INDEX | DOCKER_LIST => {
                let children = body
                    .get("manifests")
                    .and_then(Value::as_array)
                    .ok_or_else(|| format!("{what} has no manifests"))?;
                for c in children {
                    self.descriptor(c, depth + 1)?;
                }
            }
            OCI_MANIFEST | DOCKER_MANIFEST => {
                let config = body
                    .get("config")
                    .ok_or_else(|| format!("{what} has no config"))?;
                self.blob(config)?;
                for l in body
                    .get("layers")
                    .and_then(Value::as_array)
                    .ok_or_else(|| format!("{what} has no layers"))?
                {
                    self.blob(l)?;
                }
            }
            other => return Err(format!("{what} has an unsupported media type `{other}`")),
        }
        self.seen_manifests.insert(digest.clone());
        self.manifests.push(Manifest {
            digest,
            media_type,
            bytes,
        });
        Ok(())
    }

    fn blob(&mut self, d: &Value) -> Result<(), String> {
        let (digest, size, _) = parse_descriptor(d)?;
        if !self.seen_blobs.insert(digest.clone()) {
            return Ok(());
        }
        let source = self
            .store
            .blob(&digest)
            .ok_or_else(|| format!("blob {digest} is not in the input"))?;
        if source.size != size {
            return Err(format!(
                "blob {digest} has {} bytes in the input, but its descriptor says {size}",
                source.size
            ));
        }
        if size > MAX_BLOB_BYTES {
            return Err(format!("blob {digest} is larger than the 10 GiB limit"));
        }
        self.blobs.push(Blob {
            digest,
            size,
            source,
            verified: false,
        });
        Ok(())
    }
}

fn parse_descriptor(d: &Value) -> Result<(String, u64, Option<String>), String> {
    let digest = d
        .get("digest")
        .and_then(Value::as_str)
        .ok_or("a descriptor has no digest")?;
    let hex = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| format!("digest `{digest}` is not sha256"))?;
    if hex.len() != 64 || !hex.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(format!("digest `{digest}` is not valid"));
    }
    let size = d
        .get("size")
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("descriptor {digest} has no size"))?;
    let media_type = d
        .get("mediaType")
        .and_then(Value::as_str)
        .map(str::to_string);
    Ok((digest.to_string(), size, media_type))
}

/// The old `docker save` format: `manifest.json` with `Config` and `Layers` paths. The image manifest is
/// made here, as an OCI image manifest.
fn docker_legacy(store: &Store, list: &Value, tag: &str) -> Result<Image, String> {
    let entries = list
        .as_array()
        .filter(|a| !a.is_empty())
        .ok_or("manifest.json has no images")?;
    let entry = if entries.len() == 1 {
        &entries[0]
    } else {
        let has_tag = |e: &&Value| {
            e.get("RepoTags")
                .and_then(Value::as_array)
                .is_some_and(|t| {
                    t.iter()
                        .filter_map(Value::as_str)
                        .any(|r| r.rsplit_once(':').is_some_and(|(_, t)| t == tag))
                })
        };
        let hits: Vec<&Value> = entries.iter().filter(has_tag).collect();
        match hits.as_slice() {
            [one] => *one,
            _ => {
                return Err(format!(
                    "manifest.json has {} images and not exactly one has the tag `{tag}`. Save one image only",
                    entries.len()
                ))
            }
        }
    };
    let path = |v: &Value| -> Result<Source, String> {
        let p = v.as_str().ok_or("manifest.json: a path is not a string")?;
        store
            .file(&normalize(p))
            .ok_or_else(|| format!("`{p}` from manifest.json is not in the tar file"))
    };

    let mut blobs = Vec::new();
    let mut seen = HashSet::new();
    let mut add = |source: Source, media_type: &str| -> Result<Value, String> {
        if source.size > MAX_BLOB_BYTES {
            return Err("a layer is larger than the 10 GiB limit".into());
        }
        let digest = source.sha256()?;
        let size = source.size;
        if seen.insert(digest.clone()) {
            blobs.push(Blob {
                digest: digest.clone(),
                size,
                source,
                verified: true,
            });
        }
        Ok(json!({ "mediaType": media_type, "digest": digest, "size": size }))
    };

    let config = add(
        path(entry.get("Config").ok_or("manifest.json: no Config")?)?,
        OCI_CONFIG,
    )?;
    let mut layers = Vec::new();
    for l in entry
        .get("Layers")
        .and_then(Value::as_array)
        .ok_or("manifest.json: no Layers")?
    {
        let src = path(l)?;
        let media_type = if src.starts_with_gzip() {
            OCI_LAYER_GZIP
        } else {
            OCI_LAYER_TAR
        };
        layers.push(add(src, media_type)?);
    }
    let manifest = json!({
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "config": config,
        "layers": layers,
    });
    let bytes = serde_json::to_vec(&manifest).map_err(|e| e.to_string())?;
    Ok(Image {
        blobs,
        manifests: vec![Manifest {
            digest: format!("sha256:{}", hex(&Sha256::digest(&bytes))),
            media_type: OCI_MANIFEST.into(),
            bytes,
        }],
    })
}

/// Lists the regular files of a tar file with their data offset and size. Symbolic and hard links to
/// files in the archive are followed.
fn index_tar(path: &Path) -> Result<HashMap<String, (u64, u64)>, String> {
    let file = File::open(path).map_err(|e| format!("cannot open `{}`: {e}", path.display()))?;
    let mut magic = [0u8; 2];
    if (&file).read_exact(&mut magic).is_ok() && magic == [0x1f, 0x8b] {
        return Err(format!(
            "`{}` is compressed with gzip. Decompress it first (gunzip)",
            path.display()
        ));
    }
    let file = File::open(path).map_err(|e| format!("cannot open `{}`: {e}", path.display()))?;
    let mut archive = tar::Archive::new(file);
    let bad = |e: io::Error| format!("`{}` is not a valid tar file: {e}", path.display());
    let mut files = HashMap::new();
    let mut links = Vec::new();
    for entry in archive.entries_with_seek().map_err(bad)? {
        let entry = entry.map_err(bad)?;
        let name = normalize(&entry.path().map_err(bad)?.to_string_lossy());
        let kind = entry.header().entry_type();
        if kind.is_file() {
            files.insert(name, (entry.raw_file_position(), entry.size()));
        } else if kind.is_symlink() || kind.is_hard_link() {
            if let Some(target) = entry.link_name().map_err(bad)? {
                let target = target.to_string_lossy();
                let target = if kind.is_symlink() {
                    let dir = name.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
                    normalize(&format!("{dir}/{target}"))
                } else {
                    normalize(&target)
                };
                links.push((name, target));
            }
        }
    }
    // Links can point to links. Follow them a few times.
    for _ in 0..8 {
        let mut changed = false;
        for (name, target) in &links {
            if !files.contains_key(name) {
                if let Some(&v) = files.get(target) {
                    files.insert(name.clone(), v);
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    Ok(files)
}

/// Normalizes an archive path: no leading `./` or `/`, no `.` parts, `..` removes one part.
fn normalize(p: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for part in p.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            x => out.push(x),
        }
    }
    out.join("/")
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_paths() {
        assert_eq!(normalize("./blobs/sha256/ab"), "blobs/sha256/ab");
        assert_eq!(normalize("/a/./b/../c"), "a/c");
        assert_eq!(normalize("a/b/../../../c"), "c");
    }

    #[test]
    fn hex_and_digest() {
        assert_eq!(hex(&[0, 15, 255]), "000fff");
        assert_eq!(
            format!("sha256:{}", hex(&Sha256::digest(b""))),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn selects_the_top_descriptor() {
        let d = |t: &str| {
            json!({ "digest": format!("sha256:{}", "a".repeat(64)), "size": 1,
                    "annotations": { "org.opencontainers.image.ref.name": t } })
        };
        let one = json!({ "manifests": [d("x")] });
        assert!(select_top(&one, "other").is_ok());
        let two = json!({ "manifests": [d("v1"), d("v2")] });
        assert_eq!(select_top(&two, "v2").unwrap(), d("v2"));
        let err = select_top(&two, "v3").unwrap_err();
        assert!(err.contains("v1, v2"), "{err}");
        assert!(select_top(&json!({ "manifests": [] }), "x").is_err());
    }
}
