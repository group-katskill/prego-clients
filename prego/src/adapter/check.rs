//! The rules of an adapter (ADR-0052 items 4 and 5): the same checks as the registry, done before any
//! upload, and again on the files that `prego adapter get` writes.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::oci::input::Source;

pub const ARTIFACT_TYPE: &str = "application/vnd.prego.adapter.v1+json";
pub const CONFIG_TYPE: &str = "application/vnd.prego.adapter.config.v1+json";
pub const WEIGHTS_TYPE: &str = "application/vnd.prego.adapter.safetensors";
pub const FILE_TYPE: &str = "application/vnd.prego.adapter.file";
pub const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";

pub const TITLE: &str = "org.opencontainers.image.title";
pub const LICENSES: &str = "org.opencontainers.image.licenses";
pub const BASE: &str = "dev.prego.adapter.base";
pub const BASE_REVISION: &str = "dev.prego.adapter.base.revision";

/// The file name of the peft config.
pub const CONFIG_FILE: &str = "adapter_config.json";

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
const GIB: u64 = 1024 * MIB;
pub const MAX_CONFIG: u64 = 64 * KIB;
pub const MAX_EXTRA_FILES: usize = 8;
pub const MAX_EXTRA_FILE: u64 = 10 * MIB;
pub const MAX_TOTAL: u64 = 2 * GIB;
/// The largest safetensors JSON header that the registry reads.
pub const MAX_HEADER: u64 = 8 * MIB;
/// The longest annotation value and file name.
pub const MAX_TEXT: usize = 256;
/// The largest integer that the registry (JavaScript) reads without loss.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Weight files in a format that can run code on load. Prego never stores them as adapters.
const PICKLE_EXTENSIONS: [&str; 6] = [".bin", ".pt", ".pth", ".ckpt", ".pkl", ".pickle"];

/// One file of an adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterFile {
    /// The file name (the `org.opencontainers.image.title` of its layer).
    pub name: String,
    pub path: PathBuf,
    pub size: u64,
}

/// An adapter folder after the checks.
#[derive(Debug, Clone)]
pub struct Folder {
    pub config: AdapterFile,
    /// The parsed `adapter_config.json`.
    pub config_json: Map<String, Value>,
    /// `base_model_name_or_path`.
    pub base: String,
    pub peft_type: String,
    pub weights: AdapterFile,
    pub tensors: usize,
    /// Extra text files, sorted by name.
    pub extras: Vec<AdapterFile>,
    /// Hidden entries (names that start with `.`) that are not part of the adapter.
    pub skipped: Vec<String>,
    pub total: u64,
}

/// Reads an adapter folder and checks it with the rules of the registry.
pub fn read_folder(dir: &Path) -> Result<Folder, String> {
    let shown = dir.display();
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("cannot read the folder {shown}: {e}"))?;
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot read the folder {shown}: {e}"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|n| format!("the file name {n:?} in {shown} is not UTF-8"))?;
        names.push(name);
    }
    names.sort();

    let mut config = None;
    let mut weights = Vec::new();
    let mut extras = Vec::new();
    let mut skipped = Vec::new();
    for name in names {
        let path = dir.join(&name);
        if name.starts_with('.') {
            skipped.push(name);
            continue;
        }
        let meta =
            std::fs::metadata(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        if meta.is_dir() {
            return Err(format!(
                "`{name}` in {shown} is a folder. An adapter has files only: {CONFIG_FILE}, one .safetensors \
                 file and at most {MAX_EXTRA_FILES} text files. Move the folder out"
            ));
        }
        if !meta.is_file() {
            return Err(format!("`{name}` in {shown} is not a regular file"));
        }
        check_file_name(&name)?;
        let file = AdapterFile {
            name: name.clone(),
            path,
            size: meta.len(),
        };
        if name == CONFIG_FILE {
            config = Some(file);
        } else if name.ends_with(".safetensors") {
            weights.push(file);
        } else {
            extras.push(file);
        }
    }

    let config = config.ok_or_else(|| {
        format!("{shown} has no {CONFIG_FILE}. Give the folder that peft save_pretrained wrote")
    })?;
    if config.size > MAX_CONFIG {
        return Err(format!(
            "{CONFIG_FILE} is larger than {MAX_CONFIG} bytes (64 KiB)"
        ));
    }
    let config_bytes =
        std::fs::read(&config.path).map_err(|e| format!("cannot read {CONFIG_FILE}: {e}"))?;
    let (config_json, peft_type, base) = check_config(&config_bytes)?;

    let weights = match weights.len() {
        1 => weights.remove(0),
        0 => {
            return Err(format!(
                "{shown} has no .safetensors weights file. Save the adapter as safetensors (peft \
                 save_pretrained does this by default)"
            ))
        }
        n => {
            let list: Vec<&str> = weights.iter().map(|w| w.name.as_str()).collect();
            return Err(format!(
                "{shown} has {n} .safetensors files ({}). An adapter has exactly one weights file",
                list.join(", ")
            ));
        }
    };
    let tensors = check_safetensors(&weights.path, weights.size)
        .map_err(|e| format!("{}: {e}", weights.name))?;

    if extras.len() > MAX_EXTRA_FILES {
        let list: Vec<&str> = extras.iter().map(|w| w.name.as_str()).collect();
        return Err(format!(
            "{shown} has {} extra files ({}). An adapter has at most {MAX_EXTRA_FILES}. Move the other files \
             out",
            extras.len(),
            list.join(", ")
        ));
    }
    for f in &extras {
        let lower = f.name.to_ascii_lowercase();
        if PICKLE_EXTENSIONS.iter().any(|x| lower.ends_with(x)) {
            return Err(format!(
                "`{}` is a pickle file. Pickle files can run code when they load, so Prego does not accept \
                 them in an adapter. Move it out of the folder",
                f.name
            ));
        }
        if f.size > MAX_EXTRA_FILE {
            return Err(format!(
                "`{}` is larger than {MAX_EXTRA_FILE} bytes (10 MiB). An extra file is at most 10 MiB",
                f.name
            ));
        }
        check_text_file(&f.path)
            .map_err(|e| format!("`{}` {e}. Move it out of the folder", f.name))?;
    }

    let total = config.size + weights.size + extras.iter().map(|f| f.size).sum::<u64>();
    if total > MAX_TOTAL {
        return Err(format!(
            "the adapter is {total} bytes. An adapter is at most {MAX_TOTAL} bytes (2 GiB)"
        ));
    }
    Ok(Folder {
        config,
        config_json,
        base,
        peft_type,
        weights,
        tensors,
        extras,
        skipped,
        total,
    })
}

/// A plain file name of at most 256 characters: no path, not `.` or `..`.
pub fn check_file_name(name: &str) -> Result<(), String> {
    let plain = !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains(['/', '\\', '\0'])
        && name.chars().count() <= MAX_TEXT;
    if plain {
        Ok(())
    } else {
        Err(format!(
            "`{name}` is not a plain file name of at most {MAX_TEXT} characters"
        ))
    }
}

/// Checks the peft `adapter_config.json`: a UTF-8 JSON object with `peft_type` and
/// `base_model_name_or_path`. Returns the object, `peft_type` and the base model.
pub fn check_config(bytes: &[u8]) -> Result<(Map<String, Value>, String, String), String> {
    let text = std::str::from_utf8(bytes).map_err(|_| format!("{CONFIG_FILE} is not UTF-8"))?;
    let doc: Value =
        serde_json::from_str(text).map_err(|e| format!("{CONFIG_FILE} is not valid JSON: {e}"))?;
    let Value::Object(map) = doc else {
        return Err(format!("{CONFIG_FILE} must be a JSON object"));
    };
    let field = |key: &str| -> Result<String, String> {
        match map.get(key) {
            Some(Value::String(s)) if !s.is_empty() => Ok(s.clone()),
            _ => Err(format!("{CONFIG_FILE} must contain {key}")),
        }
    };
    let peft_type = field("peft_type")?;
    let base = field("base_model_name_or_path")?;
    if base.trim().is_empty() || base.chars().count() > MAX_TEXT {
        return Err(format!(
            "base_model_name_or_path in {CONFIG_FILE} must have 1 to {MAX_TEXT} characters"
        ));
    }
    Ok((map, peft_type, base))
}

/// Checks the safetensors header of a file of `size` bytes: an 8-byte little-endian length (1 to 8 MiB,
/// inside the file), then a JSON header. Returns the number of tensors.
pub fn check_safetensors(path: &Path, size: u64) -> Result<usize, String> {
    if size < 8 {
        return Err("this is not a safetensors file (it is shorter than 8 bytes)".into());
    }
    let mut f = File::open(path).map_err(|e| format!("cannot read it: {e}"))?;
    let mut len = [0u8; 8];
    f.read_exact(&mut len)
        .map_err(|e| format!("cannot read it: {e}"))?;
    let n = u64::from_le_bytes(len);
    if n == 0 || n > MAX_HEADER || n > size - 8 {
        return Err(format!(
            "the safetensors header length must be 1 to {MAX_HEADER} bytes and inside the file"
        ));
    }
    let mut header = vec![0u8; n as usize];
    f.seek(SeekFrom::Start(8))
        .and_then(|_| f.read_exact(&mut header))
        .map_err(|e| format!("cannot read it: {e}"))?;
    check_safetensors_header(&header, size - 8 - n)
}

/// Bytes per element of the safetensors dtypes with a whole number of bytes.
fn dtype_bytes(dtype: &str) -> Option<u64> {
    Some(match dtype {
        "BOOL" | "U8" | "I8" | "F8_E4M3" | "F8_E5M2" => 1,
        "I16" | "U16" | "F16" | "BF16" => 2,
        "I32" | "U32" | "F32" => 4,
        "I64" | "U64" | "F64" => 8,
        _ => return None,
    })
}

fn safe_integer(v: &Value) -> Option<u64> {
    v.as_u64().filter(|n| *n <= MAX_SAFE_INTEGER)
}

/// Checks a safetensors JSON header. `data_bytes` is the file size minus 8 minus the header length. Each
/// tensor has a dtype, a shape and `data_offsets` inside the data. For a dtype with a known element size,
/// the offsets must also match the shape. Returns the number of tensors.
pub fn check_safetensors_header(header: &[u8], data_bytes: u64) -> Result<usize, String> {
    let text = std::str::from_utf8(header)
        .map_err(|_| "the safetensors header is not UTF-8".to_string())?;
    let doc: Value = serde_json::from_str(text)
        .map_err(|_| "the safetensors header is not valid JSON".to_string())?;
    let Value::Object(map) = doc else {
        return Err("the safetensors header must be a JSON object".into());
    };
    let mut tensors = 0;
    for (name, t) in &map {
        if name == "__metadata__" {
            let ok = t
                .as_object()
                .is_some_and(|m| m.values().all(Value::is_string));
            if !ok {
                return Err("safetensors __metadata__ must map strings to strings".into());
            }
            continue;
        }
        let short: String = name.chars().take(80).collect();
        let bad = |why: &str| format!("safetensors tensor {short:?} {why}");
        let t = t.as_object().ok_or_else(|| bad("must be an object"))?;
        let dtype = t
            .get("dtype")
            .and_then(Value::as_str)
            .filter(|d| {
                let b = d.as_bytes();
                !b.is_empty()
                    && b[0].is_ascii_uppercase()
                    && b.iter()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_')
            })
            .ok_or_else(|| bad("needs a dtype"))?;
        let shape: Vec<u64> = t
            .get("shape")
            .and_then(Value::as_array)
            .and_then(|a| a.iter().map(safe_integer).collect::<Option<Vec<u64>>>())
            .ok_or_else(|| bad("needs a shape of non-negative integers"))?;
        let offsets: Vec<u64> = t
            .get("data_offsets")
            .and_then(Value::as_array)
            .and_then(|a| a.iter().map(safe_integer).collect::<Option<Vec<u64>>>())
            .filter(|o| o.len() == 2 && o[0] <= o[1] && o[1] <= data_bytes)
            .ok_or_else(|| bad("data_offsets must be inside the file"))?;
        if let Some(width) = dtype_bytes(dtype) {
            let bytes = shape
                .iter()
                .try_fold(1u64, |a, d| a.checked_mul(*d))
                .and_then(|e| e.checked_mul(width));
            if bytes != Some(offsets[1] - offsets[0]) {
                return Err(bad("data_offsets do not match its shape and dtype"));
            }
        }
        tensors += 1;
    }
    if tensors == 0 {
        return Err("the safetensors file has no tensors".into());
    }
    Ok(tensors)
}

/// Checks that a file is UTF-8 text without NUL bytes.
pub fn check_text_file(path: &Path) -> Result<(), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot be read: {e}"))?;
    check_text(&bytes)
}

pub fn check_text(bytes: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "is not UTF-8 text".to_string())?;
    if text.contains('\0') {
        return Err("is not text (it has NUL bytes)".into());
    }
    Ok(())
}

/// The license of the adapter and where it came from: `--license`, the `license` key of
/// `adapter_config.json`, or the `license` line in the front matter of `README.md` (a Hugging Face model
/// card; `license: other` with `license_name: <name>` gives `LicenseRef-<name>`).
pub fn license(flag: Option<&str>, folder: &Folder) -> Result<(String, &'static str), String> {
    if let Some(l) = flag {
        return check_license(l).map(|l| (l, "--license"));
    }
    if let Some(Value::String(l)) = folder.config_json.get("license") {
        return check_license(l).map(|l| (l, CONFIG_FILE));
    }
    let readme = folder
        .extras
        .iter()
        .find(|f| f.name.eq_ignore_ascii_case("README.md"));
    if let Some(r) = readme {
        let text = std::fs::read_to_string(&r.path).unwrap_or_default();
        if let Some(l) = license_from_model_card(&text) {
            return check_license(&l).map(|l| (l, "README.md"));
        }
    }
    Err("the adapter needs a license. Give it with --license <id>: an SPDX identifier (for example \
         Apache-2.0), or LicenseRef-<name> for a model license (for example LicenseRef-llama3.1). Or put \
         `license:` in the front matter of README.md"
        .into())
}

/// The license of a Hugging Face model card front matter, if it gives one.
pub fn license_from_model_card(text: &str) -> Option<String> {
    let mut lines = text.lines();
    if lines.next()?.trim_end() != "---" {
        return None;
    }
    let mut license = None;
    let mut name = None;
    for line in lines {
        if line.trim_end() == "---" {
            break;
        }
        let unquote = |v: &str| v.trim().trim_matches(['"', '\'']).trim().to_string();
        if let Some(v) = line.strip_prefix("license:") {
            license = Some(unquote(v));
        } else if let Some(v) = line.strip_prefix("license_name:") {
            name = Some(unquote(v));
        }
    }
    match license?.as_str() {
        "" | "unknown" => None,
        "other" => name
            .filter(|n| !n.is_empty())
            .map(|n| format!("LicenseRef-{n}")),
        l => Some(l.to_string()),
    }
}

/// A license value as the registry accepts it: 1 to 256 characters from `A-Z a-z 0-9 . + - : ( )` and
/// space.
pub fn check_license(l: &str) -> Result<String, String> {
    let ok = !l.trim().is_empty()
        && l.chars().count() <= MAX_TEXT
        && l.chars()
            .all(|c| c.is_ascii_alphanumeric() || ".+-:() ".contains(c));
    if ok {
        Ok(l.to_string())
    } else {
        Err(format!(
            "the license `{l}` is not an SPDX identifier or LicenseRef-<name> (letters, digits and . + - : ( ) \
             only, at most {MAX_TEXT} characters)"
        ))
    }
}

/// A base model revision: 1 to 256 characters.
pub fn check_revision(r: &str) -> Result<(), String> {
    if r.trim().is_empty() || r.chars().count() > MAX_TEXT {
        return Err(format!(
            "--base-revision must have 1 to {MAX_TEXT} characters"
        ));
    }
    Ok(())
}

/// The digest of a whole file.
pub fn file_digest(f: &AdapterFile) -> Result<String, String> {
    Source {
        path: f.path.clone(),
        offset: 0,
        size: f.size,
    }
    .sha256()
}

/// The manifest of an adapter. The same folder, license and revision always give the same bytes, so a
/// push that runs again after an error sends the same digest.
pub fn manifest(
    folder: &Folder,
    digests: &Digests,
    license: &str,
    revision: Option<&str>,
) -> Vec<u8> {
    let mut layers = vec![json!({
        "mediaType": WEIGHTS_TYPE,
        "digest": digests.weights,
        "size": folder.weights.size,
        "annotations": { TITLE: folder.weights.name },
    })];
    for (f, d) in folder.extras.iter().zip(&digests.extras) {
        layers.push(json!({
            "mediaType": FILE_TYPE,
            "digest": d,
            "size": f.size,
            "annotations": { TITLE: f.name },
        }));
    }
    let mut annotations = Map::new();
    annotations.insert(LICENSES.into(), license.into());
    annotations.insert(BASE.into(), folder.base.clone().into());
    if let Some(r) = revision {
        annotations.insert(BASE_REVISION.into(), r.into());
    }
    let doc = json!({
        "schemaVersion": 2,
        "mediaType": OCI_MANIFEST,
        "artifactType": ARTIFACT_TYPE,
        "config": {
            "mediaType": CONFIG_TYPE,
            "digest": digests.config,
            "size": folder.config.size,
        },
        "layers": layers,
        "annotations": annotations,
    });
    serde_json::to_vec(&doc).expect("a JSON value serializes")
}

/// The digests of the files of a folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Digests {
    pub config: String,
    pub weights: String,
    pub extras: Vec<String>,
}

/// One blob of a pulled adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part {
    /// `adapter_config.json` for the config, else the layer title.
    pub name: String,
    pub digest: String,
    pub size: u64,
    pub media_type: String,
}

/// A pulled adapter manifest after the checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pulled {
    /// The config first, then the weights, then the extra files.
    pub parts: Vec<Part>,
    pub license: Option<String>,
    pub base: Option<String>,
    pub revision: Option<String>,
}

/// Checks a pulled manifest: an OCI manifest with the adapter artifact type, the adapter media types,
/// exactly one weights layer, at most 8 extra files, plain and unique file names, and the size limits.
pub fn check_pulled(bytes: &[u8]) -> Result<Pulled, String> {
    let doc: Value =
        serde_json::from_slice(bytes).map_err(|_| "the manifest is not valid JSON".to_string())?;
    let artifact = doc.get("artifactType").and_then(Value::as_str);
    if artifact != Some(ARTIFACT_TYPE) {
        return Err(format!(
            "this is not a Prego adapter (artifactType {}). Use docker pull or oras pull for other \
             artifacts",
            artifact.unwrap_or("none")
        ));
    }
    if doc.get("mediaType").and_then(Value::as_str) != Some(OCI_MANIFEST) {
        return Err(format!(
            "an adapter is an OCI image manifest ({OCI_MANIFEST})"
        ));
    }
    let desc = |d: &Value, where_: &str| -> Result<(String, u64, String), String> {
        let digest = d
            .get("digest")
            .and_then(Value::as_str)
            .filter(|s| {
                s.strip_prefix("sha256:").is_some_and(|h| {
                    h.len() == 64
                        && h.bytes()
                            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                })
            })
            .ok_or_else(|| format!("{where_} needs a sha256 digest"))?;
        let size = d
            .get("size")
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("{where_} needs a size"))?;
        let mt = d
            .get("mediaType")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        Ok((digest.to_string(), size, mt))
    };
    let config = doc.get("config").ok_or("the manifest has no config")?;
    let (cd, cs, cmt) = desc(config, "config")?;
    if cmt != CONFIG_TYPE {
        return Err(format!("the config media type must be {CONFIG_TYPE}"));
    }
    if cs > MAX_CONFIG {
        return Err(format!("the config is larger than {MAX_CONFIG} bytes"));
    }
    let mut parts = vec![Part {
        name: CONFIG_FILE.into(),
        digest: cd,
        size: cs,
        media_type: cmt,
    }];
    let layers = doc
        .get("layers")
        .and_then(Value::as_array)
        .ok_or("the manifest has no layers")?;
    let mut names = vec![CONFIG_FILE.to_ascii_lowercase()];
    let mut weights = Vec::new();
    let mut extras = Vec::new();
    for (i, l) in layers.iter().enumerate() {
        let where_ = format!("layers[{i}]");
        let (digest, size, mt) = desc(l, &where_)?;
        let name = l
            .pointer("/annotations/org.opencontainers.image.title")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{where_} needs the annotation {TITLE}"))?
            .to_string();
        check_file_name(&name).map_err(|e| format!("{where_}: {e}"))?;
        if name.starts_with(".prego-") {
            return Err(format!("{where_}: the file name {name} is reserved"));
        }
        // Unique without case, so the files do not overwrite each other on macOS and Windows.
        let key = name.to_ascii_lowercase();
        if names.contains(&key) {
            return Err(format!("two files of the adapter have the name {name}"));
        }
        names.push(key);
        let part = Part {
            name,
            digest,
            size,
            media_type: mt.clone(),
        };
        match mt.as_str() {
            WEIGHTS_TYPE if part.name.ends_with(".safetensors") => weights.push(part),
            WEIGHTS_TYPE => {
                return Err(format!(
                    "{where_}: the weights file must end with .safetensors"
                ))
            }
            FILE_TYPE if part.size <= MAX_EXTRA_FILE => extras.push(part),
            FILE_TYPE => {
                return Err(format!(
                    "{where_}: an extra file is at most {MAX_EXTRA_FILE} bytes"
                ))
            }
            _ => return Err(format!("{where_}: media type {mt} is not an adapter part")),
        }
    }
    if weights.len() != 1 {
        return Err(format!(
            "an adapter has exactly one weights layer, this one has {}",
            weights.len()
        ));
    }
    if extras.len() > MAX_EXTRA_FILES {
        return Err(format!(
            "an adapter has at most {MAX_EXTRA_FILES} extra files"
        ));
    }
    parts.append(&mut weights);
    parts.append(&mut extras);
    let total = parts
        .iter()
        .try_fold(0u64, |a, p| a.checked_add(p.size))
        .unwrap_or(u64::MAX);
    if total > MAX_TOTAL {
        return Err(format!("an adapter is at most {MAX_TOTAL} bytes (2 GiB)"));
    }
    let annotation = |key: &str| {
        doc.pointer("/annotations")
            .and_then(|a| a.get(key))
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    Ok(Pulled {
        parts,
        license: annotation(LICENSES),
        base: annotation(BASE),
        revision: annotation(BASE_REVISION),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A safetensors file with one F32 tensor of `n` elements, and the given extra header fields.
    pub fn safetensors(n: u64) -> Vec<u8> {
        let header = format!(
            r#"{{"__metadata__":{{"format":"pt"}},"base_model.model.lora_A.weight":{{"dtype":"F32","shape":[1,{n}],"data_offsets":[0,{}]}}}}"#,
            n * 4
        );
        let mut out = (header.len() as u64).to_le_bytes().to_vec();
        out.extend_from_slice(header.as_bytes());
        out.extend((0..n * 4).map(|i| i as u8));
        out
    }

    fn header_check(header: &str, data: u64) -> Result<usize, String> {
        check_safetensors_header(header.as_bytes(), data)
    }

    pub fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("prego-adapter-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    pub const CONFIG: &str = r#"{"peft_type":"LORA","base_model_name_or_path":"meta-llama/Llama-3.1-8B-Instruct","r":16}"#;

    fn adapter_dir(name: &str) -> PathBuf {
        let dir = temp_dir(name);
        std::fs::write(dir.join(CONFIG_FILE), CONFIG).unwrap();
        std::fs::write(dir.join("adapter_model.safetensors"), safetensors(16)).unwrap();
        std::fs::write(
            dir.join("README.md"),
            "---\nlicense: apache-2.0\nbase_model: meta-llama/Llama-3.1-8B-Instruct\n---\n# Support bot\n",
        )
        .unwrap();
        dir
    }

    #[test]
    fn a_good_folder() {
        let dir = adapter_dir("good");
        std::fs::write(dir.join(".gitattributes"), "*.safetensors filter=lfs\n").unwrap();
        let f = read_folder(&dir).unwrap();
        assert_eq!(f.peft_type, "LORA");
        assert_eq!(f.base, "meta-llama/Llama-3.1-8B-Instruct");
        assert_eq!(f.weights.name, "adapter_model.safetensors");
        assert_eq!(f.tensors, 1);
        assert_eq!(f.extras.len(), 1);
        assert_eq!(f.skipped, vec![".gitattributes".to_string()]);
        assert_eq!(
            license(None, &f).unwrap(),
            ("apache-2.0".to_string(), "README.md")
        );
        assert_eq!(
            license(Some("LicenseRef-llama3.1"), &f).unwrap().0,
            "LicenseRef-llama3.1"
        );
        assert!(license(Some("MIT; rm -rf"), &f).is_err());
    }

    #[test]
    fn folder_refusals() {
        type Change<'a> = &'a dyn Fn(&Path);
        let cases: [(&str, Change); 8] = [
            ("no-config", &|d| {
                std::fs::remove_file(d.join(CONFIG_FILE)).unwrap()
            }),
            ("no-weights", &|d| {
                std::fs::remove_file(d.join("adapter_model.safetensors")).unwrap()
            }),
            ("two-weights", &|d| {
                std::fs::write(d.join("b.safetensors"), safetensors(1)).unwrap()
            }),
            ("pickle", &|d| {
                std::fs::write(d.join("training_args.bin"), "x").unwrap()
            }),
            ("binary-extra", &|d| {
                std::fs::write(d.join("vocab.txt"), [0xff, 0xfe]).unwrap()
            }),
            ("subfolder", &|d| {
                std::fs::create_dir(d.join("checkpoint-1")).unwrap()
            }),
            ("config-no-peft-type", &|d| {
                std::fs::write(d.join(CONFIG_FILE), r#"{"base_model_name_or_path":"x"}"#).unwrap()
            }),
            ("nine-extras", &|d| {
                for i in 0..8 {
                    std::fs::write(d.join(format!("f{i}.txt")), "x").unwrap();
                }
            }),
        ];
        for (name, change) in cases {
            let dir = adapter_dir(name);
            change(&dir);
            assert!(read_folder(&dir).is_err(), "{name}");
        }
    }

    #[test]
    fn safetensors_headers() {
        assert_eq!(
            header_check(
                r#"{"a":{"dtype":"F16","shape":[2,3],"data_offsets":[0,12]}}"#,
                12
            ),
            Ok(1)
        );
        // Unknown dtype: only the bounds.
        assert_eq!(
            header_check(
                r#"{"a":{"dtype":"F4","shape":[3],"data_offsets":[0,2]}}"#,
                2
            ),
            Ok(1)
        );
        for bad in [
            r#"[]"#,
            r#"{}"#,
            r#"{"__metadata__":{"a":1},"a":{"dtype":"F16","shape":[1],"data_offsets":[0,2]}}"#,
            r#"{"a":{"dtype":"f16","shape":[1],"data_offsets":[0,2]}}"#,
            r#"{"a":{"dtype":"F16","shape":[-1],"data_offsets":[0,2]}}"#,
            r#"{"a":{"dtype":"F16","shape":[1],"data_offsets":[0,99]}}"#,
            r#"{"a":{"dtype":"F16","shape":[1],"data_offsets":[2,0]}}"#,
            r#"{"a":{"dtype":"F16","shape":[2],"data_offsets":[0,2]}}"#,
            r#"{"a":{"dtype":"F16","shape":[1]}}"#,
            r#"{"a":{"dtype":"F64","shape":[4294967296,4294967296],"data_offsets":[0,2]}}"#,
        ] {
            assert!(header_check(bad, 12).is_err(), "{bad}");
        }
        assert!(check_safetensors_header(&[0xff], 0).is_err());
    }

    #[test]
    fn safetensors_lengths() {
        let dir = temp_dir("st-len");
        let p = dir.join("w.safetensors");
        let good = safetensors(4);
        std::fs::write(&p, &good).unwrap();
        assert_eq!(check_safetensors(&p, good.len() as u64), Ok(1));
        let mut zero = good.clone();
        zero[..8].copy_from_slice(&0u64.to_le_bytes());
        std::fs::write(&p, &zero).unwrap();
        assert!(check_safetensors(&p, zero.len() as u64).is_err());
        let mut long = good.clone();
        long[..8].copy_from_slice(&(good.len() as u64).to_le_bytes());
        std::fs::write(&p, &long).unwrap();
        assert!(check_safetensors(&p, long.len() as u64).is_err());
        assert!(check_safetensors(&p, 4).is_err());
    }

    #[test]
    fn model_card_licenses() {
        assert_eq!(
            license_from_model_card("---\nlicense: mit\n---\n"),
            Some("mit".into())
        );
        assert_eq!(
            license_from_model_card("---\nlicense: other\nlicense_name: \"llama3.1\"\n---\n"),
            Some("LicenseRef-llama3.1".into())
        );
        assert_eq!(license_from_model_card("---\nlicense: other\n---\n"), None);
        assert_eq!(
            license_from_model_card("# no front matter\nlicense: mit\n"),
            None
        );
        assert_eq!(
            license_from_model_card("---\ntags:\n  license: mit\n---\n"),
            None
        );
    }

    #[test]
    fn manifests_are_stable_and_pass_the_pull_check() {
        let dir = adapter_dir("manifest");
        let f = read_folder(&dir).unwrap();
        let digests = Digests {
            config: file_digest(&f.config).unwrap(),
            weights: file_digest(&f.weights).unwrap(),
            extras: f.extras.iter().map(|e| file_digest(e).unwrap()).collect(),
        };
        let a = manifest(&f, &digests, "Apache-2.0", Some("0e9e39f"));
        let b = manifest(&f, &digests, "Apache-2.0", Some("0e9e39f"));
        assert_eq!(a, b);
        let v: Value = serde_json::from_slice(&a).unwrap();
        assert_eq!(v["artifactType"], ARTIFACT_TYPE);
        assert_eq!(v["annotations"][BASE], "meta-llama/Llama-3.1-8B-Instruct");
        assert_eq!(v["annotations"][BASE_REVISION], "0e9e39f");
        assert_eq!(v["layers"][0]["mediaType"], WEIGHTS_TYPE);
        assert_eq!(v["layers"][1]["annotations"][TITLE], "README.md");
        let p = check_pulled(&a).unwrap();
        let names: Vec<&str> = p.parts.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(
            names,
            [CONFIG_FILE, "adapter_model.safetensors", "README.md"]
        );
        assert_eq!(p.license.as_deref(), Some("Apache-2.0"));
    }

    #[test]
    fn pulled_manifest_refusals() {
        let d = format!("sha256:{}", "a".repeat(64));
        let good = |layers: Value| {
            json!({
                "schemaVersion": 2, "mediaType": OCI_MANIFEST, "artifactType": ARTIFACT_TYPE,
                "config": {"mediaType": CONFIG_TYPE, "digest": d, "size": 10},
                "layers": layers,
            })
        };
        let w = |title: &str| json!({"mediaType": WEIGHTS_TYPE, "digest": d, "size": 10, "annotations": {TITLE: title}});
        let x = |title: &str| json!({"mediaType": FILE_TYPE, "digest": d, "size": 10, "annotations": {TITLE: title}});
        assert!(check_pulled(good(json!([w("a.safetensors")])).to_string().as_bytes()).is_ok());
        for (name, m) in [
            ("traversal", good(json!([w("a.safetensors"), x("../x")]))),
            ("dot-dot", good(json!([w("a.safetensors"), x("..")]))),
            (
                "same-name",
                good(json!([w("a.safetensors"), x("README.md"), x("readme.md")])),
            ),
            (
                "config-name",
                good(json!([w("a.safetensors"), x("Adapter_Config.json")])),
            ),
            (
                "two-weights",
                good(json!([w("a.safetensors"), w("b.safetensors")])),
            ),
            ("no-weights", good(json!([x("README.md")]))),
            ("pickle", good(json!([w("a.bin")]))),
            (
                "image",
                json!({"schemaVersion": 2, "mediaType": OCI_MANIFEST, "config": {}, "layers": []}),
            ),
        ] {
            assert!(check_pulled(m.to_string().as_bytes()).is_err(), "{name}");
        }
    }
}
