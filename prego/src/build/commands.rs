//! `prego build push|get|list|promote` on the routes of api.md section 16 (ADR-0066).

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use prego_auth::http::Body;
use prego_auth::Env;
use serde_json::{json, Value};

use super::{collect, parts, BuildFile, Selector, DEFAULT_PART, MAX_PART};
use crate::env::{query, text};
use crate::snippet::reference::SnipRef;
use crate::snippet::{api_error, seg, Api};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildCommand {
    Push {
        stream: String,
        files: Vec<String>,
        promote: Option<String>,
        release_url: Option<String>,
        message: Option<String>,
        expires_days: Option<u32>,
    },
    Get {
        stream: String,
        selector: Selector,
        out: Option<String>,
        no_verify: bool,
    },
    List {
        stream: String,
        commit: Option<String>,
        git_ref: Option<String>,
        run: Option<String>,
        promoted: bool,
        limit: Option<u32>,
        json: bool,
    },
    Promote {
        stream: String,
        selector: Selector,
        label: String,
    },
}

/// `<tenant>/<stream>` or `<tenant>/<namespace>/<stream>`.
fn stream_ref(s: &str) -> Result<SnipRef, String> {
    let r = SnipRef::parse(s).map_err(|_| {
        format!("bad stream `{s}`: use <tenant>/<stream> or <tenant>/<namespace>/<stream>")
    })?;
    if r.version.is_some() {
        return Err(format!(
            "bad stream `{s}`: no @ here; choose the build with an option"
        ));
    }
    Ok(r)
}

fn base(r: &SnipRef) -> String {
    format!("{}/{}/{}", seg(&r.tenant), seg(&r.namespace), seg(&r.name))
}

fn long(r: &SnipRef) -> String {
    format!("{}/{}/{}", r.tenant, r.namespace, r.name)
}

fn api(globals: &[&str], tenant: &str, env: &dyn Env) -> Result<Api, String> {
    Api::with_prefix(globals, tenant, env, "build")
}

pub fn run(globals: &[&str], c: &BuildCommand, env: &dyn Env) -> Result<(), String> {
    match c {
        BuildCommand::Push {
            stream,
            files,
            promote,
            release_url,
            message,
            expires_days,
        } => {
            let r = stream_ref(stream)?;
            if let Some(l) = promote {
                super::check_label(l)?;
            }
            if let Some(u) = release_url {
                super::check_release_url(u)?;
            }
            let set =
                collect(files).map_err(|e| format!("prego build push: {e}. Nothing was sent."))?;
            let api = api(globals, &r.tenant, env)?;
            push(
                &api,
                &r,
                &set,
                promote.as_deref(),
                release_url.as_deref(),
                message.as_deref(),
                *expires_days,
            )
        }
        BuildCommand::Get {
            stream,
            selector,
            out,
            no_verify,
        } => {
            let r = stream_ref(stream)?;
            let api = api(globals, &r.tenant, env)?;
            let build = lookup(&api, &r, selector)?;
            get(&api, &r, &build, out.as_deref().unwrap_or("."), *no_verify)
        }
        BuildCommand::List {
            stream,
            commit,
            git_ref,
            run,
            promoted,
            limit,
            json,
        } => {
            let r = stream_ref(stream)?;
            let mut q: Vec<(&str, String)> = Vec::new();
            if let Some(c) = commit {
                super::check_commit(c)?;
                q.push(("commit", c.to_ascii_lowercase()));
            }
            if let Some(g) = git_ref {
                q.push(("ref", g.clone()));
            }
            if let Some(x) = run {
                q.push(("run", x.clone()));
            }
            if *promoted {
                q.push(("promoted", "true".into()));
            }
            q.push(("limit", limit.unwrap_or(100).to_string()));
            let api = api(globals, &r.tenant, env)?;
            let what = format!("the builds of {}", long(&r));
            let (_, answer) = api.get_json(&format!("{}/builds?{}", base(&r), query(&q)), &what)?;
            if *json {
                println!("{answer:#}");
            } else {
                print!("{}", list_text(&answer));
            }
            Ok(())
        }
        BuildCommand::Promote {
            stream,
            selector,
            label,
        } => {
            let r = stream_ref(stream)?;
            super::check_label(label)?;
            let api = api(globals, &r.tenant, env)?;
            let id = match selector {
                Selector::Id(i) => i.clone(),
                other => text(&lookup(&api, &r, other)?["id"]),
            };
            let what = format!("promote {} {id}", long(&r));
            let b = api.write_json(
                "POST",
                &format!("{}/builds/{}/promote", base(&r), seg(&id)),
                &json!({ "label": label }),
                &what,
            )?;
            println!(
                "{} {} promoted as {}",
                long(&r),
                text(&b["id"]),
                text(&b["label"])
            );
            Ok(())
        }
    }
}

// ---- push ----

fn push(
    api: &Api,
    r: &SnipRef,
    set: &[BuildFile],
    promote: Option<&str>,
    release_url: Option<&str>,
    message: Option<&str>,
    expires_days: Option<u32>,
) -> Result<(), String> {
    let mut body = json!({
        "files": set.iter().map(|f| json!({"name": f.name, "size": f.size, "sha256": f.sha256})).collect::<Vec<_>>(),
    });
    if let Some(d) = expires_days {
        body["expires_days"] = d.into();
    }
    if let Some(l) = promote {
        body["promote"] = l.into();
    }
    if let Some(u) = release_url {
        body["release_url"] = u.into();
    }
    if let Some(m) = message {
        body["message"] = m.into();
    }
    let what = format!("push to {}", long(r));
    let open = api.write_json("POST", &format!("{}/uploads", base(r)), &body, &what)?;
    let id = open["upload_id"]
        .as_str()
        .ok_or_else(|| format!("prego: {what}: the answer has no upload_id"))?
        .to_string();
    let max = open["part_size_max"]
        .as_u64()
        .unwrap_or(MAX_PART)
        .min(MAX_PART);
    let min = open["part_size_min"].as_u64().unwrap_or(1);
    let part = DEFAULT_PART.clamp(min.min(max), max);
    let result = send_files(api, r, &id, set, &open, part).and_then(|()| {
        api.write_json(
            "POST",
            &format!("{}/uploads/{}/commit", base(r), seg(&id)),
            &json!({}),
            &format!("commit the upload to {}", long(r)),
        )
    });
    let build = match result {
        Ok(b) => b,
        Err(e) => {
            // The session cannot be committed now; free its bytes.
            let _ = api.send(
                "DELETE",
                &format!("{}/uploads/{}", base(r), seg(&id)),
                None,
                Body::Empty,
            );
            return Err(format!("{e} The upload was cancelled; nothing was stored."));
        }
    };
    let bid = text(&build["id"]);
    match build["label"].as_str() {
        Some(l) => eprintln!(
            "{}: build {bid}, {} files, promoted as {l}",
            long(r),
            set.len()
        ),
        None => eprintln!(
            "{}: build {bid}, {} files, expires {}",
            long(r),
            set.len(),
            text(&build["expires_at"])
        ),
    }
    println!("{bid}");
    Ok(())
}

fn send_files(
    api: &Api,
    r: &SnipRef,
    id: &str,
    set: &[BuildFile],
    open: &Value,
    part: u64,
) -> Result<(), String> {
    for f in set {
        let index = open["files"]
            .as_array()
            .and_then(|a| {
                a.iter()
                    .find(|x| x["name"].as_str() == Some(f.name.as_str()))
            })
            .map(|x| text(&x["index"]))
            .ok_or_else(|| format!("prego: the upload answer has no index for {}", f.name))?;
        let mut file =
            std::fs::File::open(&f.path).map_err(|e| format!("prego: {}: {e}", f.path))?;
        let mut buf = Vec::new();
        for (n, (offset, len)) in parts(f.size, part).into_iter().enumerate() {
            if len == 0 {
                continue;
            }
            buf.clear();
            file.seek(SeekFrom::Start(offset))
                .and_then(|_| (&mut file).take(len).read_to_end(&mut buf))
                .map_err(|e| format!("prego: {}: {e}", f.path))?;
            if buf.len() as u64 != len {
                return Err(format!(
                    "prego: {}: the file changed during the upload.",
                    f.path
                ));
            }
            let path = format!(
                "{}/uploads/{}/files/{}/parts/{}",
                base(r),
                seg(id),
                seg(&index),
                n + 1
            );
            let res = api.send(
                "PUT",
                &path,
                Some("application/octet-stream"),
                Body::Bytes(&buf),
            )?;
            if res.status != 200 {
                let what = format!("{} part {}", f.name, n + 1);
                let v: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
                if res.status == 422 && v["error"]["code"] == "digest_mismatch" {
                    return Err(format!(
                        "prego: {}: the bytes that Prego received do not have the sha256 that prego computed \\
                         before the upload. Did the file change during the upload?",
                        f.path
                    ));
                }
                return Err(api_error(&res, &what));
            }
        }
        eprintln!("  {} ({} bytes) sent", f.name, f.size);
    }
    Ok(())
}

// ---- get ----

fn selector_query(s: &Selector) -> String {
    match s {
        Selector::Id(i) => query(&[("id", i.clone())]),
        Selector::Commit(c) => query(&[("commit", c.clone())]),
        Selector::Run(r) => query(&[("run", r.clone())]),
        Selector::Version(v) => query(&[("version", v.clone())]),
        Selector::Latest { git_ref: None } => "latest".into(),
        Selector::Latest { git_ref: Some(g) } => format!("latest&{}", query(&[("ref", g.clone())])),
    }
}

fn lookup(api: &Api, r: &SnipRef, s: &Selector) -> Result<Value, String> {
    let what = format!("a build of {}", long(r));
    api.get_json(&format!("{}/lookup?{}", base(r), selector_query(s)), &what)
        .map(|(_, v)| v)
}

/// The target of a download redirect: a path on the same host, or an `https://` link (`http://` only when the
/// registry URL is `http://`, for local tests).
fn download_link(url: &str, loc: &str) -> Result<String, String> {
    let loc = loc.trim();
    if loc.starts_with('/') && !loc.starts_with("//") {
        let origin_end = url
            .find("://")
            .and_then(|i| url[i + 3..].find('/').map(|j| i + 3 + j))
            .unwrap_or(url.len());
        return Ok(format!("{}{loc}", &url[..origin_end]));
    }
    if loc.starts_with("https://") || (url.starts_with("http://") && loc.starts_with("http://")) {
        return Ok(loc.to_string());
    }
    Err(format!(
        "the registry sent a download link that is not https: `{loc}`"
    ))
}

/// A writer that hashes what it writes.
struct HashingWriter<W: Write> {
    inner: W,
    h: sha2::Sha256,
    n: u64,
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        use sha2::Digest;
        let n = self.inner.write(b)?;
        self.h.update(&b[..n]);
        self.n += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn get(api: &Api, r: &SnipRef, build: &Value, out: &str, no_verify: bool) -> Result<(), String> {
    let id = text(&build["id"]);
    let files = build["files"]
        .as_array()
        .ok_or_else(|| format!("prego: {} {id}: the answer has no file list", long(r)))?;
    let dir = PathBuf::from(out);
    // Every name is checked, and no file is replaced, before any download.
    let mut plan = Vec::new();
    for f in files {
        let name = f["name"].as_str().unwrap_or("").to_string();
        super::check_file_name(&name).map_err(|e| format!("prego: {} {id}: {e}", long(r)))?;
        let target = dir.join(&name);
        if target.exists() {
            return Err(format!(
                "prego: {}: the file exists; prego build get does not replace files",
                target.display()
            ));
        }
        let sha = f["sha256"].as_str().unwrap_or("").to_ascii_lowercase();
        if !no_verify && (sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit())) {
            return Err(format!(
                "prego: {} {id}: {name} has no sha256 in the file list",
                long(r)
            ));
        }
        plan.push((name, target, sha, f["size"].as_u64()));
    }
    std::fs::create_dir_all(&dir).map_err(|e| format!("prego: {}: {e}", dir.display()))?;
    for (name, target, sha, size) in plan {
        download(api, r, &id, &name, &target, &sha, size, no_verify)?;
        eprintln!("  {name} ok");
    }
    let check = if no_verify {
        "not checked (--no-verify)"
    } else {
        "sha256 checked"
    };
    eprintln!(
        "{} {id}: {} files in {} ({check})",
        long(r),
        files.len(),
        dir.display()
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn download(
    api: &Api,
    r: &SnipRef,
    id: &str,
    name: &str,
    target: &Path,
    sha: &str,
    size: Option<u64>,
    no_verify: bool,
) -> Result<(), String> {
    use sha2::Digest;
    let tmp = target.with_file_name(format!(".{name}.prego-tmp"));
    let _ = std::fs::remove_file(&tmp);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(|e| format!("prego: {}: {e}", tmp.display()))?;
    let mut w = HashingWriter {
        inner: file,
        h: sha2::Sha256::new(),
        n: 0,
    };
    let max = size
        .unwrap_or(super::MAX_FILE_BYTES)
        .min(super::MAX_FILE_BYTES);
    let path = format!("{}/builds/{}/files/{}", base(r), seg(id), seg(name));
    let what = format!("{} {id} {name}", long(r));
    let result = (|| {
        let res = api.get_into(&path, "application/octet-stream", &mut w, max)?;
        match res.status {
            200 => Ok(()),
            301 | 302 | 303 | 307 | 308 => {
                let loc = res.header("location").ok_or_else(|| {
                    format!("prego: {what}: a redirect without a Location header")
                })?;
                let link = download_link(&api.full_url(&path), loc)
                    .map_err(|e| format!("prego: {what}: {e}"))?;
                let r2 = api.get_link(&link, &mut w, max)?;
                if r2.status == 200 {
                    Ok(())
                } else {
                    Err(format!(
                        "prego: {what}: HTTP {} from the download link",
                        r2.status
                    ))
                }
            }
            _ => Err(api_error(&res, &what)),
        }
    })();
    let got: String =
        w.h.clone()
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
    let n = w.n;
    drop(w);
    let check = result.and_then(|()| {
        if no_verify {
            return Ok(());
        }
        if size.is_some_and(|s| s != n) {
            return Err(format!(
                "prego: {what}: got {n} bytes, the file list says {}",
                size.unwrap_or(0)
            ));
        }
        if got != sha {
            return Err(format!(
                "prego: {what}: the sha256 is {got}, the file list says {sha}"
            ));
        }
        Ok(())
    });
    match check {
        Ok(()) => {
            std::fs::rename(&tmp, target).map_err(|e| format!("prego: {}: {e}", target.display()))
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

// ---- list ----

/// One line per build: ID, time, level, commit, ref, the label or the expiry, files and bytes.
pub fn list_text(answer: &Value) -> String {
    let mut out = String::new();
    let items = answer["items"].as_array().cloned().unwrap_or_default();
    if items.is_empty() {
        out.push_str("(no builds)\n");
    }
    for b in &items {
        let commit = b["commit"]
            .as_str()
            .map(|c| &c[..c.len().min(12)])
            .unwrap_or("-");
        let state = match b["label"].as_str() {
            Some(l) => format!("promoted {l}"),
            None => format!("expires {}", text(&b["expires_at"])),
        };
        out.push_str(&format!(
            "{}  {}  {:9}  {:12}  {}  {state}  {} files  {} B\n",
            text(&b["id"]),
            text(&b["created_at"]),
            text(&b["level"]),
            commit,
            b["ref"].as_str().unwrap_or("-"),
            text(&b["file_count"]),
            text(&b["total_bytes"]),
        ));
    }
    if let Some(n) = answer["next"].as_str() {
        out.push_str(&format!("(more: the next page starts before {n})\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queries_and_links() {
        assert_eq!(selector_query(&Selector::Id("bld_1".into())), "id=bld_1");
        assert_eq!(
            selector_query(&Selector::Version("1.4.0+b".into())),
            "version=1.4.0%2Bb"
        );
        assert_eq!(
            selector_query(&Selector::Latest {
                git_ref: Some("refs/heads/main".into())
            }),
            "latest&ref=refs%2Fheads%2Fmain"
        );
        assert_eq!(
            selector_query(&Selector::Latest { git_ref: None }),
            "latest"
        );
        assert_eq!(
            download_link("https://api.x/v1/build/a/b", "/r2/f?sig=1").unwrap(),
            "https://api.x/r2/f?sig=1"
        );
        assert!(download_link("https://api.x/v1", "http://r2/x").is_err());
        assert!(stream_ref("acme/ci/api-cli@1").is_err());
        assert_eq!(
            long(&stream_ref("acme/api-cli").unwrap()),
            "acme/default/api-cli"
        );
    }

    #[test]
    fn list_lines() {
        let a = json!({"items": [
            {"id": "bld_1", "created_at": "2026-11-26T10:00:00Z", "level": "ci_source", "commit": "9f2c1ab3c4d5e6f7",
             "ref": "refs/tags/v1.4.0", "label": "v1.4.0", "file_count": 2, "total_bytes": 100},
            {"id": "bld_2", "created_at": "2026-11-26T09:00:00Z", "level": "workload", "commit": null,
             "ref": null, "label": null, "expires_at": "2026-12-26T09:00:00Z", "file_count": 1, "total_bytes": 5}
        ], "next": "bld_2"});
        let t = list_text(&a);
        assert!(t.contains("bld_1  2026-11-26T10:00:00Z  ci_source  9f2c1ab3c4d5  refs/tags/v1.4.0  promoted v1.4.0  2 files  100 B"), "{t}");
        assert!(t.contains("bld_2  2026-11-26T09:00:00Z  workload   -             -  expires 2026-12-26T09:00:00Z  1 files  5 B"), "{t}");
        assert!(t.ends_with("(more: the next page starts before bld_2)\n"));
        assert_eq!(list_text(&json!({"items": []})), "(no builds)\n");
    }
}
