//! `prego apispec`: versioned OpenAPI 3.0 and 3.1 documents (ADR-0067), on the machine routes
//! `/v1/apispec/<tenant>/<namespace>/<name>` (api.md section 15.2).
//!
//! The client checks a document before the upload only as far as it can without a full YAML parser: the
//! `openapi` and `swagger` fields at the top level, and the size. The registry does the full check. The diff is
//! the registry's diff (one implementation for the CLI and the console); the client only prints it.

use std::io::Write as _;

use prego_auth::http::Body;
use prego_auth::Env;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::env::{query, text};
use crate::snippet::reference::SnipRef;
use crate::snippet::{api_error, expect_exit, parse_json, seg, Api};

/// The largest document (ADR-0067 section 1).
pub const MAX_DOCUMENT: usize = 4 * 1024 * 1024;

/// The Swagger 2.0 refusal, as the registry words it.
pub const SWAGGER_HINT: &str = "Swagger 2.0 is not supported. Prego accepts OpenAPI 3.0 and 3.1. Convert the \
                                document to OpenAPI 3 (for example with swagger2openapi or the Swagger Editor), \
                                then publish it again.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApispecCommand {
    Push {
        file: String,
        reference: String,
        message: Option<String>,
        tag: Option<String>,
    },
    Get {
        reference: String,
        format: Option<String>,
        expect: Option<String>,
        out: Option<String>,
    },
    Diff {
        from: String,
        to: String,
        json: bool,
    },
}

/// `<tenant>/<name>` or `<tenant>/<namespace>/<name>`, with `@<version>` (a SemVer label or a tag).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecRef {
    pub tenant: String,
    pub namespace: String,
    pub name: String,
    pub version: Option<String>,
}

impl SpecRef {
    pub fn parse(text: &str) -> Result<SpecRef, String> {
        let (path, version) = match text.split_once('@') {
            Some((p, v)) => (p, Some(v)),
            None => (text, None),
        };
        let r = SnipRef::parse(path).map_err(|_| {
            format!(
                "bad API spec reference `{text}`: use <tenant>/<spec> or <tenant>/<namespace>/<spec>, with \
                 @<version> where it is allowed"
            )
        })?;
        if let Some(v) = version {
            check_selector(v)?;
        }
        Ok(SpecRef {
            tenant: r.tenant,
            namespace: r.namespace,
            name: r.name,
            version: version.map(str::to_string),
        })
    }

    pub fn long(&self) -> String {
        format!("{}/{}/{}", self.tenant, self.namespace, self.name)
    }

    fn path(&self) -> String {
        format!(
            "{}/{}/{}",
            seg(&self.tenant),
            seg(&self.namespace),
            seg(&self.name)
        )
    }
}

/// A version label: SemVer 2.0, at most 64 characters, no leading `v` (api.md section 15.1).
pub fn check_label(v: &str) -> Result<(), String> {
    let bad = || {
        format!(
            "bad version `{v}`: an API spec version is SemVer 2.0 with no leading v, for example 1.4.0 or \
             2.0.0-rc.1"
        )
    };
    if v.is_empty() || v.len() > 64 || v.starts_with('v') {
        return Err(bad());
    }
    let (core_pre, build) = match v.split_once('+') {
        Some((a, b)) => (a, Some(b)),
        None => (v, None),
    };
    let (core, pre) = match core_pre.split_once('-') {
        Some((a, b)) => (a, Some(b)),
        None => (core_pre, None),
    };
    let nums: Vec<&str> = core.split('.').collect();
    let num_ok = |n: &&str| {
        !n.is_empty()
            && n.bytes().all(|b| b.is_ascii_digit())
            && (n.len() == 1 || !n.starts_with('0'))
    };
    if nums.len() != 3 || !nums.iter().all(num_ok) {
        return Err(bad());
    }
    let ident_ok = |s: &str, numeric_rule: bool| {
        s.split('.').all(|i| {
            !i.is_empty()
                && i.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !(numeric_rule
                    && i.len() > 1
                    && i.starts_with('0')
                    && i.bytes().all(|b| b.is_ascii_digit()))
        })
    };
    if pre.is_some_and(|p| !ident_ok(p, true)) || build.is_some_and(|b| !ident_ok(b, false)) {
        return Err(bad());
    }
    Ok(())
}

/// A version in a path: a label or a tag.
fn check_selector(v: &str) -> Result<(), String> {
    if check_label(v).is_ok() || crate::snippet::reference::check_tag(v).is_ok() {
        Ok(())
    } else {
        Err(format!(
            "bad version `{v}`: use a SemVer label (1.4.0) or a tag"
        ))
    }
}

/// What the client can tell about a document before the upload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Precheck {
    /// `json` or `yaml`.
    pub format: &'static str,
    /// The `openapi` value.
    pub openapi: String,
}

/// The value of a top-level YAML key (`key: value` at column 0), unquoted. `None` when the key is not there.
fn yaml_top(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        let Some(rest) = line.strip_prefix(key) else {
            continue;
        };
        let rest = rest.trim_start_matches([' ', '\t']);
        let Some(value) = rest.strip_prefix(':') else {
            continue;
        };
        let v = value.split(" #").next().unwrap_or("").trim();
        let v = v
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .or_else(|| v.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
            .unwrap_or(v);
        return Some(v.to_string());
    }
    None
}

/// Checks a document before the upload (api.md section 15.1, as far as the client can). Error texts give the
/// JSON pointer as the registry does.
pub fn precheck(body: &[u8]) -> Result<Precheck, String> {
    if body.len() > MAX_DOCUMENT {
        return Err(format!(
            "the document has {} bytes; an API spec is at most 4 MiB",
            body.len()
        ));
    }
    let text = std::str::from_utf8(body).map_err(|_| "the document is not UTF-8".to_string())?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let (format, swagger, openapi) = if text.trim_start().starts_with('{') {
        let v: Value = serde_json::from_str(text)
            .map_err(|e| format!("the document is not valid JSON: {e}"))?;
        let s = v.get("swagger").map(|_| String::new());
        let o = match v.get("openapi") {
            None => None,
            Some(Value::String(s)) => Some(s.clone()),
            Some(other) => {
                return Err(format!(
                    "/openapi: the value is {other}, not a string such as \"3.1.0\""
                ))
            }
        };
        ("json", s, o)
    } else {
        ("yaml", yaml_top(text, "swagger"), yaml_top(text, "openapi"))
    };
    if swagger.is_some() {
        return Err(format!("/swagger: {SWAGGER_HINT}"));
    }
    let openapi = openapi.ok_or_else(|| {
        "/openapi: the document has no `openapi` field; Prego accepts OpenAPI 3.0 and 3.1 documents".to_string()
    })?;
    let ok = ["3.0.", "3.1."].iter().any(|p| {
        openapi
            .strip_prefix(p)
            .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
    });
    if !ok {
        return Err(format!(
            "/openapi: `{openapi}` is not 3.0.x or 3.1.x; Prego accepts OpenAPI 3.0 and 3.1"
        ));
    }
    Ok(Precheck { format, openapi })
}

fn hex_sha256(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

fn api(globals: &[&str], tenant: &str, env: &dyn Env) -> Result<Api, String> {
    Api::with_prefix(globals, tenant, env, "apispec")
}

pub fn run(globals: &[&str], command: &ApispecCommand, env: &dyn Env) -> Result<(), String> {
    match command {
        ApispecCommand::Push {
            file,
            reference,
            message,
            tag,
        } => {
            let r = SpecRef::parse(reference)?;
            let version = r.version.clone().ok_or_else(|| {
                format!(
                    "prego apispec push: give the version: {}@<version>",
                    r.long()
                )
            })?;
            check_label(&version).map_err(|e| format!("prego apispec push: {e}"))?;
            let body = std::fs::read(file).map_err(|e| format!("prego: {file}: {e}"))?;
            let p = precheck(&body)
                .map_err(|e| format!("prego apispec push: {file}: {e}. Nothing was sent."))?;
            push(
                &api(globals, &r.tenant, env)?,
                &r,
                &version,
                &body,
                &p,
                message.as_deref(),
                tag.as_deref(),
            )
        }
        ApispecCommand::Get {
            reference,
            format,
            expect,
            out,
        } => {
            let r = SpecRef::parse(reference)?;
            let api = api(globals, &r.tenant, env)?;
            let (version, hash, body) = get(&api, &r, format.as_deref(), expect.as_deref())?;
            match out {
                Some(path) => crate::snippet::write_bytes_atomic(path, &body)?,
                None => std::io::stdout()
                    .write_all(&body)
                    .map_err(|e| format!("prego: stdout: {e}"))?,
            }
            eprintln!("{}@{version} {hash}", r.long());
            Ok(())
        }
        ApispecCommand::Diff { from, to, json } => {
            let a = SpecRef::parse(from)?;
            let b = SpecRef::parse(to)?;
            if a.long() != b.long() {
                return Err(format!(
                    "prego apispec diff: both versions must be of one spec ({} and {})",
                    a.long(),
                    b.long()
                ));
            }
            let (Some(va), Some(vb)) = (&a.version, &b.version) else {
                return Err("usage: prego apispec diff <ref>@<version> <ref>@<version>".into());
            };
            diff(&api(globals, &a.tenant, env)?, &a, va, vb, *json)
        }
    }
}

fn push(
    api: &Api,
    r: &SpecRef,
    version: &str,
    body: &[u8],
    p: &Precheck,
    message: Option<&str>,
    tag: Option<&str>,
) -> Result<(), String> {
    let mut q: Vec<(&str, String)> = Vec::new();
    if let Some(m) = message {
        q.push(("message", m.to_string()));
    }
    if let Some(t) = tag {
        q.push(("tag", t.to_string()));
    }
    let mut path = format!("{}/{}", r.path(), seg(version));
    if !q.is_empty() {
        path = format!("{path}?{}", query(&q));
    }
    let content_type = if p.format == "json" {
        "application/json"
    } else {
        "application/yaml"
    };
    let what = format!("{}@{version}", r.long());
    let res = api.send("PUT", &path, Some(content_type), Body::Bytes(body))?;
    if !(200..300).contains(&res.status) {
        return Err(api_error(&res, &what));
    }
    let answer = parse_json(res.body.as_bytes(), &what)?;
    let v = &answer["version"];
    let local = format!("sha256:{}", hex_sha256(body));
    let hash = v["hash"].as_str().unwrap_or("");
    if hash != local {
        return Err(format!(
            "prego: {what}: the registry hash {hash} is not the hash of the document ({local})"
        ));
    }
    if answer["created"] == true {
        println!(
            "{what}: published ({hash}, OpenAPI {}, {} operations)",
            p.openapi,
            text(&v["operation_count"])
        );
    } else {
        println!("{what}: no change, the version has these bytes ({hash})");
    }
    if let Some(t) = tag {
        println!("{}: tag {t} -> {version}", r.long());
    }
    Ok(())
}

/// The version, the hash of the document as published, and the bytes. The bytes as published are checked
/// against the hash; a converted document (`--format` the other format) is checked through `expect` only.
pub(crate) fn get(
    api: &Api,
    r: &SpecRef,
    format: Option<&str>,
    expect: Option<&str>,
) -> Result<(String, String, Vec<u8>), String> {
    let selector = match &r.version {
        Some(v) => v.clone(),
        None => {
            let what = r.long();
            let (_, spec) = api.get_json(&r.path(), &what)?;
            spec["highest_version"]
                .as_str()
                .filter(|v| !v.is_empty())
                .ok_or_else(|| format!("prego: {what}: the spec has no live version"))?
                .to_string()
        }
    };
    let mut q: Vec<(&str, String)> = Vec::new();
    if let Some(f) = format {
        q.push(("format", f.to_string()));
    }
    if let Some(h) = expect {
        q.push(("expect", h.to_string()));
    }
    let mut path = format!("{}/{}", r.path(), seg(&selector));
    if !q.is_empty() {
        path = format!("{path}?{}", query(&q));
    }
    let what = format!("{}@{selector}", r.long());
    // No format: the bytes as published.
    let (res, body) = api.get_bytes(&path, "*/*", MAX_DOCUMENT as u64 * 4)?;
    if res.status != 200 {
        expect_exit(&res, &what);
        return Err(api_error(&res, &what));
    }
    let hash = res.header("x-prego-apispec-hash").unwrap_or("").to_string();
    let version = res
        .header("x-prego-apispec-version")
        .unwrap_or(&selector)
        .to_string();
    let published = format.is_none()
        || res.header("x-prego-apispec-format").map(str::trim) == Some("published");
    if published {
        let local = format!("sha256:{}", hex_sha256(&body));
        if local != hash {
            return Err(format!(
                "prego: {what}: the document has the hash {local}, not {hash} (X-Prego-Apispec-Hash)"
            ));
        }
    }
    if let Some(want) = expect {
        if want != hash {
            crate::snippet::mismatch_exit(&what, &hash, want);
        }
    }
    Ok((version, hash, body))
}

fn diff(api: &Api, r: &SpecRef, from: &str, to: &str, json: bool) -> Result<(), String> {
    let path = format!(
        "{}/diff?{}",
        r.path(),
        query(&[("from", from.to_string()), ("to", to.to_string())])
    );
    let what = format!("{} {from}..{to}", r.long());
    let (_, answer) = api.get_json(&path, &what)?;
    if json {
        println!("{answer:#}");
        return Ok(());
    }
    print!("{}", diff_text(r, &answer));
    Ok(())
}

/// The diff answer as text, one change per line, in the registry's order. `+` added, `-` removed, `~` changed.
pub fn diff_text(r: &SpecRef, a: &Value) -> String {
    let mut out = format!(
        "{} {} ({}) -> {} ({})\n",
        r.long(),
        text(&a["from"]["version"]),
        text(&a["from"]["hash"]),
        text(&a["to"]["version"]),
        text(&a["to"]["hash"])
    );
    let changes = a["changes"].as_array().cloned().unwrap_or_default();
    if changes.is_empty() {
        out.push_str("no changes at the API level\n");
    }
    for c in &changes {
        let mark = match c["change"].as_str() {
            Some("added") => "+",
            Some("removed") => "-",
            _ => "~",
        };
        let line = c["text"]
            .as_str()
            .filter(|t| !t.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| {
                let mut parts = vec![text(&c["kind"])];
                for k in ["method", "path", "in", "name", "code"] {
                    if let Some(v) = c[k].as_str().filter(|v| !v.is_empty()) {
                        parts.push(v.to_string());
                    }
                }
                if c.get("from").is_some() || c.get("to").is_some() {
                    parts.push(format!("{} -> {}", text(&c["from"]), text(&c["to"])));
                }
                parts.join(" ")
            });
        out.push_str(&format!("{mark} {line}\n"));
    }
    if a["truncated"] == true {
        out.push_str("(the list stops at 5,000 changes)\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn references_and_labels() {
        let r = SpecRef::parse("acme/payments-api@1.4.0").unwrap();
        assert_eq!(r.long(), "acme/default/payments-api");
        assert_eq!(r.version.as_deref(), Some("1.4.0"));
        assert!(SpecRef::parse("acme/ops/payments-api@stable").is_ok());
        assert!(SpecRef::parse("payments-api").is_err());
        for ok in ["1.4.0", "2.0.0-rc.1", "1.0.0+build.7", "0.0.1"] {
            check_label(ok).unwrap();
        }
        for bad in [
            "v1.4.0",
            "1.4",
            "01.2.3",
            "1.2.3-01",
            "1.2.3-",
            "",
            &"1".repeat(65),
        ] {
            assert!(check_label(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn prechecks() {
        let p = precheck(br#"{"openapi":"3.1.0","info":{"title":"t","version":"1"},"paths":{}}"#)
            .unwrap();
        assert_eq!(
            p,
            Precheck {
                format: "json",
                openapi: "3.1.0".into()
            }
        );
        let p =
            precheck(b"# api\nopenapi: '3.0.3'\ninfo:\n  title: t\n  openapi: nested\n").unwrap();
        assert_eq!(
            p,
            Precheck {
                format: "yaml",
                openapi: "3.0.3".into()
            }
        );
        let e = precheck(b"swagger: \"2.0\"\ninfo: {}\n").unwrap_err();
        assert!(
            e.starts_with("/swagger: Swagger 2.0 is not supported"),
            "{e}"
        );
        let e = precheck(br#"{"swagger":"2.0"}"#).unwrap_err();
        assert!(e.starts_with("/swagger"), "{e}");
        assert!(precheck(b"openapi: 3.2.0\n")
            .unwrap_err()
            .contains("not 3.0.x or 3.1.x"));
        assert!(precheck(br#"{"openapi":3.1}"#)
            .unwrap_err()
            .contains("not a string"));
        assert!(precheck(b"info:\n  title: t\n")
            .unwrap_err()
            .contains("no `openapi` field"));
        assert!(precheck(&[0xff, 0xfe]).unwrap_err().contains("UTF-8"));
        assert!(precheck(&vec![b' '; MAX_DOCUMENT + 1])
            .unwrap_err()
            .contains("4 MiB"));
        // A nested `openapi:` does not count.
        assert!(precheck(b"info:\n  openapi: 3.1.0\n").is_err());
    }

    #[test]
    fn diff_lines() {
        let r = SpecRef::parse("acme/payments-api").unwrap();
        let a = json!({
            "from": {"version": "1.0.0", "hash": "sha256:a"}, "to": {"version": "1.1.0", "hash": "sha256:b"},
            "changes": [
                {"change": "changed", "kind": "info_version", "from": "1.0.0", "to": "1.1.0", "text": "info.version 1.0.0 -> 1.1.0"},
                {"change": "added", "kind": "operation", "path": "/refunds", "method": "POST", "text": ""},
                {"change": "removed", "kind": "schema", "name": "Old", "text": "schema Old removed"}
            ],
            "truncated": true
        });
        assert_eq!(
            diff_text(&r, &a),
            "acme/default/payments-api 1.0.0 (sha256:a) -> 1.1.0 (sha256:b)\n\
             ~ info.version 1.0.0 -> 1.1.0\n\
             + operation POST /refunds\n\
             - schema Old removed\n\
             (the list stops at 5,000 changes)\n"
        );
        let none = json!({"from": {"version": "1"}, "to": {"version": "1"}, "changes": []});
        assert!(diff_text(&r, &none).ends_with("no changes at the API level\n"));
    }
}
