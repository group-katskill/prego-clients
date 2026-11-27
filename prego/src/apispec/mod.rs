//! `prego apispec`: versioned OpenAPI 3.0 and 3.1 documents and GraphQL schemas (ADR-0067 with Amendment 1), on the
//! machine routes
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
    /// `json`, `yaml` or `sdl` (GraphQL).
    pub format: &'static str,
    /// The `openapi` value; empty for GraphQL.
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

/// A GraphQL schema file: `.graphql` or `.gql`.
pub fn is_graphql_file(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.ends_with(".graphql") || n.ends_with(".gql")
}

/// The document to publish: a file, or a folder of `.graphql`/`.gql` files joined in path order (ADR-0067
/// Amendment 1; the registry takes one SDL file). Returns the bytes and whether they are GraphQL SDL.
pub fn read_document(path: &str) -> Result<(Vec<u8>, bool), String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("prego: {path}: {e}"))?;
    if meta.is_file() {
        let body = std::fs::read(path).map_err(|e| format!("prego: {path}: {e}"))?;
        return Ok((body, is_graphql_file(path)));
    }
    if !meta.is_dir() {
        return Err(format!("prego: {path}: not a file or a folder"));
    }
    let mut files = Vec::new();
    collect_graphql(
        std::path::Path::new(path),
        std::path::Path::new(""),
        &mut files,
    )?;
    if files.is_empty() {
        return Err(format!(
            "prego: {path}: the folder has no .graphql or .gql file. To publish OpenAPI, give the file"
        ));
    }
    files.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let mut body = Vec::new();
    for (_, full) in files {
        let mut part =
            std::fs::read(&full).map_err(|e| format!("prego: {}: {e}", full.display()))?;
        if std::str::from_utf8(&part).is_err() {
            return Err(format!("prego: {}: not UTF-8", full.display()));
        }
        if !part.is_empty() && !part.ends_with(b"\n") {
            part.push(b'\n');
        }
        body.extend(part);
        if body.len() > MAX_DOCUMENT {
            break;
        }
    }
    Ok((body, true))
}

/// The `.graphql`/`.gql` files under `dir` (not following symbolic links), with their paths relative to the
/// folder (`/` between parts).
fn collect_graphql(
    dir: &std::path::Path,
    rel: &std::path::Path,
    out: &mut Vec<(String, std::path::PathBuf)>,
) -> Result<(), String> {
    let full = dir.join(rel);
    let entries =
        std::fs::read_dir(&full).map_err(|e| format!("prego: {}: {e}", full.display()))?;
    for e in entries {
        let e = e.map_err(|e| format!("prego: {}: {e}", full.display()))?;
        let t = e.file_type().map_err(|e| format!("prego: {}: {e}", e))?;
        let name = e.file_name().to_string_lossy().into_owned();
        let r = rel.join(&name);
        if t.is_dir() {
            collect_graphql(dir, &r, out)?;
        } else if t.is_file() && is_graphql_file(&name) {
            let key = r
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            out.push((key, dir.join(&r)));
        }
    }
    Ok(())
}

/// Checks a GraphQL SDL document before the upload (ADR-0067 Amendment 1): UTF-8, at most 4 MiB, at least one
/// definition, and no executable definition (an operation `query`, `mutation`, `subscription`, a shorthand
/// `{ ... }` query, or a `fragment`). The registry does the full check. The error gives the line and column.
pub fn precheck_sdl(body: &[u8]) -> Result<Precheck, String> {
    if body.len() > MAX_DOCUMENT {
        return Err(format!(
            "the document has {} bytes; an API spec is at most 4 MiB",
            body.len()
        ));
    }
    let text = std::str::from_utf8(body).map_err(|_| "the document is not UTF-8".to_string())?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let tokens = sdl_tokens(text)?;
    if tokens.iter().all(|t| t.depth > 0 || t.text.is_empty()) || tokens.is_empty() {
        return Err("the document has no GraphQL type definition".into());
    }
    // A top-level token that starts an executable definition: an operation keyword or `fragment` where a
    // definition starts, or a `{` with no type, schema or extension before it.
    let mut prev: Option<&Tok> = None;
    for t in tokens.iter().filter(|t| t.depth == 0) {
        let at_start = match prev {
            None => true,
            Some(p) => p.text == "}",
        };
        let executable = at_start
            && matches!(
                t.text.as_str(),
                "query" | "mutation" | "subscription" | "fragment" | "{"
            );
        if executable {
            return Err(format!(
                "line {}, column {}: `{}` starts an executable definition (a query, mutation, subscription or \
                 fragment). An API spec holds the schema only (SDL: type, interface, union, enum, input, scalar, \
                 directive, schema and extend definitions)",
                t.line, t.col, t.text
            ));
        }
        prev = Some(t);
    }
    Ok(Precheck {
        format: "sdl",
        openapi: String::new(),
    })
}

/// A token of the top-level structure: a name or one punctuator, with the bracket depth before it.
#[derive(Debug)]
struct Tok {
    text: String,
    depth: usize,
    line: usize,
    col: usize,
}

/// The names and the `{`, `}` of a GraphQL document, with their depth. Strings, block strings and comments
/// are skipped. A bracket that does not close or open in order is an error.
fn sdl_tokens(text: &str) -> Result<Vec<Tok>, String> {
    let chars: Vec<char> = text.chars().collect();
    let (mut i, mut line, mut col) = (0usize, 1usize, 1usize);
    let mut depth = 0usize;
    let mut out = Vec::new();
    let advance = |i: &mut usize, line: &mut usize, col: &mut usize, c: char| {
        *i += 1;
        if c == '\n' {
            *line += 1;
            *col = 1;
        } else {
            *col += 1;
        }
    };
    while i < chars.len() {
        let c = chars[i];
        let (l0, c0) = (line, col);
        if c == '#' {
            while i < chars.len() && chars[i] != '\n' {
                {
                    let ch = chars[i];
                    advance(&mut i, &mut line, &mut col, ch);
                }
            }
        } else if c == '"' {
            let block = chars.get(i + 1) == Some(&'"') && chars.get(i + 2) == Some(&'"');
            let skip = if block { 3 } else { 1 };
            for _ in 0..skip {
                advance(&mut i, &mut line, &mut col, '"');
            }
            loop {
                if i >= chars.len() {
                    return Err(format!("line {l0}, column {c0}: a string does not end"));
                }
                let d = chars[i];
                if block
                    && d == '"'
                    && chars.get(i + 1) == Some(&'"')
                    && chars.get(i + 2) == Some(&'"')
                {
                    for _ in 0..3 {
                        advance(&mut i, &mut line, &mut col, '"');
                    }
                    break;
                }
                if !block && d == '\\' {
                    advance(&mut i, &mut line, &mut col, d);
                    if i < chars.len() {
                        {
                            let ch = chars[i];
                            advance(&mut i, &mut line, &mut col, ch);
                        }
                    }
                    continue;
                }
                if !block && d == '"' {
                    advance(&mut i, &mut line, &mut col, d);
                    break;
                }
                if !block && d == '\n' {
                    return Err(format!(
                        "line {l0}, column {c0}: a string does not end on its line"
                    ));
                }
                advance(&mut i, &mut line, &mut col, d);
            }
        } else if c == '{' || c == '(' || c == '[' {
            if c == '{' {
                out.push(Tok {
                    text: "{".into(),
                    depth,
                    line,
                    col,
                });
            }
            depth += 1;
            advance(&mut i, &mut line, &mut col, c);
        } else if c == '}' || c == ')' || c == ']' {
            depth = depth
                .checked_sub(1)
                .ok_or_else(|| format!("line {line}, column {col}: `{c}` closes nothing"))?;
            if c == '}' {
                out.push(Tok {
                    text: "}".into(),
                    depth,
                    line,
                    col,
                });
            }
            advance(&mut i, &mut line, &mut col, c);
        } else if c.is_ascii_alphabetic() || c == '_' {
            let mut name = String::new();
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                name.push(chars[i]);
                {
                    let ch = chars[i];
                    advance(&mut i, &mut line, &mut col, ch);
                }
            }
            out.push(Tok {
                text: name,
                depth,
                line: l0,
                col: c0,
            });
        } else {
            // Other punctuators and numbers: they separate names, and `=`, `|`, `&`, `@`, `:` follow a name.
            if !c.is_whitespace() && c != ',' {
                out.push(Tok {
                    text: c.to_string(),
                    depth,
                    line,
                    col,
                });
            }
            advance(&mut i, &mut line, &mut col, c);
        }
    }
    if depth != 0 {
        return Err("a `{`, `(` or `[` does not close".into());
    }
    Ok(out)
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
            let (body, graphql) = read_document(file)?;
            let p = if graphql {
                precheck_sdl(&body)
            } else {
                precheck(&body)
            }
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
    let content_type = match p.format {
        "json" => "application/json",
        "sdl" => "application/graphql",
        _ => "application/yaml",
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
        if p.format == "sdl" {
            println!(
                "{what}: published ({hash}, GraphQL SDL, {} root fields)",
                text(&v["operation_count"])
            );
        } else {
            println!(
                "{what}: published ({hash}, OpenAPI {}, {} operations)",
                p.openapi,
                text(&v["operation_count"])
            );
        }
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

/// For `prego verify`: the version label (the highest when none is given) and the hash of the document as
/// published, after the download is checked against it.
pub(crate) fn checked_version(
    globals: &[&str],
    env: &dyn Env,
    r: &SpecRef,
) -> Result<(String, String), String> {
    let api = api(globals, &r.tenant, env)?;
    let (version, hash, _) = get(&api, r, None, None)?;
    Ok((version, hash))
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
    fn sdl_prechecks() {
        let ok = "\"\"\"The payments.\"\"\"\nschema { query: Query mutation: Mutation }\n\
                  type Query { payment(id: ID!): Payment }\n\
                  type Mutation { refund(paymentId: ID!): Refund }\n\
                  # a comment with query { x }\n\
                  type Payment @key(fields: \"id\") { id: ID! amount: Int! }\n\
                  type Refund { id: ID! }\n\
                  union Result = Payment | Refund\n\
                  directive @key(fields: String!) on OBJECT | INTERFACE\n\
                  extend type Payment { note: String }\n";
        assert_eq!(precheck_sdl(ok.as_bytes()).unwrap().format, "sdl");
        let e = precheck_sdl(b"type Query { a: Int }\nquery Q { a }\n").unwrap_err();
        assert!(
            e.starts_with("line 2, column 1: `query` starts an executable definition"),
            "{e}"
        );
        assert!(precheck_sdl(b"{ a }").unwrap_err().contains("`{` starts"));
        assert!(precheck_sdl(b"type A { a: Int }\nfragment F on A { a }")
            .unwrap_err()
            .contains("`fragment`"));
        assert!(precheck_sdl(b"mutation { a }")
            .unwrap_err()
            .contains("`mutation`"));
        assert!(precheck_sdl(b"subscription S { a }")
            .unwrap_err()
            .contains("`subscription`"));
        // A field named query, and a block string with braces, are fine.
        precheck_sdl(
            b"type Query { query: String }\n\"\"\"\n{ not a query }\n\"\"\"\nscalar Date\n",
        )
        .unwrap();
        assert!(precheck_sdl(b"# only a comment\n")
            .unwrap_err()
            .contains("no GraphQL type definition"));
        assert!(precheck_sdl(b"type A { a: Int ")
            .unwrap_err()
            .contains("does not close"));
        assert!(precheck_sdl(b"type A { a: String @d(x: \"open) }").is_err());
        assert!(precheck_sdl(&[0xff]).unwrap_err().contains("UTF-8"));
    }

    #[test]
    fn graphql_folders_join_in_path_order() {
        let d = prego_auth::testing::TempDir::new("prego-apispec-sdl-folder");
        std::fs::create_dir_all(d.join("b")).unwrap();
        std::fs::write(d.join("b/query.graphql"), "type Query { a: A }").unwrap();
        std::fs::write(d.join("a.gql"), "type A { x: Int }\n").unwrap();
        std::fs::write(d.join("README.md"), "not schema").unwrap();
        let (body, graphql) = read_document(d.to_str().unwrap()).unwrap();
        assert!(graphql);
        assert_eq!(
            String::from_utf8(body).unwrap(),
            "type A { x: Int }\ntype Query { a: A }\n"
        );
        let (_, graphql) = read_document(d.join("a.gql").to_str().unwrap()).unwrap();
        assert!(graphql);
        let (_, graphql) = read_document(d.join("README.md").to_str().unwrap()).unwrap();
        assert!(!graphql);
        let empty = prego_auth::testing::TempDir::new("prego-apispec-sdl-empty");
        assert!(read_document(empty.to_str().unwrap())
            .unwrap_err()
            .contains("no .graphql"));
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
