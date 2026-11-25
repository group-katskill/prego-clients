//! `prego keys`: Keys and Certificates (ADR-0061). Named, versioned sets of typed public keys and
//! certificates under `/v1/keys/` on the control host, with a registry token. Prego never stores a private
//! key: this client checks every upload for private key material before it sends anything (item 2.4), and
//! `prego keys new` keeps the private key in a local file with mode 0600.

pub mod entry;

use prego_auth::http::FullResponse;
use prego_auth::Env;
use serde_json::{json, Value};

use crate::env::{query, text};
use crate::sign::jwk::PublicJwk;
use crate::sign::keyfile::{self, NewAlg, PrivateKey};
use crate::snippet::reference::{self, SnipRef};
use crate::snippet::{self as sn, seg, Api};
use entry::{EntryType, Info};

/// The largest `PUT` body (ADR-0061 section 4).
pub const MAX_BODY: usize = 1024 * 1024;
/// The most entries in a version (ADR-0061 item 2.3).
pub const MAX_ENTRIES: usize = 100;

/// The line that the help and the docs show.
pub const PUBLIC_ONLY: &str =
    "Keys and Certificates holds public keys and certificates only; Prego never stores a private key.";

#[derive(Debug, PartialEq, Eq)]
pub enum KeysCommand {
    Push {
        files: Vec<String>,
        reference: String,
        kind: Option<String>,
        tag: Option<String>,
        message: Option<String>,
        if_current: Option<String>,
        not_after: Option<String>,
    },
    Get {
        reference: String,
        entry: Option<String>,
        expect: Option<String>,
    },
    Ls {
        scope: String,
    },
    Log {
        reference: String,
    },
    Tag {
        reference: String,
        tag: String,
    },
    Rollback {
        reference: String,
        to: String,
        reason: String,
    },
    Revoke {
        reference: String,
        reason: String,
    },
    Fingerprint {
        file: String,
        kind: Option<String>,
    },
    New {
        alg: String,
        reference: String,
        out: Option<String>,
        message: Option<String>,
    },
}

pub fn run(globals: &[&str], command: &KeysCommand, env: &dyn Env) -> Result<(), String> {
    match command {
        KeysCommand::Fingerprint { file, kind } => fingerprint(file, kind.as_deref()),
        KeysCommand::Push {
            files,
            reference,
            kind,
            tag,
            message,
            if_current,
            not_after,
        } => {
            let r = SnipRef::parse(reference)?.no_version("push")?;
            let entries = load_entries(files, kind.as_deref())?;
            let api = api(globals, &r.tenant, env)?;
            push(
                &api,
                &r,
                &entries,
                &Opts {
                    tag: tag.as_deref(),
                    message: message.as_deref(),
                    if_current: if_current.as_deref(),
                    not_after: not_after.as_deref(),
                },
            )
            .map(|_| ())
        }
        KeysCommand::Get {
            reference,
            entry,
            expect,
        } => {
            let r = SnipRef::parse(reference)?;
            get(
                &api(globals, &r.tenant, env)?,
                &r,
                entry.as_deref(),
                expect.as_deref(),
            )
        }
        KeysCommand::Ls { scope } => {
            let (tenant, namespace) = reference::parse_scope(scope)?;
            ls(&api(globals, &tenant, env)?, &tenant, &namespace)
        }
        KeysCommand::Log { reference } => {
            let r = SnipRef::parse(reference)?.no_version("log")?;
            log(&api(globals, &r.tenant, env)?, &r)
        }
        KeysCommand::Tag { reference, tag } => {
            let r = SnipRef::parse(reference)?;
            if r.version.is_none() {
                return Err(
                    "prego: give the version to tag: prego keys tag <ref>@<version> <tag>".into(),
                );
            }
            reference::check_tag(tag).map_err(|e| format!("prego: {e}"))?;
            let api = api(globals, &r.tenant, env)?;
            sn::set_tag(&api, &r, tag).map_err(|e| grant_hint(e, &r, "publish"))
        }
        KeysCommand::Rollback {
            reference,
            to,
            reason,
        } => {
            let r = SnipRef::parse(reference)?.no_version("rollback")?;
            reference::check_selector(to)?;
            let api = api(globals, &r.tenant, env)?;
            sn::rollback(&api, &r, to, reason).map_err(|e| grant_hint(e, &r, "publish"))
        }
        KeysCommand::Revoke { reference, reason } => {
            let r = SnipRef::parse(reference)?.no_version("revoke")?;
            revoke(&api(globals, &r.tenant, env)?, &r, reason)
        }
        KeysCommand::New {
            alg,
            reference,
            out,
            message,
        } => {
            let alg = NewAlg::parse(alg).map_err(|e| format!("prego: {e}"))?;
            let r = SnipRef::parse(reference)?.no_version("new")?;
            let api = api(globals, &r.tenant, env)?;
            new_key(&api, &r, alg, out.as_deref(), message.as_deref())
        }
    }
}

fn api(globals: &[&str], tenant: &str, env: &dyn Env) -> Result<Api, String> {
    Api::with_prefix(globals, tenant, env, "keys")
}

/// The text for a missing grant on a key item (ADR-0061 section 3.6, ADR-0062 section 5).
pub fn missing_grant(action: &str, r: &SnipRef) -> String {
    format!(
        "{action} on key {} (type Keys and Certificates) is missing; ask an admin of {} for a grant",
        r.long(),
        r.tenant
    )
}

/// The text of the generic 404 of [`crate::snippet::api_error`]: no item, or no grant (the registry does not say which).
pub(crate) const NOT_FOUND: &str = "not found, or you have no grant for it";

/// Puts the grant text first when `e` is the 404 error, with the registry detail (and request id) after it.
pub(crate) fn with_grant(e: String, grant: String) -> String {
    if !e.contains(NOT_FOUND) {
        return e;
    }
    let detail = e.strip_prefix("prego: ").unwrap_or(&e);
    format!("prego: {grant} ({detail})")
}

/// The grant text for a 404 on a key item (ADR-0061 section 3.6).
fn grant_hint(e: String, r: &SnipRef, action: &str) -> String {
    with_grant(e, missing_grant(action, r))
}

fn error(res: &FullResponse, what: &str, r: &SnipRef, action: &str) -> String {
    let mut e = grant_hint(sn::api_error(res, what), r, action);
    let body: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
    let err = &body["error"];
    match err["code"].as_str().unwrap_or("") {
        "private_key_material" => {
            e.push_str(&format!("\n{PUBLIC_ONLY}"));
        }
        "key_invalid" => {
            if let Some(i) = err.get("index").filter(|v| !v.is_null()) {
                e.push_str(&format!(" (entry {}", text(i)));
                if let Some(t) = err["type"].as_str() {
                    e.push_str(&format!(", type {t}"));
                }
                if let Some(reason) = err["reason"].as_str() {
                    e.push_str(&format!(": {reason}"));
                }
                e.push(')');
            }
        }
        "plan_limit" => e.push_str(" (the plan has no room for more key items)"),
        _ => {}
    }
    e
}

// ---- Load and check entries on this computer ----

/// One entry to push.
#[derive(Debug, Clone)]
pub struct LocalEntry {
    pub kind: EntryType,
    pub bytes: Vec<u8>,
}

/// The ADR-0061 item 2.4 message for an entry with private material, with the local file. `index` counts
/// from 0, as the registry does.
pub fn private_message(index: usize, file: &str, p: &entry::Private) -> String {
    format!(
        "prego: {} (file: {file}) Nothing was sent.",
        entry::private_message(index, p)
    )
}

/// Reads the files, runs the private-material check on every byte, and checks each entry as its type.
pub fn load_entries(files: &[String], kind: Option<&str>) -> Result<Vec<LocalEntry>, String> {
    if files.is_empty() {
        return Err("prego: give one or more files".into());
    }
    if files.len() > MAX_ENTRIES {
        return Err(format!(
            "prego: {} files: a version has at most {MAX_ENTRIES} entries",
            files.len()
        ));
    }
    let declared = kind
        .map(EntryType::parse)
        .transpose()
        .map_err(|e| format!("prego: {e}"))?;
    let now = entry::now_text();
    let mut out = Vec::new();
    for (i, file) in files.iter().enumerate() {
        let n = i;
        let meta = std::fs::metadata(file).map_err(|e| format!("prego: {file}: {e}"))?;
        if meta.len() > MAX_BODY as u64 {
            return Err(format!(
                "prego: {file}: {} bytes: a push is at most 1 MiB",
                meta.len()
            ));
        }
        let bytes = std::fs::read(file).map_err(|e| format!("prego: {file}: {e}"))?;
        if let Some(p) = entry::private_material(&bytes, file) {
            return Err(private_message(n, file, &p));
        }
        let kind = match declared.or_else(|| EntryType::detect(&bytes)) {
            Some(k) => k,
            None => {
                return Err(format!(
                    "prego: entry {n} ({file}): the type is not clear; give --type ({})",
                    entry::TYPES
                ))
            }
        };
        entry::inspect(kind, &bytes, &now)
            .map_err(|e| format!("prego: entry {n} ({file}, type {}): {e}", kind.code()))?;
        out.push(LocalEntry { kind, bytes });
    }
    Ok(out)
}

fn local_hash(entries: &[LocalEntry]) -> String {
    let list: Vec<(EntryType, Vec<u8>)> =
        entries.iter().map(|e| (e.kind, e.bytes.clone())).collect();
    entry::version_hash(&list)
}

// ---- Commands ----

fn fingerprint(file: &str, kind: Option<&str>) -> Result<(), String> {
    let entries = load_entries(&[file.to_string()], kind)?;
    let e = &entries[0];
    for info in
        entry::inspect(e.kind, &e.bytes, &entry::now_text()).map_err(|x| format!("prego: {x}"))?
    {
        print_info(e.kind, &info, "");
    }
    Ok(())
}

fn print_info(kind: EntryType, i: &Info, indent: &str) {
    println!("{indent}{}  {}  {}", i.fingerprint, i.size, kind.code());
    for d in &i.details {
        println!("{indent}  {d}");
    }
}

struct Opts<'a> {
    tag: Option<&'a str>,
    message: Option<&'a str>,
    if_current: Option<&'a str>,
    not_after: Option<&'a str>,
}

/// Pushes the entries. Returns the version number and hash.
fn push(
    api: &Api,
    r: &SnipRef,
    entries: &[LocalEntry],
    o: &Opts<'_>,
) -> Result<(String, String), String> {
    let local = local_hash(entries);
    let list: Vec<Value> = entries
        .iter()
        .map(|e| {
            let (content, encoding) = entry::wire_content(&e.bytes);
            json!({"type": e.kind.code(), "content": content, "encoding": encoding})
        })
        .collect();
    let mut body = json!({ "entries": list });
    for (k, v) in [
        ("message", o.message),
        ("tag", o.tag),
        ("if_current", o.if_current),
        ("not_after", o.not_after),
    ] {
        if let Some(v) = v {
            body[k] = json!(v);
        }
    }
    let text_body = body.to_string();
    if text_body.len() > MAX_BODY {
        return Err(format!(
            "prego: the push body is {} bytes: a push is at most 1 MiB",
            text_body.len()
        ));
    }
    let what = format!("push to {}", r.long());
    let res = api.send(
        "PUT",
        &Api::snippet(r),
        Some("application/json"),
        prego_auth::http::Body::Bytes(text_body.as_bytes()),
    )?;
    if !(200..300).contains(&res.status) {
        return Err(error(&res, &what, r, "publish"));
    }
    let answer = sn::parse_json(res.body.as_bytes(), &what)?;
    let v = if answer["version"].is_object() {
        &answer["version"]
    } else {
        &answer
    };
    let hash = v["hash"].as_str().unwrap_or("").to_string();
    let number = text(&v["number"]);
    if !hash.is_empty() && hash != local {
        eprintln!("prego: warning: the registry hash {hash} is not the local hash {local}");
    }
    let created = answer["created"].as_bool().unwrap_or(res.status == 201);
    if created {
        println!(
            "{}: version {number} ({hash}), {} entries",
            r.long(),
            entries.len()
        );
    } else {
        println!(
            "{}: no change, version {number} is current ({hash})",
            r.long()
        );
    }
    if let Some(t) = o.tag {
        println!("{}: tag {t} -> version {number}", r.long());
    }
    Ok((number, if hash.is_empty() { local } else { hash }))
}

/// A version as the registry lists it.
pub struct KeyVersion {
    pub number: String,
    pub hash: String,
    pub answer: Value,
}

/// `GET <k>/v/<v>`.
pub fn version(
    api: &Api,
    r: &SnipRef,
    selector: &str,
    expect: Option<&str>,
) -> Result<KeyVersion, String> {
    let mut path = format!("{}/v/{}", Api::snippet(r), seg(selector));
    if let Some(h) = expect {
        path = format!("{path}?{}", query(&[("expect", h.to_string())]));
    }
    let what = format!("{}@{selector}", r.long());
    let (_, answer) = api
        .get_json(&path, &what)
        .map_err(|e| grant_hint(e, r, "read"))?;
    Ok(KeyVersion {
        number: text(&answer["number"]),
        hash: answer["hash"].as_str().unwrap_or("").to_string(),
        answer,
    })
}

/// `GET <k>`: the item, with `revoked_at`, `revoke_reason` and `not_after`.
pub fn item(api: &Api, r: &SnipRef) -> Result<Value, String> {
    let what = r.long();
    api.get_json(&Api::snippet(r), &what)
        .map(|(_, v)| v)
        .map_err(|e| grant_hint(e, r, "read"))
}

/// `GET <k>/v/<v>/entries/<index>`: the entry bytes as pushed.
pub fn entry_bytes(api: &Api, r: &SnipRef, selector: &str, index: &str) -> Result<Vec<u8>, String> {
    let path = format!(
        "{}/v/{}/entries/{}",
        Api::snippet(r),
        seg(selector),
        seg(index)
    );
    let what = format!("{}@{selector} entry {index}", r.long());
    let (res, bytes) = api.get_bytes(&path, "*/*", MAX_BODY as u64)?;
    if res.status != 200 {
        return Err(grant_hint(sn::api_error(&res, &what), r, "read"));
    }
    Ok(bytes)
}

/// The entries of a version with their bytes, checked against the version hash.
pub fn fetch_entries(
    api: &Api,
    r: &SnipRef,
    v: &KeyVersion,
) -> Result<Vec<(Value, EntryType, Vec<u8>)>, String> {
    let list = v.answer["entries"].as_array().ok_or_else(|| {
        format!(
            "prego: {}@{}: the answer has no entries",
            r.long(),
            v.number
        )
    })?;
    let mut out = Vec::new();
    for e in list {
        let kind = EntryType::parse(e["type"].as_str().unwrap_or(""))
            .map_err(|_| format!("prego: {}: an entry of an unknown type", r.long()))?;
        let bytes = entry_bytes(api, r, &v.hash, &text(&e["index"]))?;
        out.push((e.clone(), kind, bytes));
    }
    let local = entry::version_hash(
        &out.iter()
            .map(|(_, k, b)| (*k, b.clone()))
            .collect::<Vec<_>>(),
    );
    if !v.hash.is_empty() && local != v.hash {
        return Err(format!(
            "prego: {}@{}: the hash in the answer ({}) is not the hash of the entries ({local})",
            r.long(),
            v.number,
            v.hash
        ));
    }
    Ok(out)
}

fn get(
    api: &Api,
    r: &SnipRef,
    entry_index: Option<&str>,
    expect: Option<&str>,
) -> Result<(), String> {
    let v = version(api, r, r.selector(), expect)?;
    if let Some(i) = entry_index {
        let bytes = entry_bytes(api, r, &v.hash, i)?;
        use std::io::Write as _;
        let mut o = std::io::stdout().lock();
        return o
            .write_all(&bytes)
            .and_then(|_| o.flush())
            .map_err(|e| format!("prego: stdout: {e}"));
    }
    if let Some(want) = expect {
        // The hash is computed here from the entry bytes, so a changed answer cannot pass --expect.
        let got = fetch_entries(api, r, &v)?;
        let local = entry::version_hash(
            &got.iter()
                .map(|(_, k, b)| (*k, b.clone()))
                .collect::<Vec<_>>(),
        );
        if local != want {
            sn::mismatch_exit(&format!("{}@{}", r.long(), v.number), &local, want);
        }
    }
    let it = item(api, r).unwrap_or(Value::Null);
    println!("{}@{} {}", r.long(), v.number, v.hash);
    if let Some(at) = it["revoked_at"].as_str() {
        println!(
            "REVOKED at {at}: {}",
            it["revoke_reason"].as_str().unwrap_or("(no reason)")
        );
    }
    if let Some(na) = it["not_after"].as_str() {
        println!("not after: {na}");
    }
    let a = &v.answer;
    let tags: Vec<String> = a["tags"]
        .as_array()
        .into_iter()
        .flatten()
        .map(text)
        .collect();
    if !tags.is_empty() {
        println!("tags: {}", tags.join(", "));
    }
    println!(
        "pushed by {} at {}{}",
        text(&a["pushed_by"]),
        text(&a["pushed_at"]),
        a["message"]
            .as_str()
            .map(|m| format!(": {m}"))
            .unwrap_or_default()
    );
    for e in a["entries"].as_array().into_iter().flatten() {
        let mut alg = text(&e["alg"]);
        if let Some(b) = e["size_bits"].as_u64() {
            alg.push_str(&format!(" {b}"));
        }
        if let Some(c) = e["curve"].as_str() {
            alg.push_str(&format!(" {c}"));
        }
        println!(
            "[{}] {}  {}  {}{}",
            text(&e["index"]),
            text(&e["type"]),
            alg,
            text(&e["fingerprint"]),
            if e["expired"] == true {
                "  EXPIRED"
            } else {
                ""
            }
        );
        for k in ["kid", "subject", "issuer", "not_before", "not_after"] {
            if let Some(s) = e[k].as_str() {
                println!("    {k}: {s}");
            }
        }
        for u in e["user_ids"].as_array().into_iter().flatten() {
            println!("    user ID: {}", text(u));
        }
    }
    Ok(())
}

fn ls(api: &Api, tenant: &str, namespace: &str) -> Result<(), String> {
    let what = format!("the key items of {tenant}/{namespace}");
    let mut n = 0;
    sn::pages(
        api,
        &format!("{}/{}", seg(tenant), seg(namespace)),
        &what,
        |s| {
            n += 1;
            let current = &s["current"];
            println!(
                "{:<40} {:>5}  {}  {:>4} versions{}",
                text(&s["name"]),
                text(current.get("number").unwrap_or(&s["current_version"])),
                text(current.get("hash").unwrap_or(&s["current_hash"])),
                text(&s["version_count"]),
                if s["revoked_at"].is_string() {
                    "  REVOKED"
                } else {
                    ""
                }
            );
        },
    )?;
    if n == 0 {
        eprintln!("no key items in {tenant}/{namespace} that you can read");
    }
    Ok(())
}

fn log(api: &Api, r: &SnipRef) -> Result<(), String> {
    let what = format!("the history of {}", r.long());
    println!("{}", r.long());
    sn::pages(api, &format!("{}/versions", Api::snippet(r)), &what, |v| {
        let mark = if v["current"] == true { "*" } else { " " };
        let tags: Vec<String> = v["tags"]
            .as_array()
            .into_iter()
            .flatten()
            .map(text)
            .collect();
        let tags = if tags.is_empty() {
            String::new()
        } else {
            format!("  [{}]", tags.join(", "))
        };
        let count = v
            .get("entry_count")
            .or(v.get("entries").filter(|e| !e.is_array()))
            .map(text)
            .or_else(|| v["entries"].as_array().map(|a| a.len().to_string()))
            .unwrap_or_default();
        println!(
            "{mark}{:>5}  {}  {:>3} entries  {}  {}{tags}  {}",
            text(&v["number"]),
            text(&v["hash"]),
            count,
            text(v.get("pushed_at").unwrap_or(&v["created_at"])),
            text(&v["pushed_by"]),
            v["message"].as_str().unwrap_or("")
        );
    })
    .map_err(|e| grant_hint(e, r, "read"))
}

fn revoke(api: &Api, r: &SnipRef, reason: &str) -> Result<(), String> {
    let what = format!("revoke {}", r.long());
    let body = json!({ "reason": reason }).to_string();
    let res = api.send(
        "POST",
        &format!("{}/revoke", Api::snippet(r)),
        Some("application/json"),
        prego_auth::http::Body::Bytes(body.as_bytes()),
    )?;
    if !(200..300).contains(&res.status) {
        return Err(error(&res, &what, r, "delete"));
    }
    let a = sn::parse_json(res.body.as_bytes(), &what).unwrap_or(Value::Null);
    println!(
        "{}: revoked{}. A revoke is one-way. Signatures made with these keys now fail --verify.",
        r.long(),
        a["revoked_at"]
            .as_str()
            .map(|t| format!(" at {t}"))
            .unwrap_or_default()
    );
    Ok(())
}

/// The public JWK of a new key, with `kid` (the thumbprint), `alg` and `use`.
pub fn public_jwk_text(key: &PrivateKey) -> String {
    let mut j = key.public().to_json();
    j["kid"] = json!(key.public().thumbprint());
    j["alg"] = json!(key.alg());
    j["use"] = json!("sig");
    let mut s = serde_json::to_string_pretty(&j).expect("JSON");
    s.push('\n');
    s
}

fn new_key(
    api: &Api,
    r: &SnipRef,
    alg: NewAlg,
    out: Option<&str>,
    message: Option<&str>,
) -> Result<(), String> {
    let path = std::path::PathBuf::from(
        out.map(str::to_string)
            .unwrap_or_else(|| format!("{}.private.pem", r.name)),
    );
    let (key, pem_text) = PrivateKey::generate(alg).map_err(|e| format!("prego: {e}"))?;
    // The file comes first: if the push fails, the key is not lost.
    keyfile::write_new(&path, &pem_text).map_err(|e| format!("prego: {e}"))?;
    let public = public_jwk_text(&key);
    // `release-keys.private.pem` -> `release-keys.pub.jwk`; another name gets `.pub.jwk` added.
    let shown = path.display().to_string();
    let public_path = std::path::PathBuf::from(match shown.strip_suffix(".private.pem") {
        Some(stem) => format!("{stem}.pub.jwk"),
        None => format!("{shown}.pub.jwk"),
    });
    std::fs::write(&public_path, &public)
        .map_err(|e| format!("prego: {}: {e}", public_path.display()))?;
    let mut entries = Vec::new();
    // Keep the keys of the current version, so a new key adds to the set (rotation).
    match version(api, r, "current", None) {
        Ok(cur) => {
            for (_, kind, bytes) in fetch_entries(api, r, &cur)? {
                entries.push(LocalEntry { kind, bytes });
            }
            eprintln!(
                "{}: the new key is added to the {} entries of version {}",
                r.long(),
                entries.len(),
                cur.number
            );
        }
        Err(e) if e.contains("not found") => {}
        Err(e) => return Err(e),
    }
    entries.push(LocalEntry {
        kind: EntryType::Jwk,
        bytes: public.into_bytes(),
    });
    let default_message = format!(
        "prego keys new --alg {}",
        match alg {
            NewAlg::Ed25519 => "ed25519",
            NewAlg::Es256 => "es256",
        }
    );
    let pushed = push(
        api,
        r,
        &entries,
        &Opts {
            tag: None,
            message: Some(message.unwrap_or(&default_message)),
            if_current: None,
            not_after: None,
        },
    );
    if let Err(e) = pushed {
        return Err(format!(
            "{e}\nThe private key is in {} (mode 0600) and its public JWK in {}. When the problem is fixed, \
             push the public key: prego keys push {} {}",
            path.display(),
            public_path.display(),
            public_path.display(),
            r.long()
        ));
    }
    println!(
        "private key: {} (mode 0600; it never leaves this computer)",
        path.display()
    );
    println!("public JWK:  {}", public_path.display());
    println!("thumbprint (kid): {}", key.public().thumbprint());
    println!(
        "sign with: prego a2a push <cards> <ref> --sign {} --key {}",
        path.display(),
        r.long()
    );
    Ok(())
}

/// The public key of `kid` in a key version, with the item state. Used by `--verify` and `a2a push`.
pub struct FoundKey {
    pub key: PublicJwk,
    pub revoked: Option<(String, String)>,
    /// The end date of the item (`not_after`, RFC 3339), if it has one.
    pub not_after: Option<String>,
}

/// The first 14 digits of a time (`2026-11-24T10:00:00Z` -> `20261124100000`), to compare UTC times.
pub fn time_digits(t: &str) -> String {
    t.chars().filter(char::is_ascii_digit).take(14).collect()
}

/// Finds the key with thumbprint `kid` in `selector` (a version number, or `current`).
pub fn find_key(api: &Api, r: &SnipRef, selector: &str, kid: &str) -> Result<FoundKey, String> {
    let it = item(api, r)?;
    let v = version(api, r, selector, None)?;
    for (_, kind, bytes) in fetch_entries(api, r, &v)? {
        for k in entry::signing_keys(kind, &bytes) {
            if k.thumbprint() == kid {
                let revoked = it["revoked_at"].as_str().map(|at| {
                    (
                        at.to_string(),
                        it["revoke_reason"]
                            .as_str()
                            .unwrap_or("(no reason)")
                            .to_string(),
                    )
                });
                let not_after = it["not_after"].as_str().map(str::to_string);
                return Ok(FoundKey {
                    key: k,
                    revoked,
                    not_after,
                });
            }
        }
    }
    Err(format!(
        "prego: {}@{} has no jwk or pem-public-key entry with thumbprint {kid}",
        r.long(),
        v.number
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_key_is_refused_before_any_request() {
        let dir = crate::sign::scrub_dir::ScrubDir::new("keys");
        let pubf = dir.join("a.pub");
        std::fs::write(
            &pubf,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl x\n",
        )
        .unwrap();
        let privf = dir.join("id_ed25519");
        std::fs::write(
            &privf,
            "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
        )
        .unwrap();
        let files = vec![pubf.display().to_string(), privf.display().to_string()];
        let e = load_entries(&files, None).unwrap_err();
        assert!(
            e.starts_with(&format!(
                "prego: Keys and Certificates holds public keys and certificates only. Entry 1 holds a \
                 private key (OpenSSH private key). Upload the public key (`ssh-keygen -y -f <key>`) instead. \
                 (file: {}) Nothing was sent.",
                privf.display()
            )),
            "{e}"
        );
        let ok = load_entries(&files[..1], None).unwrap();
        assert_eq!(ok[0].kind, EntryType::Ssh);
        let e = load_entries(&files[..1], Some("jwk")).unwrap_err();
        assert!(e.contains("type jwk"), "{e}");
    }

    #[test]
    fn grant_text() {
        let r = SnipRef::parse("acme/release-keys/signer").unwrap();
        assert_eq!(
            missing_grant("read", &r),
            "read on key acme/release-keys/signer (type Keys and Certificates) is missing; ask an admin of acme \
             for a grant"
        );
        // A 404 from the registry carries a request id: the grant text comes first all the same.
        let e = "prego: acme/release-keys/signer@current: not found, or you have no grant for it (request r1)";
        assert_eq!(
            grant_hint(e.into(), &r, "read"),
            "prego: read on key acme/release-keys/signer (type Keys and Certificates) is missing; ask an admin of \
             acme for a grant (acme/release-keys/signer@current: not found, or you have no grant for it (request r1))"
        );
        assert_eq!(
            grant_hint("prego: x: 500 boom".into(), &r, "read"),
            "prego: x: 500 boom"
        );
    }
}
