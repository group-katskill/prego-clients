//! `prego a2a`: A2A (Agent2Agent) Agent Cards (ADR-0062). Signed, versioned sets of A2A 1.0 Agent Cards under
//! `/v1/a2a/` on the control host, with a registry token. Every card and every set is signed with a key from
//! Keys and Certificates (ADR-0061 section 3); `prego a2a push --sign` signs on this computer, and
//! `prego a2a get --verify` checks again with the reader's own grants. Wire contract: ADR-0062 section 3a.

pub mod card;
pub mod upgrade;

use std::path::{Path, PathBuf};

use prego_auth::http::{Body, FullResponse};
use prego_auth::Env;
use serde_json::Value;

use crate::env::{query, text};
use crate::keys;
use crate::sign::jwk::{pem_blocks, PublicJwk};
use crate::sign::jws::{self, Header};
use crate::sign::keyfile::PrivateKey;
use crate::snippet::files::{self, File, MODE_FILE};
use crate::snippet::reference::{self, SnipRef};
use crate::snippet::{self as sn, seg, Api};

/// The most cards in a version, the largest card and the largest version (ADR-0062 item 2.2).
pub const MAX_CARDS: usize = 100;
pub const MAX_CARD_BYTES: usize = 64 * 1024;
pub const MAX_VERSION_BYTES: usize = 1024 * 1024;
/// The path of the set signature in a tarball and in a folder (ADR-0062 section 3a).
pub const SET_SIG: &str = ".prego/set.jws.json";

/// The ADR-0062 item 2.4 text for an unsigned push.
pub const UNSIGNED: &str =
    "A2A Agent Cards must be signed. Sign with `prego a2a push --sign <key file> --key \
<key ref>`; make a key with `prego keys new`.";

#[derive(Debug, PartialEq, Eq)]
pub enum A2aCommand {
    Check {
        source: String,
        key_file: Option<String>,
        key: Option<String>,
    },
    Push {
        source: String,
        reference: String,
        sign: Option<String>,
        key: Option<String>,
        no_source: bool,
        tag: Option<String>,
        message: Option<String>,
        if_current: Option<String>,
    },
    Get {
        reference: String,
        folder: Option<String>,
        card: Option<String>,
        expect: Option<String>,
        verify: bool,
    },
    Ls {
        scope: String,
    },
    Log {
        reference: String,
    },
    Diff {
        reference: String,
        from: String,
        to: String,
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
    Upgrade {
        file: String,
        out: Option<String>,
        force: bool,
    },
}

pub fn run(globals: &[&str], command: &A2aCommand, env: &dyn Env) -> Result<(), String> {
    match command {
        A2aCommand::Upgrade { file, out, force } => run_upgrade(file, out.as_deref(), *force),
        A2aCommand::Check {
            source,
            key_file,
            key,
        } => check_cmd(globals, env, source, key_file.as_deref(), key.as_deref()),
        A2aCommand::Push {
            source,
            reference,
            sign,
            key,
            no_source,
            tag,
            message,
            if_current,
        } => {
            let r = SnipRef::parse(reference)?.no_version("push")?;
            push(
                globals,
                env,
                &r,
                source,
                &PushOpts {
                    sign: sign.as_deref(),
                    key: key.as_deref(),
                    no_source: *no_source,
                    tag: tag.as_deref(),
                    message: message.as_deref(),
                    if_current: if_current.as_deref(),
                },
            )
        }
        A2aCommand::Get {
            reference,
            folder,
            card,
            expect,
            verify,
        } => {
            let r = SnipRef::parse(reference)?;
            get(
                globals,
                env,
                &r,
                folder.as_deref(),
                card.as_deref(),
                expect.as_deref(),
                *verify,
            )
        }
        A2aCommand::Ls { scope } => {
            let (tenant, namespace) = reference::parse_scope(scope)?;
            ls(&api(globals, &tenant, env)?, &tenant, &namespace)
        }
        A2aCommand::Log { reference } => {
            let r = SnipRef::parse(reference)?.no_version("log")?;
            log(&api(globals, &r.tenant, env)?, &r)
        }
        A2aCommand::Diff {
            reference,
            from,
            to,
        } => {
            let r = SnipRef::parse(reference)?.no_version("diff")?;
            reference::check_selector(from)?;
            reference::check_selector(to)?;
            sn::diff(&api(globals, &r.tenant, env)?, &r, from, to).map_err(|e| hint(e, &r, "read"))
        }
        A2aCommand::Tag { reference, tag } => {
            let r = SnipRef::parse(reference)?;
            if r.version.is_none() {
                return Err(
                    "prego: give the version to tag: prego a2a tag <ref>@<version> <tag>".into(),
                );
            }
            reference::check_tag(tag).map_err(|e| format!("prego: {e}"))?;
            sn::set_tag(&api(globals, &r.tenant, env)?, &r, tag).map_err(|e| hint(e, &r, "publish"))
        }
        A2aCommand::Rollback {
            reference,
            to,
            reason,
        } => {
            let r = SnipRef::parse(reference)?.no_version("rollback")?;
            reference::check_selector(to)?;
            sn::rollback(&api(globals, &r.tenant, env)?, &r, to, reason)
                .map_err(|e| hint(e, &r, "publish"))
        }
    }
}

fn api(globals: &[&str], tenant: &str, env: &dyn Env) -> Result<Api, String> {
    Api::with_prefix(globals, tenant, env, "a2a")
}

/// The ADR-0062 section 5 text for a missing grant on a set.
pub fn missing_set_grant(action: &str, r: &SnipRef) -> String {
    format!(
        "{action} on a2a set {} (type A2A Agent Cards) is missing; ask an admin of {} for a grant",
        r.long(),
        r.tenant
    )
}

/// The grant text for a 404 on a card set (ADR-0062 section 5).
fn hint(e: String, r: &SnipRef, action: &str) -> String {
    keys::with_grant(e, missing_set_grant(action, r))
}

fn error(res: &FullResponse, what: &str, r: &SnipRef, action: &str) -> String {
    let mut e = hint(sn::api_error(res, what), r, action);
    let body: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
    let err = &body["error"];
    if let Some(f) = err["file"].as_str() {
        e.push_str(&format!(" (card: {f}"));
        if let Some(p) = err["path"].as_str().filter(|_| err["file"].is_string()) {
            e.push_str(&format!(", {p}"));
        }
        if let Some(reason) = err["reason"].as_str() {
            e.push_str(&format!(", {reason}"));
        }
        e.push(')');
    }
    match err["code"].as_str().unwrap_or("") {
        "signature_required" => e.push_str(&format!("\n{UNSIGNED}")),
        "signature_invalid" => e.push_str(
            "\nSign again with `prego a2a push --sign <key file> --key <key ref>`, and check that the key \
             is in Keys and Certificates and not revoked.",
        ),
        "card_invalid" => e.push_str("\nCheck the cards offline with `prego a2a check <folder>`."),
        "source_mismatch" => e.push_str(
            "\nPush to the set that the card names, or sign again with --sign (it sets the source to this push).",
        ),
        _ => {}
    }
    e
}

// ---- Cards on this computer ----

/// One card file.
pub struct LocalCard {
    pub file: String,
    pub bytes: Vec<u8>,
    pub json: Value,
}

/// `[a-z0-9][a-z0-9._-]{0,127}.json` (ADR-0062 item 2.2).
pub fn check_file_name(name: &str) -> Result<(), String> {
    let stem = name
        .strip_suffix(".json")
        .ok_or_else(|| format!("card file `{name}`: a card file name ends in .json"))?;
    reference::check_name(stem).map_err(|_| {
        format!(
            "card file `{name}`: use [a-z0-9][a-z0-9._-]{{0,127}}.json (lower case, dots allowed, for example \
             acme.support-bot.json)"
        )
    })
}

/// Reads the cards of a folder (top-level `<file>.json`) or one card file, and the set signature of a
/// folder if it has one. Each card is checked against A2A 1.0.
pub fn load_cards(source: &str) -> Result<(Vec<LocalCard>, Option<Value>), String> {
    let p = Path::new(source);
    let meta = std::fs::symlink_metadata(p).map_err(|e| format!("prego: {source}: {e}"))?;
    let mut paths: Vec<(String, PathBuf)> = Vec::new();
    let mut set_sig = None;
    if meta.is_dir() {
        for entry in std::fs::read_dir(p).map_err(|e| format!("prego: {source}: {e}"))? {
            let entry = entry.map_err(|e| format!("prego: {source}: {e}"))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let t = entry
                .file_type()
                .map_err(|e| format!("prego: {name}: {e}"))?;
            if name == ".git" {
                continue;
            }
            if name == ".prego" && t.is_dir() {
                let sp = entry.path().join("set.jws.json");
                if sp.is_file() {
                    let b =
                        std::fs::read(&sp).map_err(|e| format!("prego: {}: {e}", sp.display()))?;
                    set_sig = Some(
                        serde_json::from_slice(&b)
                            .map_err(|e| format!("prego: {}: not JSON ({e})", sp.display()))?,
                    );
                }
                continue;
            }
            if !t.is_file() {
                return Err(format!(
                    "prego: {source}/{name}: a card set is <file>.json files at the top level, with no folders \
                     (and no symlinks)"
                ));
            }
            if !name.ends_with(".json") {
                return Err(format!(
                    "prego: {source}/{name}: not a card file; a card set folder holds only <file>.json cards"
                ));
            }
            paths.push((name, entry.path()));
        }
    } else if meta.is_file() {
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        paths.push((name, p.to_path_buf()));
    } else {
        return Err(format!("prego: {source}: not a folder or a card file"));
    }
    if paths.is_empty() {
        return Err(format!("prego: {source}: no card files (<file>.json)"));
    }
    if paths.len() > MAX_CARDS {
        return Err(format!(
            "prego: {} cards: a version has at most {MAX_CARDS}",
            paths.len()
        ));
    }
    paths.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let mut cards = Vec::new();
    let mut total = 0;
    for (name, path) in paths {
        check_file_name(&name).map_err(|e| format!("prego: {e}"))?;
        let bytes = std::fs::read(&path).map_err(|e| format!("prego: {}: {e}", path.display()))?;
        if bytes.len() > MAX_CARD_BYTES {
            return Err(format!(
                "prego: card {name}: {} bytes: a card is at most 64 KiB",
                bytes.len()
            ));
        }
        total += bytes.len();
        let json: Value = serde_json::from_slice(&bytes)
            .map_err(|e| format!("prego: card {name}: not valid JSON ({e})"))?;
        card::check(&json).map_err(|p| format!("prego: {}", p.message(&name)))?;
        cards.push(LocalCard {
            file: name,
            bytes,
            json,
        });
    }
    if total > MAX_VERSION_BYTES {
        return Err(format!(
            "prego: the cards are {total} bytes together: a version is at most 1 MiB"
        ));
    }
    Ok((cards, set_sig))
}

/// The card files as snippet files (mode 0644), for the version hash and the tarball.
fn as_files(cards: &[LocalCard]) -> Vec<File> {
    cards
        .iter()
        .map(|c| File {
            path: c.file.clone(),
            mode: MODE_FILE,
            data: c.bytes.clone(),
        })
        .collect()
}

/// The version hash (the Snippets hash over the card files, mode 0644) and the set payload.
pub fn hash_and_payload(
    r: &SnipRef,
    cards: &[(String, Vec<u8>)],
) -> Result<(String, Vec<u8>), String> {
    let entries: Vec<files::Entry> = cards
        .iter()
        .map(|(p, b)| files::Entry {
            path: p.clone(),
            mode: MODE_FILE,
            size: b.len() as u64,
            sha256: files::hex_sha256(b),
        })
        .collect();
    let hash = files::version_hash(&entries).map_err(|e| format!("prego: {e}"))?;
    let mut list: Vec<(String, String)> = entries
        .iter()
        .map(|e| (e.path.clone(), e.sha256.clone()))
        .collect();
    list.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let payload = jws::set_payload("a2a", &r.tenant, &r.namespace, &r.name, &hash, &list);
    Ok((hash, payload))
}

/// Pretty JSON with a final newline: the bytes of a signed card file.
fn card_bytes(v: &Value) -> Vec<u8> {
    let mut s = serde_json::to_string_pretty(v).expect("JSON");
    s.push('\n');
    s.into_bytes()
}

// ---- Keys for signatures ----

/// Reads a local key for `check --key-file`: a private key file (its public part), a public JWK, or a PEM
/// `PUBLIC KEY`.
fn local_public_key(path: &str) -> Result<PublicJwk, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("prego: {path}: {e}"))?;
    let text = String::from_utf8_lossy(&bytes);
    if text.contains("PRIVATE KEY-----") {
        return PrivateKey::load(path)
            .map(|k| k.public().clone())
            .map_err(|e| format!("prego: {e}"));
    }
    if text.trim_start().starts_with('{') {
        let v: Value = serde_json::from_str(&text).map_err(|e| format!("prego: {path}: {e}"))?;
        return PublicJwk::from_json(&v).map_err(|e| format!("prego: {path}: {e}"));
    }
    match pem_blocks(&text, "PUBLIC KEY")
        .map_err(|e| format!("prego: {path}: {e}"))?
        .first()
    {
        Some(d) => PublicJwk::from_spki(d).map_err(|e| format!("prego: {path}: {e}")),
        None => Err(format!(
            "prego: {path}: not a private key, a public JWK or a PEM PUBLIC KEY"
        )),
    }
}

/// Finds signing keys in Keys and Certificates and remembers them. A revoked key fails with the reason.
struct KeyBook<'a> {
    globals: &'a [&'a str],
    env: &'a dyn Env,
    /// Signer answers: (prego_key, thumbprint) -> key version.
    versions: Vec<(String, String, String)>,
    cache: Vec<(String, String, PublicJwk)>,
    /// The signing time: the `pushed_at` of the version. A key that ended (`not_after`) before it fails;
    /// a key that ended later passes (ADR-0061 section 3.6).
    signed_at: Option<String>,
}

impl KeyBook<'_> {
    fn resolve(&mut self, h: &Header) -> Result<PublicJwk, String> {
        if let Some((_, _, k)) = self
            .cache
            .iter()
            .find(|(p, t, _)| *p == h.prego_key && *t == h.kid)
        {
            return Ok(k.clone());
        }
        let (t, ns, name) = h.key_parts()?;
        let r = SnipRef {
            tenant: t.into(),
            namespace: ns.into(),
            name: name.into(),
            version: None,
        };
        let selector = self
            .versions
            .iter()
            .find(|(p, th, _)| *p == h.prego_key && *th == h.kid)
            .map(|(_, _, v)| v.clone())
            .unwrap_or_else(|| "current".into());
        let api = Api::with_prefix(self.globals, t, self.env, "keys")?;
        let found = keys::find_key(&api, &r, &selector, &h.kid).map_err(|e| {
            if e.contains("(type Keys and Certificates) is missing") {
                format!(
                    "prego: verify needs read on key {} (type Keys and Certificates); ask an admin of {} for a \
                     grant",
                    r.long(),
                    r.tenant
                )
            } else {
                e
            }
        })?;
        if let Some((at, reason)) = found.revoked {
            return Err(format!(
                "prego: key {} was revoked at {at} ({reason}); signatures with it do not count",
                r.long()
            ));
        }
        if let (Some(end), Some(at)) = (&found.not_after, &self.signed_at) {
            if keys::time_digits(end) < keys::time_digits(at) {
                return Err(format!(
                    "prego: key {} ended at {end} (not_after), before this version was pushed at {at}; the \
                     signature does not count",
                    r.long()
                ));
            }
        }
        self.cache
            .push((h.prego_key.clone(), h.kid.clone(), found.key.clone()));
        Ok(found.key)
    }
}

// ---- check ----

fn check_cmd(
    globals: &[&str],
    env: &dyn Env,
    source: &str,
    key_file: Option<&str>,
    key: Option<&str>,
) -> Result<(), String> {
    let (cards, set_sig) = load_cards(source)?;
    let local = key_file.map(local_public_key).transpose()?;
    let mut book = KeyBook {
        globals,
        env,
        versions: Vec::new(),
        cache: Vec::new(),
        signed_at: None,
    };
    let key_ref = key
        .map(|k| SnipRef::parse(k).and_then(|r| r.no_version("check --key")))
        .transpose()?;
    let mut failed = 0;
    for c in &cards {
        println!("{}: A2A 1.0 ok: {}", c.file, card::summary(&c.json));
        if let Some(s) = card::source(&c.json) {
            println!("  source: {}/{}/{}", s.0, s.1, s.2);
        }
        let sigs = c.json["signatures"].as_array().cloned().unwrap_or_default();
        if sigs.is_empty() {
            println!("  no signatures (a push needs them). {UNSIGNED}");
            if local.is_some() || key_ref.is_some() {
                failed += 1;
            }
            continue;
        }
        let input = card::signing_input(&c.json).map_err(|e| format!("prego: {}: {e}", c.file))?;
        let mut good = 0;
        for (i, s) in sigs.iter().enumerate() {
            let h = match jws::card_header(s) {
                Ok(h) => h,
                Err(e) => {
                    println!("  signature {}: {e}", i + 1);
                    continue;
                }
            };
            let keyed = if let Some(k) = &local {
                if k.thumbprint() == h.kid {
                    Some(Ok(k.clone()))
                } else {
                    None
                }
            } else if let Some(r) = &key_ref {
                (h.prego_key == r.long()).then(|| book.resolve(&h))
            } else {
                None
            };
            match keyed {
                None => println!(
                    "  signature {}: {} by {} (kid {}): not checked (give --key-file or --key)",
                    i + 1,
                    h.alg,
                    h.prego_key,
                    h.kid
                ),
                Some(Err(e)) => println!("  signature {}: {e}", i + 1),
                Some(Ok(k)) => match jws::verify_card(&input, s, &k) {
                    Ok(_) => {
                        good += 1;
                        println!(
                            "  signature {}: good ({} by {}, kid {})",
                            i + 1,
                            h.alg,
                            h.prego_key,
                            h.kid
                        )
                    }
                    Err(e) => println!("  signature {}: BAD: {e}", i + 1),
                },
            }
        }
        if (local.is_some() || key_ref.is_some()) && good == 0 {
            failed += 1;
        }
    }
    if let (Some(sig), Some(k)) = (&set_sig, &local) {
        if let Some(sp) = card::source(&cards[0].json) {
            let r = SnipRef {
                tenant: sp.0,
                namespace: sp.1,
                name: sp.2,
                version: None,
            };
            let list: Vec<(String, Vec<u8>)> = cards
                .iter()
                .map(|c| (c.file.clone(), c.bytes.clone()))
                .collect();
            let (_, payload) = hash_and_payload(&r, &list)?;
            let k = k.clone();
            match jws::verify_set(sig, &payload, &mut |_: &Header| Ok(k.clone())) {
                Ok(_) => println!("{SET_SIG}: good for {}", r.long()),
                Err(e) => {
                    failed += 1;
                    println!("{SET_SIG}: BAD for {}: {e}", r.long())
                }
            }
        }
    }
    if failed > 0 {
        return Err(format!(
            "prego: {failed} card(s) or the set signature did not pass"
        ));
    }
    Ok(())
}

// ---- push ----

struct PushOpts<'a> {
    sign: Option<&'a str>,
    key: Option<&'a str>,
    no_source: bool,
    tag: Option<&'a str>,
    message: Option<&'a str>,
    if_current: Option<&'a str>,
}

fn push(
    globals: &[&str],
    env: &dyn Env,
    r: &SnipRef,
    source: &str,
    o: &PushOpts<'_>,
) -> Result<(), String> {
    let (mut cards, folder_sig) = load_cards(source)?;
    let set_sig = match (o.sign, o.key) {
        (Some(key_file), Some(key_ref)) => {
            let kr = SnipRef::parse(key_ref)?.no_version("push --key")?;
            if kr.tenant != r.tenant {
                return Err(format!(
                    "prego: the key {} is in tenant {}, but the set is in tenant {}: the signing key must be in \
                     the set's tenant (push the public key there with `prego keys push`)",
                    kr.long(),
                    kr.tenant,
                    r.tenant
                ));
            }
            let key = PrivateKey::load(key_file).map_err(|e| format!("prego: {e}"))?;
            let kid = key.public().thumbprint();
            // The public key must be in Keys and Certificates; say so before the push.
            let kapi = Api::with_prefix(globals, &kr.tenant, env, "keys")?;
            match keys::find_key(&kapi, &kr, "current", &kid) {
                Ok(f) => {
                    if let Some((at, reason)) = f.revoked {
                        return Err(format!(
                            "prego: key {} was revoked at {at} ({reason}); make a new key with `prego keys new`",
                            kr.long()
                        ));
                    }
                    if let Some(end) = f.not_after.filter(|e| keys::time_digits(e) < keys::entry::now_text()) {
                        return Err(format!(
                            "prego: key {} ended at {end} (not_after); make a new key with `prego keys new`",
                            kr.long()
                        ));
                    }
                }
                Err(e) if e.contains("has no jwk or pem-public-key entry") => {
                    return Err(format!(
                        "{e}. The key in {key_file} is not registered there: push its public key \
                         (`prego keys push <public JWK file> {}`), or make a key with `prego keys new`",
                        kr.long()
                    ))
                }
                Err(e) => return Err(e),
            }
            let prego_key = kr.long();
            for c in &mut cards {
                let mut v = c.json.clone();
                let changed =
                    !o.no_source && card::set_source(&mut v, &r.tenant, &r.namespace, &r.name);
                let mut sigs: Vec<Value> = v["signatures"].as_array().cloned().unwrap_or_default();
                let before = sigs.len();
                sigs.retain(|s| {
                    !changed && jws::card_header(s).map(|h| h.kid != kid).unwrap_or(false)
                });
                if changed && before > 0 {
                    eprintln!(
                        "{}: the source extension changed the card, so {before} old signature(s) no longer \
                         match and are removed",
                        c.file
                    );
                }
                if let Some(obj) = v.as_object_mut() {
                    obj.remove("signatures");
                }
                let input =
                    card::signing_input(&v).map_err(|e| format!("prego: {}: {e}", c.file))?;
                sigs.push(jws::sign_card(&input, &key, &prego_key)?);
                v["signatures"] = Value::Array(sigs);
                c.bytes = card_bytes(&v);
                if c.bytes.len() > MAX_CARD_BYTES {
                    return Err(format!(
                        "prego: card {}: {} bytes after signing: a card is at most 64 KiB",
                        c.file,
                        c.bytes.len()
                    ));
                }
                c.json = v;
            }
            let list: Vec<(String, Vec<u8>)> = cards
                .iter()
                .map(|c| (c.file.clone(), c.bytes.clone()))
                .collect();
            let (_, payload) = hash_and_payload(r, &list)?;
            jws::sign_set(&payload, &key, &prego_key)?
        }
        (Some(_), None) => {
            return Err(
                "prego: --sign needs --key <key ref> (the Keys and Certificates item of the key)"
                    .into(),
            )
        }
        (None, Some(_)) => return Err("prego: --key needs --sign <key file>".into()),
        (None, None) => {
            for c in &cards {
                if c.json["signatures"].as_array().is_none_or(Vec::is_empty) {
                    return Err(format!(
                        "prego: card {} has no signature. {UNSIGNED}",
                        c.file
                    ));
                }
            }
            let sig = folder_sig.ok_or_else(|| {
                format!("prego: {source} has no set signature ({SET_SIG}). {UNSIGNED}")
            })?;
            let list: Vec<(String, Vec<u8>)> = cards
                .iter()
                .map(|c| (c.file.clone(), c.bytes.clone()))
                .collect();
            let (_, payload) = hash_and_payload(r, &list)?;
            if let Some(p) = sig["payload"].as_str() {
                use base64::Engine as _;
                if base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&payload) != p {
                    return Err(format!(
                        "prego: the set signature in {SET_SIG} is for other cards or another set than {}. Sign \
                         again with --sign <key file> --key <key ref>",
                        r.long()
                    ));
                }
            }
            sig
        }
    };
    // The source extension must name this push (the registry checks it too: source_mismatch).
    for c in &cards {
        if let Some((t, ns, s)) = card::source(&c.json) {
            if (t.as_str(), ns.as_str(), s.as_str())
                != (r.tenant.as_str(), r.namespace.as_str(), r.name.as_str())
            {
                return Err(format!(
                    "prego: card {} says it comes from {t}/{ns}/{s}; this push is to {}. Sign again with --sign \
                     (it sets the source to this push), or push to {t}/{ns}/{s}",
                    c.file,
                    r.long()
                ));
            }
        }
    }
    let list: Vec<(String, Vec<u8>)> = cards
        .iter()
        .map(|c| (c.file.clone(), c.bytes.clone()))
        .collect();
    let (local, _) = hash_and_payload(r, &list)?;
    let mut tar_files = as_files(&cards);
    tar_files.push(File {
        path: SET_SIG.into(),
        mode: MODE_FILE,
        data: card_bytes(&set_sig),
    });
    let body = files::tar_gz(&tar_files);
    let mut q: Vec<(&str, String)> = Vec::new();
    for (k, v) in [
        ("message", o.message),
        ("if_current", o.if_current),
        ("tag", o.tag),
    ] {
        if let Some(v) = v {
            q.push((k, v.to_string()));
        }
    }
    let mut path = Api::snippet(r);
    if !q.is_empty() {
        path = format!("{path}?{}", query(&q));
    }
    let what = format!("push to {}", r.long());
    let api = api(globals, &r.tenant, env)?;
    let res = api.send("PUT", &path, Some("application/gzip"), Body::Bytes(&body))?;
    if !(200..300).contains(&res.status) {
        return Err(error(&res, &what, r, "publish"));
    }
    let answer = sn::parse_json(res.body.as_bytes(), &what)?;
    let v = &answer["version"];
    let hash = v["hash"].as_str().unwrap_or("");
    let number = text(&v["number"]);
    if !hash.is_empty() && hash != local {
        eprintln!("prego: warning: the registry hash {hash} is not the local hash {local}");
    }
    let created = answer["created"].as_bool().unwrap_or(res.status == 201);
    if created {
        println!(
            "{}: version {number} ({hash}), {} cards, signed",
            r.long(),
            cards.len()
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
    Ok(())
}

// ---- get ----

#[allow(clippy::too_many_arguments)]
fn get(
    globals: &[&str],
    env: &dyn Env,
    r: &SnipRef,
    folder: Option<&str>,
    one: Option<&str>,
    expect: Option<&str>,
    verify: bool,
) -> Result<(), String> {
    let api = api(globals, &r.tenant, env)?;
    let sel = r.selector();
    let mut path = format!("{}/v/{}", Api::snippet(r), seg(sel));
    if let Some(h) = expect {
        path = format!("{path}?{}", query(&[("expect", h.to_string())]));
    }
    let what = format!("{}@{sel}", r.long());
    let (_, answer) = api.get_json(&path, &what).map_err(|e| hint(e, r, "read"))?;
    let number = text(&answer["number"]);
    let list = answer["cards"]
        .as_array()
        .ok_or_else(|| format!("prego: {what}: the answer has no card list"))?;
    let mut entries = Vec::new();
    for c in list {
        let file = c["file"]
            .as_str()
            .ok_or_else(|| format!("prego: {what}: a card has no file name"))?;
        check_file_name(file).map_err(|e| format!("prego: {what}: {e}"))?;
        let sha = files::sha_from(&c["sha256"])
            .ok_or_else(|| format!("prego: {what}: {file}: no sha256"))?;
        let size = c["size"]
            .as_u64()
            .ok_or_else(|| format!("prego: {what}: {file}: no size"))?;
        entries.push(files::Entry {
            path: file.to_string(),
            mode: MODE_FILE,
            size,
            sha256: sha,
        });
    }
    let local = files::version_hash(&entries).map_err(|e| format!("prego: {e}"))?;
    if let Some(server) = answer["hash"].as_str() {
        if server != local {
            return Err(format!(
                "prego: {what}: the hash in the answer ({server}) is not the hash of the card list ({local})"
            ));
        }
    }
    if let Some(want) = expect {
        if want != local {
            sn::mismatch_exit(&what, &local, want);
        }
    }
    // Download every card by the version hash, and check each against the list.
    let mut got: Vec<(String, Vec<u8>)> = Vec::new();
    for e in &entries {
        if one.is_some_and(|f| f != e.path) && !verify {
            continue;
        }
        let p = format!(
            "{}/v/{}/cards/{}",
            Api::snippet(r),
            seg(&local),
            seg(&e.path)
        );
        let w = format!("{}@{number} card {}", r.long(), e.path);
        let (res, data) = api.get_bytes(&p, "application/json", MAX_CARD_BYTES as u64)?;
        if res.status != 200 {
            return Err(hint(sn::api_error(&res, &w), r, "read"));
        }
        if data.len() as u64 != e.size || files::hex_sha256(&data) != e.sha256 {
            return Err(format!(
                "prego: {w}: the content does not match the card list (size or sha256)"
            ));
        }
        got.push((e.path.clone(), data));
    }
    if let Some(f) = one {
        if !entries.iter().any(|e| e.path == f) {
            return Err(format!(
                "prego: {}@{number}: there is no card {f}",
                r.long()
            ));
        }
    }
    let sig_path = format!("{}/v/{}/set.jws.json", Api::snippet(r), seg(&local));
    let (res, sig_bytes) = api.get_bytes(&sig_path, "application/json", sn::MAX_JSON)?;
    if res.status != 200 {
        return Err(hint(
            sn::api_error(&res, &format!("{what} set signature")),
            r,
            "read",
        ));
    }
    let set_sig: Value = sn::parse_json(&sig_bytes, &format!("{what} set signature"))?;
    if verify {
        let versions: Vec<(String, String, String)> = answer["signatures"]
            .as_array()
            .into_iter()
            .flatten()
            .chain(
                list.iter()
                    .flat_map(|c| c["signers"].as_array().into_iter().flatten()),
            )
            .filter_map(|s| {
                Some((
                    s["key"].as_str()?.to_string(),
                    s["thumbprint"].as_str()?.to_string(),
                    text(&s["key_version"]),
                ))
            })
            .collect();
        let mut book = KeyBook {
            globals,
            env,
            versions,
            cache: Vec::new(),
            signed_at: answer["pushed_at"].as_str().map(str::to_string),
        };
        verify_version(r, &got, &set_sig, &mut book)?;
        eprintln!(
            "{}@{number}: the set signature and every card signature verify",
            r.long()
        );
    }
    if let Some(f) = one {
        let (_, data) = got.iter().find(|(p, _)| p == f).expect("fetched");
        use std::io::Write as _;
        let mut o = std::io::stdout().lock();
        return o
            .write_all(data)
            .and_then(|_| o.flush())
            .map_err(|e| format!("prego: stdout: {e}"));
    }
    let dir = PathBuf::from(folder.unwrap_or(r.name.as_str()));
    files::check_folder(&dir).map_err(|e| format!("prego: {e}"))?;
    let mut out: Vec<File> = got
        .iter()
        .map(|(p, d)| File {
            path: p.clone(),
            mode: MODE_FILE,
            data: d.clone(),
        })
        .collect();
    out.push(File {
        path: SET_SIG.into(),
        mode: MODE_FILE,
        data: sig_bytes,
    });
    let created = files::prepare_folder(&dir).map_err(|e| format!("prego: {e}"))?;
    if let Err(e) = files::write_all(&dir, &out) {
        if created {
            let _ = std::fs::remove_dir_all(&dir);
        }
        return Err(format!("prego: {e}"));
    }
    eprintln!("{}@{number} {local} ({} cards)", r.long(), got.len());
    println!("{}", dir.display());
    Ok(())
}

/// Checks the set signature and at least one Prego signature on every card, with keys from Keys and
/// Certificates and the reader's own grants (ADR-0061 section 3.6).
fn verify_version(
    r: &SnipRef,
    cards: &[(String, Vec<u8>)],
    set_sig: &Value,
    book: &mut KeyBook<'_>,
) -> Result<(), String> {
    let (_, payload) = hash_and_payload(r, cards)?;
    jws::verify_set(set_sig, &payload, &mut |h: &Header| book.resolve(h)).map_err(|e| {
        if e.starts_with("prego: ") {
            e
        } else {
            format!(
                "prego: {}: the set signature does not verify: {e}",
                r.long()
            )
        }
    })?;
    for (file, bytes) in cards {
        let v: Value =
            serde_json::from_slice(bytes).map_err(|e| format!("prego: card {file}: {e}"))?;
        let input = card::signing_input(&v).map_err(|e| format!("prego: card {file}: {e}"))?;
        let sigs = v["signatures"].as_array().cloned().unwrap_or_default();
        let mut last = format!("card {file} has no signature");
        let mut ok = false;
        for s in &sigs {
            let Ok(h) = jws::card_header(s) else { continue };
            match book
                .resolve(&h)
                .and_then(|k| jws::verify_card(&input, s, &k))
            {
                Ok(_) => {
                    ok = true;
                    break;
                }
                Err(e) => last = e,
            }
        }
        if !ok {
            return Err(if last.starts_with("prego: ") {
                last
            } else {
                format!("prego: card {file}: no signature verifies ({last})")
            });
        }
    }
    Ok(())
}

// ---- ls, log ----

fn ls(api: &Api, tenant: &str, namespace: &str) -> Result<(), String> {
    let what = format!("the A2A card sets of {tenant}/{namespace}");
    let mut n = 0;
    sn::pages(
        api,
        &format!("{}/{}", seg(tenant), seg(namespace)),
        &what,
        |s| {
            n += 1;
            let current = &s["current"];
            println!(
                "{:<40} {:>5}  {}  {:>4} versions  {}",
                text(&s["name"]),
                text(current.get("number").unwrap_or(&s["current_version"])),
                text(current.get("hash").unwrap_or(&s["current_hash"])),
                text(&s["version_count"]),
                text(&s["updated_at"]),
            );
        },
    )?;
    if n == 0 {
        eprintln!("no A2A card sets in {tenant}/{namespace} that you can read");
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
        let signers: Vec<String> = v["signatures"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|s| text(&s["key"]))
            .collect();
        println!(
            "{mark}{:>5}  {}  {:>3} cards  {}  {}{tags}  signed by {}  {}",
            text(&v["number"]),
            text(&v["hash"]),
            text(v.get("card_count").unwrap_or(&v["file_count"])),
            text(v.get("pushed_at").unwrap_or(&v["created_at"])),
            text(&v["pushed_by"]),
            if signers.is_empty() {
                "?".into()
            } else {
                signers.join(", ")
            },
            v["message"].as_str().unwrap_or("")
        );
    })
    .map_err(|e| hint(e, r, "read"))
}

// ---- upgrade ----

fn run_upgrade(file: &str, out: Option<&str>, force: bool) -> Result<(), String> {
    let bytes = std::fs::read(file).map_err(|e| format!("prego: {file}: {e}"))?;
    let v: Value = serde_json::from_slice(&bytes)
        .map_err(|e| format!("prego: {file}: not valid JSON ({e})"))?;
    let u = upgrade::upgrade(&v).map_err(|e| format!("prego: {file}: {e}"))?;
    let target = match out {
        Some(o) => PathBuf::from(o),
        None => Path::new(file)
            .parent()
            .unwrap_or(Path::new(""))
            .join("agent-card.json"),
    };
    if target.exists() && !force {
        return Err(format!(
            "prego: {} exists; give another file with -o <file>, or --force to replace it",
            target.display()
        ));
    }
    for c in &u.changes {
        eprintln!("{c}");
    }
    std::fs::write(&target, card_bytes(&u.card))
        .map_err(|e| format!("prego: {}: {e}", target.display()))?;
    eprintln!(
        "The card is A2A 1.0 and unsigned. Sign it: prego a2a push <folder> <ref> --sign <key file> --key <key ref>"
    );
    println!("{}", target.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_names() {
        check_file_name("acme.support-bot.json").unwrap();
        check_file_name("agent-card.json").unwrap();
        assert!(check_file_name("Agent.json").is_err());
        assert!(check_file_name("agent").is_err());
        assert!(check_file_name(".x.json").is_err());
    }

    #[test]
    fn v03_message() {
        let p = card::Problem::V03("has protocolVersion \"0.3.0\"".into());
        assert_eq!(
            p.message("agent.json"),
            "A2A 1.0 only. Card agent.json looks like A2A 0.3 (has protocolVersion \"0.3.0\"). Run `prego a2a \
             upgrade agent.json` to make a 1.0 card, then sign it again."
        );
    }

    #[test]
    fn grant_text() {
        let r = SnipRef::parse("acme/agents/support").unwrap();
        assert!(missing_set_grant("read", &r)
            .starts_with("read on a2a set acme/agents/support (type A2A Agent Cards) is missing"));
    }

    #[test]
    fn payload_files_are_sorted() {
        let r = SnipRef::parse("acme/agents").unwrap();
        let (h, p) = hash_and_payload(
            &r,
            &[
                ("b.json".into(), b"{}".to_vec()),
                ("a.json".into(), b"{}".to_vec()),
            ],
        )
        .unwrap();
        let v: Value = serde_json::from_slice(&p).unwrap();
        assert_eq!(v["files"][0]["path"], "a.json");
        assert_eq!(v["hash"], h);
        assert_eq!(v["namespace"], "default");
        assert_eq!(v["type"], "a2a");
    }
}
