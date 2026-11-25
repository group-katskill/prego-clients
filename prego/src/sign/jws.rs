//! JWS (RFC 7515) for Prego signed sets (ADR-0061 section 3) and A2A card signatures (A2A 1.0 section 8.4).
//!
//! - A **set signature** is the JWS JSON serialization (general, or flattened on read) of the RFC 8785 text
//!   of `{"type", "tenant", "namespace", "name", "hash", "files": [{"path", "sha256"}]}`. The payload is
//!   attached; a reader also takes a detached form and then uses the payload it computes. A signature that
//!   verifies over another payload gives `payload_mismatch`. The protected header is
//!   `{"alg", "kid", "prego_key"}`.
//! - A **card signature** is one entry of the card's `signatures`: `{"protected", "signature", "header"?}`
//!   over `BASE64URL(protected) "." BASE64URL(JCS(card without signatures and default values))`. The
//!   protected header is `{"alg", "typ": "JOSE", "kid", "prego_key"}`.
//!
//! `kid` is the RFC 7638 thumbprint of the signing JWK. ECDSA signatures are `r || s`. The verify rules and
//! the error codes (the start of each error text) are those of `tests/vectors/signing/README.md`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::{json, Map, Value};

use super::jwk::{b64u_decode, PublicJwk};
use super::keyfile::PrivateKey;
use crate::env::jcs;

/// The algorithms of ADR-0061 item 3.2.
pub const ALGS: [&str; 5] = ["EdDSA", "ES256", "ES384", "PS256", "RS256"];

/// The header members that must be in `protected` only.
const PROTECTED_ONLY: [&str; 5] = ["alg", "kid", "prego_key", "crit", "b64"];

/// The protected header of one signature, read and checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub alg: String,
    /// The RFC 7638 thumbprint of the signing key.
    pub kid: String,
    /// `<tenant>/<namespace>/<name>`: the Keys and Certificates item that holds the key.
    pub prego_key: String,
}

impl Header {
    /// The parts of `prego_key`.
    pub fn key_parts(&self) -> Result<(&str, &str, &str), String> {
        let p: Vec<&str> = self.prego_key.split('/').collect();
        match p.as_slice() {
            [t, ns, name] if !t.is_empty() && !ns.is_empty() && !name.is_empty() => {
                Ok((t, ns, name))
            }
            _ => Err(format!(
                "prego_key_invalid: prego_key `{}` is not <tenant>/<namespace>/<name>",
                self.prego_key
            )),
        }
    }
}

/// The code at the start of an error text (`bad_signature: ...` -> `bad_signature`).
#[cfg_attr(not(test), allow(dead_code))]
pub fn code(e: &str) -> &str {
    let e = e.strip_prefix("prego: ").unwrap_or(e);
    e.split(':').next().unwrap_or(e)
}

fn b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The signed-set payload (ADR-0061 item 3.1) as RFC 8785 bytes. `files` is `(path, sha256 hex)`, in the
/// order of the version.
pub fn set_payload(
    kind: &str,
    tenant: &str,
    namespace: &str,
    name: &str,
    hash: &str,
    files: &[(String, String)],
) -> Vec<u8> {
    let files: Vec<Value> = files
        .iter()
        .map(|(p, s)| json!({"path": p, "sha256": s}))
        .collect();
    let v = json!({
        "type": kind, "tenant": tenant, "namespace": namespace, "name": name,
        "hash": hash, "files": files,
    });
    jcs::canonical(&v).expect("text members only").into_bytes()
}

fn protected_for(key: &PrivateKey, prego_key: &str, typ: bool) -> String {
    let mut h = json!({
        "alg": key.alg(),
        "kid": key.public().thumbprint(),
        "prego_key": prego_key,
    });
    if typ {
        h["typ"] = json!("JOSE");
    }
    b64u(jcs::canonical(&h).expect("text").as_bytes())
}

/// Signs a set payload: the JWS JSON general serialization with one signature.
pub fn sign_set(payload: &[u8], key: &PrivateKey, prego_key: &str) -> Result<Value, String> {
    let protected = protected_for(key, prego_key, false);
    let payload_b64 = b64u(payload);
    let sig = key.sign(format!("{protected}.{payload_b64}").as_bytes())?;
    Ok(json!({
        "payload": payload_b64,
        "signatures": [{"protected": protected, "signature": b64u(&sig)}],
    }))
}

/// Reads and checks a protected header, and the unprotected `header` (which must not hold the members of
/// [`PROTECTED_ONLY`]).
pub fn read_protected(protected: &str, unprotected: Option<&Value>) -> Result<Header, String> {
    if let Some(Value::Object(u)) = unprotected {
        if let Some(m) = PROTECTED_ONLY.iter().find(|m| u.contains_key(**m)) {
            return Err(format!(
                "header_unprotected: `{m}` is in the unprotected header"
            ));
        }
    }
    let bytes = b64u_decode(protected, "the protected header")?;
    let v: Value = serde_json::from_slice(&bytes)
        .map_err(|_| "bad_header: the protected header is not JSON".to_string())?;
    let o = v
        .as_object()
        .ok_or("bad_header: the protected header is not an object")?;
    if o.get("b64") == Some(&Value::Bool(false)) {
        return Err("b64_false: an unencoded payload (b64: false) is not supported".into());
    }
    if o.contains_key("crit") {
        return Err(
            "crit_present: the protected header has `crit`, which Prego does not support".into(),
        );
    }
    let alg = o.get("alg").and_then(Value::as_str).unwrap_or("");
    if !ALGS.contains(&alg) {
        return Err(format!(
            "alg_not_allowed: algorithm `{alg}` is not allowed (use one of {})",
            ALGS.join(", ")
        ));
    }
    let prego_key = o
        .get("prego_key")
        .and_then(Value::as_str)
        .ok_or("prego_key_missing: the protected header has no prego_key")?;
    let kid = o.get("kid").and_then(Value::as_str).unwrap_or("");
    let is_thumbprint = kid.len() == 43
        && kid
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !is_thumbprint {
        return Err(format!(
            "kid_not_thumbprint: kid `{kid}` is not an RFC 7638 thumbprint"
        ));
    }
    let h = Header {
        alg: alg.to_string(),
        kid: kid.to_string(),
        prego_key: prego_key.to_string(),
    };
    h.key_parts()?;
    Ok(h)
}

/// A way to get the public key of a signature: by `prego_key` and `kid`. An unknown key is an error that
/// starts with `key_not_found`.
pub type Resolve<'a> = dyn FnMut(&Header) -> Result<PublicJwk, String> + 'a;

fn check_kid(key: &PublicJwk, h: &Header) -> Result<(), String> {
    if key.thumbprint() != h.kid {
        return Err(format!(
            "key_not_found: the key of {} has thumbprint {}, not the kid {}",
            h.prego_key,
            key.thumbprint(),
            h.kid
        ));
    }
    Ok(())
}

/// Checks a set JWS against the payload computed here. Every signature must verify; there must be one.
/// Returns the headers, in order.
pub fn verify_set(
    jws: &Value,
    payload: &[u8],
    resolve: &mut Resolve<'_>,
) -> Result<Vec<Header>, String> {
    let o = jws
        .as_object()
        .ok_or("bad_jws: the set signature is not a JSON object")?;
    let expected_b64 = b64u(payload);
    let attached = match o.get("payload") {
        None | Some(Value::Null) => None,
        Some(Value::String(p)) => {
            b64u_decode(p, "the payload")?;
            Some(p.clone())
        }
        Some(_) => return Err("bad_jws: payload is not a string".into()),
    };
    let signed_b64 = attached.clone().unwrap_or_else(|| expected_b64.clone());
    let sigs: Vec<&Map<String, Value>> = match o.get("signatures") {
        Some(Value::Array(a)) => a
            .iter()
            .map(|s| s.as_object().ok_or("bad_jws: a signature is not an object"))
            .collect::<Result<_, _>>()?,
        None if o.contains_key("protected") => vec![o],
        _ => return Err("bad_jws: the set signature has no signatures".into()),
    };
    if sigs.is_empty() {
        return Err("bad_jws: the set signature has no signatures".into());
    }
    let mut out = Vec::new();
    for s in sigs {
        let protected = s
            .get("protected")
            .and_then(Value::as_str)
            .ok_or("bad_jws: a signature has no protected")?;
        let signature = s
            .get("signature")
            .and_then(Value::as_str)
            .ok_or("bad_jws: a signature has no signature")?;
        let h = read_protected(protected, s.get("header"))?;
        let sig = b64u_decode(signature, "the signature")?;
        let key = resolve(&h)?;
        check_kid(&key, &h)?;
        key.verify(&h.alg, format!("{protected}.{signed_b64}").as_bytes(), &sig)
            .map_err(|e| format!("{e} (key {}, kid {})", h.prego_key, h.kid))?;
        out.push(h);
    }
    if signed_b64 != expected_b64 {
        return Err("payload_mismatch: the signature is good, but for another payload (another item, tenant or version)".into());
    }
    Ok(out)
}

/// A card signature entry `{"protected", "signature"}` over the signing input of a card. `canonical` is the
/// RFC 8785 text of the card without `signatures` and without default values.
pub fn sign_card(canonical: &[u8], key: &PrivateKey, prego_key: &str) -> Result<Value, String> {
    let protected = protected_for(key, prego_key, true);
    let sig = key.sign(format!("{protected}.{}", b64u(canonical)).as_bytes())?;
    Ok(json!({"protected": protected, "signature": b64u(&sig)}))
}

/// Reads the protected header of a card signature entry.
pub fn card_header(entry: &Value) -> Result<Header, String> {
    let protected = entry["protected"]
        .as_str()
        .ok_or("bad_jws: a card signature has no protected")?;
    read_protected(protected, entry.get("header"))
}

/// Checks one card signature entry with a key.
pub fn verify_card(canonical: &[u8], entry: &Value, key: &PublicJwk) -> Result<Header, String> {
    let h = card_header(entry)?;
    let protected = entry["protected"].as_str().unwrap_or("");
    check_kid(key, &h)?;
    let sig = b64u_decode(
        entry["signature"]
            .as_str()
            .ok_or("bad_jws: a card signature has no signature")?,
        "the signature",
    )?;
    key.verify(
        &h.alg,
        format!("{protected}.{}", b64u(canonical)).as_bytes(),
        &sig,
    )?;
    Ok(h)
}

#[cfg(test)]
mod tests {
    use super::super::keyfile::NewAlg;
    use super::*;

    #[test]
    fn set_sign_and_verify() {
        let (k, _) = PrivateKey::generate(NewAlg::Ed25519).unwrap();
        let files = vec![("a.json".to_string(), "00".repeat(32))];
        let payload = set_payload("a2a", "acme", "default", "agents", "sha256:x", &files);
        assert_eq!(
            String::from_utf8(payload.clone()).unwrap(),
            format!(
                r#"{{"files":[{{"path":"a.json","sha256":"{}"}}],"hash":"sha256:x","name":"agents","namespace":"default","tenant":"acme","type":"a2a"}}"#,
                "00".repeat(32)
            )
        );
        let jws = sign_set(&payload, &k, "acme/default/signer").unwrap();
        let public = k.public().clone();
        let mut resolve = |h: &Header| {
            assert_eq!(h.prego_key, "acme/default/signer");
            Ok(public.clone())
        };
        let hs = verify_set(&jws, &payload, &mut resolve).unwrap();
        assert_eq!(hs[0].alg, "EdDSA");
        assert_eq!(hs[0].kid, k.public().thumbprint());
        let mut detached = jws.clone();
        detached.as_object_mut().unwrap().remove("payload");
        verify_set(&detached, &payload, &mut resolve).unwrap();
        let other = set_payload("a2a", "evil", "default", "agents", "sha256:x", &files);
        assert_eq!(
            code(&verify_set(&jws, &other, &mut resolve).unwrap_err()),
            "payload_mismatch"
        );
        assert_eq!(
            code(&verify_set(&detached, &other, &mut resolve).unwrap_err()),
            "bad_signature"
        );
        let (k2, _) = PrivateKey::generate(NewAlg::Es256).unwrap();
        let p2 = k2.public().clone();
        let e = verify_set(&jws, &payload, &mut |_: &Header| Ok(p2.clone())).unwrap_err();
        assert_eq!(code(&e), "key_not_found");
    }

    #[test]
    fn card_sign_and_verify() {
        let (k, _) = PrivateKey::generate(NewAlg::Es256).unwrap();
        let canonical = br#"{"name":"x"}"#;
        let entry = sign_card(canonical, &k, "acme/default/signer").unwrap();
        assert_eq!(card_header(&entry).unwrap().alg, "ES256");
        verify_card(canonical, &entry, k.public()).unwrap();
        assert!(verify_card(br#"{"name":"y"}"#, &entry, k.public()).is_err());
        let protected = entry["protected"].as_str().unwrap();
        let v: Value = serde_json::from_slice(&b64u_decode(protected, "p").unwrap()).unwrap();
        assert_eq!(v["typ"], "JOSE");
    }
}
