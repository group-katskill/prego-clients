//! The entry types of Keys and Certificates (ADR-0061 item 2.3), the private-material check (item 2.4), and
//! the offline fingerprints of `prego keys fingerprint`. Written from the ADR, RFC 4253 and PROTOCOL.certkeys
//! (SSH), RFC 9580 (OpenPGP), RFC 7517/7638 (JWK), RFC 5280 (X.509), RFC 7292 (PKCS #12 shape) and the shared
//! test vectors (`tests/vectors/keys/`), never from server code. The error texts are the vector reasons.

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine as _;
use serde_json::Value;

use crate::sign::der;
use crate::sign::jwk::{pem_blocks, pem_labels, private_members, PublicJwk};
use crate::snippet::files::hex_sha256;

/// The declared type of an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryType {
    Ssh,
    Openpgp,
    Jwk,
    PemPublicKey,
    X509,
}

pub const TYPES: &str = "ssh, openpgp, jwk, pem-public-key, x509";

impl EntryType {
    pub fn parse(s: &str) -> Result<EntryType, String> {
        Ok(match s {
            "ssh" => EntryType::Ssh,
            "openpgp" => EntryType::Openpgp,
            "jwk" => EntryType::Jwk,
            "pem-public-key" => EntryType::PemPublicKey,
            "x509" => EntryType::X509,
            _ => return Err(format!("--type `{s}`: use one of {TYPES}")),
        })
    }

    pub fn code(self) -> &'static str {
        match self {
            EntryType::Ssh => "ssh",
            EntryType::Openpgp => "openpgp",
            EntryType::Jwk => "jwk",
            EntryType::PemPublicKey => "pem-public-key",
            EntryType::X509 => "x509",
        }
    }

    /// The type that the content looks like, or `None`.
    pub fn detect(bytes: &[u8]) -> Option<EntryType> {
        if let Ok(t) = std::str::from_utf8(bytes) {
            let t = t.trim_start();
            if t.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----") {
                return Some(EntryType::Openpgp);
            }
            if t.contains("-----BEGIN CERTIFICATE-----") {
                return Some(EntryType::X509);
            }
            if t.contains("-----BEGIN PUBLIC KEY-----") {
                return Some(EntryType::PemPublicKey);
            }
            if t.starts_with('{') {
                return Some(EntryType::Jwk);
            }
            if ssh_key_type(t.split_whitespace().next().unwrap_or("")) {
                return Some(EntryType::Ssh);
            }
        }
        match bytes.first() {
            Some(&der::SEQUENCE) => Some(EntryType::X509),
            Some(b) if packet_tag(*b) == Some(6) => Some(EntryType::Openpgp),
            _ => None,
        }
    }
}

/// What a check found about one key or certificate of an entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info {
    /// `ed25519`, `ecdsa`, `rsa`, `ed25519-sk`, `ed25519-cert`, `x509` (the vector `alg` codes).
    pub alg: String,
    /// `RSA 3072`, `P-256`, `Ed25519`: for people.
    pub size: String,
    /// The fingerprint in the form of ADR-0061 section 4a.
    pub fingerprint: String,
    /// Other lines to show (user IDs, subject, validity, `kid`).
    pub details: Vec<String>,
    /// `true` for a certificate that is past `notAfter`.
    pub expired: bool,
}

// ---- Private material (ADR-0061 item 2.4) ----

/// A kind of private material found in an upload, and what to upload instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Private {
    pub kind: String,
    pub hint: &'static str,
}

const HINT_PEM: &str = "Upload the public key (`openssl pkey -in <key> -pubout`) instead.";
const HINT_SSH: &str = "Upload the public key (`ssh-keygen -y -f <key>`) instead.";
const HINT_PGP: &str = "Upload the public key (`gpg --armor --export <key id>`) instead.";
const HINT_JWK: &str =
    "Upload the public JWK without the members d, p, q, dp, dq, qi, oth and k instead.";
const HINT_P12: &str =
    "Export the certificates as PEM (`openssl pkcs12 -in <file> -nokeys`) and upload them instead.";

/// The ADR-0061 item 2.4 message. `index` counts from 0, as `entries/<index>`.
pub fn private_message(index: usize, p: &Private) -> String {
    format!(
        "Keys and Certificates holds public keys and certificates only. Entry {index} holds a private key ({}). {}",
        p.kind, p.hint
    )
}

/// Looks for private key material anywhere in the bytes, also outside the declared entry, for every type.
/// `file` is the local file name (a `.p12` or `.pfx` name is PKCS #12).
pub fn private_material(bytes: &[u8], file: &str) -> Option<Private> {
    let found = |kind: &str, hint| {
        Some(Private {
            kind: kind.to_string(),
            hint,
        })
    };
    let lower = file.to_ascii_lowercase();
    if lower.ends_with(".p12") || lower.ends_with(".pfx") || is_pkcs12(bytes) {
        return found("PKCS #12", HINT_P12);
    }
    let text = String::from_utf8_lossy(bytes);
    for label in pem_labels(&text) {
        match label.as_str() {
            "OPENSSH PRIVATE KEY" => return found("OpenSSH private key", HINT_SSH),
            "PGP PRIVATE KEY BLOCK" => return found("OpenPGP private key block", HINT_PGP),
            "PRIVATE KEY"
            | "RSA PRIVATE KEY"
            | "EC PRIVATE KEY"
            | "ENCRYPTED PRIVATE KEY"
            | "DSA PRIVATE KEY" => return found(&format!("PEM {label}"), HINT_PEM),
            _ => {}
        }
    }
    if let Some(m) = json_private_member(&text) {
        return found(&format!("JWK private member {m}"), HINT_JWK);
    }
    // OpenPGP: armored blocks and binary packets.
    let mut pgp: Vec<Vec<u8>> = armor_blocks(&text);
    if bytes.first().is_some_and(|b| b & 0x80 != 0) {
        pgp.push(bytes.to_vec());
    }
    for data in pgp {
        if let Ok(ps) = packets(&data) {
            if ps.iter().any(|(t, _)| *t == 5) {
                return found("OpenPGP secret-key packet", HINT_PGP);
            }
            if ps.iter().any(|(t, _)| *t == 7) {
                return found("OpenPGP secret-subkey packet", HINT_PGP);
            }
        }
    }
    // DER private keys, and DER inside other PEM blocks.
    let mut ders = vec![bytes.to_vec()];
    for label in pem_labels(&text) {
        if let Ok(b) = pem_blocks(&text, &label) {
            ders.extend(b);
        }
    }
    for d in ders {
        if let Some(kind) = der_private(&d) {
            return found(kind, HINT_PEM);
        }
        if is_pkcs12(&d) {
            return found("PKCS #12", HINT_P12);
        }
    }
    None
}

/// The first private member (in [`PRIVATE_MEMBERS`] order) of any JSON object in the text.
fn json_private_member(text: &str) -> Option<&'static str> {
    // An object's own members first (a JWK with `oth` names `oth`), then the objects inside it.
    fn walk(v: &Value) -> Option<&'static str> {
        match v {
            Value::Object(o) => private_members(o)
                .first()
                .copied()
                .or_else(|| o.values().find_map(walk)),
            Value::Array(a) => a.iter().find_map(walk),
            _ => None,
        }
    }
    let t = text.trim();
    if !(t.starts_with('{') || t.starts_with('[')) {
        return None;
    }
    walk(&serde_json::from_str(t).ok()?)
}

fn der_private(bytes: &[u8]) -> Option<&'static str> {
    let top = der::read_all(bytes).ok()?;
    if top.tag != der::SEQUENCE {
        return None;
    }
    let kids = der::children(top.content).ok()?;
    let int = |i: usize, v: u8| {
        kids.get(i)
            .is_some_and(|t| t.tag == der::INTEGER && t.content == [v])
    };
    if (int(0, 0) || int(0, 1))
        && kids.get(1).is_some_and(|t| t.tag == der::SEQUENCE)
        && kids.get(2).is_some_and(|t| t.tag == der::OCTET_STRING)
    {
        return Some("DER PKCS #8 private key");
    }
    if int(0, 0) && kids.len() >= 9 && kids.iter().all(|t| t.tag == der::INTEGER) {
        return Some("DER RSA private key");
    }
    if int(0, 1) && kids.get(1).is_some_and(|t| t.tag == der::OCTET_STRING) {
        return Some("DER EC private key");
    }
    None
}

/// PFX (RFC 7292): SEQUENCE { INTEGER 3, ContentInfo { OID pkcs7-data or signedData, ... }, ... }.
fn is_pkcs12(bytes: &[u8]) -> bool {
    let Ok(top) = der::read_all(bytes) else {
        return false;
    };
    if top.tag != der::SEQUENCE {
        return false;
    }
    let Ok(kids) = der::children(top.content) else {
        return false;
    };
    let v3 = kids
        .first()
        .is_some_and(|t| t.tag == der::INTEGER && t.content == [3]);
    let ci = kids
        .get(1)
        .filter(|t| t.tag == der::SEQUENCE)
        .and_then(|t| der::children(t.content).ok())
        .and_then(|c| c.first().copied())
        .filter(|t| t.tag == der::OID)
        .map(|t| der::oid_text(t.content));
    v3 && matches!(
        ci.as_deref(),
        Some("1.2.840.113549.1.7.1") | Some("1.2.840.113549.1.7.2")
    )
}

// ---- SSH ----

const SSH_TYPES: [&str; 8] = [
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-rsa",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "ssh-dss",
];

fn ssh_key_type(t: &str) -> bool {
    SSH_TYPES.contains(&t) || t.ends_with("-cert-v01@openssh.com")
}

/// The least RSA size for `ssh` (ADR-0061 question 3).
pub const SSH_RSA_MIN_BITS: usize = 3072;

struct SshReader<'a>(&'a [u8]);

impl<'a> SshReader<'a> {
    fn string(&mut self) -> Result<&'a [u8], String> {
        if self.0.len() < 4 {
            return Err("not an OpenSSH public key line".into());
        }
        let n = u32::from_be_bytes([self.0[0], self.0[1], self.0[2], self.0[3]]) as usize;
        if self.0.len() < 4 + n {
            return Err("not an OpenSSH public key line".into());
        }
        let s = &self.0[4..4 + n];
        self.0 = &self.0[4 + n..];
        Ok(s)
    }
}

fn put(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

/// The plain key blob of an OpenSSH certificate: the certified key (PROTOCOL.certkeys).
fn certified_key(cert_type: &str, r: &mut SshReader<'_>) -> Result<(String, Vec<u8>), String> {
    let base = cert_type.trim_end_matches("-cert-v01@openssh.com");
    let plain = if base.starts_with("sk-") {
        format!("{base}@openssh.com")
    } else {
        base.to_string()
    };
    let _nonce = r.string()?;
    let n_fields = match plain.as_str() {
        "ssh-ed25519" => 1,
        "ssh-rsa" => 2,
        p if p.starts_with("ecdsa-sha2-") => 2,
        "sk-ssh-ed25519@openssh.com" => 2,
        "sk-ecdsa-sha2-nistp256@openssh.com" => 3,
        _ => return Err("not an OpenSSH public key line".into()),
    };
    let mut blob = Vec::new();
    put(&mut blob, plain.as_bytes());
    for _ in 0..n_fields {
        put(&mut blob, r.string()?);
    }
    Ok((plain, blob))
}

fn ssh_alg(kind: &str) -> &'static str {
    match kind {
        "ssh-ed25519" => "ed25519",
        "ssh-rsa" => "rsa",
        "sk-ssh-ed25519@openssh.com" => "ed25519-sk",
        "sk-ecdsa-sha2-nistp256@openssh.com" => "ecdsa-sk",
        k if k.starts_with("ecdsa-sha2-") => "ecdsa",
        _ => "ssh",
    }
}

fn inspect_ssh(bytes: &[u8]) -> Result<Vec<Info>, String> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| "not an OpenSSH public key line".to_string())?;
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    if lines.len() != 1 {
        return Err("ssh needs exactly one public key line".into());
    }
    let mut parts = lines[0].split_whitespace();
    let kind = parts.next().unwrap_or("");
    if kind == "ssh-dss" {
        return Err("DSA keys are refused".into());
    }
    if !ssh_key_type(kind) {
        return Err("not an OpenSSH public key line".into());
    }
    let blob = parts
        .next()
        .and_then(|b| STANDARD.decode(b).ok())
        .ok_or("not an OpenSSH public key line")?;
    let comment: Vec<&str> = parts.collect();
    let mut r = SshReader(&blob);
    let inner = String::from_utf8_lossy(r.string()?).into_owned();
    if inner == "ssh-dss" {
        return Err("DSA keys are refused".into());
    }
    if inner != kind {
        return Err(format!(
            "key type {kind} does not match the key blob ({inner})"
        ));
    }
    let is_cert = kind.ends_with("-cert-v01@openssh.com");
    let (plain, fp_blob) = if is_cert {
        certified_key(kind, &mut r)?
    } else {
        (kind.to_string(), blob.clone())
    };
    let mut size = plain.clone();
    if plain == "ssh-rsa" {
        let mut pr = SshReader(&fp_blob);
        let _t = pr.string()?;
        let _e = pr.string()?;
        let bits = der::bit_len(pr.string()?);
        if bits < SSH_RSA_MIN_BITS {
            return Err(format!(
                "RSA key is {bits} bits; ssh needs at least {SSH_RSA_MIN_BITS}"
            ));
        }
        size = format!("RSA {bits}");
    }
    let fingerprint = format!(
        "SHA256:{}",
        STANDARD_NO_PAD.encode(ring::digest::digest(&ring::digest::SHA256, &fp_blob))
    );
    let mut details = Vec::new();
    if !comment.is_empty() {
        details.push(format!("comment: {}", comment.join(" ")));
    }
    let mut alg = ssh_alg(&plain).to_string();
    if is_cert {
        details.push("OpenSSH certificate (the fingerprint is of the certified key)".into());
        alg.push_str("-cert");
    }
    Ok(vec![Info {
        alg,
        size,
        fingerprint,
        details,
        expired: false,
    }])
}

// ---- OpenPGP ----

/// The packet tag of a first header byte, or `None`.
fn packet_tag(b: u8) -> Option<u8> {
    if b & 0x80 == 0 {
        None
    } else if b & 0x40 != 0 {
        Some(b & 0x3f)
    } else {
        Some((b >> 2) & 0x0f)
    }
}

/// The packets: (tag, body). Partial and indeterminate lengths are refused.
fn packets(mut data: &[u8]) -> Result<Vec<(u8, &[u8])>, String> {
    let short = || "an OpenPGP packet is cut short".to_string();
    let mut out = Vec::new();
    while !data.is_empty() {
        let b = data[0];
        let tag = packet_tag(b).ok_or("not an OpenPGP packet")?;
        let (len, head) = if b & 0x40 != 0 {
            match data.get(1).copied() {
                Some(o) if o < 192 => (usize::from(o), 2),
                Some(o) if o < 224 => {
                    let o2 = *data.get(2).ok_or_else(short)?;
                    (((usize::from(o) - 192) << 8) + usize::from(o2) + 192, 3)
                }
                Some(255) => {
                    let l = data.get(2..6).ok_or_else(short)?;
                    (u32::from_be_bytes([l[0], l[1], l[2], l[3]]) as usize, 6)
                }
                _ => return Err("an OpenPGP partial length is not supported".into()),
            }
        } else {
            match b & 3 {
                0 => (usize::from(*data.get(1).ok_or_else(short)?), 2),
                1 => {
                    let l = data.get(1..3).ok_or_else(short)?;
                    (usize::from(u16::from_be_bytes([l[0], l[1]])), 3)
                }
                2 => {
                    let l = data.get(1..5).ok_or_else(short)?;
                    (u32::from_be_bytes([l[0], l[1], l[2], l[3]]) as usize, 5)
                }
                _ => return Err("an OpenPGP indeterminate length is not supported".into()),
            }
        };
        let body = data.get(head..head + len).ok_or_else(short)?;
        out.push((tag, body));
        data = &data[head + len..];
    }
    Ok(out)
}

/// The binary of every ASCII-armored block.
fn armor_blocks(text: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut lines = text.lines().map(str::trim_end);
    while let Some(l) = lines.next() {
        if !(l.starts_with("-----BEGIN PGP ") && l.ends_with("-----")) {
            continue;
        }
        let mut body = String::new();
        let mut in_headers = true;
        for l in lines.by_ref() {
            if l.starts_with("-----END PGP ") {
                break;
            }
            if in_headers {
                if l.is_empty() {
                    in_headers = false;
                } else if !l.contains(": ") {
                    in_headers = false;
                    body.push_str(l);
                }
                continue;
            }
            if l.starts_with('=') {
                continue; // CRC-24
            }
            body.push_str(l);
        }
        if let Ok(b) = STANDARD.decode(body) {
            out.push(b);
        }
    }
    out
}

const PGP_ALGS: [(u8, &str); 8] = [
    (1, "rsa"),
    (16, "elgamal"),
    (17, "dsa"),
    (18, "x25519"),
    (19, "ecdsa"),
    (22, "ed25519"),
    (25, "x25519"),
    (27, "ed25519"),
];

fn inspect_openpgp(bytes: &[u8]) -> Result<Vec<Info>, String> {
    let not_key = || "not a v4 or v6 OpenPGP public key".to_string();
    let data = match std::str::from_utf8(bytes)
        .ok()
        .filter(|t| t.contains("-----BEGIN PGP"))
    {
        Some(t) => {
            let mut blocks = armor_blocks(t);
            if blocks.len() != 1 {
                return Err(not_key());
            }
            blocks.remove(0)
        }
        None => bytes.to_vec(),
    };
    let ps = packets(&data).map_err(|_| not_key())?;
    let mut infos = Vec::new();
    let mut user_ids = Vec::new();
    let mut subkeys = Vec::new();
    for (tag, body) in &ps {
        match tag {
            6 | 14 => {
                let version = *body.first().ok_or_else(not_key)?;
                let fp = match version {
                    4 => {
                        let len = u16::try_from(body.len()).map_err(|_| not_key())?;
                        let mut m = vec![0x99];
                        m.extend_from_slice(&len.to_be_bytes());
                        m.extend_from_slice(body);
                        upper_hex(
                            ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &m)
                                .as_ref(),
                        )
                    }
                    6 => return Err("OpenPGP v6 keys are not supported yet".into()),
                    _ => return Err(not_key()),
                };
                let alg_id = *body.get(5).ok_or_else(not_key)?;
                let alg = PGP_ALGS
                    .iter()
                    .find(|(i, _)| *i == alg_id)
                    .map(|(_, n)| (*n).to_string())
                    .unwrap_or_else(|| format!("algorithm {alg_id}"));
                if *tag == 6 {
                    infos.push(Info {
                        alg: alg.clone(),
                        size: format!("OpenPGP v4 {alg}"),
                        fingerprint: fp,
                        details: Vec::new(),
                        expired: false,
                    });
                } else {
                    subkeys.push(format!("subkey {fp} ({alg})"));
                }
            }
            13 => user_ids.push(format!("user ID: {}", String::from_utf8_lossy(body))),
            _ => {}
        }
    }
    if infos.len() != 1 {
        return Err(not_key());
    }
    infos[0].details.extend(user_ids);
    infos[0].details.extend(subkeys);
    Ok(infos)
}

fn upper_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

fn lower_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ---- JWK and PEM ----

fn jwk_alg(k: &PublicJwk) -> &'static str {
    match k {
        PublicJwk::Ed25519 { .. } => "ed25519",
        PublicJwk::Ec { .. } => "ecdsa",
        PublicJwk::Rsa { .. } => "rsa",
    }
}

fn jwk_info(k: &PublicJwk, kid: Option<&str>) -> Info {
    let mut details = Vec::new();
    if let Some(k) = kid {
        details.push(format!("kid: {k}"));
    }
    Info {
        alg: jwk_alg(k).into(),
        size: k.describe(),
        fingerprint: k.thumbprint(),
        details,
        expired: false,
    }
}

fn inspect_jwk(bytes: &[u8]) -> Result<Vec<Info>, String> {
    let v: Value =
        serde_json::from_slice(bytes).map_err(|_| "not a JSON JWK or JWK Set".to_string())?;
    if !v.is_object() {
        return Err("not a JSON JWK or JWK Set".into());
    }
    let set = v.get("keys").is_some();
    let list: Vec<&Value> = match v.get("keys") {
        Some(Value::Array(a)) => a.iter().collect(),
        Some(_) => return Err("not a JSON JWK or JWK Set".into()),
        None => vec![&v],
    };
    if list.is_empty() {
        return Err("JWK Set has no keys".into());
    }
    list.into_iter()
        .enumerate()
        .map(|(i, k)| {
            let key = PublicJwk::from_json(k).map_err(|e| {
                if set {
                    format!("key {} of the set: {e}", i + 1)
                } else {
                    e
                }
            })?;
            Ok(jwk_info(&key, k["kid"].as_str()))
        })
        .collect()
}

fn inspect_pem_public(bytes: &[u8]) -> Result<Vec<Info>, String> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "pem-public-key needs exactly one PUBLIC KEY block".to_string())?;
    let blocks = pem_blocks(text, "PUBLIC KEY")?;
    match blocks.as_slice() {
        [one] => Ok(vec![jwk_info(&PublicJwk::from_spki(one)?, None)]),
        [] => match pem_labels(text).first() {
            Some(l) => Err(format!(
                "PEM label {l} is not PUBLIC KEY (SubjectPublicKeyInfo)"
            )),
            None => Err("pem-public-key needs exactly one PUBLIC KEY block".into()),
        },
        _ => Err("pem-public-key needs exactly one PUBLIC KEY block".into()),
    }
}

// ---- X.509 ----

/// The most certificates in one `x509` entry.
pub const MAX_CERTS: usize = 100;

fn inspect_x509(bytes: &[u8], now: &str) -> Result<Vec<Info>, String> {
    let ders = match std::str::from_utf8(bytes) {
        Ok(t) if t.contains("-----BEGIN") => {
            let d = pem_blocks(t, "CERTIFICATE")?;
            if d.is_empty() {
                let l = pem_labels(t).into_iter().next().unwrap_or_default();
                return Err(format!("no certificate found ({l} is not a certificate)"));
            }
            d
        }
        _ => vec![bytes.to_vec()],
    };
    if ders.len() > MAX_CERTS {
        return Err(format!(
            "the bundle has {} certificates; at most {MAX_CERTS}",
            ders.len()
        ));
    }
    ders.iter()
        .enumerate()
        .map(|(i, d)| {
            cert_info(d, now).map_err(|_| {
                if ders.len() > 1 {
                    format!("certificate {} of the bundle does not parse", i + 1)
                } else {
                    "the certificate does not parse".to_string()
                }
            })
        })
        .collect()
}

fn cert_info(d: &[u8], now: &str) -> Result<Info, String> {
    let cert = der::expect(der::read_all(d)?, der::SEQUENCE, "Certificate")?;
    let parts = der::children(cert.content)?;
    if parts.len() != 3 {
        return Err("not a certificate".into());
    }
    let tbs = der::expect(parts[0], der::SEQUENCE, "TBSCertificate")?;
    let mut f = der::children(tbs.content)?.into_iter();
    let mut next = f.next().ok_or("empty TBSCertificate")?;
    if next.tag == 0xa0 {
        next = f.next().ok_or("cut short")?; // [0] version
    }
    let serial = der::expect(next, der::INTEGER, "serial")?;
    let _sig_alg = f.next().ok_or("cut short")?;
    let issuer = f.next().ok_or("cut short")?;
    let validity = der::expect(f.next().ok_or("cut short")?, der::SEQUENCE, "validity")?;
    let subject = f.next().ok_or("cut short")?;
    let spki = der::expect(
        f.next().ok_or("cut short")?,
        der::SEQUENCE,
        "SubjectPublicKeyInfo",
    )?;
    let key_alg = der::children(spki.content)?
        .first()
        .and_then(|a| der::children(a.content).ok())
        .and_then(|a| a.first().map(|t| der::oid_text(t.content)))
        .unwrap_or_default();
    let alg = match key_alg.as_str() {
        "1.3.101.112" => "ed25519",
        "1.3.101.110" => "x25519",
        "1.2.840.10045.2.1" => "ecdsa",
        "1.2.840.113549.1.1.1" => "rsa",
        _ => "other",
    };
    let times = der::children(validity.content)?;
    if times.len() != 2 {
        return Err("bad validity".into());
    }
    let not_before = asn1_time(times[0])?;
    let not_after = asn1_time(times[1])?;
    let expired = not_after.as_str() < now;
    let details = vec![
        format!("subject: {}", name_text(subject.content)),
        format!("issuer: {}", name_text(issuer.content)),
        format!("serial: {}", lower_hex(der::unsigned(serial.content))),
        format!(
            "valid: {} to {}{}",
            show_time(&not_before),
            show_time(&not_after),
            if expired { " (EXPIRED)" } else { "" }
        ),
    ];
    Ok(Info {
        alg: alg.into(),
        size: "X.509".into(),
        fingerprint: format!("sha256:{}", hex_sha256(d)),
        details,
        expired,
    })
}

/// `YYYYMMDDHHMMSS` of a UTCTime or GeneralizedTime in `Z`.
fn asn1_time(t: der::Tlv<'_>) -> Result<String, String> {
    let s = std::str::from_utf8(t.content).map_err(|_| "bad time")?;
    let s = s.strip_suffix('Z').ok_or("a time not in UTC")?;
    match t.tag {
        der::UTC_TIME if s.len() == 12 => {
            let yy: u32 = s[..2].parse().map_err(|_| "bad time")?;
            Ok(format!("{}{s}", if yy >= 50 { "19" } else { "20" }))
        }
        der::GENERALIZED_TIME if s.len() == 14 => Ok(s.to_string()),
        _ => Err("bad time".into()),
    }
}

fn show_time(t: &str) -> String {
    format!(
        "{}-{}-{} {}:{} UTC",
        &t[..4],
        &t[4..6],
        &t[6..8],
        &t[8..10],
        &t[10..12]
    )
}

/// The CN, O, OU and C of a Name, for people.
fn name_text(content: &[u8]) -> String {
    let mut parts = Vec::new();
    for rdn in der::children(content).unwrap_or_default() {
        for atv in der::children(rdn.content).unwrap_or_default() {
            let kv = der::children(atv.content).unwrap_or_default();
            if kv.len() == 2 && kv[0].tag == der::OID {
                let key = match der::oid_text(kv[0].content).as_str() {
                    "2.5.4.3" => "CN",
                    "2.5.4.10" => "O",
                    "2.5.4.11" => "OU",
                    "2.5.4.6" => "C",
                    _ => continue,
                };
                parts.push(format!("{key}={}", String::from_utf8_lossy(kv[1].content)));
            }
        }
    }
    if parts.is_empty() {
        "(no CN or O)".into()
    } else {
        parts.join(", ")
    }
}

/// The current time as `YYYYMMDDHHMMSS` (UTC).
pub fn now_text() -> String {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = t.div_euclid(86_400);
    let secs = t.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}{m:02}{d:02}{:02}{:02}{:02}",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

/// Parses an entry as its declared type. Run the private-material check first.
pub fn inspect(t: EntryType, bytes: &[u8], now: &str) -> Result<Vec<Info>, String> {
    match t {
        EntryType::Ssh => inspect_ssh(bytes),
        EntryType::Openpgp => inspect_openpgp(bytes),
        EntryType::Jwk => inspect_jwk(bytes),
        EntryType::PemPublicKey => inspect_pem_public(bytes),
        EntryType::X509 => inspect_x509(bytes, now),
    }
}

/// The public JWKs of a `jwk` or `pem-public-key` entry: the keys that can check a signature.
pub fn signing_keys(t: EntryType, bytes: &[u8]) -> Vec<PublicJwk> {
    match t {
        EntryType::Jwk => {
            let Ok(v) = serde_json::from_slice::<Value>(bytes) else {
                return Vec::new();
            };
            let list: Vec<Value> = match v.get("keys") {
                Some(Value::Array(a)) => a.clone(),
                _ => vec![v],
            };
            list.iter()
                .filter_map(|k| PublicJwk::from_json(k).ok())
                .collect()
        }
        EntryType::PemPublicKey => std::str::from_utf8(bytes)
            .ok()
            .and_then(|t| pem_blocks(t, "PUBLIC KEY").ok())
            .unwrap_or_default()
            .iter()
            .filter_map(|d| PublicJwk::from_spki(d).ok())
            .collect(),
        _ => Vec::new(),
    }
}

/// The entry as pushed: text when it is UTF-8 with no NUL, else base64 (ADR-0061 section 4a).
pub fn wire_content(bytes: &[u8]) -> (String, &'static str) {
    match std::str::from_utf8(bytes) {
        Ok(t) if !t.contains('\0') => (t.to_string(), "text"),
        _ => (STANDARD.encode(bytes), "base64"),
    }
}

/// The version hash of a key version (ADR-0061 section 4a): `sha256:` of the RFC 8785 JSON of
/// `{"entries": [{"type", "sha256"}]}` in push order.
pub fn version_hash(entries: &[(EntryType, Vec<u8>)]) -> String {
    let list: Vec<Value> = entries
        .iter()
        .map(|(t, b)| serde_json::json!({"type": t.code(), "sha256": hex_sha256(b)}))
        .collect();
    crate::env::jcs::hash(&serde_json::json!({ "entries": list })).expect("text members")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times() {
        assert_eq!(now_text().len(), 14);
        let t = der::read_all(b"\x17\x0d491231235959Z").unwrap();
        assert_eq!(asn1_time(t).unwrap(), "20491231235959");
        let t = der::read_all(b"\x17\x0d500101000000Z").unwrap();
        assert_eq!(asn1_time(t).unwrap(), "19500101000000");
    }

    #[test]
    fn wire_forms() {
        assert_eq!(wire_content(b"{}").1, "text");
        assert_eq!(wire_content(&[0x30, 0x00, 0xff]).1, "base64");
    }
}
