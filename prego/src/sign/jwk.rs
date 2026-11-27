//! Public JSON Web Keys (RFC 7517, RFC 8037), the RFC 7638 thumbprint, the PEM `PUBLIC KEY`
//! (SubjectPublicKeyInfo) form, and signature checks (RFC 7518) with ring.
//!
//! ADR-0061 item 2.3: `kty` `OKP` (Ed25519), `EC` (P-256, P-384), `RSA` (at least 2048 bits). `oct` is
//! refused, and a JWK with a private member is refused (item 2.4). The error texts are the reasons of the
//! shared test vectors (`tests/vectors/keys/`).

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ring::signature::{self, UnparsedPublicKey};
use serde_json::{json, Map, Value};

use super::der;

/// The private members of a JWK (RFC 7518 section 6, and `k` of `oct`). ADR-0061 item 2.4.
pub const PRIVATE_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// The least RSA size for `jwk` and `pem-public-key` (ADR-0061 question 3).
pub const RSA_MIN_BITS: usize = 2048;

const OID_RSA: &str = "1.2.840.113549.1.1.1";
const OID_EC: &str = "1.2.840.10045.2.1";
const OID_ED25519: &str = "1.3.101.112";
const OID_X25519: &str = "1.3.101.110";
const OID_ED448: &str = "1.3.101.113";
const OID_X448: &str = "1.3.101.111";
const OID_P256: &str = "1.2.840.10045.3.1.7";
const OID_P384: &str = "1.3.132.0.34";
const OID_P521: &str = "1.3.132.0.35";
const OID_SECP256K1: &str = "1.3.132.0.10";

/// A public key that Prego can check signatures with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicJwk {
    /// Ed25519: the 32-byte public key.
    Ed25519 { x: Vec<u8> },
    /// P-256 or P-384: the coordinates.
    Ec { crv: Curve, x: Vec<u8>, y: Vec<u8> },
    /// RSA: modulus and exponent, unsigned big-endian.
    Rsa { n: Vec<u8>, e: Vec<u8> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    P256,
    P384,
}

impl Curve {
    pub fn name(self) -> &'static str {
        match self {
            Curve::P256 => "P-256",
            Curve::P384 => "P-384",
        }
    }
    pub fn len(self) -> usize {
        match self {
            Curve::P256 => 32,
            Curve::P384 => 48,
        }
    }
}

fn b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes base64url without padding (RFC 7515 section 2). Padding and the standard alphabet are refused.
pub fn b64u_decode(s: &str, what: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| format!("bad_base64url: {what} is not base64url without padding"))
}

fn member<'a>(o: &'a Map<String, Value>, name: &str) -> Result<&'a str, String> {
    o.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("JWK member {name} is missing"))
}

fn curve_refused(name: &str) -> String {
    format!("curve {name} is not allowed; use Ed25519, P-256 or P-384")
}

/// The private members that a JSON object has, in [`PRIVATE_MEMBERS`] order.
pub fn private_members(o: &Map<String, Value>) -> Vec<&'static str> {
    PRIVATE_MEMBERS
        .iter()
        .copied()
        .filter(|m| o.contains_key(*m))
        .collect()
}

impl PublicJwk {
    /// Reads one public JWK of a `jwk` entry.
    pub fn from_json(v: &Value) -> Result<PublicJwk, String> {
        Self::from_json_for(v, "jwk")
    }

    /// Reads one public JWK. `kind` names the entry type in the RSA size message.
    pub fn from_json_for(v: &Value, kind: &str) -> Result<PublicJwk, String> {
        let o = v.as_object().ok_or("not a JSON JWK or JWK Set")?;
        if let Some(m) = private_members(o).first() {
            return Err(format!(
                "the JWK has the private member {m}: give the public JWK only"
            ));
        }
        let key = match member(o, "kty")? {
            "OKP" => {
                let crv = member(o, "crv")?;
                if crv != "Ed25519" {
                    return Err(curve_refused(crv));
                }
                let x = b64u_decode(member(o, "x")?, "the JWK x")?;
                if x.len() != 32 {
                    return Err("an Ed25519 x is 32 bytes".into());
                }
                PublicJwk::Ed25519 { x }
            }
            "EC" => {
                let crv = match member(o, "crv")? {
                    "P-256" => Curve::P256,
                    "P-384" => Curve::P384,
                    c => return Err(curve_refused(c)),
                };
                let x = b64u_decode(member(o, "x")?, "the JWK x")?;
                let y = b64u_decode(member(o, "y")?, "the JWK y")?;
                if x.len() != crv.len() || y.len() != crv.len() {
                    return Err(format!(
                        "a {} coordinate is {} bytes",
                        crv.name(),
                        crv.len()
                    ));
                }
                PublicJwk::Ec { crv, x, y }
            }
            "RSA" => {
                let n = b64u_decode(member(o, "n")?, "the JWK n")?;
                let e = b64u_decode(member(o, "e")?, "the JWK e")?;
                PublicJwk::Rsa {
                    n: der::unsigned(&n).to_vec(),
                    e: der::unsigned(&e).to_vec(),
                }
            }
            "oct" => {
                return Err(
                    "kty oct is a secret key; Keys and Certificates holds public keys only".into(),
                )
            }
            other => return Err(format!("kty {other} is not allowed; use OKP, EC or RSA")),
        };
        key.check_size(kind)?;
        Ok(key)
    }

    /// RSA keys are at least [`RSA_MIN_BITS`]. `kind` names the entry type in the message.
    pub fn check_size(&self, kind: &str) -> Result<(), String> {
        if let PublicJwk::Rsa { n, .. } = self {
            let bits = der::bit_len(n);
            if bits < RSA_MIN_BITS {
                return Err(format!(
                    "RSA key is {bits} bits; {kind} needs at least {RSA_MIN_BITS}"
                ));
            }
        }
        Ok(())
    }

    /// Reads a DER SubjectPublicKeyInfo of a `pem-public-key` entry.
    pub fn from_spki(spki: &[u8]) -> Result<PublicJwk, String> {
        let top = der::expect(der::read_all(spki)?, der::SEQUENCE, "SubjectPublicKeyInfo")?;
        let parts = der::children(top.content)?;
        if parts.len() != 2 {
            return Err("not a SubjectPublicKeyInfo".into());
        }
        let alg = der::children(der::expect(parts[0], der::SEQUENCE, "algorithm")?.content)?;
        let oid = der::oid_text(
            der::expect(
                *alg.first().ok_or("no algorithm OID")?,
                der::OID,
                "algorithm",
            )?
            .content,
        );
        let bits = der::bit_string(parts[1])?;
        let key = match oid.as_str() {
            OID_ED25519 => {
                if bits.len() != 32 {
                    return Err("an Ed25519 public key is 32 bytes".into());
                }
                PublicJwk::Ed25519 { x: bits.to_vec() }
            }
            OID_X25519 => return Err(curve_refused("X25519")),
            OID_ED448 => return Err(curve_refused("Ed448")),
            OID_X448 => return Err(curve_refused("X448")),
            OID_EC => {
                let curve_oid = alg
                    .get(1)
                    .filter(|t| t.tag == der::OID)
                    .map(|t| der::oid_text(t.content))
                    .ok_or("an EC key without a named curve")?;
                let crv = match curve_oid.as_str() {
                    OID_P256 => Curve::P256,
                    OID_P384 => Curve::P384,
                    OID_P521 => return Err(curve_refused("P-521")),
                    OID_SECP256K1 => return Err(curve_refused("secp256k1")),
                    c => return Err(curve_refused(c)),
                };
                Self::ec_from_point(crv, bits)?
            }
            OID_RSA => {
                let seq = der::expect(der::read_all(bits)?, der::SEQUENCE, "RSAPublicKey")?;
                let ne = der::children(seq.content)?;
                if ne.len() != 2 || ne.iter().any(|t| t.tag != der::INTEGER) {
                    return Err("not an RSAPublicKey".into());
                }
                PublicJwk::Rsa {
                    n: der::unsigned(ne[0].content).to_vec(),
                    e: der::unsigned(ne[1].content).to_vec(),
                }
            }
            other => return Err(format!("public key algorithm {other} is not allowed")),
        };
        key.check_size("pem-public-key")?;
        Ok(key)
    }

    /// An uncompressed EC point `04 || x || y`.
    pub fn ec_from_point(crv: Curve, point: &[u8]) -> Result<PublicJwk, String> {
        let l = crv.len();
        if point.len() != 1 + 2 * l || point[0] != 4 {
            return Err(format!(
                "a {} public key is an uncompressed point",
                crv.name()
            ));
        }
        Ok(PublicJwk::Ec {
            crv,
            x: point[1..1 + l].to_vec(),
            y: point[1 + l..].to_vec(),
        })
    }

    /// The public JWK as JSON (members of the thumbprint only).
    pub fn to_json(&self) -> Value {
        match self {
            PublicJwk::Ed25519 { x } => json!({"crv": "Ed25519", "kty": "OKP", "x": b64u(x)}),
            PublicJwk::Ec { crv, x, y } => {
                json!({"crv": crv.name(), "kty": "EC", "x": b64u(x), "y": b64u(y)})
            }
            PublicJwk::Rsa { n, e } => json!({"e": b64u(e), "kty": "RSA", "n": b64u(n)}),
        }
    }

    /// The RFC 7638 thumbprint: base64url of SHA-256 of the required members in lexicographic order,
    /// no whitespace.
    pub fn thumbprint(&self) -> String {
        // The required members are plain ASCII, so RFC 8785 text is the RFC 7638 text.
        let text = crate::env::jcs::canonical(&self.to_json()).expect("plain text members");
        b64u(ring::digest::digest(&ring::digest::SHA256, text.as_bytes()).as_ref())
    }

    /// `Ed25519`, `P-256`, `P-384` or `RSA <bits>`.
    pub fn describe(&self) -> String {
        match self {
            PublicJwk::Ed25519 { .. } => "Ed25519".into(),
            PublicJwk::Ec { crv, .. } => crv.name().into(),
            PublicJwk::Rsa { n, .. } => format!("RSA {}", der::bit_len(n)),
        }
    }

    /// The JWS algorithms that this key can check (RFC 7518, ADR-0061 item 3.2).
    pub fn algs(&self) -> &'static [&'static str] {
        match self {
            PublicJwk::Ed25519 { .. } => &["EdDSA"],
            PublicJwk::Ec {
                crv: Curve::P256, ..
            } => &["ES256"],
            PublicJwk::Ec {
                crv: Curve::P384, ..
            } => &["ES384"],
            PublicJwk::Rsa { .. } => &["PS256", "RS256"],
        }
    }

    /// Checks a JWS signature over `input` with `alg`. The error starts with a stable code of the signing
    /// vectors: `alg_key_mismatch`, `ecdsa_der` or `bad_signature`.
    pub fn verify(&self, alg: &str, input: &[u8], sig: &[u8]) -> Result<(), String> {
        if !self.algs().contains(&alg) {
            return Err(format!(
                "alg_key_mismatch: algorithm {alg} does not fit the key ({})",
                self.describe()
            ));
        }
        let ok = match self {
            PublicJwk::Ed25519 { x } => UnparsedPublicKey::new(&signature::ED25519, x)
                .verify(input, sig)
                .is_ok(),
            PublicJwk::Ec { crv, x, y } => {
                if sig.len() != 2 * crv.len() {
                    return Err(if sig.first() == Some(&der::SEQUENCE) {
                        "ecdsa_der: the ECDSA signature is DER; JWS uses r || s".into()
                    } else {
                        "bad_signature: the ECDSA signature has the wrong length".into()
                    });
                }
                let point = [&[4u8][..], x, y].concat();
                let a: &dyn signature::VerificationAlgorithm = match crv {
                    Curve::P256 => &signature::ECDSA_P256_SHA256_FIXED,
                    Curve::P384 => &signature::ECDSA_P384_SHA384_FIXED,
                };
                UnparsedPublicKey::new(a, &point).verify(input, sig).is_ok()
            }
            PublicJwk::Rsa { n, e } => {
                let params = if alg == "PS256" {
                    &signature::RSA_PSS_2048_8192_SHA256
                } else {
                    &signature::RSA_PKCS1_2048_8192_SHA256
                };
                signature::RsaPublicKeyComponents { n, e }
                    .verify(params, input, sig)
                    .is_ok()
            }
        };
        if ok {
            Ok(())
        } else {
            Err("bad_signature: the signature does not verify".into())
        }
    }
}

/// The DER bytes of the PEM blocks with this label, in order.
pub fn pem_blocks(text: &str, label: &str) -> Result<Vec<Vec<u8>>, String> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find(&begin) {
        let after = &rest[i + begin.len()..];
        let j = after
            .find(&end)
            .ok_or_else(|| format!("a PEM {label} block has no END line"))?;
        let body: String = after[..j]
            .lines()
            .filter(|l| !l.contains(':'))
            .collect::<String>()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        out.push(
            STANDARD
                .decode(body)
                .map_err(|_| format!("a PEM {label} block is not base64"))?,
        );
        rest = &after[j + end.len()..];
    }
    Ok(out)
}

/// The labels of the PEM blocks in a text, in order.
pub fn pem_labels(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find("-----BEGIN ") {
        let after = &rest[i + 11..];
        let Some(j) = after.find("-----") else { break };
        out.push(after[..j].to_string());
        rest = &after[j + 5..];
    }
    out
}

/// PEM text of DER bytes, 64 characters a line.
pub fn pem(label: &str, der: &[u8]) -> String {
    let b = STANDARD.encode(der);
    let mut s = format!("-----BEGIN {label}-----\n");
    for chunk in b.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        s.push('\n');
    }
    s.push_str(&format!("-----END {label}-----\n"));
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7638 section 3.1.
    #[test]
    fn rfc7638_thumbprint() {
        let jwk = json!({
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
            "alg": "RS256",
            "kid": "2011-04-29"
        });
        let k = PublicJwk::from_json(&jwk).unwrap();
        assert_eq!(
            k.thumbprint(),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
        assert_eq!(k.describe(), "RSA 2048");
    }

    /// RFC 8037 appendix A.4: the Ed25519 signature of "Example of Ed25519 signing".
    #[test]
    fn rfc8037_ed25519_verify() {
        let k = PublicJwk::from_json(&json!({
            "kty": "OKP", "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        }))
        .unwrap();
        assert_eq!(
            k.thumbprint(),
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
        let input = b"eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc";
        let sig = b64u_decode(
            "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg",
            "sig",
        )
        .unwrap();
        k.verify("EdDSA", input, &sig).unwrap();
        assert!(k
            .verify("EdDSA", b"other", &sig)
            .unwrap_err()
            .starts_with("bad_signature"));
        assert!(k
            .verify("ES256", input, &sig)
            .unwrap_err()
            .starts_with("alg_key_mismatch"));
    }

    #[test]
    fn refused_jwks() {
        let e = PublicJwk::from_json(&json!({"kty": "oct", "k": "AAAA"})).unwrap_err();
        assert!(e.contains("private member k"), "{e}");
        let e = PublicJwk::from_json(&json!({"kty": "EC", "crv": "P-521", "x": "", "y": ""}))
            .unwrap_err();
        assert_eq!(e, "curve P-521 is not allowed; use Ed25519, P-256 or P-384");
        let small = json!({"kty": "RSA", "n": b64u(&[0xc1; 128]), "e": "AQAB"});
        let e = PublicJwk::from_json(&small).unwrap_err();
        assert_eq!(e, "RSA key is 1024 bits; jwk needs at least 2048");
        let e = PublicJwk::from_json(&json!({"kty": "OKP", "crv": "Ed25519"})).unwrap_err();
        assert_eq!(e, "JWK member x is missing");
    }

    #[test]
    fn pem_round_trip() {
        let text = pem("PUBLIC KEY", &[1, 2, 3, 4]);
        assert_eq!(
            pem_blocks(&text, "PUBLIC KEY").unwrap(),
            vec![vec![1, 2, 3, 4]]
        );
        assert_eq!(pem_labels(&text), vec!["PUBLIC KEY".to_string()]);
        assert!(pem_blocks("x", "PUBLIC KEY").unwrap().is_empty());
    }
}
