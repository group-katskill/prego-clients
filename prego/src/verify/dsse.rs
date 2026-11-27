//! DSSE envelopes (https://github.com/secure-systems-lab/dsse, protocol v1) and their check with the Prego
//! attestation keys (ADR-0065 section 5).

use base64::Engine as _;
use serde_json::Value;

use crate::sign::jwk::PublicJwk;

/// The payload type of an in-toto Statement in DSSE.
pub const IN_TOTO_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// The largest envelope that Prego stores (ADR-0065 section 6).
pub const MAX_ENVELOPE: usize = 8 * 1024;

#[derive(Debug, Clone)]
pub struct Signature {
    pub keyid: Option<String>,
    pub sig: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Envelope {
    pub payload_type: String,
    pub payload: Vec<u8>,
    pub signatures: Vec<Signature>,
}

/// DSSE accepts standard and URL-safe base64, with or without padding.
fn b64_any(s: &str, what: &str) -> Result<Vec<u8>, String> {
    let t = s.trim_end_matches('=');
    let cfg = base64::engine::GeneralPurposeConfig::new()
        .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent);
    let std = base64::engine::GeneralPurpose::new(&base64::alphabet::STANDARD, cfg);
    let url = base64::engine::GeneralPurpose::new(&base64::alphabet::URL_SAFE, cfg);
    std.decode(t)
        .or_else(|_| url.decode(t))
        .map_err(|_| format!("bad_envelope: {what} is not base64"))
}

impl Envelope {
    /// Parses the JSON envelope. Error codes: `bad_envelope`, `too_large`.
    pub fn parse(bytes: &[u8]) -> Result<Envelope, String> {
        if bytes.len() > MAX_ENVELOPE {
            return Err(format!(
                "too_large: the envelope has {} bytes; Prego stores at most {MAX_ENVELOPE}",
                bytes.len()
            ));
        }
        let v: Value = serde_json::from_slice(bytes)
            .map_err(|e| format!("bad_envelope: the envelope is not JSON: {e}"))?;
        let payload_type = v["payloadType"]
            .as_str()
            .ok_or("bad_envelope: no payloadType")?
            .to_string();
        let payload = b64_any(
            v["payload"].as_str().ok_or("bad_envelope: no payload")?,
            "payload",
        )?;
        let sigs = v["signatures"]
            .as_array()
            .filter(|a| !a.is_empty())
            .ok_or("bad_envelope: no signatures")?;
        let mut signatures = Vec::new();
        for s in sigs {
            signatures.push(Signature {
                keyid: s["keyid"]
                    .as_str()
                    .filter(|k| !k.is_empty())
                    .map(str::to_string),
                sig: b64_any(
                    s["sig"]
                        .as_str()
                        .ok_or("bad_envelope: a signature has no sig")?,
                    "sig",
                )?,
            });
        }
        Ok(Envelope {
            payload_type,
            payload,
            signatures,
        })
    }

    /// The pre-authentication encoding (DSSE v1): `DSSEv1 SP len(type) SP type SP len(body) SP body`.
    pub fn pae(&self) -> Vec<u8> {
        pae(&self.payload_type, &self.payload)
    }

    /// Checks that at least one signature verifies with a key of `keys`, and returns the `kid` of that key.
    /// A signature with a `keyid` is checked only with the key of that `kid`. ES256 signatures may be DER or
    /// the fixed 64-byte form (the wire contract uses DER). Error codes: `wrong_payload_type`, `unknown_key`, `bad_signature`.
    pub fn verify(&self, keys: &[(String, PublicJwk)]) -> Result<String, String> {
        if self.payload_type != IN_TOTO_PAYLOAD_TYPE {
            return Err(format!(
                "wrong_payload_type: the payload type is `{}`, not `{IN_TOTO_PAYLOAD_TYPE}`",
                self.payload_type
            ));
        }
        let input = self.pae();
        let mut unknown = Vec::new();
        for s in &self.signatures {
            let candidates: Vec<&(String, PublicJwk)> = match &s.keyid {
                Some(k) => keys.iter().filter(|(kid, _)| kid == k).collect(),
                None => keys.iter().collect(),
            };
            if candidates.is_empty() {
                unknown.push(s.keyid.clone().unwrap_or_default());
                continue;
            }
            for (kid, key) in candidates {
                let Some(alg) = key.algs().first() else {
                    continue;
                };
                let fixed = match key {
                    PublicJwk::Ec { crv, .. } => match ecdsa_der_to_fixed(&s.sig, crv.len()) {
                        Some(f) => f,
                        None => s.sig.clone(),
                    },
                    _ => s.sig.clone(),
                };
                if key.verify(alg, &input, &fixed).is_ok() {
                    return Ok(kid.clone());
                }
            }
        }
        if !unknown.is_empty() && unknown.len() == self.signatures.len() {
            return Err(format!(
                "unknown_key: no Prego attestation key has the key ID {}",
                unknown.join(", ")
            ));
        }
        Err("bad_signature: the attestation signature does not verify with the Prego attestation keys".into())
    }
}

pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    )
    .into_bytes();
    out.extend_from_slice(payload);
    out
}

/// A DER `ECDSA-Sig-Value` (SEQUENCE of two INTEGERs) as the fixed `r || s` form of `n` bytes each. `None` when
/// `sig` is not DER.
pub fn ecdsa_der_to_fixed(sig: &[u8], n: usize) -> Option<Vec<u8>> {
    use crate::sign::der;
    let top = der::read_all(sig).ok()?;
    if top.tag != der::SEQUENCE {
        return None;
    }
    let parts = der::children(top.content).ok()?;
    if parts.len() != 2 || parts.iter().any(|p| p.tag != der::INTEGER) {
        return None;
    }
    let mut out = Vec::with_capacity(2 * n);
    for p in parts {
        let v = der::unsigned(p.content);
        if v.len() > n {
            return None;
        }
        out.extend(std::iter::repeat_n(0u8, n - v.len()));
        out.extend_from_slice(v);
    }
    Some(out)
}

/// The keys of a JWKS (`{"keys": [...]}`) by `kid`. A key with no `kid` gets its RFC 7638 thumbprint. Keys
/// that are not signing keys Prego knows are skipped. Error code: `bad_keys`.
pub fn parse_jwks(bytes: &[u8]) -> Result<Vec<(String, PublicJwk)>, String> {
    let v: Value = serde_json::from_slice(bytes)
        .map_err(|e| format!("bad_keys: the attestation key set is not JSON: {e}"))?;
    let arr = v["keys"]
        .as_array()
        .ok_or("bad_keys: the attestation key set has no `keys` list")?;
    let mut out = Vec::new();
    for k in arr {
        if k["use"].as_str().is_some_and(|u| u != "sig") {
            continue;
        }
        let Ok(jwk) = PublicJwk::from_json(k) else {
            continue;
        };
        let kid = k["kid"]
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| jwk.thumbprint());
        out.push((kid, jwk));
    }
    if out.is_empty() {
        return Err("bad_keys: the attestation key set has no usable key".into());
    }
    Ok(out)
}

/// For tests: an envelope as JSON with standard base64.
#[cfg(test)]
pub fn envelope_json(payload_type: &str, payload: &[u8], sigs: &[(Option<&str>, &[u8])]) -> String {
    serde_json::json!({
        "payloadType": payload_type,
        "payload": base64::engine::general_purpose::STANDARD.encode(payload),
        "signatures": sigs.iter().map(|(k, s)| {
            let mut o = serde_json::json!({ "sig": base64::engine::general_purpose::URL_SAFE.encode(s) });
            if let Some(k) = k { o["keyid"] = (*k).into(); }
            o
        }).collect::<Vec<_>>(),
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{
        EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED_SIGNING,
    };

    fn key(fixed: bool) -> (EcdsaKeyPair, PublicJwk) {
        let rng = SystemRandom::new();
        let alg = if fixed {
            &ECDSA_P256_SHA256_FIXED_SIGNING
        } else {
            &ECDSA_P256_SHA256_ASN1_SIGNING
        };
        let doc = EcdsaKeyPair::generate_pkcs8(alg, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(alg, doc.as_ref(), &rng).unwrap();
        let jwk = PublicJwk::ec_from_point(crate::sign::jwk::Curve::P256, kp.public_key().as_ref())
            .unwrap();
        (kp, jwk)
    }

    #[test]
    fn pae_matches_the_dsse_spec_example() {
        // From the DSSE protocol document.
        assert_eq!(
            pae("http://example.com/HelloWorld", b"hello world"),
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
        );
    }

    #[test]
    fn der_and_fixed_signatures_verify_and_tampering_fails() {
        let rng = SystemRandom::new();
        let payload = br#"{"_type":"https://in-toto.io/Statement/v1"}"#;
        for fixed in [false, true] {
            let (kp, jwk) = key(fixed);
            let kid = jwk.thumbprint();
            let sig = kp.sign(&rng, &pae(IN_TOTO_PAYLOAD_TYPE, payload)).unwrap();
            let keys = vec![(kid.clone(), jwk)];
            let env = Envelope::parse(
                envelope_json(IN_TOTO_PAYLOAD_TYPE, payload, &[(Some(&kid), sig.as_ref())])
                    .as_bytes(),
            )
            .unwrap();
            assert_eq!(env.verify(&keys).unwrap(), kid);
            // No keyid: every key is tried.
            let env = Envelope::parse(
                envelope_json(IN_TOTO_PAYLOAD_TYPE, payload, &[(None, sig.as_ref())]).as_bytes(),
            )
            .unwrap();
            assert_eq!(env.verify(&keys).unwrap(), kid);
            // A changed payload.
            let env = Envelope::parse(
                envelope_json(IN_TOTO_PAYLOAD_TYPE, b"{}", &[(Some(&kid), sig.as_ref())])
                    .as_bytes(),
            )
            .unwrap();
            assert!(env.verify(&keys).unwrap_err().starts_with("bad_signature"));
            // A changed payload type is refused before the check.
            let env = Envelope::parse(
                envelope_json("application/json", payload, &[(Some(&kid), sig.as_ref())])
                    .as_bytes(),
            )
            .unwrap();
            assert!(env
                .verify(&keys)
                .unwrap_err()
                .starts_with("wrong_payload_type"));
            // An unknown key ID.
            let env = Envelope::parse(
                envelope_json(
                    IN_TOTO_PAYLOAD_TYPE,
                    payload,
                    &[(Some("other"), sig.as_ref())],
                )
                .as_bytes(),
            )
            .unwrap();
            assert!(env.verify(&keys).unwrap_err().starts_with("unknown_key"));
        }
    }

    #[test]
    fn another_key_does_not_verify() {
        let rng = SystemRandom::new();
        let (kp, _) = key(false);
        let (_, other) = key(false);
        let sig = kp.sign(&rng, &pae(IN_TOTO_PAYLOAD_TYPE, b"x")).unwrap();
        let env = Envelope::parse(
            envelope_json(IN_TOTO_PAYLOAD_TYPE, b"x", &[(None, sig.as_ref())]).as_bytes(),
        )
        .unwrap();
        assert!(env
            .verify(&[("k".into(), other)])
            .unwrap_err()
            .starts_with("bad_signature"));
    }

    #[test]
    fn bad_envelopes() {
        assert!(Envelope::parse(b"[]")
            .unwrap_err()
            .starts_with("bad_envelope"));
        assert!(Envelope::parse(
            br#"{"payloadType":"t","payload":"!!","signatures":[{"sig":"AA"}]}"#
        )
        .unwrap_err()
        .starts_with("bad_envelope"));
        assert!(
            Envelope::parse(br#"{"payloadType":"t","payload":"AA","signatures":[]}"#)
                .unwrap_err()
                .starts_with("bad_envelope")
        );
        assert!(Envelope::parse(&vec![b' '; MAX_ENVELOPE + 1])
            .unwrap_err()
            .starts_with("too_large"));
    }

    #[test]
    fn jwks_by_kid_and_thumbprint() {
        let (_, a) = key(false);
        let (_, b) = key(false);
        let mut ja = a.to_json();
        ja["kid"] = "k1".into();
        ja["use"] = "sig".into();
        let jb = b.to_json();
        let mut enc = a.to_json();
        enc["use"] = "enc".into();
        let set = serde_json::json!({ "keys": [ja, jb, enc, {"kty": "oct", "k": "AA"}] });
        let keys = parse_jwks(set.to_string().as_bytes()).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].0, "k1");
        assert_eq!(keys[1].0, b.thumbprint());
        assert!(parse_jwks(br#"{"keys":[]}"#)
            .unwrap_err()
            .starts_with("bad_keys"));
    }
}
