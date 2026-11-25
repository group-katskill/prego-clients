//! Local private key files for signing: PKCS #8 `PRIVATE KEY` PEM (RFC 5208, RFC 5958), as OpenSSL writes
//! them. `prego keys new` makes them with mode 0600. The private key stays on this computer: Prego gets the
//! public JWK and signatures only (ADR-0061 sections 3.3 and 6).

use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, Ed25519KeyPair, KeyPair as _, RsaKeyPair};

use super::der;
use super::jwk::{pem, pem_blocks, Curve, PublicJwk};

/// A loaded private key.
pub struct PrivateKey {
    inner: Inner,
    public: PublicJwk,
}

enum Inner {
    Ed25519(Ed25519KeyPair),
    Ec(EcdsaKeyPair, Curve),
    Rsa(RsaKeyPair),
}

/// The algorithms of `prego keys new`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewAlg {
    Ed25519,
    Es256,
}

impl NewAlg {
    pub fn parse(s: &str) -> Result<NewAlg, String> {
        match s {
            "ed25519" => Ok(NewAlg::Ed25519),
            "es256" => Ok(NewAlg::Es256),
            _ => Err(format!("--alg `{s}`: use ed25519 or es256")),
        }
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material.
        write!(f, "PrivateKey({})", self.public.describe())
    }
}

impl PrivateKey {
    /// Makes a new key pair. Returns the key and its PKCS #8 PEM text.
    pub fn generate(alg: NewAlg) -> Result<(PrivateKey, String), String> {
        let rng = SystemRandom::new();
        let doc = match alg {
            NewAlg::Ed25519 => Ed25519KeyPair::generate_pkcs8(&rng),
            NewAlg::Es256 => {
                EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            }
        }
        .map_err(|_| "the key pair cannot be made (no system random source)".to_string())?;
        // ring writes Ed25519 as PKCS #8 v2 (RFC 5958, with the public key). OpenSSL 3.0 and other tools read
        // only v1, so the file gets the v1 form; the public key is derived again on load.
        let der = match alg {
            NewAlg::Ed25519 => ed25519_v1(doc.as_ref())?,
            NewAlg::Es256 => doc.as_ref().to_vec(),
        };
        let key = PrivateKey::from_pkcs8(&der)?;
        Ok((key, pem("PRIVATE KEY", &der)))
    }

    /// Reads a key file. The error says how to make a usable file.
    pub fn load(path: &str) -> Result<PrivateKey, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
        let text = String::from_utf8_lossy(&bytes);
        if text.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----") {
            return Err(format!(
                "{path}: the key is encrypted. Write a plain copy for this run \
                 (`openssl pkcs8 -in {path} -out <plain file>`) and keep it with mode 0600"
            ));
        }
        for (label, how) in [
            ("EC PRIVATE KEY", "openssl pkcs8 -topk8 -nocrypt -in"),
            ("RSA PRIVATE KEY", "openssl pkcs8 -topk8 -nocrypt -in"),
            ("OPENSSH PRIVATE KEY", "ssh-keygen -p -m PKCS8 -f"),
        ] {
            if text.contains(&format!("-----BEGIN {label}-----")) {
                return Err(format!(
                    "{path}: an {label} file: prego reads PKCS #8 (`-----BEGIN PRIVATE KEY-----`). \
                     Convert it: `{how} {path}`"
                ));
            }
        }
        let blocks = pem_blocks(&text, "PRIVATE KEY").map_err(|e| format!("{path}: {e}"))?;
        let der = match blocks.as_slice() {
            [one] => one.clone(),
            [] if bytes.first() == Some(&der::SEQUENCE) => bytes.clone(),
            [] => {
                return Err(format!(
                "{path}: no `-----BEGIN PRIVATE KEY-----` block. Make a key with `prego keys new`"
            ))
            }
            _ => return Err(format!("{path}: more than one private key block")),
        };
        PrivateKey::from_pkcs8(&der).map_err(|e| format!("{path}: {e}"))
    }

    fn from_pkcs8(der: &[u8]) -> Result<PrivateKey, String> {
        let rng = SystemRandom::new();
        if let Ok(k) = Ed25519KeyPair::from_pkcs8_maybe_unchecked(der) {
            let public = PublicJwk::Ed25519 {
                x: k.public_key().as_ref().to_vec(),
            };
            return Ok(PrivateKey {
                inner: Inner::Ed25519(k),
                public,
            });
        }
        for (alg, crv) in [
            (&signature::ECDSA_P256_SHA256_FIXED_SIGNING, Curve::P256),
            (&signature::ECDSA_P384_SHA384_FIXED_SIGNING, Curve::P384),
        ] {
            if let Ok(k) = EcdsaKeyPair::from_pkcs8(alg, der, &rng) {
                let public = PublicJwk::ec_from_point(crv, k.public_key().as_ref())?;
                return Ok(PrivateKey {
                    inner: Inner::Ec(k, crv),
                    public,
                });
            }
        }
        if let Ok(k) = RsaKeyPair::from_pkcs8(der) {
            // The public key is the DER RSAPublicKey.
            let seq = der::expect(
                der::read_all(k.public_key().as_ref())?,
                der::SEQUENCE,
                "RSAPublicKey",
            )?;
            let ne = der::children(seq.content)?;
            if ne.len() != 2 {
                return Err("not an RSA public key".into());
            }
            let public = PublicJwk::Rsa {
                n: der::unsigned(ne[0].content).to_vec(),
                e: der::unsigned(ne[1].content).to_vec(),
            };
            public.check_size("jwk")?;
            return Ok(PrivateKey {
                inner: Inner::Rsa(k),
                public,
            });
        }
        Err(
            "the key is not an Ed25519, P-256, P-384 or RSA (2048 to 8192 bits) PKCS #8 private key"
                .into(),
        )
    }

    pub fn public(&self) -> &PublicJwk {
        &self.public
    }

    /// The JWS algorithm: EdDSA, ES256, ES384, or PS256 for RSA.
    pub fn alg(&self) -> &'static str {
        match &self.inner {
            Inner::Ed25519(_) => "EdDSA",
            Inner::Ec(_, Curve::P256) => "ES256",
            Inner::Ec(_, Curve::P384) => "ES384",
            Inner::Rsa(_) => "PS256",
        }
    }

    /// A JWS signature over `input` with [`PrivateKey::alg`]. ECDSA signatures are `r || s` (RFC 7518 3.4).
    pub fn sign(&self, input: &[u8]) -> Result<Vec<u8>, String> {
        let rng = SystemRandom::new();
        match &self.inner {
            Inner::Ed25519(k) => Ok(k.sign(input).as_ref().to_vec()),
            Inner::Ec(k, _) => k
                .sign(&rng, input)
                .map(|s| s.as_ref().to_vec())
                .map_err(|_| "the signature cannot be made".into()),
            Inner::Rsa(k) => {
                let mut sig = vec![0u8; k.public().modulus_len()];
                k.sign(&signature::RSA_PSS_SHA256, &rng, input, &mut sig)
                    .map_err(|_| "the signature cannot be made".to_string())?;
                Ok(sig)
            }
        }
    }
}

/// The PKCS #8 v1 form (RFC 5208) of an Ed25519 key: `SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 },
/// OCTET STRING { OCTET STRING <32-byte seed> } }` (RFC 8410 section 7). It takes the seed from the v1 or v2
/// document that ring makes.
fn ed25519_v1(doc: &[u8]) -> Result<Vec<u8>, String> {
    let bad = || "the new Ed25519 key is not in the expected PKCS #8 form".to_string();
    let top = der::expect(der::read_all(doc)?, der::SEQUENCE, "PKCS #8")?;
    let parts = der::children(top.content)?;
    let alg = parts
        .get(1)
        .filter(|t| t.tag == der::SEQUENCE)
        .ok_or_else(bad)?;
    let oid = der::children(alg.content)?
        .first()
        .map(|t| der::oid_text(t.content));
    if oid.as_deref() != Some("1.3.101.112") {
        return Err(bad());
    }
    let outer = parts
        .get(2)
        .filter(|t| t.tag == der::OCTET_STRING)
        .ok_or_else(bad)?;
    let seed = der::expect(der::read_all(outer.content)?, der::OCTET_STRING, "seed")?.content;
    if seed.len() != 32 {
        return Err(bad());
    }
    let mut out = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    out.extend_from_slice(seed);
    Ok(out)
}

/// Writes a new private key file with mode 0600. An existing file is never replaced.
pub fn write_new(path: &std::path::Path, pem_text: &str) -> Result<(), String> {
    use std::io::Write as _;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        o.mode(0o600);
    }
    let mut f = o.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            format!(
                "{}: the file exists; prego never replaces a key file. Give another --out",
                path.display()
            )
        } else {
            format!("{}: {e}", path.display())
        }
    })?;
    f.write_all(pem_text.as_bytes())
        .and_then(|_| f.sync_all())
        .map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_ed25519_keys_are_pkcs8_v1_and_v2_still_loads() {
        let (k, text) = PrivateKey::generate(NewAlg::Ed25519).unwrap();
        let der = pem_blocks(&text, "PRIVATE KEY").unwrap().remove(0);
        // SEQUENCE, length 46, version INTEGER 0: v1, no public key field.
        assert_eq!(&der[..5], &[0x30, 0x2e, 0x02, 0x01, 0x00]);
        assert_eq!(der.len(), 48);
        // A v2 document (as ring and newer tools write it) still loads, to the same key.
        let rng = SystemRandom::new();
        let v2 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        assert_eq!(v2.as_ref()[4], 0x01, "ring writes v2");
        let from_v2 = PrivateKey::from_pkcs8(v2.as_ref()).unwrap();
        let from_v1 = PrivateKey::from_pkcs8(&ed25519_v1(v2.as_ref()).unwrap()).unwrap();
        assert_eq!(from_v1.public(), from_v2.public());
        let sig = k.sign(b"x").unwrap();
        k.public().verify("EdDSA", b"x", &sig).unwrap();
    }

    /// When an `openssl` binary is on the PATH (it is on CI), it must read the files that `prego keys new`
    /// writes, and give the same public key.
    #[test]
    fn openssl_reads_new_key_files() {
        let Ok(v) = std::process::Command::new("openssl")
            .arg("version")
            .output()
        else {
            eprintln!("no openssl on the PATH: skipped");
            return;
        };
        eprintln!("{}", String::from_utf8_lossy(&v.stdout).trim());
        let dir = prego_auth::testing::TempDir::new("prego-openssl");
        for alg in [NewAlg::Ed25519, NewAlg::Es256] {
            let (k, text) = PrivateKey::generate(alg).unwrap();
            let path = dir.join(format!("{alg:?}.pem"));
            write_new(&path, &text).unwrap();
            let out = std::process::Command::new("openssl")
                .args(["pkey", "-pubout", "-outform", "DER", "-in"])
                .arg(&path)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{alg:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert_eq!(
                &PublicJwk::from_spki(&out.stdout).unwrap(),
                k.public(),
                "{alg:?}"
            );
        }
    }

    #[test]
    fn generate_sign_verify_and_reload() {
        let dir = prego_auth::testing::TempDir::new("prego-keyfile");
        for alg in [NewAlg::Ed25519, NewAlg::Es256] {
            let (k, text) = PrivateKey::generate(alg).unwrap();
            assert!(text.starts_with("-----BEGIN PRIVATE KEY-----\n"));
            let sig = k.sign(b"input").unwrap();
            k.public().verify(k.alg(), b"input", &sig).unwrap();
            let path = dir.join(format!("{alg:?}.pem"));
            write_new(&path, &text).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let mode = std::fs::metadata(&path).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o600);
            }
            let e = write_new(&path, &text).unwrap_err();
            assert!(e.contains("never replaces"), "{e}");
            let again = PrivateKey::load(path.to_str().unwrap()).unwrap();
            assert_eq!(again.public(), k.public());
            assert!(!format!("{again:?}").contains("PRIVATE"));
        }
        assert_eq!(
            PrivateKey::generate(NewAlg::Es256).unwrap().0.alg(),
            "ES256"
        );
        let p = dir.join("ec.pem");
        std::fs::write(
            &p,
            "-----BEGIN EC PRIVATE KEY-----\nAA==\n-----END EC PRIVATE KEY-----\n",
        )
        .unwrap();
        let e = PrivateKey::load(p.to_str().unwrap()).unwrap_err();
        assert!(e.contains("openssl pkcs8 -topk8"), "{e}");
    }
}
