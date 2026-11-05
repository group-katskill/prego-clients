//! Small JWT helpers. They never check signatures, so never use them for a trust decision.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

/// Maximum token size that the STS accepts.
pub const MAX_TOKEN_BYTES: usize = 8 * 1024;

/// Checks that `token` looks like a compact JWT: three non-empty parts and at most 8 KiB.
pub fn check_shape(token: &str) -> Result<(), String> {
    if token.len() > MAX_TOKEN_BYTES {
        return Err(format!("token is larger than {MAX_TOKEN_BYTES} bytes"));
    }
    let parts: Vec<&str> = token.split('.').collect();
    let base64url = |p: &&str| {
        !p.is_empty()
            && p.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'=')
    };
    if parts.len() != 3 || !parts.iter().all(base64url) {
        return Err("value is not a JWT".into());
    }
    Ok(())
}

/// Reads the claims without a signature check. Use them only to show information or as a cache hint.
pub fn unverified_claims(token: &str) -> Option<serde_json::Map<String, serde_json::Value>> {
    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Reads the `exp` claim without a signature check. Used only as a cache hint.
pub fn unverified_exp(token: &str) -> Option<i64> {
    let claims = unverified_claims(token)?;
    let exp = claims.get("exp")?;
    exp.as_i64().or_else(|| exp.as_f64().map(|f| f as i64))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jwt(payload: &str) -> String {
        format!(
            "{}.{}.sig",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256"}"#),
            URL_SAFE_NO_PAD.encode(payload)
        )
    }

    #[test]
    fn reads_exp() {
        assert_eq!(
            unverified_exp(&jwt(r#"{"exp":1700000900}"#)),
            Some(1700000900)
        );
        assert_eq!(
            unverified_exp(&jwt(r#"{"exp":1700000900.5}"#)),
            Some(1700000900)
        );
        assert_eq!(unverified_exp(&jwt(r#"{"sub":"x"}"#)), None);
        assert_eq!(unverified_exp("not-a-jwt"), None);
        let claims = unverified_claims(&jwt(r#"{"sub":"prn_1","tid":"ten_1"}"#)).unwrap();
        assert_eq!(claims["sub"], "prn_1");
    }

    #[test]
    fn shape() {
        assert!(check_shape(&jwt("{}")).is_ok());
        assert!(check_shape("a.b").is_err());
        assert!(check_shape("a..c").is_err());
        assert!(check_shape("a.b c.d").is_err());
        assert!(check_shape(&"a".repeat(MAX_TOKEN_BYTES + 1)).is_err());
    }
}
