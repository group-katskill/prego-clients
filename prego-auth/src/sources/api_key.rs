//! `api-key` source: a Prego API key from `PREGO_API_KEY`.

use crate::secret::Secret;

/// Checks the `prk_` prefix. The STS does the real check.
pub(crate) fn read(value: &str) -> Result<Secret, String> {
    let key = value.trim();
    if !key.starts_with("prk_") || key.len() <= 4 {
        return Err("PREGO_API_KEY must start with `prk_`".into());
    }
    if key.len() > crate::jwt::MAX_TOKEN_BYTES || key.chars().any(char::is_whitespace) {
        return Err("PREGO_API_KEY has a bad format".into());
    }
    Ok(Secret::new(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_prk_keys() {
        assert_eq!(read(" prk_abc\n").unwrap().expose(), "prk_abc");
    }

    #[test]
    fn refuses_other_values_without_echo() {
        let e = read("ghp_secretvalue").unwrap_err();
        assert!(e.contains("prk_"));
        assert!(!e.contains("secretvalue"));
        assert!(read("prk_").is_err());
        assert!(read("prk_a b").is_err());
    }
}
