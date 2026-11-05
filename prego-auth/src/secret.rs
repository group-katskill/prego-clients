use std::fmt;

/// A token value. `Debug` does not show the value, and there is no `Display`.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// Wraps a token value.
    pub fn new(value: impl Into<String>) -> Self {
        Secret(value.into())
    }

    /// Returns the token value. Use it only to send the token, never to print it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_hides_value() {
        let s = Secret::new("prk_very_secret");
        assert_eq!(format!("{s:?}"), "Secret(<redacted>)");
        assert_eq!(s.expose(), "prk_very_secret");
    }
}
