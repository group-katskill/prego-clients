//! Environment lookup. Tests use [`MapEnv`] instead of the process environment.

use std::collections::HashMap;

/// Reads environment variables. An empty or blank value counts as not set.
pub trait Env: Send + Sync {
    /// Returns the value of `name`, or `None` if it is not set or blank.
    fn var(&self, name: &str) -> Option<String>;
}

/// The process environment.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProcessEnv;

impl Env for ProcessEnv {
    fn var(&self, name: &str) -> Option<String> {
        std::env::var(name).ok().filter(|v| !v.trim().is_empty())
    }
}

/// A fixed set of variables, for tests.
#[derive(Debug, Default, Clone)]
pub struct MapEnv(HashMap<String, String>);

impl MapEnv {
    /// Makes an empty environment.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one variable.
    pub fn with(mut self, name: &str, value: &str) -> Self {
        self.0.insert(name.to_string(), value.to_string());
        self
    }
}

impl Env for MapEnv {
    fn var(&self, name: &str) -> Option<String> {
        self.0.get(name).filter(|v| !v.trim().is_empty()).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blank_is_unset() {
        let env = MapEnv::new().with("A", "  ").with("B", "x");
        assert_eq!(env.var("A"), None);
        assert_eq!(env.var("B").as_deref(), Some("x"));
        assert_eq!(env.var("C"), None);
    }
}
