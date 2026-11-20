//! Snippet references (ADR-0057 item 3): `<tenant>/<snippet>` (namespace `default`) or
//! `<tenant>/<namespace>/<snippet>`, with `@<version>`: a number, a tag, `sha256:<hex>` or `current`.

use crate::env::jcs;
use crate::env::reference::slug;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnipRef {
    pub tenant: String,
    pub namespace: String,
    pub name: String,
    /// The version selector after `@`, if any.
    pub version: Option<String>,
}

/// `[a-z0-9][a-z0-9._-]{0,127}`.
pub fn check_name(s: &str) -> Result<(), String> {
    let ok = !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && s.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        });
    if ok {
        Ok(())
    } else {
        Err(format!(
            "bad snippet name `{s}`: 1 to 128 characters from a-z, 0-9, `.`, `_` and `-`, starting with a \
             letter or a digit"
        ))
    }
}

/// `[A-Za-z0-9][A-Za-z0-9._+-]{0,127}`, not all digits, not `current`, not starting with `sha256`.
pub fn check_tag(s: &str) -> Result<(), String> {
    let chars_ok = !s.is_empty()
        && s.len() <= 128
        && s.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'));
    if !chars_ok {
        return Err(format!(
            "bad tag `{s}`: 1 to 128 characters from A-Z, a-z, 0-9, `.`, `_`, `+` and `-`, starting with a \
             letter or a digit"
        ));
    }
    if s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!(
            "bad tag `{s}`: a tag is not all digits (that is a version number)"
        ));
    }
    if s == "current" || s.starts_with("sha256") {
        return Err(format!(
            "bad tag `{s}`: `current` and names that start with `sha256` are kept"
        ));
    }
    if s.ends_with(".tar.gz") {
        return Err(format!(
            "bad tag `{s}`: a tag does not end in .tar.gz (that is the tarball route)"
        ));
    }
    Ok(())
}

/// A version selector: a number from 1, `current`, `sha256:<64 lowercase hex>` or a tag.
pub fn check_selector(s: &str) -> Result<(), String> {
    if s == "current" || jcs::is_hash(s) {
        return Ok(());
    }
    if s.bytes().all(|b| b.is_ascii_digit()) && !s.is_empty() {
        return match s.parse::<u64>() {
            Ok(n) if n > 0 => Ok(()),
            _ => Err(format!("bad version `{s}`: version numbers start at 1")),
        };
    }
    if s.starts_with("sha256") {
        return Err(format!(
            "bad version `{s}`: a hash is sha256:<64 lowercase hex>"
        ));
    }
    check_tag(s)
        .map_err(|_| format!("bad version `{s}`: use a number, a tag, sha256:<hex> or current"))
}

/// The JSON form of a selector in a request body: a number stays a number.
pub fn selector_json(s: &str) -> serde_json::Value {
    match s.parse::<u64>() {
        Ok(n) => serde_json::json!(n),
        Err(_) => serde_json::json!(s),
    }
}

impl SnipRef {
    pub fn parse(text: &str) -> Result<SnipRef, String> {
        let usage = || {
            format!(
                "bad snippet reference `{text}`: use <tenant>/<snippet> or <tenant>/<namespace>/<snippet>, \
                 with @<version> where it is allowed"
            )
        };
        let (path, version) = match text.split_once('@') {
            Some((p, v)) => (p, Some(v)),
            None => (text, None),
        };
        let parts: Vec<&str> = path.split('/').collect();
        let (tenant, namespace, name) = match parts.as_slice() {
            [t, n] => (*t, "default", *n),
            [t, ns, n] => (*t, *ns, *n),
            _ => return Err(usage()),
        };
        slug("tenant", tenant)?;
        slug("namespace", namespace)?;
        check_name(name)?;
        if let Some(v) = version {
            check_selector(v)?;
        }
        Ok(SnipRef {
            tenant: tenant.into(),
            namespace: namespace.into(),
            name: name.into(),
            version: version.map(str::to_string),
        })
    }

    /// `<tenant>/<namespace>/<snippet>`.
    pub fn long(&self) -> String {
        format!("{}/{}/{}", self.tenant, self.namespace, self.name)
    }

    /// The selector, `current` by default.
    pub fn selector(&self) -> &str {
        self.version.as_deref().unwrap_or("current")
    }

    /// Refuses `@<version>` where a command does not take one.
    pub fn no_version(self, command: &str) -> Result<SnipRef, String> {
        if self.version.is_some() {
            return Err(format!(
                "prego snippet {command} takes <tenant>/[<namespace>/]<snippet> without @<version>"
            ));
        }
        Ok(self)
    }
}

/// The scope of `prego snippet ls`: `<tenant>` (namespace `default`) or `<tenant>/<namespace>`.
pub fn parse_scope(text: &str) -> Result<(String, String), String> {
    let (tenant, namespace) = match text.split_once('/') {
        Some((t, ns)) => (t, ns),
        None => (text, "default"),
    };
    slug("tenant", tenant)?;
    slug("namespace", namespace)?;
    Ok((tenant.into(), namespace.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references() {
        let r = SnipRef::parse("acme/deploy-script").unwrap();
        assert_eq!(r.long(), "acme/default/deploy-script");
        assert_eq!(r.selector(), "current");
        let h = format!("sha256:{}", "0".repeat(64));
        let r = SnipRef::parse(&format!("acme/tools/agent.skill@{h}")).unwrap();
        assert_eq!(r.namespace, "tools");
        assert_eq!(r.version.as_deref(), Some(h.as_str()));
        assert_eq!(SnipRef::parse("a/b@7").unwrap().selector(), "7");
        assert_eq!(SnipRef::parse("a/b@v1.2+x").unwrap().selector(), "v1.2+x");
        assert!(SnipRef::parse("a/b@v1.tar.gz").is_err());
        assert!(check_tag("v1.tar").is_ok() && check_tag("v1.gz").is_ok());
        for bad in [
            "acme",
            "acme/",
            "a/b/c/d",
            "a/B",
            "a/.x",
            "a/b@",
            "a/b@0",
            "a/b@sha256:abc",
            "a/b@a b",
            "A/b",
        ] {
            assert!(SnipRef::parse(bad).is_err(), "{bad}");
        }
        assert!(SnipRef::parse("a/b@1").unwrap().no_version("log").is_err());
    }

    #[test]
    fn tags() {
        for ok in ["v1", "prod", "1.2.3", "R2-d2_x+y", "1a"] {
            assert!(check_tag(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "123",
            "current",
            "sha256",
            "sha256x",
            "-a",
            "a/b",
            "v1.tar.gz",
            "x.tar.gz",
            &"a".repeat(129),
        ] {
            assert!(check_tag(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn scopes_and_selector_json() {
        assert_eq!(
            parse_scope("acme").unwrap(),
            ("acme".into(), "default".into())
        );
        assert_eq!(
            parse_scope("acme/tools").unwrap(),
            ("acme".into(), "tools".into())
        );
        assert!(parse_scope("acme/tools/x").is_err());
        assert_eq!(selector_json("3"), serde_json::json!(3));
        assert_eq!(selector_json("prod"), serde_json::json!("prod"));
    }
}
