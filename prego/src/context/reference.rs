//! Context references (ADR-0058 item 8): `<tenant>/<context>` (namespace `default`) or
//! `<tenant>/<namespace>/<context>`, with `@<sel>`: `latest` (the default), a number, a tag or
//! `sha256:<hex>`. Names and tags follow the Snippets rules (ADR-0057 items 3 and 8).

use crate::env::jcs;
use crate::env::reference::slug;
use crate::snippet::reference::check_name;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CtxRef {
    pub tenant: String,
    pub namespace: String,
    pub name: String,
    /// The selector after `@`, if any.
    pub sel: Option<String>,
}

/// A tag: the Snippets tag rules, and not `latest`.
pub fn check_tag(s: &str) -> Result<(), String> {
    crate::snippet::reference::check_tag(s)?;
    if s == "latest" {
        return Err(format!("bad tag `{s}`: `latest` is kept"));
    }
    Ok(())
}

/// A checkpoint selector: `latest`, a number from 1, `sha256:<64 lowercase hex>` or a tag.
pub fn check_selector(s: &str) -> Result<(), String> {
    if s == "latest" || jcs::is_hash(s) {
        return Ok(());
    }
    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
        return match s.parse::<u64>() {
            Ok(n) if n > 0 => Ok(()),
            _ => Err(format!(
                "bad checkpoint `{s}`: checkpoint numbers start at 1"
            )),
        };
    }
    if s.starts_with("sha256") {
        return Err(format!(
            "bad checkpoint `{s}`: a hash is sha256:<64 lowercase hex>"
        ));
    }
    check_tag(s)
        .map_err(|_| format!("bad checkpoint `{s}`: use latest, a number, a tag or sha256:<hex>"))
}

/// A session: 1 to 128 characters, no control characters and no `/`.
pub fn check_session(s: &str) -> Result<(), String> {
    let n = s.chars().count();
    if n == 0 || n > 128 || s.chars().any(|c| c.is_control() || c == '/') || s.trim() != s {
        return Err(format!(
            "bad session `{}`: 1 to 128 characters, with no `/`, no control characters and no space at \
             the start or the end",
            s.escape_debug()
        ));
    }
    Ok(())
}

impl CtxRef {
    pub fn parse(text: &str) -> Result<CtxRef, String> {
        let usage = || {
            format!(
                "bad context reference `{text}`: use <tenant>/<context> or <tenant>/<namespace>/<context>, \
                 with @<checkpoint> where it is allowed"
            )
        };
        let (path, sel) = match text.split_once('@') {
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
        check_name(name).map_err(|e| e.replace("snippet name", "context name"))?;
        if let Some(v) = sel {
            check_selector(v)?;
        }
        Ok(CtxRef {
            tenant: tenant.into(),
            namespace: namespace.into(),
            name: name.into(),
            sel: sel.map(str::to_string),
        })
    }

    /// `<tenant>/<namespace>/<context>`.
    pub fn long(&self) -> String {
        format!("{}/{}/{}", self.tenant, self.namespace, self.name)
    }

    /// The selector, `latest` by default.
    pub fn selector(&self) -> &str {
        self.sel.as_deref().unwrap_or("latest")
    }

    /// Refuses `@<sel>` where a command does not take one.
    pub fn no_sel(self, command: &str) -> Result<CtxRef, String> {
        if self.sel.is_some() {
            return Err(format!(
                "prego context {command} takes <tenant>/[<namespace>/]<context> without @<checkpoint>"
            ));
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references() {
        let r = CtxRef::parse("acme/billing-agent").unwrap();
        assert_eq!(r.long(), "acme/default/billing-agent");
        assert_eq!(r.selector(), "latest");
        let r = CtxRef::parse("acme/agents/billing-agent@42").unwrap();
        assert_eq!((r.namespace.as_str(), r.selector()), ("agents", "42"));
        let h = format!("sha256:{}", "a".repeat(64));
        assert_eq!(
            CtxRef::parse(&format!("a/b@{h}")).unwrap().selector(),
            h.as_str()
        );
        assert_eq!(
            CtxRef::parse("a/b@handoff-to-review").unwrap().selector(),
            "handoff-to-review"
        );
        for bad in [
            "acme",
            "a/b/c/d",
            "a/B",
            "a/b@",
            "a/b@0",
            "a/b@current",
            "a/b@sha256:ab",
            "a/b@x.tar.gz",
        ] {
            assert!(CtxRef::parse(bad).is_err(), "{bad}");
        }
        let e = CtxRef::parse("a/Bad").unwrap_err();
        assert!(e.contains("context name"), "{e}");
        assert!(CtxRef::parse("a/b@1").unwrap().no_sel("log").is_err());
    }

    #[test]
    fn tags_and_sessions() {
        assert!(check_tag("handoff-to-review").is_ok());
        for bad in ["latest", "current", "12", "sha256x", "a.tar.gz"] {
            assert!(check_tag(bad).is_err(), "{bad}");
        }
        for ok in ["2026-11-20-a", "run 7", "ses_01HZ", &"s".repeat(128)] {
            assert!(check_session(ok).is_ok(), "{ok}");
        }
        for bad in ["", "a/b", "a\nb", " a", &"s".repeat(129)] {
            assert!(check_session(bad).is_err(), "{bad}");
        }
    }
}
