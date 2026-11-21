//! Database references (ADR-0059 item 11): `<tenant>/<database>` (namespace `default`) or
//! `<tenant>/<namespace>/<database>`, with `@<sel>`: `latest` (the default), a number, a tag or
//! `sha256:<hex>`. Names and tags follow the Snippets rules (ADR-0057 items 3 and 8).

use crate::env::jcs;
use crate::env::reference::slug;
use crate::snippet::reference::check_name;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbRef {
    pub tenant: String,
    pub namespace: String,
    pub name: String,
    /// The selector after `@`, if any.
    pub sel: Option<String>,
}

/// A tag: the Snippets tag rules, not `latest`, and not ending in `.db.gz` (the content route).
pub fn check_tag(s: &str) -> Result<(), String> {
    crate::snippet::reference::check_tag(s)?;
    if s == "latest" {
        return Err(format!("bad tag `{s}`: `latest` is kept"));
    }
    if s.ends_with(".db.gz") {
        return Err(format!(
            "bad tag `{s}`: a tag does not end in .db.gz (that is the content route)"
        ));
    }
    Ok(())
}

/// A snapshot selector: `latest`, a number from 1, `sha256:<64 lowercase hex>` or a tag.
pub fn check_selector(s: &str) -> Result<(), String> {
    if s == "latest" || jcs::is_hash(s) {
        return Ok(());
    }
    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
        return match s.parse::<u64>() {
            Ok(n) if n > 0 => Ok(()),
            _ => Err(format!("bad snapshot `{s}`: snapshot numbers start at 1")),
        };
    }
    if s.starts_with("sha256") {
        return Err(format!(
            "bad snapshot `{s}`: a hash is sha256:<64 lowercase hex>"
        ));
    }
    check_tag(s)
        .map_err(|_| format!("bad snapshot `{s}`: use latest, a number, a tag or sha256:<hex>"))
}

impl DbRef {
    pub fn parse(text: &str) -> Result<DbRef, String> {
        let usage = || {
            format!(
                "bad database reference `{text}`: use <tenant>/<database> or <tenant>/<namespace>/<database>, \
                 with @<snapshot> where it is allowed"
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
        check_name(name).map_err(|e| e.replace("snippet name", "database name"))?;
        if let Some(v) = sel {
            check_selector(v)?;
        }
        Ok(DbRef {
            tenant: tenant.into(),
            namespace: namespace.into(),
            name: name.into(),
            sel: sel.map(str::to_string),
        })
    }

    /// `<tenant>/<namespace>/<database>`.
    pub fn long(&self) -> String {
        format!("{}/{}/{}", self.tenant, self.namespace, self.name)
    }

    /// The selector, `latest` by default.
    pub fn selector(&self) -> &str {
        self.sel.as_deref().unwrap_or("latest")
    }

    /// Refuses `@<sel>` where a command does not take one.
    pub fn no_sel(self, command: &str) -> Result<DbRef, String> {
        if self.sel.is_some() {
            return Err(format!(
                "prego sqlite {command} takes <tenant>/[<namespace>/]<database> without @<snapshot>"
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
        let r = DbRef::parse("acme/lookup").unwrap();
        assert_eq!(r.long(), "acme/default/lookup");
        assert_eq!(r.selector(), "latest");
        let h = format!("sha256:{}", "a".repeat(64));
        for (s, sel) in [
            ("acme/fleet/lookup@42", "42"),
            ("acme/fleet/lookup@2026-11-20", "2026-11-20"),
            ("acme/fleet/lookup@latest", "latest"),
        ] {
            assert_eq!(DbRef::parse(s).unwrap().selector(), sel);
        }
        assert_eq!(
            DbRef::parse(&format!("acme/fleet/lookup@{h}"))
                .unwrap()
                .selector(),
            h
        );
        for bad in [
            "acme",
            "acme/a/b/c",
            "acme/fleet/lookup@0",
            "acme/fleet/lookup@sha256:abc",
            "acme/fleet/Lookup",
            "acme/fleet/lookup@x.db.gz",
            "acme/fleet/lookup@",
        ] {
            assert!(DbRef::parse(bad).is_err(), "{bad}");
        }
        assert!(DbRef::parse("acme/x@3").unwrap().no_sel("save").is_err());
        assert!(check_tag("latest").is_err());
        assert!(check_tag("v1.db.gz").is_err());
        assert!(check_tag("2026-11-20").is_ok());
    }
}
