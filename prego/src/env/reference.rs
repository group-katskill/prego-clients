//! Release Variable references: `<tenant>/<package>@<version>` (namespace `default`),
//! `<tenant>/<namespace>/<package...>@<version>`, and with `--level`, `<tenant>` or `<tenant>/<namespace>`.

/// The level of a set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Tenant,
    Namespace,
    Version,
}

impl Level {
    pub fn parse(s: &str) -> Result<Level, String> {
        match s {
            "tenant" => Ok(Level::Tenant),
            "namespace" => Ok(Level::Namespace),
            "version" => Ok(Level::Version),
            _ => Err(format!("--level `{s}` is not tenant, namespace or version")),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Level::Tenant => "tenant",
            Level::Namespace => "namespace",
            Level::Version => "version",
        }
    }
}

/// A parsed reference. `namespace` is set for the namespace and version levels, `package` and `version`
/// for the version level only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ref {
    pub level: Level,
    pub tenant: String,
    pub namespace: Option<String>,
    pub package: Option<String>,
    pub version: Option<String>,
}

fn slug(what: &str, s: &str) -> Result<(), String> {
    let ok = !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
    if ok {
        Ok(())
    } else {
        Err(format!(
            "bad {what} `{s}`: use lowercase letters, digits, `-` and `_`"
        ))
    }
}

/// A package name: 1 to 214 characters from `[a-z0-9._~@/-]`, starting with a letter, a digit, `@` or `_`,
/// no empty segment (`//` or a `/` at the end).
fn package_ok(s: &str) -> bool {
    s.len() <= 214
        && s.bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'@' || b == b'_')
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._~@/-".contains(&b))
        && s.split('/').all(|seg| !seg.is_empty())
}

/// The version string: 1 to 128 characters from `[A-Za-z0-9._+-]`, compared exactly (no `v` folding).
fn version_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
}

impl Ref {
    /// Parses `text` for the given level.
    pub fn parse(text: &str, level: Level) -> Result<Ref, String> {
        let usage = || match level {
            Level::Version => format!(
                "bad reference `{text}`: use <tenant>/<package>@<version> or \
                 <tenant>/<namespace>/<package>@<version>"
            ),
            Level::Namespace => {
                format!("bad reference `{text}`: with --level namespace, use <tenant>/<namespace>")
            }
            Level::Tenant => format!("bad reference `{text}`: with --level tenant, use <tenant>"),
        };
        match level {
            Level::Tenant => {
                if text.contains(['/', '@']) {
                    return Err(usage());
                }
                slug("tenant", text)?;
                Ok(Ref {
                    level,
                    tenant: text.into(),
                    namespace: None,
                    package: None,
                    version: None,
                })
            }
            Level::Namespace => {
                let (t, ns) = text.split_once('/').ok_or_else(usage)?;
                if ns.contains(['/', '@']) {
                    return Err(usage());
                }
                slug("tenant", t)?;
                slug("namespace", ns)?;
                Ok(Ref {
                    level,
                    tenant: t.into(),
                    namespace: Some(ns.into()),
                    package: None,
                    version: None,
                })
            }
            Level::Version => {
                let (path, version) = text.rsplit_once('@').ok_or_else(usage)?;
                if !version_ok(version) {
                    return Err(format!(
                        "bad version `{version}`: 1 to 128 characters from A-Z a-z 0-9 . _ + -"
                    ));
                }
                let segs: Vec<&str> = path.split('/').collect();
                let (t, ns, pkg) = match segs.as_slice() {
                    [t, p] => (*t, "default", vec![*p]),
                    [t, ns, rest @ ..] if !rest.is_empty() => (*t, *ns, rest.to_vec()),
                    _ => return Err(usage()),
                };
                slug("tenant", t)?;
                slug("namespace", ns)?;
                let package = pkg.join("/");
                if !package_ok(&package) {
                    return Err(format!(
                        "bad package name `{package}` in `{text}`: names are lowercase \
                         (letters, digits, `.`, `_`, `~`, `@`, `-`, `/`), at most 214 characters"
                    ));
                }
                Ok(Ref {
                    level,
                    tenant: t.into(),
                    namespace: Some(ns.into()),
                    package: Some(package),
                    version: Some(version.into()),
                })
            }
        }
    }

    /// The long form: `tenant`, `tenant/namespace` or `tenant/namespace/package@version`.
    pub fn long(&self) -> String {
        match (&self.namespace, &self.package, &self.version) {
            (Some(ns), Some(p), Some(v)) => format!("{}/{ns}/{p}@{v}", self.tenant),
            (Some(ns), _, _) => format!("{}/{ns}", self.tenant),
            _ => self.tenant.clone(),
        }
    }

    /// The query pairs that name this set on `GET /v1/vars/sets`, and the fields of a push body.
    pub fn fields(&self) -> Vec<(&'static str, String)> {
        let mut f = vec![
            ("tenant", self.tenant.clone()),
            ("level", self.level.name().to_string()),
        ];
        if let Some(ns) = &self.namespace {
            f.push(("namespace", ns.clone()));
        }
        if let Some(p) = &self.package {
            f.push(("package", p.clone()));
        }
        if let Some(v) = &self.version {
            f.push(("version", v.clone()));
        }
        f
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Result<Ref, String> {
        Ref::parse(s, Level::Version)
    }

    #[test]
    fn two_segments_use_the_default_namespace() {
        let r = v("acme/payments@1.4.0").unwrap();
        assert_eq!(r.namespace.as_deref(), Some("default"));
        assert_eq!(r.package.as_deref(), Some("payments"));
        assert_eq!(r.version.as_deref(), Some("1.4.0"));
        assert_eq!(r.long(), "acme/default/payments@1.4.0");
    }

    #[test]
    fn three_segments_name_the_namespace() {
        let r = v("acme/releases/payments@1.4.0").unwrap();
        assert_eq!(r.namespace.as_deref(), Some("releases"));
        assert_eq!(r.package.as_deref(), Some("payments"));
    }

    #[test]
    fn four_and_more_segments_are_a_nested_package() {
        let r = v("acme/default/apps/web@2026-11-03").unwrap();
        assert_eq!(r.namespace.as_deref(), Some("default"));
        assert_eq!(r.package.as_deref(), Some("apps/web"));
        assert_eq!(r.version.as_deref(), Some("2026-11-03"));
        let r = v("acme/rel/a/b/c@v1.0.0+build.1").unwrap();
        assert_eq!(r.package.as_deref(), Some("a/b/c"));
        assert_eq!(r.version.as_deref(), Some("v1.0.0+build.1"));
        // An npm scoped package needs the long form: the second segment is always the namespace.
        let r = v("acme/default/@web/ui@1.2.3").unwrap();
        assert_eq!(r.package.as_deref(), Some("@web/ui"));
        assert_eq!(r.version.as_deref(), Some("1.2.3"));
        assert_eq!(
            v("acme/@web/ui@1.2.3").unwrap_err(),
            "bad namespace `@web`: use lowercase letters, digits, `-` and `_`"
        );
    }

    #[test]
    fn bad_references() {
        for bad in [
            "acme",
            "acme/payments",
            "payments@1.0.0",
            "acme/@1.0.0",
            "acme/Payments@1.0.0",
            "acme/ns/@1.0.0",
            "acme//p@1.0.0",
            "acme/ns/a//b@1.0.0",
            "acme/ns/.x@1.0.0",
            "acme/p@",
            "acme/p@1.0 0",
            "Acme/p@1.0.0",
        ] {
            assert!(v(bad).is_err(), "{bad}");
        }
        assert!(v(&format!("acme/p@{}", "1".repeat(129))).is_err());
    }

    #[test]
    fn tenant_and_namespace_levels() {
        let r = Ref::parse("acme", Level::Tenant).unwrap();
        assert_eq!(
            r.fields(),
            vec![("tenant", "acme".into()), ("level", "tenant".into())]
        );
        let r = Ref::parse("acme/releases", Level::Namespace).unwrap();
        assert_eq!(r.long(), "acme/releases");
        assert!(Ref::parse("acme/releases", Level::Tenant).is_err());
        assert!(Ref::parse("acme", Level::Namespace).is_err());
        assert!(Ref::parse("acme/a/b", Level::Namespace).is_err());
        assert!(Ref::parse("acme/p@1", Level::Namespace).is_err());
        assert!(Level::parse("package").is_err());
    }
}
