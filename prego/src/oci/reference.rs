//! Image references: `[host/]<tenant>/<namespace>/<repo>[:tag]`.

use prego_auth::oci::DEFAULT_OCI_HOST;

/// Longest image name (without the host), as the registry allows.
const MAX_NAME: usize = 255;

/// A parsed image reference for a push.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    /// Host with port if not 443, lowercase.
    pub host: String,
    /// `<tenant>/<namespace>/<repo>`.
    pub name: String,
    /// The tag. `latest` if the reference has none.
    pub tag: String,
}

impl Reference {
    /// Parses a reference. A first part with a `.` or `:`, or `localhost`, is the host. Else the host is
    /// `oci.prego.k8skill.com`.
    pub fn parse(s: &str) -> Result<Self, String> {
        let bad = |why: &str| format!("bad image reference `{s}`: {why}");
        if s.contains('@') {
            return Err(bad("push needs a tag, not a digest"));
        }
        let (host, rest) = match s.split_once('/') {
            Some((first, rest))
                if first.contains('.') || first.contains(':') || first == "localhost" =>
            {
                (first.to_ascii_lowercase(), rest)
            }
            _ => (DEFAULT_OCI_HOST.to_string(), s),
        };
        let host = host.strip_suffix(":443").unwrap_or(&host).to_string();
        let (name, tag) = match rest.rsplit_once(':') {
            Some((n, t)) if !t.contains('/') => (n, t),
            _ => (rest, "latest"),
        };
        check_name(name).map_err(|w| bad(&w))?;
        if !valid_tag(tag) {
            return Err(bad("the tag must match [A-Za-z0-9_][A-Za-z0-9._-]{0,127}"));
        }
        Ok(Reference {
            host,
            name: name.to_string(),
            tag: tag.to_string(),
        })
    }

    /// The tenant: the first part of the name.
    pub fn tenant(&self) -> &str {
        self.name.split('/').next().unwrap_or("")
    }

    /// `http` for a loopback host (local tests), else `https`.
    pub fn scheme(&self) -> &'static str {
        if is_loopback(&self.host) {
            "http"
        } else {
            "https"
        }
    }
}

/// Checks an image name: 3 to 6 parts (`<tenant>/<namespace>/<repo>`, the repo has 1 to 4 parts), each part
/// in the OCI form `[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*`, at most 255 characters.
pub fn check_name(name: &str) -> Result<(), String> {
    if name.len() > MAX_NAME {
        return Err(format!("the name is longer than {MAX_NAME} characters"));
    }
    let parts: Vec<&str> = name.split('/').collect();
    if parts.len() < 3 || parts.len() > 6 {
        return Err(
            "the name must be <tenant>/<namespace>/<repo>, with 1 to 4 parts in the repo".into(),
        );
    }
    if let Some(p) = parts.iter().find(|p| !valid_component(p)) {
        return Err(format!(
            "`{p}` is not a valid name part (lowercase letters, digits, and . _ __ - between them)"
        ));
    }
    Ok(())
}

fn valid_component(p: &str) -> bool {
    let b = p.as_bytes();
    let alnum = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    if b.is_empty() || !alnum(b[0]) || !alnum(b[b.len() - 1]) {
        return false;
    }
    let mut i = 0;
    while i < b.len() {
        if alnum(b[i]) {
            i += 1;
            continue;
        }
        // A separator: ".", "_", "__" or one or more "-".
        let start = i;
        match b[i] {
            b'.' => i += 1,
            b'_' => {
                i += 1;
                if i < b.len() && b[i] == b'_' {
                    i += 1;
                }
            }
            b'-' => {
                while i < b.len() && b[i] == b'-' {
                    i += 1;
                }
            }
            _ => return false,
        }
        if i == start || i >= b.len() || !alnum(b[i]) {
            return false;
        }
    }
    true
}

fn valid_tag(t: &str) -> bool {
    let b = t.as_bytes();
    !b.is_empty()
        && b.len() <= 128
        && (b[0].is_ascii_alphanumeric() || b[0] == b'_')
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
}

/// True for `localhost`, `127.0.0.1` and `[::1]`, with or without a port.
pub fn is_loopback(host: &str) -> bool {
    let h = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host)
    };
    matches!(h, "localhost" | "127.0.0.1" | "::1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_references() {
        let r = Reference::parse("acme/default/api:1.2.0").unwrap();
        assert_eq!(
            r,
            Reference {
                host: DEFAULT_OCI_HOST.into(),
                name: "acme/default/api".into(),
                tag: "1.2.0".into()
            }
        );
        assert_eq!(r.tenant(), "acme");
        assert_eq!(r.scheme(), "https");

        let r = Reference::parse("OCI.Prego.K8skill.com:443/acme/rel/tools/build-x").unwrap();
        assert_eq!(r.host, DEFAULT_OCI_HOST);
        assert_eq!(r.name, "acme/rel/tools/build-x");
        assert_eq!(r.tag, "latest");

        let r = Reference::parse("127.0.0.1:5000/acme/d/a:v1").unwrap();
        assert_eq!(r.host, "127.0.0.1:5000");
        assert_eq!(r.scheme(), "http");
        assert_eq!(
            Reference::parse("localhost/acme/d/a").unwrap().scheme(),
            "http"
        );
    }

    #[test]
    fn refuses_bad_references() {
        for bad in [
            "acme/api:1",
            "acme/d/API:1",
            "acme/d/a@sha256:00",
            "acme/d/a:",
            "acme/d/a:-x",
            "acme/d/a/b/c/d/e:1",
            "acme/d/a..b",
            "acme/d/a___b",
            "acme/d/-a",
            "acme//a",
        ] {
            assert!(Reference::parse(bad).is_err(), "{bad}");
        }
        let long = format!("acme/d/{}", "a".repeat(260));
        assert!(Reference::parse(&long).is_err());
        for good in [
            "acme/d/a.b",
            "acme/d/a__b",
            "acme/d/a---b",
            "acme/d/a_b-c.d",
        ] {
            assert!(Reference::parse(good).is_ok(), "{good}");
        }
    }

    #[test]
    fn loopback_hosts() {
        for h in [
            "localhost",
            "localhost:5000",
            "127.0.0.1:8080",
            "[::1]:5000",
        ] {
            assert!(is_loopback(h), "{h}");
        }
        for h in ["oci.prego.k8skill.com", "127.0.0.2", "localhost.evil.test"] {
            assert!(!is_loopback(h), "{h}");
        }
    }
}
