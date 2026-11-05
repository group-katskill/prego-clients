//! Go module path, file path and version rules, as in `golang.org/x/mod/module` and `golang.org/x/mod/semver`.
//!
//! The rules here follow the published Go module reference. They decide which files can go into a module
//! zip and which module paths and versions a publish can use.

/// Checks a module path like `module.CheckPath`.
pub fn check_path(path: &str) -> Result<(), String> {
    let bad = |why: &str| Err(format!("malformed module path `{path}`: {why}"));
    check_elems(path, Kind::Module).or_else(|w| bad(&w))?;
    let first = path.split('/').next().unwrap_or("");
    if !first.contains('.') {
        return bad("missing dot in first path element");
    }
    if first.starts_with('-') {
        return bad("leading dash in first path element");
    }
    if let Some(c) = first
        .chars()
        .find(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-' || *c == '.'))
    {
        return bad(&format!("invalid char `{c}` in first path element"));
    }
    if split_path_major(path).is_none() {
        return bad("invalid version suffix");
    }
    Ok(())
}

/// Checks a file path inside a module like `module.CheckFilePath`.
pub fn check_file_path(path: &str) -> Result<(), String> {
    check_elems(path, Kind::File).map_err(|w| format!("malformed file path `{path}`: {w}"))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Module,
    File,
}

fn check_elems(path: &str, kind: Kind) -> Result<(), String> {
    if path.is_empty() {
        return Err("empty string".into());
    }
    if path.starts_with('-') && kind != Kind::File {
        return Err("leading dash".into());
    }
    if path.contains("//") {
        return Err("double slash".into());
    }
    if path.ends_with('/') {
        return Err("trailing slash".into());
    }
    if path.starts_with('/') {
        return Err("leading slash".into());
    }
    for elem in path.split('/') {
        check_elem(elem, kind)?;
    }
    Ok(())
}

const BAD_WINDOWS_NAMES: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

fn check_elem(elem: &str, kind: Kind) -> Result<(), String> {
    if elem.is_empty() {
        return Err("empty path element".into());
    }
    if elem.chars().all(|c| c == '.') {
        return Err(format!("invalid path element `{elem}`"));
    }
    if elem.starts_with('.') && kind == Kind::Module {
        return Err("leading dot in path element".into());
    }
    if elem.ends_with('.') {
        return Err("trailing dot in path element".into());
    }
    for c in elem.chars() {
        let ok = match kind {
            Kind::Module => c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~'),
            Kind::File => file_name_ok(c),
        };
        if !ok {
            return Err(format!("invalid char `{c}`"));
        }
    }
    let short = elem.split('.').next().unwrap_or(elem);
    if BAD_WINDOWS_NAMES
        .iter()
        .chain(["COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³"].iter())
        .any(|b| b.eq_ignore_ascii_case(short) || *b == short.to_uppercase())
    {
        return Err(format!(
            "`{short}` disallowed as path element component on Windows"
        ));
    }
    if let Some(t) = short.rfind('~') {
        let suffix = &short[t + 1..];
        if !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()) {
            return Err("trailing tilde and digits in path element".into());
        }
    }
    Ok(())
}

fn file_name_ok(c: char) -> bool {
    if c.is_ascii() {
        c.is_ascii_alphanumeric() || "!#$%&()+,-.=@[]^_{}~ ".contains(c)
    } else {
        c.is_alphabetic()
    }
}

/// Splits `path` into (prefix, major) like `module.SplitPathVersion`: `example.com/m/v2` gives
/// `("example.com/m", Some(2))`, `example.com/m` gives `("example.com/m", None)`. `None` if the suffix is
/// a bad major version (`/v0`, `/v1`, `/v02`).
pub fn split_path_major(path: &str) -> Option<(&str, Option<u64>)> {
    let Some((prefix, last)) = path.rsplit_once('/') else {
        return Some((path, None));
    };
    let Some(digits) = last.strip_prefix('v') else {
        return Some((path, None));
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Some((path, None));
    }
    if digits.starts_with('0') || digits == "1" {
        return None;
    }
    digits.parse().ok().map(|n| (prefix, Some(n)))
}

/// A canonical release or prerelease version `vX.Y.Z[-pre]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub text: String,
    pub major: u64,
}

/// Checks a version for publish: canonical semver with `v`, no build metadata, not a pseudo-version, not
/// `+incompatible`.
pub fn parse_version(v: &str) -> Result<Version, String> {
    let bad = |why: &str| Err(format!("version `{v}` {why}"));
    if v.contains('+') {
        return bad(
            "has build metadata or +incompatible; Prego takes only canonical tags such as v1.2.3",
        );
    }
    let Some(rest) = v.strip_prefix('v') else {
        return bad("must start with v, as in v1.2.3");
    };
    let (core, pre) = match rest.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (rest, None),
    };
    let nums: Vec<&str> = core.split('.').collect();
    if nums.len() != 3 || !nums.iter().all(|n| numeric_ok(n)) {
        return bad("is not canonical semver (vMAJOR.MINOR.PATCH)");
    }
    if let Some(pre) = pre {
        let ok = !pre.is_empty()
            && pre.split('.').all(|id| {
                !id.is_empty()
                    && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    && (!id.bytes().all(|b| b.is_ascii_digit()) || numeric_ok(id))
            });
        if !ok {
            return bad("has a bad prerelease part");
        }
        if is_pseudo(nums[1], nums[2], pre) {
            return bad("is a pseudo-version; publish a tagged release");
        }
    }
    Ok(Version {
        text: v.to_string(),
        major: nums[0]
            .parse()
            .map_err(|_| format!("version `{v}`: major too big"))?,
    })
}

fn numeric_ok(n: &str) -> bool {
    !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) && (n == "0" || !n.starts_with('0'))
}

/// True for the three pseudo-version forms of `module.IsPseudoVersion`.
fn is_pseudo(minor: &str, patch: &str, pre: &str) -> bool {
    let stamp_hash = |s: &str| -> bool {
        match s.split_once('-') {
            Some((stamp, hash)) => {
                stamp.len() == 14
                    && stamp.bytes().all(|b| b.is_ascii_digit())
                    && !hash.is_empty()
                    && hash.bytes().all(|b| b.is_ascii_alphanumeric())
            }
            None => false,
        }
    };
    if minor == "0" && patch == "0" && stamp_hash(pre) {
        return true;
    }
    // `-0.<stamp>-<hash>` or `-<pre>.0.<stamp>-<hash>`.
    let tail = if let Some(t) = pre.strip_prefix("0.") {
        Some(t)
    } else {
        pre.find(".0.").map(|i| &pre[i + 3..])
    };
    tail.is_some_and(stamp_hash)
}

/// Checks the major version rule: `v0` and `v1` need a path without a `/vN` suffix; `v2` and later need the
/// suffix `/vN` with the same N.
pub fn check_major(path: &str, version: &Version) -> Result<(), String> {
    let major = split_path_major(path).and_then(|(_, m)| m);
    match (version.major, major) {
        (0 | 1, None) => Ok(()),
        (0 | 1, Some(n)) => Err(format!(
            "module path `{path}` ends in /v{n}, so its versions must be v{n}.x.y, not {}",
            version.text
        )),
        (m, Some(n)) if m == n => Ok(()),
        (m, _) => Err(format!(
            "version {} needs a module path that ends in /v{m}, not `{path}`",
            version.text
        )),
    }
}

/// Case-encodes a module path or version for a URL, like `module.EscapePath`: `A` becomes `!a`.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_uppercase() {
            out.push('!');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_paths() {
        for ok in [
            "go.acme.com/core",
            "github.com/Acme/Core_x/v2",
            "example.com/repo.git/sub",
            "go.acme.com/a~b",
        ] {
            check_path(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
        for bad in [
            "",
            "core",
            "Go.acme.com/core",
            "-go.acme.com/x",
            "go.acme.com//x",
            "go.acme.com/x/",
            "go.acme.com/.x",
            "go.acme.com/x.",
            "go.acme.com/x/v1",
            "go.acme.com/x/v02",
            "go.acme.com/con",
            "go.acme.com/x~1",
            "go.acme.com/a b",
            "go.acme.com/ä",
        ] {
            assert!(check_path(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn file_paths() {
        for ok in [
            "a.go",
            ".gitignore",
            "-x",
            "dir/sp ace.txt",
            "ünï/x",
            "a+b@c=[1]",
        ] {
            check_file_path(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
        for bad in [
            "a/../b",
            "a//b",
            "a.",
            "x/aux.txt",
            "a\"b",
            "a*b",
            "a:b",
            "a\\b",
            "x/A~12",
        ] {
            assert!(check_file_path(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn versions() {
        assert_eq!(parse_version("v1.2.3").unwrap().major, 1);
        assert_eq!(parse_version("v2.0.0-rc.1").unwrap().major, 2);
        parse_version("v0.0.1-alpha-x.0").unwrap();
        for bad in [
            "1.2.3",
            "v1.2",
            "v01.2.3",
            "v1.2.3+meta",
            "v2.0.0+incompatible",
            "v1.2.3-",
            "v1.2.3-01",
            "v0.0.0-20261104010203-abcdefabcdef",
            "v1.2.4-0.20261104010203-abcdefabcdef",
            "v1.2.3-pre.0.20261104010203-abcdefabcdef",
        ] {
            assert!(parse_version(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn major_rule() {
        let v = |s| parse_version(s).unwrap();
        check_major("go.acme.com/x", &v("v1.0.0")).unwrap();
        check_major("go.acme.com/x", &v("v0.1.0")).unwrap();
        check_major("go.acme.com/x/v2", &v("v2.3.0")).unwrap();
        assert!(check_major("go.acme.com/x", &v("v2.0.0")).is_err());
        assert!(check_major("go.acme.com/x/v2", &v("v1.0.0")).is_err());
        assert!(check_major("go.acme.com/x/v3", &v("v2.0.0")).is_err());
    }

    #[test]
    fn escaping() {
        assert_eq!(escape("github.com/Acme/Core"), "github.com/!acme/!core");
        assert_eq!(escape("v1.0.0-RC"), "v1.0.0-!r!c");
    }
}
