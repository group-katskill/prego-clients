//! `svid-file` and `token-file` sources: read a JWT from a file.

use std::fs::File;
use std::io::Read;

use crate::jwt::MAX_TOKEN_BYTES;
use crate::secret::Secret;

/// Reads a token from `path`. Trailing whitespace is removed. Files larger than 8 KiB are refused.
pub(crate) fn read_token(path: &str) -> Result<Secret, String> {
    let file = File::open(path).map_err(|e| format!("cannot open `{path}`: {e}"))?;
    let mut buf = String::new();
    // Read one byte more than the limit to find files that are too large.
    file.take(MAX_TOKEN_BYTES as u64 + 64)
        .read_to_string(&mut buf)
        .map_err(|e| format!("cannot read `{path}`: {e}"))?;
    let token = buf.trim();
    if token.is_empty() {
        return Err(format!("`{path}` is empty"));
    }
    if token.len() > MAX_TOKEN_BYTES {
        return Err(format!("`{path}` holds more than {MAX_TOKEN_BYTES} bytes"));
    }
    Ok(Secret::new(token))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, SourceChoice};
    use crate::env::MapEnv;
    use crate::http::Http;
    use crate::sources::{find_subject_token, SourceKind};

    const JWT: &str = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln";

    fn temp_file(name: &str, content: &str) -> String {
        let dir = std::env::temp_dir().join(format!("prego-auth-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, content).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn find(kind: SourceKind, var: &str, path: &str) -> Result<crate::SubjectToken, crate::Error> {
        let cfg = Config {
            tenant: "acme".into(),
            sts_url: crate::DEFAULT_STS_URL.into(),
            audience: crate::DEFAULT_AUDIENCE.into(),
            source: SourceChoice::Only(kind),
            ca_file: None,
        };
        find_subject_token(&cfg, &MapEnv::new().with(var, path), &Http::new("test"))
    }

    #[test]
    fn svid_file_source() {
        let p = temp_file("svid.jwt", &format!("{JWT}\n"));
        let t = find(SourceKind::SvidFile, "PREGO_SVID_FILE", &p).unwrap();
        assert_eq!(t.value.expose(), JWT);
    }

    #[test]
    fn token_file_source() {
        let p = temp_file("token.jwt", JWT);
        let t = find(SourceKind::TokenFile, "PREGO_TOKEN_FILE", &p).unwrap();
        assert_eq!(t.kind, SourceKind::TokenFile);
        assert_eq!(t.value.expose(), JWT);
    }

    #[test]
    fn missing_empty_and_large_files() {
        assert!(read_token("/nonexistent/prego/token").is_err());
        let empty = temp_file("empty.jwt", " \n");
        assert!(read_token(&empty).unwrap_err().contains("empty"));
        let big = temp_file("big.jwt", &"a".repeat(MAX_TOKEN_BYTES + 1));
        assert!(read_token(&big).unwrap_err().contains("more than"));
    }

    #[test]
    fn file_with_non_jwt_is_refused() {
        let p = temp_file("junk.jwt", "hello");
        let e = find(SourceKind::TokenFile, "PREGO_TOKEN_FILE", &p).unwrap_err();
        assert!(e.to_string().contains("not a JWT"), "{e}");
        assert!(!e.to_string().contains("hello"));
    }
}
