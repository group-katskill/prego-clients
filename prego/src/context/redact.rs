//! Client redaction of secret-shaped strings before a context save (ADR-0058 item 12). The shapes are the
//! ones that the registry refuses (ADR-0035 section 9): Prego API keys (`prk_`), PEM private keys, AWS
//! access key IDs (`AKIA`, `ASIA`), GitHub tokens (`ghp_`, `github_pat_`), GitLab tokens (`glpat-`), Slack
//! tokens (`xox?-`), Stripe live keys (`sk_live_`) and JWT-shaped strings. Each match is replaced with
//! `[REDACTED:<kind>]`. The matched text is never printed or kept.
//!
//! The matchers are written by hand from that list; a string that is close to a shape but is not one is
//! kept as it is, and the registry still checks every file.

/// Replaces every secret-shaped string in `text`. Returns the new text and the number of replaced strings.
pub fn redact(text: &str) -> (String, usize) {
    let b = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut n = 0;
    let mut copied = 0;
    let mut i = 0;
    while i < b.len() {
        // Every shape starts with an ASCII byte, so `i` is a char boundary when a match starts, and every
        // match ends after an ASCII byte.
        if let Some((len, kind)) = match_at(b, i) {
            out.push_str(&text[copied..i]);
            out.push_str("[REDACTED:");
            out.push_str(kind);
            out.push(']');
            n += 1;
            i += len;
            copied = i;
        } else {
            i += 1;
        }
    }
    if n == 0 {
        return (text.to_string(), 0);
    }
    out.push_str(&text[copied..]);
    (out, n)
}

fn is_word(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

fn is_b64url(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'-'
}

/// The length of the run of bytes from `i` that match `f`.
fn run(b: &[u8], i: usize, f: impl Fn(u8) -> bool) -> usize {
    b[i.min(b.len())..].iter().take_while(|c| f(**c)).count()
}

/// A prefix followed by at least `min` bytes of `f`, taken to the end of the run.
fn prefixed(
    b: &[u8],
    i: usize,
    prefix: &[u8],
    min: usize,
    f: impl Fn(u8) -> bool,
) -> Option<usize> {
    if !b[i..].starts_with(prefix) {
        return None;
    }
    let tail = run(b, i + prefix.len(), f);
    (tail >= min).then_some(prefix.len() + tail)
}

fn match_at(b: &[u8], i: usize) -> Option<(usize, &'static str)> {
    let c = b[i];
    if c == b'-' {
        return pem(b, i).map(|l| (l, "private_key"));
    }
    if !c.is_ascii_alphabetic() {
        return None;
    }
    // A shape starts a word: `xprk_...` or `abcAKIA...` is not a match.
    if i > 0 && is_word(b[i - 1]) {
        return None;
    }
    let found = match c {
        b'p' => prefixed(b, i, b"prk_", 8, is_b64url).map(|l| (l, "prego_api_key")),
        b'A' => aws(b, i).map(|l| (l, "aws_access_key")),
        b'g' => prefixed(b, i, b"ghp_", 36, |c| c.is_ascii_alphanumeric())
            .or_else(|| prefixed(b, i, b"github_pat_", 22, is_word))
            .map(|l| (l, "github_token"))
            .or_else(|| prefixed(b, i, b"glpat-", 20, is_b64url).map(|l| (l, "gitlab_token"))),
        b'x' => slack(b, i).map(|l| (l, "slack_token")),
        b's' => prefixed(b, i, b"sk_live_", 16, |c| c.is_ascii_alphanumeric())
            .map(|l| (l, "stripe_key")),
        b'e' => jwt(b, i).map(|l| (l, "jwt")),
        _ => None,
    }?;
    Some(found)
}

/// `AKIA` or `ASIA` and 16 upper-case letters or digits, as a whole word.
fn aws(b: &[u8], i: usize) -> Option<usize> {
    if !(b[i..].starts_with(b"AKIA") || b[i..].starts_with(b"ASIA")) {
        return None;
    }
    let tail = run(b, i + 4, |c| c.is_ascii_uppercase() || c.is_ascii_digit());
    let end = i + 4 + tail;
    (tail == 16 && b.get(end).is_none_or(|c| !c.is_ascii_alphanumeric())).then_some(20)
}

/// `xox` and one letter or digit, `-`, then at least 10 letters, digits or `-`.
fn slack(b: &[u8], i: usize) -> Option<usize> {
    if !b[i..].starts_with(b"xox") || b.len() < i + 5 {
        return None;
    }
    if !b[i + 3].is_ascii_alphanumeric() || b[i + 4] != b'-' {
        return None;
    }
    let tail = run(b, i + 5, |c| c.is_ascii_alphanumeric() || c == b'-');
    (tail >= 10).then_some(5 + tail)
}

/// Three base64url parts joined by `.`, the first starting with `eyJ` (a JSON object).
fn jwt(b: &[u8], i: usize) -> Option<usize> {
    if !b[i..].starts_with(b"eyJ") {
        return None;
    }
    let h = run(b, i, is_b64url);
    if h < 10 || b.get(i + h) != Some(&b'.') {
        return None;
    }
    let p_start = i + h + 1;
    let p = run(b, p_start, is_b64url);
    if p < 8 || b.get(p_start + p) != Some(&b'.') {
        return None;
    }
    let s_start = p_start + p + 1;
    let s = run(b, s_start, is_b64url);
    (s >= 8).then_some(s_start + s - i)
}

/// A PEM private key: `-----BEGIN ... PRIVATE KEY-----` to the matching `-----END ... PRIVATE KEY-----`,
/// or to the end of the text when the end line is missing.
fn pem(b: &[u8], i: usize) -> Option<usize> {
    const BEGIN: &[u8] = b"-----BEGIN ";
    const TAIL: &[u8] = b"PRIVATE KEY-----";
    if !b[i..].starts_with(BEGIN) {
        return None;
    }
    let line_end = b[i..]
        .iter()
        .position(|c| *c == b'\n')
        .map_or(b.len(), |p| i + p);
    let line = &b[i + BEGIN.len()..line_end];
    let at = find(line, TAIL)?;
    // Only letters and spaces between BEGIN and PRIVATE KEY (`RSA `, `EC `, `ENCRYPTED `, or none).
    if !line[..at]
        .iter()
        .all(|c| c.is_ascii_uppercase() || *c == b' ')
    {
        return None;
    }
    let after = i + BEGIN.len() + at + TAIL.len();
    let mut from = after;
    while let Some(p) = find(&b[from..], b"-----END ") {
        let start = from + p + b"-----END ".len();
        let end_line = b[start..]
            .iter()
            .position(|c| *c == b'\n')
            .map_or(b.len(), |q| start + q);
        if let Some(t) = find(&b[start..end_line], TAIL) {
            return Some(start + t + TAIL.len() - i);
        }
        from = start;
    }
    Some(b.len() - i)
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The secret-shaped strings are made at run time, so this file has no string that a secret scanner
    // takes for a real key.
    fn k(prefix: &str, tail: &str) -> String {
        format!("{prefix}{tail}")
    }

    fn one(text: &str, kind: &str) {
        let (out, n) = redact(text);
        assert_eq!(n, 1, "{text}");
        assert!(out.contains(&format!("[REDACTED:{kind}]")), "{out}");
    }

    #[test]
    fn each_shape() {
        one(&k("prk", "_live_0123456789abcdef"), "prego_api_key");
        one(&k("AK", "IAABCDEFGHIJKLMNOP"), "aws_access_key");
        one(&k("AS", "IA0123456789ABCDEF"), "aws_access_key");
        one(&k("gh", &format!("p_{}", "a1".repeat(18))), "github_token");
        one(
            &k("github", &format!("_pat_{}", "B2_".repeat(10))),
            "github_token",
        );
        one(&k("gl", "pat-abcdefghij0123456789"), "gitlab_token");
        one(&k("xo", "xb-1234567890-abcdefghij"), "slack_token");
        one(&k("sk", "_live_0123456789abcdefXYZ"), "stripe_key");
        one(
            &k(
                "ey",
                "JhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJlLXZhbHVl",
            ),
            "jwt",
        );
    }

    #[test]
    fn whole_text() {
        let key = k("AK", "IAABCDEFGHIJKLMNOP");
        let text = format!("é line one\nAWS_KEY={key} # ü\n{key}\n");
        let (out, n) = redact(&text);
        assert_eq!(n, 2);
        assert_eq!(
            out,
            "é line one\nAWS_KEY=[REDACTED:aws_access_key] # ü\n[REDACTED:aws_access_key]\n"
        );
    }

    #[test]
    fn pem_blocks() {
        let body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nabcdef==\n";
        let block = format!(
            "{}RSA PRIVATE KEY-----\n{body}-----END RSA PRIVATE KEY-----",
            k("-----BEG", "IN ")
        );
        let (out, n) = redact(&format!("before\n{block}\nafter\n"));
        assert_eq!(
            (out.as_str(), n),
            ("before\n[REDACTED:private_key]\nafter\n", 1)
        );
        // No end line: to the end of the text.
        let open = format!("{}PRIVATE KEY-----\n{body}", k("-----BEG", "IN "));
        assert_eq!(redact(&format!("x\n{open}")).0, "x\n[REDACTED:private_key]");
        // A certificate or a public key is kept.
        for keep in [
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
            "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----\n",
        ] {
            assert_eq!(redact(keep), (keep.to_string(), 0));
        }
    }

    #[test]
    fn near_misses_are_kept() {
        for keep in [
            "prk_short".to_string(),
            k("xprk", "_live_0123456789abcdef"),
            k("AK", "IAABCDEFGHIJKLMNOPQ"), // 17 characters after AKIA
            k("AK", "IAABCDEFGHIJKLMNO"),   // 15
            k("xAK", "IAABCDEFGHIJKLMNOP"),
            k("gh", "p_tooshort"),
            k("gl", "pat-short"),
            k("xo", "xb-short"),
            k("sk", "_test_0123456789abcdefXYZ"),
            "eyJhbGciOi.short.x".to_string(),
            "a plain line, with eyJ and AKIA and ghp_ in it".to_string(),
            "-----BEGIN".to_string(),
        ] {
            assert_eq!(redact(&keep), (keep.clone(), 0), "{keep}");
        }
    }

    #[test]
    fn many_in_one_text() {
        let text = format!(
            "{} {} {}",
            k("gl", "pat-abcdefghij0123456789"),
            k("sk", "_live_0123456789abcdefXYZ"),
            k("prk", "_0123456789")
        );
        let (out, n) = redact(&text);
        assert_eq!(n, 3);
        assert_eq!(
            out,
            "[REDACTED:gitlab_token] [REDACTED:stripe_key] [REDACTED:prego_api_key]"
        );
    }
}
