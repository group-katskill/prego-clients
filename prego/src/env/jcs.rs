//! RFC 8785 JSON Canonicalization Scheme (JCS) and the content hash of a Release Variable set.
//!
//! The registry computes the same bytes and the same hash, so `prego env hash` works offline.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

/// The canonical form of `value` as UTF-8 text: object keys sorted by UTF-16 code units, no whitespace,
/// numbers as ECMAScript formats an IEEE 754 double, strings with the minimal escapes.
pub fn canonical(value: &Value) -> Result<String, String> {
    let mut out = String::new();
    write_value(&mut out, value)?;
    Ok(out)
}

/// `sha256:<64 hex>` of the canonical form.
pub fn hash(value: &Value) -> Result<String, String> {
    Ok(hash_bytes(canonical(value)?.as_bytes()))
}

/// `sha256:<64 hex>` of some bytes.
pub fn hash_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity(71);
    s.push_str("sha256:");
    for b in digest {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Checks the text form `sha256:<64 lowercase hex>`.
pub fn is_hash(s: &str) -> bool {
    s.strip_prefix("sha256:").is_some_and(|h| {
        h.len() == 64
            && h.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn write_value(out: &mut String, value: &Value) -> Result<(), String> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            let f = n
                .as_f64()
                .ok_or_else(|| format!("the number {n} is not an IEEE 754 double"))?;
            out.push_str(&number(f)?);
        }
        Value::String(s) => write_string(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, v) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, v)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut entries: Vec<(Vec<u16>, &String, &Value)> = map
                .iter()
                .map(|(k, v)| (k.encode_utf16().collect(), k, v))
                .collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            out.push('{');
            for (i, (_, k, v)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, k);
                out.push(':');
                write_value(out, v)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// ECMAScript `Number.prototype.toString` for a finite double (ECMA-262, Number::toString).
pub fn number(f: f64) -> Result<String, String> {
    if !f.is_finite() {
        return Err("NaN and Infinity are not JSON numbers".into());
    }
    if f == 0.0 {
        return Ok("0".into());
    }
    // Rust gives the shortest digits that read back as the same double, as ECMAScript requires.
    let sci = format!("{:e}", f.abs());
    let (mantissa, exp) = sci.split_once('e').expect("{:e} has an exponent");
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let digits = tie_to_even(f.abs(), digits, exp);
    let k = digits.len() as i32;
    // The value is 0.<digits> x 10^n.
    let n = exp.parse::<i32>().expect("{:e} exponent is a number") + 1;
    let mut s = String::new();
    if f < 0.0 {
        s.push('-');
    }
    if k <= n && n <= 21 {
        s.push_str(&digits);
        s.extend(std::iter::repeat_n('0', (n - k) as usize));
    } else if 0 < n && n <= 21 {
        s.push_str(&digits[..n as usize]);
        s.push('.');
        s.push_str(&digits[n as usize..]);
    } else if -6 < n && n <= 0 {
        s.push_str("0.");
        s.extend(std::iter::repeat_n('0', (-n) as usize));
        s.push_str(&digits);
    } else {
        s.push_str(&digits[..1]);
        if k > 1 {
            s.push('.');
            s.push_str(&digits[1..]);
        }
        let e = n - 1;
        let _ = write!(s, "e{}{}", if e < 0 { '-' } else { '+' }, e.abs());
    }
    Ok(s)
}

/// ECMAScript picks the even last digit when two shortest digit strings are equally near the exact value;
/// Rust picks the larger one. The exact value has at most 767 significant digits, and `{:.1100e}` prints them
/// all.
fn tie_to_even(f: f64, digits: String, exp: &str) -> String {
    let k = digits.len();
    let exact = format!("{f:.1100e}");
    let (m, e) = exact.split_once('e').expect("{:e} has an exponent");
    if e != exp {
        return digits;
    }
    let all: Vec<u8> = m.bytes().filter(|b| *b != b'.').collect();
    let tie = all.get(k) == Some(&b'5') && all[k + 1..].iter().all(|b| *b == b'0');
    let last = digits.as_bytes()[k - 1];
    if !tie || (last - b'0').is_multiple_of(2) {
        return digits;
    }
    let mut lower = all[..k].to_vec();
    if lower.last() == Some(&last) {
        // The shortest digits are the truncated ones and are odd: the even neighbour is one up.
        let Some(l) = lower.last_mut().filter(|l| **l < b'9') else {
            return digits;
        };
        *l += 1;
    }
    let candidate = String::from_utf8(lower).expect("ASCII digits");
    let text = format!("{}.{}e{exp}", &candidate[..1], &candidate[1..]);
    if text.parse::<f64>() == Ok(f) && (candidate.as_bytes()[k - 1] - b'0').is_multiple_of(2) {
        candidate
    } else {
        digits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8785 Appendix B: IEEE 754 bit patterns and their canonical text.
    #[test]
    fn rfc8785_appendix_b_numbers() {
        let cases: [(u64, &str); 23] = [
            (0x0000000000000000, "0"),
            (0x8000000000000000, "0"),
            (0x0000000000000001, "5e-324"),
            (0x8000000000000001, "-5e-324"),
            (0x7fefffffffffffff, "1.7976931348623157e+308"),
            (0xffefffffffffffff, "-1.7976931348623157e+308"),
            (0x4340000000000000, "9007199254740992"),
            (0xc340000000000000, "-9007199254740992"),
            (0x4430000000000000, "295147905179352830000"),
            (0x44b52d02c7e14af5, "9.999999999999997e+22"),
            (0x44b52d02c7e14af6, "1e+23"),
            (0x44b52d02c7e14af7, "1.0000000000000001e+23"),
            (0x444b1ae4d6e2ef4e, "999999999999999700000"),
            (0x444b1ae4d6e2ef4f, "999999999999999900000"),
            (0x444b1ae4d6e2ef50, "1e+21"),
            (0x3eb0c6f7a0b5ed8c, "9.999999999999997e-7"),
            (0x3eb0c6f7a0b5ed8d, "0.000001"),
            (0x41b3de4355555553, "333333333.3333332"),
            (0x41b3de4355555554, "333333333.33333325"),
            (0x41b3de4355555555, "333333333.3333333"),
            (0x41b3de4355555556, "333333333.3333334"),
            (0x41b3de4355555557, "333333333.33333343"),
            (0xbecbf647612f3696, "-0.0000033333333333333333"),
        ];
        for (bits, want) in cases {
            assert_eq!(number(f64::from_bits(bits)).unwrap(), want, "{bits:016x}");
        }
        assert_eq!(
            number(f64::from_bits(0x43143ff3c1cb0959)).unwrap(),
            "1424953923781206.2"
        );
        assert!(number(f64::from_bits(0x7fffffffffffffff)).is_err());
        assert!(number(f64::from_bits(0x7ff0000000000000)).is_err());
    }

    /// RFC 8785 section 3.2.2 example.
    #[test]
    fn rfc8785_sample() {
        let input = r#"{
          "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
          "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
          "literals": [null, true, false]
        }"#;
        let v: Value = serde_json::from_str(input).unwrap();
        assert_eq!(
            canonical(&v).unwrap(),
            r#"{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}"#
        );
    }

    /// RFC 8785 section 3.2.3: sort by UTF-16 code units, not by code points or UTF-8 bytes.
    #[test]
    fn rfc8785_sorting() {
        let input = r#"{
          "€": "Euro Sign",
          "\r": "Carriage Return",
          "דּ": "Hebrew Letter Dalet With Dagesh",
          "1": "One",
          "😀": "Emoji: Grinning Face",
          "\u0080": "Control",
          "ö": "Latin Small Letter O With Diaeresis"
        }"#;
        let v: Value = serde_json::from_str(input).unwrap();
        let out = canonical(&v).unwrap();
        let back: serde_json::Map<String, Value> = serde_json::from_str(&out).unwrap();
        let values: Vec<&str> = back.values().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(
            values,
            [
                "Carriage Return",
                "One",
                "Control",
                "Latin Small Letter O With Diaeresis",
                "Euro Sign",
                "Emoji: Grinning Face",
                "Hebrew Letter Dalet With Dagesh"
            ]
        );
    }

    #[test]
    fn hash_does_not_change_with_key_order_or_number_form() {
        let a: Value = serde_json::from_str(r#"{"B":1,"A":[1.0,2e0,"x"]}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"A":[1,2,"x"],"B":1.00}"#).unwrap();
        assert_eq!(hash(&a).unwrap(), hash(&b).unwrap());
        assert_eq!(canonical(&a).unwrap(), r#"{"A":[1,2,"x"],"B":1}"#);
        // sha256 of `{}`.
        assert_eq!(
            hash(&serde_json::json!({})).unwrap(),
            "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        );
        assert!(is_hash(&hash(&a).unwrap()));
        assert!(!is_hash("sha256:ABC"));
    }
}
