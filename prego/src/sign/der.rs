//! A small DER reader (ITU-T X.690): enough for SubjectPublicKeyInfo, PKCS #8, RSAPublicKey, X.509
//! certificates and the PKCS #12 shape. It reads; it never writes. Indefinite lengths are refused.

/// One element: the tag byte and the content bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    /// The whole element, with the tag and the length bytes.
    pub raw: &'a [u8],
}

pub const SEQUENCE: u8 = 0x30;
pub const INTEGER: u8 = 0x02;
pub const BIT_STRING: u8 = 0x03;
pub const OCTET_STRING: u8 = 0x04;
pub const OID: u8 = 0x06;
pub const UTC_TIME: u8 = 0x17;
pub const GENERALIZED_TIME: u8 = 0x18;

/// Reads one element at the start of `input`. Returns it and the rest.
pub fn read(input: &[u8]) -> Result<(Tlv<'_>, &[u8]), String> {
    let (&tag, rest) = input.split_first().ok_or("DER: no data")?;
    if tag & 0x1f == 0x1f {
        return Err("DER: a high tag number is not supported".into());
    }
    let (&first, mut rest) = rest.split_first().ok_or("DER: no length")?;
    let len = if first < 0x80 {
        usize::from(first)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return Err("DER: bad length".into());
        }
        let mut len = 0usize;
        for &b in &rest[..n] {
            len = (len << 8) | usize::from(b);
        }
        rest = &rest[n..];
        len
    };
    if rest.len() < len {
        return Err("DER: the element is longer than the data".into());
    }
    let head = input.len() - rest.len();
    Ok((
        Tlv {
            tag,
            content: &rest[..len],
            raw: &input[..head + len],
        },
        &rest[len..],
    ))
}

/// Reads exactly one element: no bytes may follow.
pub fn read_all(input: &[u8]) -> Result<Tlv<'_>, String> {
    let (t, rest) = read(input)?;
    if !rest.is_empty() {
        return Err("DER: data after the end".into());
    }
    Ok(t)
}

/// The elements of a constructed element's content.
pub fn children(content: &[u8]) -> Result<Vec<Tlv<'_>>, String> {
    let mut out = Vec::new();
    let mut rest = content;
    while !rest.is_empty() {
        let (t, r) = read(rest)?;
        out.push(t);
        rest = r;
    }
    Ok(out)
}

/// Expects the tag, else an error that names `what`.
pub fn expect<'a>(t: Tlv<'a>, tag: u8, what: &str) -> Result<Tlv<'a>, String> {
    if t.tag == tag {
        Ok(t)
    } else {
        Err(format!("DER: {what}: tag 0x{:02x}, not 0x{tag:02x}", t.tag))
    }
}

/// The dotted text of an OID, for example `1.2.840.10045.2.1`.
pub fn oid_text(content: &[u8]) -> String {
    let mut parts: Vec<u64> = Vec::new();
    let mut v: u64 = 0;
    for (i, &b) in content.iter().enumerate() {
        v = (v << 7) | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            if parts.is_empty() {
                let first = if v < 40 {
                    0
                } else if v < 80 {
                    1
                } else {
                    2
                };
                parts.push(first);
                parts.push(v - first * 40);
            } else {
                parts.push(v);
            }
            v = 0;
        } else if i == content.len() - 1 {
            return "?".into();
        }
    }
    parts
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

/// An unsigned big-endian integer without leading zero bytes.
pub fn unsigned(content: &[u8]) -> &[u8] {
    let mut c = content;
    while c.len() > 1 && c[0] == 0 {
        c = &c[1..];
    }
    c
}

/// The bit length of an unsigned big-endian integer.
pub fn bit_len(bytes: &[u8]) -> usize {
    let b = unsigned(bytes);
    match b.first() {
        None | Some(0) => 0,
        Some(&f) => (b.len() - 1) * 8 + (8 - f.leading_zeros() as usize),
    }
}

/// The bytes of a BIT STRING with no unused bits.
pub fn bit_string(t: Tlv<'_>) -> Result<&[u8], String> {
    let t = expect(t, BIT_STRING, "bit string")?;
    match t.content.split_first() {
        Some((0, rest)) => Ok(rest),
        _ => Err("DER: a bit string with unused bits".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oids_and_lengths() {
        // 1.2.840.10045.2.1 (id-ecPublicKey)
        assert_eq!(
            oid_text(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]),
            "1.2.840.10045.2.1"
        );
        assert_eq!(oid_text(&[0x2b, 0x65, 0x70]), "1.3.101.112");
        let long = [vec![0x04, 0x81, 0x80], vec![7u8; 128]].concat();
        let (t, rest) = read(&long).unwrap();
        assert_eq!(t.content.len(), 128);
        assert!(rest.is_empty());
        assert!(read(&[0x04, 0x05, 1]).is_err());
        assert_eq!(bit_len(&[0x00, 0x80, 0x00]), 16);
        assert_eq!(bit_len(&[0x01]), 1);
    }
}
