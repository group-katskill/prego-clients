//! Sizes for people: binary units (KiB, MiB, GiB, TiB). `--json` output stays in bytes.

use serde_json::Value;

const UNITS: [&str; 4] = ["KiB", "MiB", "GiB", "TiB"];

/// A size in binary units. Under 1 KiB: `N bytes`. An exact multiple of the unit: a whole number (`8 MiB`).
/// Any other value: one decimal (`1.5 KiB`), in the next unit when it rounds up to 1024.
pub fn human(bytes: u64) -> String {
    if bytes < 1024 {
        return if bytes == 1 {
            "1 byte".into()
        } else {
            format!("{bytes} bytes")
        };
    }
    let mut u = 0;
    while u + 1 < UNITS.len() && bytes >= 1u64 << (10 * (u + 2)) {
        u += 1;
    }
    let unit = 1u64 << (10 * (u + 1));
    if bytes % unit == 0 {
        return format!("{} {}", bytes / unit, UNITS[u]);
    }
    let v = format!("{:.1}", bytes as f64 / unit as f64);
    if v == "1024.0" && u + 1 < UNITS.len() {
        return format!("1.0 {}", UNITS[u + 1]);
    }
    format!("{v} {}", UNITS[u])
}

/// [`human`] of a JSON number of bytes, or `None` when the value is not a non-negative integer.
pub fn human_of(v: &Value) -> Option<String> {
    v.as_u64().map(human)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_units() {
        assert_eq!(human(0), "0 bytes");
        assert_eq!(human(1), "1 byte");
        assert_eq!(human(1023), "1023 bytes");
        assert_eq!(human(1024), "1 KiB");
        assert_eq!(human(1536), "1.5 KiB");
        assert_eq!(human(2048), "2 KiB");
        assert_eq!(human(4096), "4 KiB");
        assert_eq!(human(64 << 10), "64 KiB");
        assert_eq!(human((1 << 20) - 1), "1.0 MiB");
        assert_eq!(human(8 << 20), "8 MiB");
        assert_eq!(human(8388608), "8 MiB");
        assert_eq!(human((300 << 20) + 1), "300.0 MiB");
        assert_eq!(human(3 * (1 << 20) + (1 << 19)), "3.5 MiB");
        assert_eq!(human(95 << 20), "95 MiB");
        assert_eq!(human(2 << 30), "2 GiB");
        assert_eq!(human((2 << 30) + (1 << 29)), "2.5 GiB");
        assert_eq!(human(3 << 40), "3 TiB");
        assert_eq!(human(u64::MAX), "16777216.0 TiB");
    }

    #[test]
    fn json_values() {
        assert_eq!(human_of(&serde_json::json!(16384)).as_deref(), Some("16 KiB"));
        assert_eq!(human_of(&Value::Null), None);
        assert_eq!(human_of(&serde_json::json!("x")), None);
    }
}
