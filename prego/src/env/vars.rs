//! Release Variable maps: the key rule, input (JSON file, `.env` file, `--set`), and output (env lines,
//! table, diff).

use super::jcs;
use serde_json::{Map, Value};

/// Checks a key: `^[A-Za-z_][A-Za-z0-9_]{0,127}$`.
pub fn check_key(key: &str) -> Result<(), String> {
    let b = key.as_bytes();
    let ok = !b.is_empty()
        && b.len() <= 128
        && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_');
    if ok {
        Ok(())
    } else {
        Err(format!(
            "bad key `{key}`: use A-Z, a-z, 0-9 and `_`, not a digit first, at most 128 characters"
        ))
    }
}

/// Reads a JSON object of variables (`vars.json`).
pub fn from_json(text: &str, name: &str) -> Result<Map<String, Value>, String> {
    let v: Value =
        serde_json::from_str(text).map_err(|e| format!("{name}: not valid JSON: {e}"))?;
    let Value::Object(map) = v else {
        return Err(format!("{name}: give a JSON object of KEY: value"));
    };
    for k in map.keys() {
        check_key(k).map_err(|e| format!("{name}: {e}"))?;
    }
    Ok(map)
}

/// Reads a `.env` file. Every value is a string. Lines: `KEY=value`, `export KEY=value`, `# comment`,
/// blank. A value in single quotes is literal; in double quotes, `\n`, `\t`, `\r`, `\"`, `\\` and `\$` are
/// escapes. An unquoted value ends at ` #` and has its outer spaces removed.
pub fn from_dotenv(text: &str, name: &str) -> Result<Map<String, Value>, String> {
    let mut map = Map::new();
    let mut lines = text.lines().enumerate();
    while let Some((i, line)) = lines.next() {
        let n = i + 1;
        let line = line.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        let (key, rest) = line
            .split_once('=')
            .ok_or_else(|| format!("{name}:{n}: no `=` in the line"))?;
        let key = key.trim_end();
        check_key(key).map_err(|e| format!("{name}:{n}: {e}"))?;
        let rest = rest.trim_start();
        let value = if let Some(body) = rest.strip_prefix('\'') {
            // Single quotes can span lines and have no escapes.
            let mut text = body.to_string();
            loop {
                if let Some(end) = text.find('\'') {
                    check_tail(&text[end + 1..], name, n)?;
                    text.truncate(end);
                    break text;
                }
                let (_, next) = lines
                    .next()
                    .ok_or_else(|| format!("{name}:{n}: no closing `'`"))?;
                text.push('\n');
                text.push_str(next);
            }
        } else if let Some(body) = rest.strip_prefix('"') {
            let mut out = String::new();
            let mut chars: Vec<char> = body.chars().collect();
            let mut j = 0;
            loop {
                if j >= chars.len() {
                    let (_, next) = lines
                        .next()
                        .ok_or_else(|| format!("{name}:{n}: no closing `\"`"))?;
                    out.push('\n');
                    chars = next.chars().collect();
                    j = 0;
                    continue;
                }
                match chars[j] {
                    '"' => {
                        let tail: String = chars[j + 1..].iter().collect();
                        check_tail(&tail, name, n)?;
                        break out;
                    }
                    '\\' if j + 1 < chars.len() => {
                        j += 1;
                        match chars[j] {
                            'n' => out.push('\n'),
                            't' => out.push('\t'),
                            'r' => out.push('\r'),
                            c @ ('"' | '\\' | '$') => out.push(c),
                            // Any other escape stays as it is.
                            c => {
                                out.push('\\');
                                out.push(c);
                            }
                        }
                    }
                    c => out.push(c),
                }
                j += 1;
            }
        } else {
            let end = rest.find(" #").unwrap_or(rest.len());
            rest[..end].trim_end().to_string()
        };
        map.insert(key.to_string(), Value::String(value));
    }
    Ok(map)
}

fn check_tail(tail: &str, name: &str, n: usize) -> Result<(), String> {
    let t = tail.trim_start();
    if t.is_empty() || t.starts_with('#') {
        Ok(())
    } else {
        Err(format!("{name}:{n}: text after the closing quote"))
    }
}

/// Applies `--set KEY=VALUE` (a string) and `--set-json KEY=<JSON>` on top of `map`, in this order.
pub fn apply_sets(
    map: &mut Map<String, Value>,
    sets: &[String],
    set_jsons: &[String],
) -> Result<(), String> {
    for s in sets {
        let (k, v) = s
            .split_once('=')
            .ok_or_else(|| format!("--set `{s}`: use KEY=VALUE"))?;
        check_key(k)?;
        map.insert(k.to_string(), Value::String(v.to_string()));
    }
    for s in set_jsons {
        let (k, v) = s
            .split_once('=')
            .ok_or_else(|| format!("--set-json `{s}`: use KEY=<JSON>"))?;
        check_key(k)?;
        let value: Value =
            serde_json::from_str(v).map_err(|e| format!("--set-json {k}: not valid JSON: {e}"))?;
        map.insert(k.to_string(), value);
    }
    Ok(())
}

/// Puts a value in single quotes for a POSIX shell: `'` becomes `'\''`.
pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// The text of a value for env output: a string as it is, a JSON value as its canonical JSON text.
pub fn value_text(v: &Value) -> Result<String, String> {
    match v {
        Value::String(s) => Ok(s.clone()),
        other => jcs::canonical(other),
    }
}

/// `KEY='value'` lines, sorted by key, every value shell-quoted.
pub fn env_lines(vars: &Map<String, Value>) -> Result<String, String> {
    let mut keys: Vec<&String> = vars.keys().collect();
    keys.sort();
    let mut out = String::new();
    for k in keys {
        // A server key is checked again: it becomes a shell variable name.
        check_key(k)?;
        out.push_str(&format!("{k}={}\n", shell_quote(&value_text(&vars[k])?)));
    }
    Ok(out)
}

/// One change between two versions of a set.
#[derive(Debug, PartialEq, Eq)]
pub enum Change {
    Added(String, String),
    Removed(String, String),
    Changed(String, String, String),
}

/// Key-level diff from `old` to `new`, sorted by key. Values compare by their canonical form.
pub fn diff(old: &Map<String, Value>, new: &Map<String, Value>) -> Result<Vec<Change>, String> {
    let mut keys: Vec<&String> = old.keys().chain(new.keys()).collect();
    keys.sort();
    keys.dedup();
    let mut out = Vec::new();
    for k in keys {
        match (old.get(k), new.get(k)) {
            (None, Some(n)) => out.push(Change::Added(k.clone(), jcs::canonical(n)?)),
            (Some(o), None) => out.push(Change::Removed(k.clone(), jcs::canonical(o)?)),
            (Some(o), Some(n)) => {
                let (o, n) = (jcs::canonical(o)?, jcs::canonical(n)?);
                if o != n {
                    out.push(Change::Changed(k.clone(), o, n));
                }
            }
            (None, None) => {}
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keys() {
        for ok in ["A", "_", "API_BASE_URL", "a1", &"K".repeat(128)] {
            assert!(check_key(ok).is_ok(), "{ok}");
        }
        for bad in ["", "1A", "A-B", "A.B", "A B", "Ä", &"K".repeat(129)] {
            assert!(check_key(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn json_input_must_be_an_object_with_good_keys() {
        assert!(from_json("[1]", "f").is_err());
        assert!(from_json(r#"{"a-b":1}"#, "f").is_err());
        assert!(from_json("{", "f").is_err());
        let m = from_json(r#"{"A":1,"B":{"x":[true]}}"#, "f").unwrap();
        assert_eq!(m["B"], json!({"x":[true]}));
    }

    #[test]
    fn dotenv_values_are_strings() {
        let text = "# comment\n\
                    \n\
                    A=1\n\
                    export B = true \n\
                    C=plain value # note\n\
                    D='keep $HOME \\n' # c\n\
                    E=\"line\\nnext \\\"q\\\" \\$X \\d\"\n\
                    F='two\n\
                    lines'\n\
                    G=\n\
                    H=a#b\n";
        let m = from_dotenv(text, ".env").unwrap();
        assert_eq!(m["A"], json!("1"));
        assert_eq!(m["B"], json!("true"));
        assert_eq!(m["C"], json!("plain value"));
        assert_eq!(m["D"], json!("keep $HOME \\n"));
        assert!(from_dotenv("D='it''s'\n", "x").is_err());
        assert_eq!(m["E"], json!("line\nnext \"q\" $X \\d"));
        assert_eq!(m["F"], json!("two\nlines"));
        assert_eq!(m["G"], json!(""));
        assert_eq!(m["H"], json!("a#b"));
        assert!(m.values().all(Value::is_string));
        assert!(from_dotenv("NOEQUALS\n", "x").is_err());
        assert!(from_dotenv("1A=x\n", "x").is_err());
        assert!(from_dotenv("A='open\n", "x").is_err());
        assert!(from_dotenv("A=\"x\" y\n", "x").is_err());
    }

    #[test]
    fn sets_go_on_top() {
        let mut m = from_json(r#"{"A":"file","B":1}"#, "f").unwrap();
        apply_sets(
            &mut m,
            &["A=flag=with=equals".into()],
            &["B={\"x\":1}".into(), "C=null".into()],
        )
        .unwrap();
        assert_eq!(m["A"], json!("flag=with=equals"));
        assert_eq!(m["B"], json!({"x":1}));
        assert_eq!(m["C"], json!(null));
        assert!(apply_sets(&mut m, &["NOVALUE".into()], &[]).is_err());
        assert!(apply_sets(&mut m, &[], &["J={".into()]).is_err());
        assert!(apply_sets(&mut m, &["bad-key=1".into()], &[]).is_err());
    }

    #[test]
    fn env_output_is_shell_quoted() {
        let vars = from_json(
            r#"{"Z":"it's $(rm -rf /) `x` \"q\"","A":{"b":2,"a":[1.0]},"N":null,"S":""}"#,
            "f",
        )
        .unwrap();
        assert_eq!(
            env_lines(&vars).unwrap(),
            "A='{\"a\":[1],\"b\":2}'\nN='null'\nS=''\nZ='it'\\''s $(rm -rf /) `x` \"q\"'\n"
        );
        // A key the server should never send is refused, not printed.
        let mut bad = Map::new();
        bad.insert("A;rm".into(), json!("x"));
        assert!(env_lines(&bad).is_err());
    }

    #[test]
    fn diff_by_key() {
        let old = from_json(r#"{"A":1,"B":"x","C":[1]}"#, "f").unwrap();
        let new = from_json(r#"{"A":1.0,"B":"y","D":true}"#, "f").unwrap();
        assert_eq!(
            diff(&old, &new).unwrap(),
            vec![
                Change::Changed("B".into(), "\"x\"".into(), "\"y\"".into()),
                Change::Removed("C".into(), "[1]".into()),
                Change::Added("D".into(), "true".into()),
            ]
        );
    }
}
