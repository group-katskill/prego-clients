//! `prego env`: Release Variables. Plain release settings stored in Prego next to the release. They are not
//! secrets: everyone who can pull the release can read them.

pub mod jcs;
pub mod reference;
pub mod vars;

use prego_auth::http::{Body, FullResponse, Http};
use prego_auth::{Config, Env, FileConfig};
use reference::{Level, Ref};
use serde_json::{json, Map, Value};
use std::io::IsTerminal;

/// The line that the help, the docs and the console show.
pub const NOT_SECRETS: &str =
    "Release Variables are plain text, readable by everyone who can pull the \
release. Do not store passwords, tokens or keys here.";

/// The exit code when `--expect` does not match.
pub const EXIT_EXPECT: i32 = 3;

/// Output format of `prego env pull`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Env,
    Json,
    Flat,
}

impl Format {
    pub fn parse(s: &str) -> Result<Format, String> {
        match s {
            "env" => Ok(Format::Env),
            "json" => Ok(Format::Json),
            "flat" => Ok(Format::Flat),
            _ => Err(format!("--format `{s}` is not env, json or flat")),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum EnvCommand {
    Pull {
        reference: String,
        format: Option<Format>,
        expect: Option<String>,
        out: Option<String>,
    },
    Push {
        reference: String,
        level: Level,
        file: Option<String>,
        env_file: Option<String>,
        sets: Vec<String>,
        set_jsons: Vec<String>,
        message: Option<String>,
        if_current: Option<String>,
    },
    History {
        reference: String,
        level: Level,
    },
    Rollback {
        reference: String,
        level: Level,
        to: u64,
        reason: String,
    },
    Diff {
        reference: String,
        level: Level,
        from: u64,
        to: u64,
    },
    Hash {
        file: String,
    },
}

pub fn run(globals: &[&str], command: &EnvCommand, env: &dyn Env) -> Result<(), String> {
    match command {
        EnvCommand::Hash { file } => {
            let text = read_input(file)?;
            let map = vars::from_json(&text, file)?;
            println!("{}", jcs::hash(&Value::Object(map))?);
            Ok(())
        }
        EnvCommand::Pull {
            reference,
            format,
            expect,
            out,
        } => {
            let r = Ref::parse(reference, Level::Version)?;
            pull(
                &Api::new(globals, &r, env)?,
                &r,
                *format,
                expect.as_deref(),
                out.as_deref(),
            )
        }
        EnvCommand::Push {
            reference,
            level,
            file,
            env_file,
            sets,
            set_jsons,
            message,
            if_current,
        } => {
            let r = Ref::parse(reference, *level)?;
            let mut map = match (file, env_file) {
                (Some(f), None) => vars::from_json(&read_input(f)?, f)?,
                (None, Some(f)) => vars::from_dotenv(&read_input(f)?, f)?,
                (None, None) => Map::new(),
                (Some(_), Some(_)) => {
                    return Err("prego: give --file or --env-file, not both".into())
                }
            };
            vars::apply_sets(&mut map, sets, set_jsons).map_err(|e| format!("prego: {e}"))?;
            let api = Api::new(globals, &r, env)?;
            push(&api, &r, map, message.as_deref(), if_current.as_deref())
        }
        EnvCommand::History { reference, level } => {
            let r = Ref::parse(reference, *level)?;
            history(&Api::new(globals, &r, env)?, &r)
        }
        EnvCommand::Rollback {
            reference,
            level,
            to,
            reason,
        } => {
            let r = Ref::parse(reference, *level)?;
            rollback(&Api::new(globals, &r, env)?, &r, *to, reason)
        }
        EnvCommand::Diff {
            reference,
            level,
            from,
            to,
        } => {
            let r = Ref::parse(reference, *level)?;
            diff(&Api::new(globals, &r, env)?, &r, *from, *to)
        }
    }
}

/// Reads a file, or stdin for `-`.
fn read_input(path: &str) -> Result<String, String> {
    if path == "-" {
        let mut s = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)
            .map_err(|e| format!("prego: stdin: {e}"))?;
        return Ok(s);
    }
    std::fs::read_to_string(path).map_err(|e| format!("prego: {path}: {e}"))
}

/// The machine routes `/v1/vars/*` on the STS host, with a registry token.
struct Api {
    http: Http,
    base: String,
    auth: String,
}

impl Api {
    /// Gets a registry token. The token's tenant is the configured tenant (for a cross-tenant pull, the
    /// grantee); with no tenant configured, it is the tenant of the reference.
    fn new(globals: &[&str], r: &Ref, env: &dyn Env) -> Result<Api, String> {
        let file = FileConfig::load(env).map_err(|e| e.to_string())?;
        let has_tenant = globals.iter().any(|g| g.starts_with("--tenant="))
            || env.var("PREGO_TENANT").is_some()
            || file.tenant.is_some();
        let tenant_arg = format!("--tenant={}", r.tenant);
        let mut all: Vec<&str> = globals.to_vec();
        if !has_tenant {
            all.push(&tenant_arg);
        }
        let config = Config::from_parts(&all, env, &file).map_err(|e| e.to_string())?;
        let base = config
            .sts_url
            .strip_suffix("/v1/sts/token")
            .ok_or_else(|| {
                format!(
                    "prego: the STS URL `{}` does not end in /v1/sts/token",
                    config.sts_url
                )
            })?
            .to_string();
        let (_, token) = crate::token::registry_token(&config, &[], None, env)?;
        let http = Http::with_ca_file(crate::USER_AGENT, config.ca_file.as_deref())
            .map_err(|e| format!("prego: PREGO_CA_FILE: {e}"))?;
        Ok(Api {
            http,
            base,
            auth: format!("Bearer {}", token.token.expose()),
        })
    }

    fn call(&self, method: &str, path: &str, body: Option<&Value>) -> Result<FullResponse, String> {
        let url = format!("{}/v1/vars/{path}", self.base);
        let text = body.map(Value::to_string);
        let mut headers = vec![
            ("Authorization", self.auth.as_str()),
            ("Accept", "application/json"),
        ];
        if text.is_some() {
            headers.push(("Content-Type", "application/json"));
        }
        let body = match &text {
            Some(t) => Body::Bytes(t.as_bytes()),
            None => Body::Empty,
        };
        self.http
            .send(method, &url, &headers, body)
            .map_err(|e| format!("prego: {url}: {e}"))
    }

    /// A 2xx JSON body, or an error with the server's message.
    fn json(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
        what: &str,
    ) -> Result<(u16, Value), String> {
        let res = self.call(method, path, body)?;
        if !(200..300).contains(&res.status) {
            return Err(api_error(&res, what));
        }
        let v = serde_json::from_str(&res.body)
            .map_err(|e| format!("prego: {what}: the answer is not JSON: {e}"))?;
        Ok((res.status, v))
    }

    /// The current version of a set, or version `number`.
    fn set(&self, r: &Ref, number: Option<u64>) -> Result<Value, String> {
        let mut q = r.fields();
        if let Some(n) = number {
            q.push(("version_number", n.to_string()));
        }
        let what = match number {
            Some(n) => format!("version {n} of the {} set of {}", r.level.name(), r.long()),
            None => format!("the {} set of {}", r.level.name(), r.long()),
        };
        Ok(self
            .json("GET", &format!("sets?{}", query(&q)), None, &what)?
            .1)
    }
}

/// The error text for a refused request. `404` means no set or no grant: the registry does not say which.
fn api_error(res: &FullResponse, what: &str) -> String {
    let body: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
    let err = &body["error"];
    let code = err["code"].as_str().or(err.as_str()).unwrap_or("");
    let message = err["message"]
        .as_str()
        .or(body["message"].as_str())
        .unwrap_or("");
    let mut msg = match res.status {
        404 => format!("prego: {what}: not found, or you have no grant for it"),
        401 => format!("prego: {what}: the registry refused the token (401). {message}"),
        _ => format!("prego: {what}: {} {code}: {message}", res.status),
    };
    if let Some(keys) = err["keys"].as_array() {
        let keys: Vec<String> = keys.iter().map(text).collect();
        msg.push_str(&format!(" (keys: {})", keys.join(", ")));
    }
    if let Some(f) = err["field"].as_str() {
        msg.push_str(&format!(" (field: {f})"));
    }
    if code == "conflict" {
        if let Some(h) = err.get("current_hash") {
            msg.push_str(&format!(" (current hash: {})", text(h)));
        }
    }
    if let Some(s) = res.header("retry-after") {
        msg.push_str(&format!(" (retry after {s} s)"));
    }
    if let Some(id) = err["request_id"].as_str() {
        msg.push_str(&format!(" (request {id})"));
    }
    if code == "looks_like_secret" {
        msg.push_str(&format!("\n{NOT_SECRETS}"));
    }
    msg
}

/// URL query text with percent-encoding of everything but the unreserved characters.
fn query(pairs: &[(&str, String)]) -> String {
    let enc = |s: &str| {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    (b as char).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect::<String>()
    };
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn text(v: &Value) -> String {
    match v {
        Value::Null => "-".into(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// The plain `{key: value}` map of a set or resolve answer. The answer gives each variable as
/// `{"value": ..., "type": ..., ...}`.
fn plain(variables: &Value) -> Result<Map<String, Value>, String> {
    let Value::Object(m) = variables else {
        return Err("prego: the answer has no variables object".into());
    };
    let wrapped = m.values().all(|x| {
        x.get("value").is_some()
            && matches!(
                x.get("type").and_then(Value::as_str),
                Some("string" | "json")
            )
    });
    Ok(m.iter()
        .map(|(k, x)| {
            (
                k.clone(),
                if wrapped {
                    x["value"].clone()
                } else {
                    x.clone()
                },
            )
        })
        .collect())
}

fn pull(
    api: &Api,
    r: &Ref,
    format: Option<Format>,
    expect: Option<&str>,
    out: Option<&str>,
) -> Result<(), String> {
    let what = format!("the variables of {}", r.long());
    let path = format!("resolve?{}", query(&[("ref", r.long())]));
    let (_, answer) = api.json("GET", &path, None, &what)?;
    let flat = plain(&answer["variables"])?;
    // The hash is computed here too, so a changed answer cannot pass `--expect`.
    let local = jcs::hash(&Value::Object(flat.clone()))?;
    let server = answer["resolved_hash"].as_str().unwrap_or("");
    if server != local {
        return Err(format!(
            "prego: {what}: the resolved hash in the answer ({server}) is not the hash of the variables ({local})"
        ));
    }
    if let Some(want) = expect {
        if want != local {
            eprintln!(
                "prego: {}: the resolved hash is {local}, not the expected {want}",
                r.long()
            );
            std::process::exit(EXIT_EXPECT);
        }
    }
    let to_terminal = out.is_none() && std::io::stdout().is_terminal();
    let text = match format {
        Some(Format::Json) => format!("{:#}\n", answer),
        Some(Format::Flat) => format!("{:#}\n", Value::Object(flat)),
        None if to_terminal => table(r, &answer, &local)?,
        _ => {
            // The same header as the registry's `format=env`.
            let mut t = format!("# ref {}\n# resolved_hash {local}\n", r.long());
            for l in answer["levels"].as_array().into_iter().flatten() {
                t.push_str(&format!(
                    "# {} {} {} {}\n",
                    text(&l["level"]),
                    text(&l["set_id"]),
                    text(&l["version"]),
                    text(&l["hash"])
                ));
            }
            t.push_str(&vars::env_lines(&flat)?);
            t
        }
    };
    match out {
        None => print!("{text}"),
        Some(path) => write_atomic(path, &text)?,
    }
    Ok(())
}

/// The terminal view: one line per key with the level it came from.
fn table(r: &Ref, answer: &Value, hash: &str) -> Result<String, String> {
    let mut t = format!("{}  {hash}\n", r.long());
    let Value::Object(m) = &answer["variables"] else {
        return Ok(t);
    };
    if m.is_empty() {
        t.push_str("(no variables)\n");
        return Ok(t);
    }
    let width = m.keys().map(String::len).max().unwrap_or(0);
    let mut keys: Vec<&String> = m.keys().collect();
    keys.sort();
    for k in keys {
        let x = &m[k];
        let value = x.get("value").unwrap_or(x);
        let from = x.get("from").and_then(Value::as_str).unwrap_or("");
        t.push_str(&format!(
            "{k:width$}  {from:9}  {}\n",
            vars::value_text(value)?
        ));
    }
    Ok(t)
}

pub(crate) fn write_atomic(path: &str, text: &str) -> Result<(), String> {
    let p = std::path::Path::new(path);
    let tmp = p.with_extension("prego-tmp");
    std::fs::write(&tmp, text).map_err(|e| format!("prego: {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, p).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("prego: {path}: {e}")
    })
}

fn push(
    api: &Api,
    r: &Ref,
    map: Map<String, Value>,
    message: Option<&str>,
    if_current: Option<&str>,
) -> Result<(), String> {
    let local = jcs::hash(&Value::Object(map.clone()))?;
    let mut body = Map::new();
    for (k, v) in r.fields() {
        body.insert(k.into(), Value::String(v));
    }
    body.insert("variables".into(), Value::Object(map));
    if let Some(m) = message {
        body.insert("message".into(), json!(m));
    }
    if let Some(h) = if_current {
        body.insert("if_current".into(), json!(h));
    }
    let what = format!("push to the {} set of {}", r.level.name(), r.long());
    let (_, answer) = api.json("PUT", "sets", Some(&Value::Object(body)), &what)?;
    let hash = answer["version"]["hash"].as_str().unwrap_or("");
    let version = text(&answer["version"]["number"]);
    if !hash.is_empty() && hash != local {
        eprintln!("prego: warning: the registry hash {hash} is not the local hash {local}");
    }
    for w in answer["warnings"].as_array().into_iter().flatten() {
        if w["code"] == "secret_like_key" {
            eprintln!(
                "prego: warning: the name of {} looks like a secret. {NOT_SECRETS}",
                text(&w["key"])
            );
        } else {
            eprintln!("prego: warning: {} {}", text(&w["key"]), text(&w["code"]));
        }
    }
    if answer["created"] == true {
        println!(
            "{}: {} set version {version} ({hash})",
            r.long(),
            r.level.name()
        );
    } else {
        println!(
            "{}: no change, {} set version {version} is current ({hash})",
            r.long(),
            r.level.name()
        );
    }
    Ok(())
}

fn set_id(set: &Value) -> Result<String, String> {
    set["id"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| "prego: the answer has no set id".into())
}

fn history(api: &Api, r: &Ref) -> Result<(), String> {
    let set = api.set(r, None)?;
    let id = set_id(&set)?;
    let what = format!("the history of {}", r.long());
    let (_, answer) = api.json(
        "GET",
        &format!("sets/{}/versions", query_part(&id)),
        None,
        &what,
    )?;
    let list = answer["items"]
        .as_array()
        .ok_or_else(|| format!("prego: {what}: the answer has no version list"))?;
    println!("{} ({} set {id})", r.long(), r.level.name());
    for v in list {
        let mark = if v["current"] == true { "*" } else { " " };
        println!(
            "{mark}{:>5}  {}  {:>8} B  {:>4} keys  {}  {}  {}",
            text(&v["number"]),
            text(&v["hash"]),
            text(&v["size_bytes"]),
            text(&v["key_count"]),
            text(&v["created_at"]),
            text(&v["pushed_by"]),
            v["message"].as_str().unwrap_or("")
        );
    }
    Ok(())
}

/// A set id is `rvs_` and base32 text. Encode it anyway: it goes into the path.
fn query_part(s: &str) -> String {
    query(&[("x", s.to_string())])[2..].to_string()
}

fn rollback(api: &Api, r: &Ref, to: u64, reason: &str) -> Result<(), String> {
    let set = api.set(r, None)?;
    let id = set_id(&set)?;
    let what = format!("move the current version of {}", r.long());
    let body = json!({ "version": to, "reason": reason });
    let (_, answer) = api.json(
        "POST",
        &format!("sets/{}/current", query_part(&id)),
        Some(&body),
        &what,
    )?;
    println!(
        "{}: current {} set version is now {} ({})",
        r.long(),
        r.level.name(),
        text(&answer["current_version"]),
        text(&answer["current_hash"])
    );
    Ok(())
}

fn diff(api: &Api, r: &Ref, from: u64, to: u64) -> Result<(), String> {
    let old = plain(&api.set(r, Some(from))?["variables"])?;
    let new = plain(&api.set(r, Some(to))?["variables"])?;
    let changes = vars::diff(&old, &new)?;
    if changes.is_empty() {
        println!("no changes from version {from} to version {to}");
    }
    for c in changes {
        match c {
            vars::Change::Added(k, v) => println!("+ {k} = {v}"),
            vars::Change::Removed(k, v) => println!("- {k} = {v}"),
            vars::Change::Changed(k, o, n) => println!("~ {k} = {o} -> {n}"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_is_percent_encoded() {
        assert_eq!(
            query(&[
                ("ref", "acme/default/apps/web@1.0.0+b".into()),
                ("level", "version".into())
            ]),
            "ref=acme%2Fdefault%2Fapps%2Fweb%401.0.0%2Bb&level=version"
        );
        assert_eq!(query_part("rvs_01ABC"), "rvs_01ABC");
    }

    #[test]
    fn plain_unwraps_the_answer_form() {
        let a = json!({"A": {"value": {"x": 1}, "type": "json", "from": "version"},
                       "B": {"value": "s", "type": "string", "from": "tenant"}});
        assert_eq!(
            Value::Object(plain(&a).unwrap()),
            json!({"A": {"x": 1}, "B": "s"})
        );
        let b = json!({"A": 1, "B": {"value": 2}});
        assert_eq!(Value::Object(plain(&b).unwrap()), b);
        assert!(plain(&json!([1])).is_err());
    }

    #[test]
    fn error_text() {
        let res = |status, body: &str| FullResponse {
            status,
            headers: vec![],
            body: body.into(),
        };
        assert_eq!(
            api_error(&res(404, ""), "x"),
            "prego: x: not found, or you have no grant for it"
        );
        let t = api_error(
            &res(
                422,
                r#"{"error":{"code":"looks_like_secret","message":"API_KEY looks like a secret","keys":["API_KEY"],"request_id":"r1"}}"#,
            ),
            "push",
        );
        assert!(t.starts_with("prego: push: 422 looks_like_secret: API_KEY looks like a secret (keys: API_KEY) (request r1)\n"));
        assert!(t.ends_with(NOT_SECRETS));
        let t = api_error(
            &res(
                409,
                r#"{"error":{"code":"conflict","message":"the current hash differs","current_hash":null}}"#,
            ),
            "push",
        );
        assert_eq!(
            t,
            "prego: push: 409 conflict: the current hash differs (current hash: -)"
        );
    }
}
