//! `prego a2a upgrade`: converts an A2A 0.3 Agent Card to an A2A 1.0 card, offline (ADR-0062 section 5).
//! Every field change is reported. A field that cannot be mapped with certainty stops the upgrade and is
//! named by its JSON pointer. The output has no signatures: the user signs the new card.
//!
//! Written from the A2A 0.3 specification (section 5.5), the A2A 1.0 proto (tag v1.0.1) and the upgrade
//! rules of the shared test vectors (`tests/vectors/a2a/README.md`):
//! - `url` and `preferredTransport` (default `JSONRPC`) become `supportedInterfaces[0]`; each
//!   `additionalInterfaces` entry becomes one more interface (`transport` becomes `protocolBinding`); an entry
//!   with the same URL and transport as the first one is removed. Each interface gets `protocolVersion: "0.3"`:
//!   the agent still serves A2A 0.3 at that URL.
//! - `supportsAuthenticatedExtendedCard` becomes `capabilities.extendedAgentCard`;
//!   `capabilities.stateTransitionHistory` is removed.
//! - `security` becomes `securityRequirements` (`[{"schemes": {<name>: {"list": [...]}}}]`), on the card and
//!   on each skill. Each security scheme becomes the 1.0 oneof form (`apiKey` `in` becomes `location`).
//! - `signatures` is removed.

use serde_json::{json, Map, Value};

/// The result: the 1.0 card and the list of changes, one line each.
pub struct Upgraded {
    pub card: Value,
    pub changes: Vec<String>,
}

/// Why the upgrade stopped: the JSON pointer of the field and the reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stop {
    pub field: String,
    pub reason: String,
}

impl std::fmt::Display for Stop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let field = if self.field.is_empty() {
            "(the card)"
        } else {
            &self.field
        };
        write!(f, "cannot upgrade {field}: {}", self.reason)
    }
}

fn stop(field: &str, reason: impl Into<String>) -> Stop {
    Stop {
        field: field.to_string(),
        reason: reason.into(),
    }
}

fn ptr(path: &str, key: &str) -> String {
    format!("{path}/{}", key.replace('~', "~0").replace('/', "~1"))
}

const UNKNOWN: &str = "not an A2A 0.3 field; the upgrade cannot map it";

fn obj<'a>(v: &'a Value, field: &str) -> Result<&'a Map<String, Value>, Stop> {
    v.as_object().ok_or_else(|| stop(field, "expected object"))
}

fn arr<'a>(v: &'a Value, field: &str) -> Result<&'a Vec<Value>, Stop> {
    v.as_array().ok_or_else(|| stop(field, "expected array"))
}

fn only_keys(o: &Map<String, Value>, field: &str, known: &[&str]) -> Result<(), Stop> {
    match o.keys().find(|k| !known.contains(&k.as_str())) {
        Some(k) => Err(stop(&ptr(field, k), UNKNOWN)),
        None => Ok(()),
    }
}

fn requirements(v: &Value, field: &str) -> Result<Value, Stop> {
    let mut out = Vec::new();
    for (i, item) in arr(v, field)?.iter().enumerate() {
        let here = format!("{field}/{i}");
        let mut schemes = Map::new();
        for (name, scopes) in obj(item, &here)? {
            let s = scopes
                .as_array()
                .filter(|a| a.iter().all(Value::is_string))
                .ok_or_else(|| stop(&ptr(&here, name), "expected array of strings"))?;
            schemes.insert(name.clone(), json!({ "list": s }));
        }
        out.push(json!({ "schemes": schemes }));
    }
    Ok(Value::Array(out))
}

fn copy(from: &Map<String, Value>, to: &mut Map<String, Value>, keys: &[(&str, &str)]) {
    for (a, b) in keys {
        if let Some(v) = from.get(*a) {
            to.insert((*b).to_string(), v.clone());
        }
    }
}

fn scheme(name: &str, v: &Value, changes: &mut Vec<String>) -> Result<Value, Stop> {
    let field = ptr("/securitySchemes", name);
    let o = obj(v, &field)?;
    let kind = o
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| stop(&ptr(&field, "type"), "the scheme has no type"))?;
    let mut inner = Map::new();
    let wrapper = match kind {
        "apiKey" => {
            only_keys(o, &field, &["type", "description", "in", "name"])?;
            copy(
                o,
                &mut inner,
                &[
                    ("description", "description"),
                    ("in", "location"),
                    ("name", "name"),
                ],
            );
            "apiKeySecurityScheme"
        }
        "http" => {
            only_keys(
                o,
                &field,
                &["type", "description", "scheme", "bearerFormat"],
            )?;
            copy(
                o,
                &mut inner,
                &[
                    ("description", "description"),
                    ("scheme", "scheme"),
                    ("bearerFormat", "bearerFormat"),
                ],
            );
            "httpAuthSecurityScheme"
        }
        "oauth2" => {
            only_keys(
                o,
                &field,
                &["type", "description", "flows", "oauth2MetadataUrl"],
            )?;
            copy(
                o,
                &mut inner,
                &[
                    ("description", "description"),
                    ("oauth2MetadataUrl", "oauth2MetadataUrl"),
                ],
            );
            let ff = ptr(&field, "flows");
            let flows = obj(o.get("flows").unwrap_or(&Value::Null), &ff)?;
            if flows.len() != 1 {
                return Err(stop(
                    &ff,
                    format!(
                        "A2A 1.0 allows one OAuth flow per scheme; this scheme has {}. Split it into two schemes, then \
                         run the upgrade again.",
                        flows.len()
                    ),
                ));
            }
            let (flow, body) = flows.iter().next().expect("one flow");
            let fp = ptr(&ff, flow);
            let known: &[&str] = match flow.as_str() {
                "authorizationCode" => &["authorizationUrl", "tokenUrl", "refreshUrl", "scopes"],
                "clientCredentials" => &["tokenUrl", "refreshUrl", "scopes"],
                "implicit" => &["authorizationUrl", "refreshUrl", "scopes"],
                "password" => &["tokenUrl", "refreshUrl", "scopes"],
                _ => return Err(stop(&fp, UNKNOWN)),
            };
            only_keys(obj(body, &fp)?, &fp, known)?;
            if matches!(flow.as_str(), "implicit" | "password") {
                changes.push(format!(
                    "! {fp}: kept, but A2A 1.0 marks this flow as deprecated"
                ));
            }
            inner.insert("flows".into(), json!({ flow.clone(): body.clone() }));
            "oauth2SecurityScheme"
        }
        "openIdConnect" => {
            only_keys(o, &field, &["type", "description", "openIdConnectUrl"])?;
            copy(
                o,
                &mut inner,
                &[
                    ("description", "description"),
                    ("openIdConnectUrl", "openIdConnectUrl"),
                ],
            );
            "openIdConnectSecurityScheme"
        }
        "mutualTLS" => {
            only_keys(o, &field, &["type", "description"])?;
            copy(o, &mut inner, &[("description", "description")]);
            "mtlsSecurityScheme"
        }
        other => {
            return Err(stop(
                &ptr(&field, "type"),
                format!("security scheme type {other} has no A2A 1.0 form"),
            ))
        }
    };
    changes.push(format!("~ {field}: type {kind} -> {field}/{wrapper}"));
    if kind == "apiKey" && o.contains_key("in") {
        changes.push(format!("~ {field}/in -> {field}/{wrapper}/location"));
    }
    Ok(json!({ wrapper: inner }))
}

/// Converts a 0.3 card.
pub fn upgrade(card: &Value) -> Result<Upgraded, Stop> {
    let o = card
        .as_object()
        .ok_or_else(|| stop("", "expected object"))?;
    let pv = match o.get("protocolVersion") {
        None => "0.3.0".to_string(),
        Some(Value::String(v)) => v.clone(),
        Some(_) => return Err(stop("/protocolVersion", "expected string")),
    };
    if pv != "0.3" && !pv.starts_with("0.3.") {
        return Err(stop(
            "/protocolVersion",
            format!("the upgrade reads A2A 0.3 cards only; this card says {pv}"),
        ));
    }
    if !o.contains_key("url") && o.contains_key("supportedInterfaces") {
        return Err(stop(
            "/supportedInterfaces",
            "the upgrade reads A2A 0.3 cards only; this card is A2A 1.0",
        ));
    }
    only_keys(
        o,
        "",
        &[
            "protocolVersion",
            "name",
            "description",
            "url",
            "preferredTransport",
            "additionalInterfaces",
            "iconUrl",
            "provider",
            "version",
            "documentationUrl",
            "capabilities",
            "securitySchemes",
            "security",
            "defaultInputModes",
            "defaultOutputModes",
            "skills",
            "supportsAuthenticatedExtendedCard",
            "signatures",
        ],
    )?;
    let mut changes = Vec::new();
    let mut out = Map::new();
    let get = |k: &str| o.get(k).cloned();

    for k in ["name", "description"] {
        if let Some(v) = get(k) {
            out.insert(k.into(), v);
        }
    }

    // Interfaces.
    if o.contains_key("protocolVersion") {
        changes.push(format!(
            "- /protocolVersion {pv}: the card format is now 1.0"
        ));
    }
    let url = o
        .get("url")
        .and_then(Value::as_str)
        .ok_or_else(|| stop("/url", "the 0.3 card has no url"))?;
    let binding = match o.get("preferredTransport") {
        Some(Value::String(t)) => t.clone(),
        Some(_) => return Err(stop("/preferredTransport", "expected string")),
        None => {
            changes
                .push("+ /supportedInterfaces/0/protocolBinding JSONRPC: the 0.3 default".into());
            "JSONRPC".to_string()
        }
    };
    let mut interfaces =
        vec![json!({"url": url, "protocolBinding": binding, "protocolVersion": "0.3"})];
    changes.push("~ /url -> /supportedInterfaces/0/url".into());
    if o.contains_key("preferredTransport") {
        changes.push("~ /preferredTransport -> /supportedInterfaces/0/protocolBinding".into());
    }
    if let Some(extra) = o.get("additionalInterfaces") {
        for (i, item) in arr(extra, "/additionalInterfaces")?.iter().enumerate() {
            let f = format!("/additionalInterfaces/{i}");
            let io = obj(item, &f)?;
            only_keys(io, &f, &["url", "transport"])?;
            let u = io
                .get("url")
                .and_then(Value::as_str)
                .ok_or_else(|| stop(&ptr(&f, "url"), "expected string"))?;
            let t = io
                .get("transport")
                .and_then(Value::as_str)
                .ok_or_else(|| stop(&ptr(&f, "transport"), "expected string"))?;
            if u == url && t == binding {
                changes.push(format!("- {f}: the same as the first interface"));
                continue;
            }
            interfaces.push(json!({"url": u, "protocolBinding": t, "protocolVersion": "0.3"}));
            changes.push(format!(
                "~ {f} -> /supportedInterfaces/{} (transport -> protocolBinding)",
                interfaces.len() - 1
            ));
        }
    }
    changes.push(
        "+ /supportedInterfaces/*/protocolVersion \"0.3\": the agent still serves A2A 0.3 at these URLs; change it \
         when the agent serves 1.0"
            .into(),
    );
    out.insert("supportedInterfaces".into(), Value::Array(interfaces));

    if let Some(p) = get("provider") {
        only_keys(obj(&p, "/provider")?, "/provider", &["organization", "url"])?;
        out.insert("provider".into(), p);
    }
    if let Some(v) = get("version") {
        out.insert("version".into(), v);
    }
    if let Some(v) = get("documentationUrl") {
        out.insert("documentationUrl".into(), v);
    }

    // Capabilities.
    let mut caps = Map::new();
    if let Some(c) = get("capabilities") {
        let co = obj(&c, "/capabilities")?;
        only_keys(
            co,
            "/capabilities",
            &[
                "streaming",
                "pushNotifications",
                "stateTransitionHistory",
                "extensions",
            ],
        )?;
        copy(
            co,
            &mut caps,
            &[
                ("streaming", "streaming"),
                ("pushNotifications", "pushNotifications"),
            ],
        );
        if let Some(exts) = co.get("extensions") {
            for (i, e) in arr(exts, "/capabilities/extensions")?.iter().enumerate() {
                let f = format!("/capabilities/extensions/{i}");
                only_keys(
                    obj(e, &f)?,
                    &f,
                    &["uri", "description", "required", "params"],
                )?;
            }
            caps.insert("extensions".into(), exts.clone());
        }
        if co.contains_key("stateTransitionHistory") {
            changes.push("- /capabilities/stateTransitionHistory: not in A2A 1.0".into());
        }
    }
    if let Some(v) = o.get("supportsAuthenticatedExtendedCard") {
        caps.insert("extendedAgentCard".into(), v.clone());
        changes
            .push("~ /supportsAuthenticatedExtendedCard -> /capabilities/extendedAgentCard".into());
    }
    out.insert("capabilities".into(), Value::Object(caps));

    // Security.
    if let Some(s) = get("securitySchemes") {
        let mut schemes = Map::new();
        for (name, v) in obj(&s, "/securitySchemes")? {
            schemes.insert(name.clone(), scheme(name, v, &mut changes)?);
        }
        out.insert("securitySchemes".into(), Value::Object(schemes));
    }
    if let Some(s) = get("security") {
        out.insert(
            "securityRequirements".into(),
            requirements(&s, "/security")?,
        );
        changes.push(
            "~ /security -> /securityRequirements ({\"schemes\": {<name>: {\"list\": [...]}}})"
                .into(),
        );
    }

    for k in ["defaultInputModes", "defaultOutputModes"] {
        if let Some(v) = get(k) {
            out.insert(k.into(), v);
        }
    }

    // Skills.
    if let Some(s) = get("skills") {
        let mut skills = Vec::new();
        for (i, sk) in arr(&s, "/skills")?.iter().enumerate() {
            let f = format!("/skills/{i}");
            let so = obj(sk, &f)?;
            only_keys(
                so,
                &f,
                &[
                    "id",
                    "name",
                    "description",
                    "tags",
                    "examples",
                    "inputModes",
                    "outputModes",
                    "security",
                ],
            )?;
            let mut n = Map::new();
            copy(
                so,
                &mut n,
                &[
                    ("id", "id"),
                    ("name", "name"),
                    ("description", "description"),
                    ("tags", "tags"),
                    ("examples", "examples"),
                    ("inputModes", "inputModes"),
                    ("outputModes", "outputModes"),
                ],
            );
            if let Some(sec) = so.get("security") {
                n.insert(
                    "securityRequirements".into(),
                    requirements(sec, &format!("{f}/security"))?,
                );
                changes.push(format!("~ {f}/security -> {f}/securityRequirements"));
            }
            skills.push(Value::Object(n));
        }
        out.insert("skills".into(), Value::Array(skills));
    }
    if let Some(v) = get("iconUrl") {
        out.insert("iconUrl".into(), v);
    }
    if let Some(sigs) = o.get("signatures") {
        let n = sigs.as_array().map(Vec::len).unwrap_or(0);
        changes.push(format!(
            "- /signatures: {n} removed (they sign the 0.3 card; sign the 1.0 card again)"
        ));
    }
    let card = Value::Object(out);
    if let Err(p) = super::card::check(&card) {
        return Err(match p {
            super::card::Problem::Invalid { path, reason } => {
                stop(&path, format!("the 1.0 card is not valid ({reason}); fix the 0.3 card, then run the upgrade again"))
            }
            super::card::Problem::V03(reason) => stop("", reason),
        });
    }
    Ok(Upgraded { card, changes })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v03() -> Value {
        json!({
            "protocolVersion": "0.3.0",
            "name": "Support bot",
            "description": "Answers questions",
            "url": "https://agent.example.com/a2a",
            "preferredTransport": "JSONRPC",
            "additionalInterfaces": [
                {"url": "https://agent.example.com/a2a", "transport": "JSONRPC"},
                {"url": "https://agent.example.com/grpc", "transport": "GRPC"}
            ],
            "provider": {"organization": "Acme", "url": "https://acme.example.com"},
            "version": "1.0.0",
            "capabilities": {"streaming": true, "stateTransitionHistory": false},
            "securitySchemes": {
                "key": {"type": "apiKey", "in": "header", "name": "X-Key"},
                "oauth": {"type": "oauth2", "flows": {"clientCredentials": {"tokenUrl": "https://id.example.com/token", "scopes": {"read": "Read"}}}}
            },
            "security": [{"key": []}],
            "defaultInputModes": ["text/plain"],
            "defaultOutputModes": ["text/plain"],
            "skills": [{"id": "faq", "name": "FAQ", "description": "d", "tags": ["t"], "security": [{"key": []}]}],
            "supportsAuthenticatedExtendedCard": true,
            "signatures": [{"protected": "x", "signature": "y"}]
        })
    }

    #[test]
    fn upgrades_a_full_card() {
        let u = upgrade(&v03()).unwrap();
        let c = &u.card;
        assert_eq!(c["supportedInterfaces"].as_array().unwrap().len(), 2);
        assert_eq!(
            c["capabilities"],
            json!({"streaming": true, "extendedAgentCard": true})
        );
        assert_eq!(
            c["securitySchemes"]["key"],
            json!({"apiKeySecurityScheme": {"location": "header", "name": "X-Key"}})
        );
        assert_eq!(
            c["skills"][0]["securityRequirements"],
            json!([{"schemes": {"key": {"list": []}}}])
        );
        assert!(c.get("signatures").is_none() && c.get("url").is_none());
        let text = u.changes.join("\n");
        assert!(text.contains("/signatures: 1 removed"), "{text}");
    }

    #[test]
    fn stops_and_names_the_field() {
        let mut c = v03();
        c["homepage"] = json!("x");
        assert_eq!(upgrade(&c).err().unwrap(), stop("/homepage", UNKNOWN));
        let mut c = v03();
        c["protocolVersion"] = json!("0.2.5");
        assert_eq!(upgrade(&c).err().unwrap().field, "/protocolVersion");
    }
}
