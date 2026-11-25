//! A2A 1.0 Agent Cards (ADR-0062): the card check, the A2A 0.3 detection, the signature input of A2A 1.0
//! section 8.4, and the Prego source extension (ADR-0062 item 2.9).
//!
//! The field table below is written from the normative A2A proto, `specification/a2a.proto` at tag `v1.0.1`
//! (commit 3303592588e388e62e0f69f701af531d2f4e3991), the source that ADR-0062 pins. JSON names are the
//! ProtoJSON camelCase names; the snake_case proto names are also accepted on read, as ProtoJSON does.
//! "Passes the A2A 1.0 schema" means: only known fields, the right JSON types, every field that the proto
//! marks REQUIRED, and a required array has at least one item.

use serde_json::{Map, Value};

/// The kind of value of one field.
#[derive(Clone, Copy)]
enum Kind {
    Str,
    Bool,
    Msg(&'static Msg),
    /// `repeated string`.
    Strs,
    /// `repeated <message>`.
    Msgs(&'static Msg),
    /// `map<string, <message>>`.
    MsgMap(&'static Msg),
    /// `map<string, string>`.
    StrMap,
    /// `google.protobuf.Struct`: any JSON object.
    Struct,
}

#[derive(Clone, Copy)]
struct Field {
    json: &'static str,
    kind: Kind,
    /// `[(google.api.field_behavior) = REQUIRED]`.
    required: bool,
    /// The proto3 `optional` label (explicit presence): kept on signing even at the default value.
    optional: bool,
}

struct Msg {
    #[cfg_attr(not(test), allow(dead_code))]
    name: &'static str,
    fields: &'static [Field],
    /// A proto `oneof` (its name) whose members are all the fields: exactly one must be set.
    oneof: Option<&'static str>,
}

const fn f(json: &'static str, kind: Kind) -> Field {
    Field {
        json,
        kind,
        required: false,
        optional: false,
    }
}
const fn req(json: &'static str, kind: Kind) -> Field {
    Field {
        json,
        kind,
        required: true,
        optional: false,
    }
}
const fn opt(json: &'static str, kind: Kind) -> Field {
    Field {
        json,
        kind,
        required: false,
        optional: true,
    }
}

static AGENT_INTERFACE: Msg = Msg {
    name: "AgentInterface",
    oneof: None,
    fields: &[
        req("url", Kind::Str),
        req("protocolBinding", Kind::Str),
        f("tenant", Kind::Str),
        req("protocolVersion", Kind::Str),
    ],
};
static AGENT_PROVIDER: Msg = Msg {
    name: "AgentProvider",
    oneof: None,
    fields: &[req("url", Kind::Str), req("organization", Kind::Str)],
};
static AGENT_EXTENSION: Msg = Msg {
    name: "AgentExtension",
    oneof: None,
    fields: &[
        f("uri", Kind::Str),
        f("description", Kind::Str),
        f("required", Kind::Bool),
        f("params", Kind::Struct),
    ],
};
static AGENT_CAPABILITIES: Msg = Msg {
    name: "AgentCapabilities",
    oneof: None,
    fields: &[
        opt("streaming", Kind::Bool),
        opt("pushNotifications", Kind::Bool),
        f("extensions", Kind::Msgs(&AGENT_EXTENSION)),
        opt("extendedAgentCard", Kind::Bool),
    ],
};
static STRING_LIST: Msg = Msg {
    name: "StringList",
    oneof: None,
    fields: &[f("list", Kind::Strs)],
};
static SECURITY_REQUIREMENT: Msg = Msg {
    name: "SecurityRequirement",
    oneof: None,
    fields: &[f("schemes", Kind::MsgMap(&STRING_LIST))],
};
static AGENT_SKILL: Msg = Msg {
    name: "AgentSkill",
    oneof: None,
    fields: &[
        req("id", Kind::Str),
        req("name", Kind::Str),
        req("description", Kind::Str),
        req("tags", Kind::Strs),
        f("examples", Kind::Strs),
        f("inputModes", Kind::Strs),
        f("outputModes", Kind::Strs),
        f("securityRequirements", Kind::Msgs(&SECURITY_REQUIREMENT)),
    ],
};
static AGENT_CARD_SIGNATURE: Msg = Msg {
    name: "AgentCardSignature",
    oneof: None,
    fields: &[
        req("protected", Kind::Str),
        req("signature", Kind::Str),
        f("header", Kind::Struct),
    ],
};
static API_KEY_SCHEME: Msg = Msg {
    name: "APIKeySecurityScheme",
    oneof: None,
    fields: &[
        f("description", Kind::Str),
        req("location", Kind::Str),
        req("name", Kind::Str),
    ],
};
static HTTP_AUTH_SCHEME: Msg = Msg {
    name: "HTTPAuthSecurityScheme",
    oneof: None,
    fields: &[
        f("description", Kind::Str),
        req("scheme", Kind::Str),
        f("bearerFormat", Kind::Str),
    ],
};
static AUTH_CODE_FLOW: Msg = Msg {
    name: "AuthorizationCodeOAuthFlow",
    oneof: None,
    fields: &[
        req("authorizationUrl", Kind::Str),
        req("tokenUrl", Kind::Str),
        f("refreshUrl", Kind::Str),
        req("scopes", Kind::StrMap),
        f("pkceRequired", Kind::Bool),
    ],
};
static CLIENT_CREDENTIALS_FLOW: Msg = Msg {
    name: "ClientCredentialsOAuthFlow",
    oneof: None,
    fields: &[
        req("tokenUrl", Kind::Str),
        f("refreshUrl", Kind::Str),
        req("scopes", Kind::StrMap),
    ],
};
static DEVICE_CODE_FLOW: Msg = Msg {
    name: "DeviceCodeOAuthFlow",
    oneof: None,
    fields: &[
        req("deviceAuthorizationUrl", Kind::Str),
        req("tokenUrl", Kind::Str),
        f("refreshUrl", Kind::Str),
        req("scopes", Kind::StrMap),
    ],
};
static IMPLICIT_FLOW: Msg = Msg {
    name: "ImplicitOAuthFlow",
    oneof: None,
    fields: &[
        f("authorizationUrl", Kind::Str),
        f("refreshUrl", Kind::Str),
        f("scopes", Kind::StrMap),
    ],
};
static PASSWORD_FLOW: Msg = Msg {
    name: "PasswordOAuthFlow",
    oneof: None,
    fields: &[
        f("tokenUrl", Kind::Str),
        f("refreshUrl", Kind::Str),
        f("scopes", Kind::StrMap),
    ],
};
static OAUTH_FLOWS: Msg = Msg {
    name: "OAuthFlows",
    oneof: Some("flow"),
    fields: &[
        f("authorizationCode", Kind::Msg(&AUTH_CODE_FLOW)),
        f("clientCredentials", Kind::Msg(&CLIENT_CREDENTIALS_FLOW)),
        f("implicit", Kind::Msg(&IMPLICIT_FLOW)),
        f("password", Kind::Msg(&PASSWORD_FLOW)),
        f("deviceCode", Kind::Msg(&DEVICE_CODE_FLOW)),
    ],
};
static OAUTH2_SCHEME: Msg = Msg {
    name: "OAuth2SecurityScheme",
    oneof: None,
    fields: &[
        f("description", Kind::Str),
        req("flows", Kind::Msg(&OAUTH_FLOWS)),
        f("oauth2MetadataUrl", Kind::Str),
    ],
};
static OIDC_SCHEME: Msg = Msg {
    name: "OpenIdConnectSecurityScheme",
    oneof: None,
    fields: &[
        f("description", Kind::Str),
        req("openIdConnectUrl", Kind::Str),
    ],
};
static MTLS_SCHEME: Msg = Msg {
    name: "MutualTlsSecurityScheme",
    oneof: None,
    fields: &[f("description", Kind::Str)],
};
static SECURITY_SCHEME: Msg = Msg {
    name: "SecurityScheme",
    oneof: Some("scheme"),
    fields: &[
        f("apiKeySecurityScheme", Kind::Msg(&API_KEY_SCHEME)),
        f("httpAuthSecurityScheme", Kind::Msg(&HTTP_AUTH_SCHEME)),
        f("oauth2SecurityScheme", Kind::Msg(&OAUTH2_SCHEME)),
        f("openIdConnectSecurityScheme", Kind::Msg(&OIDC_SCHEME)),
        f("mtlsSecurityScheme", Kind::Msg(&MTLS_SCHEME)),
    ],
};
static AGENT_CARD: Msg = Msg {
    name: "AgentCard",
    oneof: None,
    fields: &[
        req("name", Kind::Str),
        req("description", Kind::Str),
        req("supportedInterfaces", Kind::Msgs(&AGENT_INTERFACE)),
        f("provider", Kind::Msg(&AGENT_PROVIDER)),
        req("version", Kind::Str),
        opt("documentationUrl", Kind::Str),
        req("capabilities", Kind::Msg(&AGENT_CAPABILITIES)),
        f("securitySchemes", Kind::MsgMap(&SECURITY_SCHEME)),
        f("securityRequirements", Kind::Msgs(&SECURITY_REQUIREMENT)),
        req("defaultInputModes", Kind::Strs),
        req("defaultOutputModes", Kind::Strs),
        req("skills", Kind::Msgs(&AGENT_SKILL)),
        f("signatures", Kind::Msgs(&AGENT_CARD_SIGNATURE)),
        opt("iconUrl", Kind::Str),
    ],
};

/// Every message of the table: (message, json name, required, optional, repeated, oneof). For the test
/// against the vectors' `card-fields.json`.
#[cfg(test)]
pub(crate) type Row = (
    &'static str,
    &'static str,
    bool,
    bool,
    bool,
    Option<&'static str>,
);

#[cfg(test)]
pub(crate) fn table() -> Vec<Row> {
    let all: [&Msg; 21] = [
        &AGENT_CARD,
        &AGENT_INTERFACE,
        &AGENT_PROVIDER,
        &AGENT_CAPABILITIES,
        &SECURITY_SCHEME,
        &SECURITY_REQUIREMENT,
        &AGENT_SKILL,
        &AGENT_CARD_SIGNATURE,
        &AGENT_EXTENSION,
        &API_KEY_SCHEME,
        &HTTP_AUTH_SCHEME,
        &OAUTH2_SCHEME,
        &OIDC_SCHEME,
        &MTLS_SCHEME,
        &STRING_LIST,
        &OAUTH_FLOWS,
        &AUTH_CODE_FLOW,
        &CLIENT_CREDENTIALS_FLOW,
        &IMPLICIT_FLOW,
        &PASSWORD_FLOW,
        &DEVICE_CODE_FLOW,
    ];
    let mut out = Vec::new();
    for m in all {
        for f in m.fields {
            let repeated = matches!(f.kind, Kind::Strs | Kind::Msgs(_));
            out.push((m.name, f.json, f.required, f.optional, repeated, m.oneof));
        }
    }
    out
}

/// The snake_case proto name of a camelCase JSON name (`oauth2MetadataUrl` -> `oauth2_metadata_url`).
fn snake(json: &str) -> String {
    let mut s = String::new();
    for c in json.chars() {
        if c.is_ascii_uppercase() {
            s.push('_');
            s.push(c.to_ascii_lowercase());
        } else {
            s.push(c);
        }
    }
    s
}

/// The field of a JSON key, by its camelCase or snake_case name.
fn field_of(m: &Msg, key: &str) -> Option<Field> {
    m.fields
        .iter()
        .copied()
        .find(|f| f.json == key || snake(f.json) == key)
}

/// RFC 6901: one pointer segment.
fn child(path: &str, key: &str) -> String {
    format!("{path}/{}", key.replace('~', "~0").replace('/', "~1"))
}

/// Why a card is not an A2A 1.0 card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    /// It looks like A2A 0.3: the reason.
    V03(String),
    /// It breaks the card rule: an RFC 6901 pointer (`""` for the card) and the reason.
    Invalid { path: String, reason: String },
}

impl Problem {
    fn at(path: &str, reason: impl Into<String>) -> Problem {
        Problem::Invalid {
            path: path.to_string(),
            reason: reason.into(),
        }
    }

    /// The message for a card file (ADR-0062 item 2.3).
    pub fn message(&self, file: &str) -> String {
        match self {
            Problem::V03(reason) => format!(
                "A2A 1.0 only. Card {file} looks like A2A 0.3 ({reason}). Run `prego a2a upgrade {file}` to make a \
                 1.0 card, then sign it again."
            ),
            Problem::Invalid { path, reason } if path.is_empty() => format!("card {file}: {reason}"),
            Problem::Invalid { path, reason } => format!("card {file}: {path}: {reason}"),
        }
    }
}

/// Checks a card against A2A 1.0 (the card rule of `tests/vectors/a2a/README.md`). The 0.3 detection runs
/// first; then the first error in document order wins.
pub fn check(card: &Value) -> Result<(), Problem> {
    if !card.is_object() {
        return Err(Problem::at("", "expected object"));
    }
    if let Some(reason) = looks_like_v03(card) {
        return Err(Problem::V03(reason));
    }
    check_msg(card, &AGENT_CARD, "")
}

fn check_msg(v: &Value, m: &Msg, path: &str) -> Result<(), Problem> {
    let o = v
        .as_object()
        .ok_or_else(|| Problem::at(path, "expected object"))?;
    let mut seen: Vec<(&'static str, &str)> = Vec::new();
    for (k, val) in o {
        let here = child(path, k);
        let fd = field_of(m, k).ok_or_else(|| Problem::at(&here, "unknown field"))?;
        if let Some((_, other)) = seen.iter().find(|(j, _)| *j == fd.json) {
            return Err(Problem::at(&here, format!("duplicate field ({other})")));
        }
        seen.push((fd.json, k.as_str()));
        check_value(val, fd, &here)?;
    }
    for fd in m.fields.iter().filter(|f| f.required) {
        if !seen.iter().any(|(j, _)| *j == fd.json) {
            return Err(Problem::at(
                &child(path, fd.json),
                "required field is missing",
            ));
        }
    }
    if let Some(name) = m.oneof {
        if seen.len() != 1 {
            return Err(Problem::at(
                path,
                format!("exactly one of {name} must be set"),
            ));
        }
    }
    Ok(())
}

fn check_value(v: &Value, fd: Field, path: &str) -> Result<(), Problem> {
    match fd.kind {
        Kind::Str => {
            let s = v
                .as_str()
                .ok_or_else(|| Problem::at(path, "expected string"))?;
            if fd.required && s.is_empty() {
                return Err(Problem::at(path, "required field is empty"));
            }
            Ok(())
        }
        Kind::Bool if v.is_boolean() => Ok(()),
        Kind::Bool => Err(Problem::at(path, "expected boolean")),
        Kind::Struct if v.is_object() => Ok(()),
        Kind::Struct => Err(Problem::at(path, "expected object")),
        Kind::Msg(m) => check_msg(v, m, path),
        Kind::Strs | Kind::Msgs(_) => {
            let a = v
                .as_array()
                .ok_or_else(|| Problem::at(path, "expected array"))?;
            if fd.required && a.is_empty() {
                return Err(Problem::at(path, "required array is empty"));
            }
            for (i, item) in a.iter().enumerate() {
                let here = format!("{path}/{i}");
                match fd.kind {
                    Kind::Msgs(m) => check_msg(item, m, &here)?,
                    _ if !item.is_string() => return Err(Problem::at(&here, "expected string")),
                    _ => {}
                }
            }
            Ok(())
        }
        Kind::MsgMap(m) => {
            let o = v
                .as_object()
                .ok_or_else(|| Problem::at(path, "expected object"))?;
            for (k, item) in o {
                check_msg(item, m, &child(path, k))?;
            }
            Ok(())
        }
        Kind::StrMap => {
            let o = v
                .as_object()
                .ok_or_else(|| Problem::at(path, "expected object"))?;
            for (k, item) in o {
                if !item.is_string() {
                    return Err(Problem::at(&child(path, k), "expected string"));
                }
            }
            Ok(())
        }
    }
}

/// The reason why a card looks like A2A 0.3, or `None` (the seven rules of the a2a vectors, in order).
pub fn looks_like_v03(card: &Value) -> Option<String> {
    let o = card.as_object()?;
    if let Some(p) = o.get("protocolVersion") {
        return Some(format!("has protocolVersion {p}"));
    }
    if o.contains_key("url") {
        return Some("has top-level url".into());
    }
    for k in [
        "preferredTransport",
        "additionalInterfaces",
        "supportsAuthenticatedExtendedCard",
    ] {
        if o.contains_key(k) {
            return Some(format!("has {k}"));
        }
    }
    if o.contains_key("security") {
        return Some("has security, not securityRequirements".into());
    }
    if let Some(Value::Object(s)) = o.get("securitySchemes") {
        if let Some((name, _)) = s.iter().find(|(_, v)| v.get("type").is_some()) {
            return Some(format!("security scheme {name} has type"));
        }
    }
    None
}

/// The card without `signatures` and without fields at their default value (A2A 1.0 section 8.4.1, by
/// proto field presence): an unset optional field is absent; a set `optional` field stays; a REQUIRED field
/// stays; a non-optional scalar at its default (`""`, `false`) and an empty non-required list or map go.
pub fn signing_form(card: &Value) -> Value {
    let mut v = strip(card, &AGENT_CARD);
    if let Some(o) = v.as_object_mut() {
        o.remove("signatures");
    }
    v
}

/// The RFC 8785 bytes of [`signing_form`]: the payload of a card signature.
pub fn signing_input(card: &Value) -> Result<Vec<u8>, String> {
    Ok(crate::env::jcs::canonical(&signing_form(card))?.into_bytes())
}

fn strip(v: &Value, m: &Msg) -> Value {
    let Some(o) = v.as_object() else {
        return v.clone();
    };
    let mut out = Map::new();
    for (k, val) in o {
        let Some(fd) = field_of(m, k) else {
            out.insert(k.clone(), val.clone());
            continue;
        };
        let keep_default = fd.required || fd.optional;
        let stripped = match fd.kind {
            Kind::Str if !keep_default && val.as_str() == Some("") => None,
            Kind::Bool if !keep_default && val.as_bool() == Some(false) => None,
            Kind::Strs | Kind::Msgs(_)
                if !fd.required && val.as_array().is_some_and(Vec::is_empty) =>
            {
                None
            }
            Kind::MsgMap(_) | Kind::StrMap
                if !fd.required && val.as_object().is_some_and(Map::is_empty) =>
            {
                None
            }
            Kind::Msg(inner) => Some(strip(val, inner)),
            Kind::Msgs(inner) => Some(Value::Array(
                val.as_array()
                    .map(|a| a.iter().map(|x| strip(x, inner)).collect())
                    .unwrap_or_default(),
            )),
            Kind::MsgMap(inner) => Some(Value::Object(
                val.as_object()
                    .map(|mo| {
                        mo.iter()
                            .map(|(k2, x)| (k2.clone(), strip(x, inner)))
                            .collect()
                    })
                    .unwrap_or_default(),
            )),
            _ => Some(val.clone()),
        };
        if let Some(s) = stripped {
            out.insert(k.clone(), s);
        }
    }
    Value::Object(out)
}

// ---- Source extension (ADR-0062 item 2.9) ----

pub const SOURCE_URI: &str = "https://prego.k8skill.com/ext/a2a-source/v1";

/// The `(tenant, namespace, set)` of a card's source extension, if it has one.
pub fn source(card: &Value) -> Option<(String, String, String)> {
    let exts = card.get("capabilities")?.get("extensions")?.as_array()?;
    let e = exts.iter().find(|e| e["uri"] == SOURCE_URI)?;
    let p = &e["params"];
    let t = |k: &str| p[k].as_str().unwrap_or("").to_string();
    Some((t("tenant"), t("namespace"), t("set")))
}

/// Sets the source extension. Returns `true` if the card changed.
pub fn set_source(card: &mut Value, tenant: &str, namespace: &str, set: &str) -> bool {
    let want = serde_json::json!({
        "uri": SOURCE_URI,
        "params": {"tenant": tenant, "namespace": namespace, "set": set},
    });
    let Some(o) = card.as_object_mut() else {
        return false;
    };
    let caps = o
        .entry("capabilities")
        .or_insert_with(|| Value::Object(Map::new()));
    let Some(caps) = caps.as_object_mut() else {
        return false;
    };
    let exts = caps
        .entry("extensions")
        .or_insert_with(|| Value::Array(Vec::new()));
    let Some(exts) = exts.as_array_mut() else {
        return false;
    };
    if let Some(e) = exts.iter_mut().find(|e| e["uri"] == SOURCE_URI) {
        if *e == want {
            return false;
        }
        *e = want;
    } else {
        exts.push(want);
    }
    true
}

/// The agent name and the skill names, for messages.
pub fn summary(card: &Value) -> String {
    let skills: Vec<&str> = card["skills"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| s["name"].as_str())
        .collect();
    format!(
        "{} ({} skills: {})",
        card["name"].as_str().unwrap_or("?"),
        skills.len(),
        skills.join(", ")
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    pub fn card() -> Value {
        json!({
            "name": "Support bot",
            "description": "Answers support questions",
            "supportedInterfaces": [
                {"url": "https://agent.example.com/a2a", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
            ],
            "version": "1.2.0",
            "capabilities": {"streaming": false, "extensions": []},
            "securitySchemes": {
                "google": {"openIdConnectSecurityScheme": {"openIdConnectUrl": "https://accounts.example.com/.well-known/openid-configuration"}}
            },
            "securityRequirements": [{"schemes": {"google": {"list": ["openid"]}}}],
            "defaultInputModes": ["text/plain"],
            "defaultOutputModes": ["text/plain"],
            "skills": [{"id": "faq", "name": "FAQ", "description": "Questions", "tags": ["support"], "examples": [], "inputModes": []}]
        })
    }

    #[test]
    fn a_good_card_passes() {
        check(&card()).unwrap();
        let mut c = card();
        c["default_input_modes"] = c["defaultInputModes"].take();
        c.as_object_mut().unwrap().remove("defaultInputModes");
        check(&c).unwrap();
    }

    #[test]
    fn bad_cards_name_the_path() {
        let at = |path: &str, reason: &str| Problem::Invalid {
            path: path.into(),
            reason: reason.into(),
        };
        let mut c = card();
        c.as_object_mut().unwrap().remove("skills");
        assert_eq!(check(&c), Err(at("/skills", "required field is missing")));
        let mut c = card();
        c["skills"] = json!([]);
        assert_eq!(check(&c), Err(at("/skills", "required array is empty")));
        let mut c = card();
        c["skills"][0]["tags"] = json!("x");
        assert_eq!(check(&c), Err(at("/skills/0/tags", "expected array")));
        let mut c = card();
        c["extra"] = json!(1);
        assert_eq!(check(&c), Err(at("/extra", "unknown field")));
        let mut c = card();
        c["securitySchemes"]["google"]["mtlsSecurityScheme"] = json!({});
        assert_eq!(
            check(&c),
            Err(at(
                "/securitySchemes/google",
                "exactly one of scheme must be set"
            ))
        );
        let mut c = card();
        c["name"] = json!("");
        assert_eq!(check(&c), Err(at("/name", "required field is empty")));
        assert_eq!(check(&json!([])), Err(at("", "expected object")));
        assert_eq!(
            at("/name", "required field is empty").message("a.json"),
            "card a.json: /name: required field is empty"
        );
    }

    #[test]
    fn v03_is_detected() {
        let mut c = card();
        c["protocolVersion"] = json!("0.3.0");
        assert_eq!(
            check(&c),
            Err(Problem::V03("has protocolVersion \"0.3.0\"".into()))
        );
        let mut c = card();
        c["securitySchemes"] = json!({"k": {"type": "apiKey", "in": "header", "name": "X"}});
        assert_eq!(looks_like_v03(&c).unwrap(), "security scheme k has type");
    }

    #[test]
    fn signing_form_drops_defaults_by_presence() {
        let f = signing_form(&card());
        // `streaming: false` is an optional field that is set: it stays. Empty non-required lists go.
        assert_eq!(f["capabilities"], json!({"streaming": false}));
        // An empty non-required list goes.
        assert!(f["skills"][0].get("examples").is_none());
        assert!(f["skills"][0].get("inputModes").is_none());
        let mut c = card();
        c["signatures"] = json!([{"protected": "a", "signature": "b"}]);
        c["capabilities"]["extensions"] =
            json!([{"uri": "u", "description": "", "required": false}]);
        let f = signing_form(&c);
        assert!(f.get("signatures").is_none());
        assert_eq!(f["capabilities"]["extensions"], json!([{"uri": "u"}]));
        let a = signing_input(&c).unwrap();
        let b = signing_input(&signing_form(&c)).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn source_extension() {
        let mut c = card();
        assert_eq!(source(&c), None);
        assert!(set_source(&mut c, "acme", "default", "agents"));
        assert!(!set_source(&mut c, "acme", "default", "agents"));
        assert_eq!(
            source(&c),
            Some(("acme".into(), "default".into(), "agents".into()))
        );
        check(&c).unwrap();
        assert!(set_source(&mut c, "acme", "prod", "agents"));
        assert_eq!(c["capabilities"]["extensions"].as_array().unwrap().len(), 1);
    }
}
