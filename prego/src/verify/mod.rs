//! `prego verify <type>:<tenant>/<namespace>/<name>[@<version>]` (ADR-0065 section 7 and the wire contract of
//! 2026-11-26): gets the publish attestation of a version, checks its DSSE signature with the Prego attestation
//! keys, checks that it names this version, recomputes the content digest, checks the policy options and prints
//! the facts.
//!
//! Exit codes: 0 all match; 1 a signature, version, digest or policy mismatch; 3 the version has no attestation
//! (published before attestations started); 2 usage or network errors.

pub mod content;
pub mod dsse;
pub mod registries;
pub mod statement;

use prego_auth::Env;
use serde_json::{json, Value};

use crate::snippet::{seg, Api};
use statement::{Policy, Statement, Subject};

pub const EXIT_MISMATCH: i32 = 1;
pub const EXIT_ERROR: i32 = 2;
pub const EXIT_NO_ATTESTATION: i32 = 3;

/// The public keys (wire contract item 4), relative to the control host.
pub const KEYS_PATH: &str = "/.well-known/prego-attestation-keys.json";

/// The types (grant ecosystem names) that have versions and attestations (wire contract item 1).
pub const TYPES: [&str; 13] = [
    "cargo", "npm", "go", "python", "oci", "snippet", "context", "sqlite", "key", "a2a", "rv",
    "apispec", "build",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub typ: String,
    pub tenant: String,
    pub namespace: String,
    pub name: String,
    pub version: Option<String>,
}

impl Target {
    /// `<type>:<tenant>/<namespace>/<name>[@<version>]`. The name can hold `/` (Go modules, OCI repositories)
    /// and start with `@` (npm scopes). The version is after the last `@` that is not the first character of
    /// the name.
    pub fn parse(s: &str) -> Result<Target, String> {
        let usage = || {
            format!(
                "the reference `{s}` is not <type>:<tenant>/<namespace>/<name>[@<version>] (types: {})",
                TYPES.join(", ")
            )
        };
        let (typ, rest) = s.split_once(':').ok_or_else(usage)?;
        if !TYPES.contains(&typ) {
            return Err(usage());
        }
        let mut parts = rest.splitn(3, '/');
        let tenant = parts.next().unwrap_or("");
        let namespace = parts.next().unwrap_or("");
        let tail = parts.next().unwrap_or("");
        // Release Variables: `<package>@<package-version>`, `_namespace` or `_tenant` is the name, and the
        // set version follows `#` (wire contract item 11).
        let (name, version) = if typ == "rv" {
            match tail.split_once('#') {
                Some((n, v)) => (n, Some(v)),
                None => (tail, None),
            }
        } else {
            match tail.rfind('@') {
                Some(i) if i > 0 => (&tail[..i], Some(&tail[i + 1..])),
                _ => (tail, None),
            }
        };
        if typ == "rv" && !(name == "_namespace" || name == "_tenant" || name.contains('@')) {
            return Err(format!(
                "the Release Variables reference `{s}` is not rv:<tenant>/<namespace>/<package>@<package-version>[#<n>], \
                 rv:<tenant>/<namespace>/_namespace[#<n>] or rv:<tenant>/_tenant/_tenant[#<n>]"
            ));
        }
        if tenant.is_empty()
            || namespace.is_empty()
            || name.is_empty()
            || version.is_some_and(str::is_empty)
        {
            return Err(usage());
        }
        Ok(Target {
            typ: typ.to_string(),
            tenant: tenant.to_string(),
            namespace: namespace.to_string(),
            name: name.to_string(),
            version: version.map(str::to_string),
        })
    }

    pub fn long(&self) -> String {
        let sep = if self.typ == "rv" { "#" } else { "@" };
        let v = self
            .version
            .as_deref()
            .map(|v| format!("{sep}{v}"))
            .unwrap_or_default();
        format!(
            "{}:{}/{}/{}{v}",
            self.typ, self.tenant, self.namespace, self.name
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyCommand {
    pub reference: String,
    pub policy: Policy,
    /// A local JWKS file instead of the published keys.
    pub keys: Option<String>,
    pub no_content: bool,
    pub json: bool,
    /// `publish` (default) or `promote` (ADR-0066).
    pub kind: String,
    /// The registry host for cargo, npm, python, go and oci, instead of the configured or default host.
    pub registry: Option<String>,
}

/// The outcome before printing: the code and the messages for a mismatch.
struct Outcome {
    code: i32,
    problems: Vec<String>,
}

pub fn run(globals: &[&str], cmd: &VerifyCommand, env: &dyn Env) -> Result<i32, String> {
    let target = Target::parse(&cmd.reference).map_err(|e| format!("prego verify: {e}"))?;
    cmd.policy.check_options()?;
    if cmd.kind != "publish" && cmd.kind != "promote" {
        return Err("prego verify: --kind is publish or promote".into());
    }
    if cmd.kind == "promote" && target.typ != "build" {
        return Err("prego verify: --kind promote applies to build artifacts only".into());
    }
    if cmd.no_content && target.version.is_none() {
        return Err(
            "prego verify: --no-content needs a version (<ref>@<version>); without the content, prego cannot \
             find the latest version"
                .into(),
        );
    }
    let what = target.long();

    // 1. The content: the version (the latest when none is given) and its digests, computed here.
    let content = if cmd.no_content {
        None
    } else {
        Some(content::fetch(
            globals,
            env,
            &target,
            cmd.registry.as_deref(),
        )?)
    };
    // The canonical name (Python: PEP 503; cargo: as in the index) names the attestation.
    let canonical = content
        .as_ref()
        .and_then(|c| c.name.clone())
        .or_else(|| (target.typ == "python").then(|| registries::pep503(&target.name)));
    let target = match canonical {
        Some(name) => Target { name, ..target },
        None => target,
    };
    let version = content
        .as_ref()
        .map(|c| c.version.clone())
        .or_else(|| target.version.clone())
        .unwrap_or_default();

    // The reference with the resolved version, for the messages.
    let shown = Target {
        version: Some(version.clone()),
        ..target.clone()
    }
    .long();

    // 2. The attestation.
    let api = Api::with_prefix(globals, &target.tenant, env, "attestations")?;
    let mut path = format!(
        "{}/{}/{}/{}/{}",
        seg(&target.tenant),
        seg(&target.namespace),
        seg(&target.typ),
        seg(&target.name),
        seg(&version)
    );
    if cmd.kind == "promote" {
        path.push_str("?kind=promote");
    }
    let (res, body) = api.get_bytes(
        &path,
        "application/vnd.dsse.envelope.v1+json, application/json",
        dsse::MAX_ENVELOPE as u64 + 1,
    )?;
    if res.status == 404 {
        let v: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
        if v["error"]["code"].as_str() == Some("no_attestation") {
            let msg = format!(
                "prego verify: {shown}: no attestation (published before attestations started)"
            );
            if cmd.json {
                println!(
                    "{}",
                    json!({"verified": false, "reference": what, "version": version, "attestation": null})
                );
            }
            eprintln!("{msg}");
            return Ok(EXIT_NO_ATTESTATION);
        }
    }
    if res.status != 200 {
        return Err(crate::snippet::api_error(
            &res,
            &format!("{shown} attestation"),
        ));
    }
    let attestation_id = res
        .header("x-prego-attestation-id")
        .unwrap_or("")
        .to_string();

    // 3. The keys.
    let key_bytes = match &cmd.keys {
        Some(file) => {
            std::fs::read(file).map_err(|e| format!("prego verify: --keys {file}: {e}"))?
        }
        None => api.get_root(KEYS_PATH, "application/json", 1024 * 1024)?,
    };
    let keys = dsse::parse_jwks(&key_bytes).map_err(|e| format!("prego verify: {e}"))?;

    // 4. Check everything; collect the problems.
    let mut out = Outcome {
        code: 0,
        problems: Vec::new(),
    };
    let mut key_id = String::new();
    let mut st: Option<Statement> = None;
    match dsse::Envelope::parse(&body).and_then(|e| e.verify(&keys).map(|k| (e, k))) {
        Err(e) => out.problems.push(e),
        Ok((env_, kid)) => {
            key_id = kid;
            match statement::parse(&env_.payload) {
                Err(e) => out.problems.push(e),
                Ok(s) => {
                    if let Err(e) = s.check_target(
                        &cmd.kind,
                        &target.tenant,
                        &target.namespace,
                        &target.typ,
                        &target.name,
                        Some(&version),
                    ) {
                        out.problems.push(e);
                    }
                    if let Some(c) = &content {
                        out.problems.extend(compare(&s, c));
                    }
                    out.problems.extend(
                        cmd.policy
                            .failures(&s)
                            .into_iter()
                            .map(|f| format!("policy: {f}")),
                    );
                    st = Some(s);
                }
            }
        }
    }
    if !out.problems.is_empty() {
        out.code = EXIT_MISMATCH;
    }

    // 5. Print.
    let facts = st.as_ref().map(Statement::fact_lines).unwrap_or_default();
    if cmd.json {
        let mut f = serde_json::Map::new();
        for (k, v) in &facts {
            f.insert(k.clone(), Value::String(v.clone()));
        }
        println!(
            "{}",
            json!({
                "verified": out.code == 0,
                "reference": what,
                "version": version,
                "attestation_id": attestation_id,
                "key_id": key_id,
                "content_checked": content.is_some(),
                "facts": f,
                "problems": out.problems,
            })
        );
    } else {
        let width = facts.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
        for (k, v) in &facts {
            println!("{k:width$}  {v}");
        }
    }
    let name = &shown;
    if out.code == 0 {
        let checked = if content.is_some() {
            "signature, version, content digest"
        } else {
            "signature, version (content not checked: --no-content)"
        };
        let policy = if cmd.policy == Policy::default() {
            String::new()
        } else {
            ", policy".into()
        };
        eprintln!("prego verify: {name}: verified ({checked}{policy}) with key {key_id}");
    } else {
        for p in &out.problems {
            eprintln!("prego verify: {name}: {p}");
        }
        eprintln!("prego verify: {name}: NOT verified");
    }
    Ok(out.code)
}

/// Compares the digests computed here with the subjects of the statement. Every computed subject must be in
/// the statement with the same digest for each algorithm that both name, and the statement must not name more
/// subjects (python and build: the same file set). Error code: `digest_mismatch`.
pub fn compare(st: &Statement, c: &content::Content) -> Vec<String> {
    let mut out = Vec::new();
    let find = |want: &Subject| -> Option<&Subject> {
        st.subjects
            .iter()
            .find(|s| want.name.is_empty() || s.name.is_empty() || s.name == want.name)
    };
    for want in &c.subjects {
        let label = if want.name.is_empty() {
            "the content".to_string()
        } else {
            format!("`{}`", want.name)
        };
        let Some(got) = find(want) else {
            out.push(format!(
                "digest_mismatch: the attestation has no subject for {label}"
            ));
            continue;
        };
        let mut shared = 0;
        for (alg, hex) in &want.digest {
            if let Some(g) = got.get(alg) {
                shared += 1;
                if g != hex {
                    out.push(format!(
                        "digest_mismatch: {label}: the {alg} here is {hex}, the attestation says {g}"
                    ));
                }
            }
        }
        if shared == 0 {
            out.push(format!(
                "digest_mismatch: {label}: the attestation names no digest that prego can check ({})",
                got.digest
                    .iter()
                    .map(|(a, _)| a.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    if st.subjects.len() > c.subjects.len() {
        out.push(format!(
            "digest_mismatch: the attestation names {} subjects; the version has {}",
            st.subjects.len(),
            c.subjects.len()
        ));
    }
    if let Some(h1) = &c.go_h1 {
        match st.predicate.get("go_h1").and_then(Value::as_str) {
            Some(g) if g == h1 => {}
            Some(g) => out.push(format!(
                "digest_mismatch: the h1 hash here is {h1}, the attestation says {g}"
            )),
            None => out.push("digest_mismatch: the attestation has no go_h1".into()),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references() {
        let t = Target::parse("cargo:acme/default/payments@1.4.0").unwrap();
        assert_eq!(
            (
                t.typ.as_str(),
                t.tenant.as_str(),
                t.namespace.as_str(),
                t.name.as_str()
            ),
            ("cargo", "acme", "default", "payments")
        );
        assert_eq!(t.version.as_deref(), Some("1.4.0"));
        let t = Target::parse("npm:acme/default/@acme/hello@1.0.0").unwrap();
        assert_eq!(
            (t.name.as_str(), t.version.as_deref()),
            ("@acme/hello", Some("1.0.0"))
        );
        let t = Target::parse("npm:acme/default/@acme/hello").unwrap();
        assert_eq!((t.name.as_str(), t.version), ("@acme/hello", None));
        let t = Target::parse("go:acme/default/go.acme.com/core@v1.4.0").unwrap();
        assert_eq!(t.name, "go.acme.com/core");
        let t = Target::parse("oci:acme/default/api/server@sha256:ab").unwrap();
        assert_eq!(
            (t.name.as_str(), t.version.as_deref()),
            ("api/server", Some("sha256:ab"))
        );
        for bad in [
            "payments@1.0",
            "zip:acme/default/x",
            "cargo:acme/default",
            "cargo:acme//x",
            "cargo:acme/default/x@",
        ] {
            assert!(Target::parse(bad).is_err(), "{bad}");
        }
        // Release Variables: the set version follows `#`.
        let t = Target::parse("rv:acme/default/@acme/pay@1.4.0#3").unwrap();
        assert_eq!(
            (t.name.as_str(), t.version.as_deref()),
            ("@acme/pay@1.4.0", Some("3"))
        );
        assert_eq!(t.long(), "rv:acme/default/@acme/pay@1.4.0#3");
        let t = Target::parse("rv:acme/default/_namespace").unwrap();
        assert_eq!((t.name.as_str(), t.version), ("_namespace", None));
        assert!(Target::parse("rv:acme/_tenant/_tenant#1").is_ok());
        assert!(Target::parse("rv:acme/default/payments").is_err());
        assert!(Target::parse("rv:acme/default/payments@1.4.0#").is_err());
    }

    fn st(subjects: Value, go_h1: Option<&str>) -> Statement {
        let mut p = json!({"level": "api_key"});
        if let Some(h) = go_h1 {
            p["go_h1"] = h.into();
        }
        statement::parse(
            json!({"_type": statement::STATEMENT_TYPE, "subject": subjects,
                   "predicateType": statement::PUBLISH_PREDICATE, "predicate": p})
            .to_string()
            .as_bytes(),
        )
        .unwrap()
    }

    fn subj(name: &str, d: &[(&str, &str)]) -> Subject {
        Subject {
            name: name.into(),
            digest: d
                .iter()
                .map(|(a, h)| (a.to_string(), h.to_string()))
                .collect(),
        }
    }

    #[test]
    fn digest_compare() {
        let c = content::Content {
            version: "1".into(),
            subjects: vec![
                subj("a.whl", &[("sha256", "aa")]),
                subj("a.tar.gz", &[("sha256", "bb")]),
            ],
            go_h1: None,
            name: None,
        };
        let s = st(
            json!([{"name": "a.tar.gz", "digest": {"sha256": "bb"}}, {"name": "a.whl", "digest": {"sha256": "aa"}}]),
            None,
        );
        assert!(compare(&s, &c).is_empty());
        let s = st(json!([{"name": "a.whl", "digest": {"sha256": "aa"}}]), None);
        assert_eq!(compare(&s, &c).len(), 1);
        let s = st(
            json!([{"name": "a.tar.gz", "digest": {"sha256": "cc"}}, {"name": "a.whl", "digest": {"sha256": "aa"}}]),
            None,
        );
        let p = compare(&s, &c);
        assert!(p[0].contains("`a.tar.gz`: the sha256 here is bb"), "{p:?}");
        // npm: both digests are checked.
        let c = content::Content {
            version: "1".into(),
            subjects: vec![subj("", &[("sha256", "aa"), ("sha512", "bb")])],
            go_h1: None,
            name: None,
        };
        assert!(compare(
            &st(
                json!([{"name": "x.tgz", "digest": {"sha256": "aa", "sha512": "bb"}}]),
                None
            ),
            &c
        )
        .is_empty());
        assert_eq!(
            compare(
                &st(
                    json!([{"name": "x.tgz", "digest": {"sha256": "aa", "sha512": "cc"}}]),
                    None
                ),
                &c
            )
            .len(),
            1
        );
        // Go: h1 in the predicate.
        let c = content::Content {
            version: "v1".into(),
            subjects: vec![subj("", &[("sha256", "aa")])],
            go_h1: Some("h1:x".into()),
            name: None,
        };
        assert!(compare(
            &st(
                json!([{"name": "m.zip", "digest": {"sha256": "aa"}}]),
                Some("h1:x")
            ),
            &c
        )
        .is_empty());
        assert_eq!(
            compare(
                &st(
                    json!([{"name": "m.zip", "digest": {"sha256": "aa"}}]),
                    Some("h1:y")
                ),
                &c
            )
            .len(),
            1
        );
        assert_eq!(
            compare(
                &st(json!([{"name": "m.zip", "digest": {"sha256": "aa"}}]), None),
                &c
            )
            .len(),
            1
        );
    }
}
