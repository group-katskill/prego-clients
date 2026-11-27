//! The in-toto Statement v1 of a Prego publish attestation (ADR-0065 sections 1 to 4, wire contract items 5
//! and 6), and the policy options of `prego verify`.

use serde_json::{Map, Value};

pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
pub const PUBLISH_PREDICATE: &str = "https://prego.k8skill.com/attestation/publish/v1";

/// The four levels (ADR-0065 section 2).
pub const LEVELS: [&str; 4] = ["ci_source", "workload", "person", "api_key"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    pub name: String,
    /// Algorithm name to lowercase hex, for example `sha256`.
    pub digest: Vec<(String, String)>,
}

impl Subject {
    pub fn get(&self, alg: &str) -> Option<&str> {
        self.digest
            .iter()
            .find(|(a, _)| a == alg)
            .map(|(_, h)| h.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct Statement {
    pub subjects: Vec<Subject>,
    pub predicate_type: String,
    pub predicate: Map<String, Value>,
}

/// Parses the payload of the envelope. Error code: `bad_statement`.
pub fn parse(payload: &[u8]) -> Result<Statement, String> {
    let v: Value = serde_json::from_slice(payload)
        .map_err(|e| format!("bad_statement: the attestation payload is not JSON: {e}"))?;
    if v["_type"].as_str() != Some(STATEMENT_TYPE) {
        return Err(format!(
            "bad_statement: the payload is not an in-toto Statement v1 (`_type` is {})",
            v["_type"]
        ));
    }
    let mut subjects = Vec::new();
    for s in v["subject"]
        .as_array()
        .filter(|a| !a.is_empty())
        .ok_or("bad_statement: the statement has no subject")?
    {
        let digest = s["digest"]
            .as_object()
            .filter(|d| !d.is_empty())
            .ok_or("bad_statement: a subject has no digest")?
            .iter()
            .map(|(k, v)| {
                v.as_str()
                    .filter(|h| !h.is_empty() && h.bytes().all(|b| b.is_ascii_hexdigit()))
                    .map(|h| (k.to_ascii_lowercase(), h.to_ascii_lowercase()))
                    .ok_or_else(|| format!("bad_statement: the subject digest `{k}` is not hex"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        subjects.push(Subject {
            name: s["name"].as_str().unwrap_or("").to_string(),
            digest,
        });
    }
    let predicate = v["predicate"]
        .as_object()
        .cloned()
        .ok_or("bad_statement: the statement has no predicate")?;
    Ok(Statement {
        subjects,
        predicate_type: v["predicateType"].as_str().unwrap_or("").to_string(),
        predicate,
    })
}

impl Statement {
    fn text(&self, key: &str) -> Option<&str> {
        self.predicate.get(key).and_then(Value::as_str)
    }

    pub fn level(&self) -> &str {
        self.text("level").unwrap_or("")
    }

    pub fn identity(&self) -> &Map<String, Value> {
        static EMPTY: std::sync::OnceLock<Map<String, Value>> = std::sync::OnceLock::new();
        self.predicate
            .get("identity")
            .and_then(Value::as_object)
            .unwrap_or_else(|| EMPTY.get_or_init(Map::new))
    }

    fn id_text(&self, key: &str) -> Option<String> {
        match self.identity().get(key)? {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            Value::Bool(b) => Some(b.to_string()),
            _ => None,
        }
    }

    /// Checks that the attestation is a publish attestation for this version (`predicateType`, tenant,
    /// namespace, type, name, version), so an attestation of another version cannot stand in. `kind` is
    /// `publish` or `promote` (ADR-0066 promote). Error code: `wrong_version`.
    pub fn check_target(
        &self,
        kind: &str,
        tenant: &str,
        namespace: &str,
        typ: &str,
        name: &str,
        version: Option<&str>,
    ) -> Result<(), String> {
        let want_pt = if kind == "promote" {
            "https://prego.k8skill.com/attestation/promote/v1"
        } else {
            PUBLISH_PREDICATE
        };
        if self.predicate_type != want_pt {
            return Err(format!(
                "wrong_version: the predicate type is `{}`, not `{want_pt}`",
                self.predicate_type
            ));
        }
        let mut checks = vec![
            ("tenant", tenant),
            ("namespace", namespace),
            ("type", typ),
            ("name", name),
        ];
        if let Some(v) = version {
            checks.push(("version", v));
        }
        for (k, want) in checks {
            let got = self.text(k).unwrap_or("");
            if got != want {
                return Err(format!(
                    "wrong_version: the attestation is for {k} `{got}`, not `{want}`"
                ));
            }
        }
        if !LEVELS.contains(&self.level()) {
            return Err(format!(
                "bad_statement: the level `{}` is not one of {}",
                self.level(),
                LEVELS.join(", ")
            ));
        }
        Ok(())
    }

    /// The facts as `key: value` lines, in a fixed order: the predicate fields, then the identity claims.
    pub fn fact_lines(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for k in [
            "tenant",
            "namespace",
            "type",
            "name",
            "version",
            "version_id",
            "published_at",
            "level",
            "principal_id",
            "user_id",
            "go_h1",
            "set_level",
            "package_version",
        ] {
            if let Some(v) = self.text(k) {
                out.push((k.to_string(), v.to_string()));
            }
        }
        for k in self.identity().keys() {
            if let Some(v) = self.id_text(k) {
                out.push((format!("identity.{k}"), v));
            }
        }
        out
    }
}

/// The policy options of `prego verify` (ADR-0065 section 7).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    pub repository: Option<String>,
    pub git_ref: Option<String>,
    pub sha: Option<String>,
    pub level: Option<String>,
    pub hosted_runner: bool,
}

impl Policy {
    /// Checks the options themselves (usage errors).
    pub fn check_options(&self) -> Result<(), String> {
        if let Some(l) = &self.level {
            if !LEVELS.contains(&l.as_str()) {
                return Err(format!(
                    "prego verify: --level must be one of {}",
                    LEVELS.join(", ")
                ));
            }
        }
        if let Some(s) = &self.sha {
            if !(s.len() == 40 || s.len() == 64) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(
                    "prego verify: --sha takes the full commit hash (40 or 64 hex characters)"
                        .into(),
                );
            }
        }
        Ok(())
    }

    /// The failed options, as messages. Empty when the attestation meets the policy.
    pub fn failures(&self, st: &Statement) -> Vec<String> {
        let mut out = Vec::new();
        let level = st.level();
        if let Some(want) = &self.level {
            if level != want {
                out.push(format!("--level {want}: the level is {level}"));
            }
        }
        if let Some(want) = &self.repository {
            let got = st
                .id_text("repository")
                .or_else(|| st.id_text("project_path"));
            match got {
                Some(g) if g.eq_ignore_ascii_case(want) => {}
                Some(g) => out.push(format!("--repository {want}: the repository is {g}")),
                None => out.push(format!(
                    "--repository {want}: the attestation names no repository (level {level})"
                )),
            }
        }
        if let Some(want) = &self.git_ref {
            match st.id_text("ref") {
                Some(g) if ref_matches(&g, want) => {}
                Some(g) => out.push(format!("--ref {want}: the ref is {g}")),
                None => out.push(format!(
                    "--ref {want}: the attestation names no ref (level {level})"
                )),
            }
        }
        if let Some(want) = &self.sha {
            match st.id_text("sha") {
                Some(g) if g.eq_ignore_ascii_case(want) => {}
                Some(g) => out.push(format!("--sha {want}: the commit is {g}")),
                None => out.push(format!(
                    "--sha {want}: the attestation names no commit (level {level})"
                )),
            }
        }
        if self.hosted_runner {
            match st.id_text("runner_environment") {
                Some(g) if g == "github-hosted" || g == "gitlab-hosted" => {}
                Some(g) => out.push(format!("--hosted-runner: the runner is {g}")),
                None => out.push(format!(
                    "--hosted-runner: the attestation names no runner environment (level {level})"
                )),
            }
        }
        out
    }
}

/// `want` matches the ref exactly, or, when `want` has no `refs/` prefix, a GitHub `refs/heads/<want>` or
/// `refs/tags/<want>` (GitLab refs have no prefix).
pub fn ref_matches(got: &str, want: &str) -> bool {
    got == want
        || (!want.starts_with("refs/")
            && (got == format!("refs/heads/{want}") || got == format!("refs/tags/{want}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    pub fn github_statement() -> Value {
        json!({
            "_type": STATEMENT_TYPE,
            "subject": [{"name": "payments-1.4.0.crate", "digest": {"sha256": "AB12"}}],
            "predicateType": PUBLISH_PREDICATE,
            "predicate": {
                "tenant": "acme", "namespace": "default", "type": "cargo", "name": "payments",
                "version": "1.4.0", "version_id": "ver_1", "published_at": "2026-11-26T10:00:00Z",
                "level": "ci_source", "principal_id": "prn_1",
                "identity": {
                    "iss": "https://token.actions.githubusercontent.com",
                    "repository": "acme/payments", "ref": "refs/tags/v1.4.0",
                    "sha": "9f2c000000000000000000000000000000000000",
                    "runner_environment": "github-hosted", "run_id": "456", "run_attempt": "1"
                }
            }
        })
    }

    fn st(v: &Value) -> Statement {
        parse(v.to_string().as_bytes()).unwrap()
    }

    #[test]
    fn parses_and_checks_the_target() {
        let s = st(&github_statement());
        assert_eq!(s.subjects[0].get("sha256"), Some("ab12"));
        assert_eq!(s.level(), "ci_source");
        s.check_target(
            "publish",
            "acme",
            "default",
            "cargo",
            "payments",
            Some("1.4.0"),
        )
        .unwrap();
        s.check_target("publish", "acme", "default", "cargo", "payments", None)
            .unwrap();
        let e = s
            .check_target(
                "publish",
                "acme",
                "default",
                "cargo",
                "payments",
                Some("1.4.1"),
            )
            .unwrap_err();
        assert!(
            e.starts_with("wrong_version: the attestation is for version `1.4.0`"),
            "{e}"
        );
        let e = s
            .check_target("publish", "acme", "default", "npm", "payments", None)
            .unwrap_err();
        assert!(e.contains("type `cargo`"), "{e}");
        let e = s
            .check_target("promote", "acme", "default", "cargo", "payments", None)
            .unwrap_err();
        assert!(e.contains("predicate type"), "{e}");
        let facts = s.fact_lines();
        assert_eq!(facts[0], ("tenant".into(), "acme".into()));
        assert!(facts.contains(&("identity.repository".into(), "acme/payments".into())));
    }

    #[test]
    fn bad_statements() {
        let mut v = github_statement();
        v["_type"] = "x".into();
        assert!(parse(v.to_string().as_bytes())
            .unwrap_err()
            .starts_with("bad_statement"));
        let mut v = github_statement();
        v["subject"] = json!([]);
        assert!(parse(v.to_string().as_bytes())
            .unwrap_err()
            .starts_with("bad_statement"));
        let mut v = github_statement();
        v["subject"][0]["digest"]["sha256"] = "zz".into();
        assert!(parse(v.to_string().as_bytes())
            .unwrap_err()
            .starts_with("bad_statement"));
        let mut v = github_statement();
        v["predicate"]["level"] = "root".into();
        let e = st(&v)
            .check_target("publish", "acme", "default", "cargo", "payments", None)
            .unwrap_err();
        assert!(e.starts_with("bad_statement: the level"), "{e}");
    }

    #[test]
    fn policy_passes_and_fails() {
        let s = st(&github_statement());
        let ok = Policy {
            repository: Some("ACME/Payments".into()),
            git_ref: Some("v1.4.0".into()),
            sha: Some("9F2C000000000000000000000000000000000000".into()),
            level: Some("ci_source".into()),
            hosted_runner: true,
        };
        ok.check_options().unwrap();
        assert!(ok.failures(&s).is_empty(), "{:?}", ok.failures(&s));
        let bad = Policy {
            repository: Some("acme/other".into()),
            git_ref: Some("main".into()),
            sha: Some("1".repeat(40)),
            level: Some("workload".into()),
            hosted_runner: false,
        };
        assert_eq!(bad.failures(&s).len(), 4);
        // An API key publish has no source facts.
        let mut v = github_statement();
        v["predicate"]["level"] = "api_key".into();
        v["predicate"]["identity"] = json!({});
        let f = ok.failures(&st(&v));
        assert_eq!(f.len(), 5, "{f:?}");
        assert!(
            f[1].contains("names no repository (level api_key)"),
            "{f:?}"
        );
        // GitLab: project_path and a short ref.
        let mut v = github_statement();
        v["predicate"]["identity"] = json!({"project_path": "acme/payments", "ref": "main",
            "runner_environment": "gitlab-hosted"});
        let p = Policy {
            repository: Some("acme/payments".into()),
            git_ref: Some("main".into()),
            hosted_runner: true,
            ..Policy::default()
        };
        assert!(p.failures(&st(&v)).is_empty());
        // Self-hosted runner.
        let mut v = github_statement();
        v["predicate"]["identity"]["runner_environment"] = "self-hosted".into();
        assert_eq!(
            Policy {
                hosted_runner: true,
                ..Policy::default()
            }
            .failures(&st(&v)),
            vec!["--hosted-runner: the runner is self-hosted".to_string()]
        );
    }

    #[test]
    fn option_checks() {
        assert!(Policy {
            level: Some("root".into()),
            ..Policy::default()
        }
        .check_options()
        .is_err());
        assert!(Policy {
            sha: Some("9f2c".into()),
            ..Policy::default()
        }
        .check_options()
        .is_err());
        assert!(!ref_matches("refs/tags/v1", "refs/heads/v1"));
        assert!(ref_matches("refs/heads/main", "main"));
    }
}
