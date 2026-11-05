//! Identity sources: where a client finds its subject token.

mod api_key;
mod file;
mod github;
mod spiffe;

use crate::config::{Config, SourceChoice};
use crate::env::Env;
use crate::error::Error;
use crate::http::Http;
use crate::jwt;
use crate::secret::Secret;

/// One identity source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceKind {
    /// SPIFFE Workload API (`SPIFFE_ENDPOINT_SOCKET`).
    Spiffe,
    /// JWT-SVID in a file (`PREGO_SVID_FILE`).
    SvidFile,
    /// GitLab CI `id_tokens` (`PREGO_ID_TOKEN`).
    Gitlab,
    /// GitHub Actions OIDC (`ACTIONS_ID_TOKEN_REQUEST_URL` and `_TOKEN`).
    Github,
    /// OIDC JWT in a file (`PREGO_TOKEN_FILE`).
    TokenFile,
    /// Prego API key (`PREGO_API_KEY`).
    ApiKey,
}

impl SourceKind {
    /// The order that `auto` mode uses.
    pub const AUTO_ORDER: [SourceKind; 6] = [
        SourceKind::Spiffe,
        SourceKind::SvidFile,
        SourceKind::Gitlab,
        SourceKind::Github,
        SourceKind::TokenFile,
        SourceKind::ApiKey,
    ];

    /// The name used by `--source`.
    pub fn name(self) -> &'static str {
        match self {
            SourceKind::Spiffe => "spiffe",
            SourceKind::SvidFile => "svid-file",
            SourceKind::Gitlab => "gitlab",
            SourceKind::Github => "github",
            SourceKind::TokenFile => "token-file",
            SourceKind::ApiKey => "api-key",
        }
    }

    /// Parses a `--source` name.
    pub fn parse(name: &str) -> Option<SourceKind> {
        Self::AUTO_ORDER.into_iter().find(|k| k.name() == name)
    }

    /// The environment variables that make this source present.
    pub fn trigger(self) -> &'static str {
        match self {
            SourceKind::Spiffe => "SPIFFE_ENDPOINT_SOCKET",
            SourceKind::SvidFile => "PREGO_SVID_FILE",
            SourceKind::Gitlab => "PREGO_ID_TOKEN",
            SourceKind::Github => "ACTIONS_ID_TOKEN_REQUEST_URL + ACTIONS_ID_TOKEN_REQUEST_TOKEN",
            SourceKind::TokenFile => "PREGO_TOKEN_FILE",
            SourceKind::ApiKey => "PREGO_API_KEY",
        }
    }

    /// The `subject_token_type` this source gives.
    pub fn token_type(self) -> TokenType {
        match self {
            SourceKind::ApiKey => TokenType::ApiKey,
            _ => TokenType::Jwt,
        }
    }

    /// True if the environment holds what this source needs.
    pub fn is_present(self, env: &dyn Env) -> bool {
        match self {
            SourceKind::Github => {
                env.var("ACTIONS_ID_TOKEN_REQUEST_URL").is_some()
                    && env.var("ACTIONS_ID_TOKEN_REQUEST_TOKEN").is_some()
            }
            other => env.var(other.trigger()).is_some(),
        }
    }

    fn fetch(self, env: &dyn Env, audience: &str, http: &Http) -> Result<Secret, String> {
        // `is_present` was true, so the variables below are set.
        let var = |name: &str| env.var(name).unwrap_or_default();
        match self {
            SourceKind::Spiffe => spiffe::fetch(&var("SPIFFE_ENDPOINT_SOCKET"), audience),
            SourceKind::SvidFile => file::read_token(&var("PREGO_SVID_FILE")),
            SourceKind::Gitlab => Ok(Secret::new(var("PREGO_ID_TOKEN").trim())),
            SourceKind::Github => github::fetch(
                http,
                &var("ACTIONS_ID_TOKEN_REQUEST_URL"),
                &var("ACTIONS_ID_TOKEN_REQUEST_TOKEN"),
                audience,
            ),
            SourceKind::TokenFile => file::read_token(&var("PREGO_TOKEN_FILE")),
            SourceKind::ApiKey => api_key::read(&var("PREGO_API_KEY")),
        }
    }
}

/// The `subject_token_type` sent to the STS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    /// A JWT-SVID or an OIDC ID token.
    Jwt,
    /// A Prego API key.
    ApiKey,
}

impl TokenType {
    /// The URN for the `subject_token_type` field.
    pub fn urn(self) -> &'static str {
        match self {
            TokenType::Jwt => "urn:ietf:params:oauth:token-type:jwt",
            TokenType::ApiKey => "urn:k8skill:prego:token-type:api-key",
        }
    }
}

/// A subject token and where it came from.
#[derive(Debug, Clone)]
pub struct SubjectToken {
    /// The source that gave the token.
    pub kind: SourceKind,
    /// The `subject_token_type`.
    pub token_type: TokenType,
    /// The token value.
    pub value: Secret,
}

/// Finds the subject token that `config` selects.
///
/// In `auto` mode the first present source is used. If it fails, the error is returned; the next source is
/// not tried, so the client never uses an identity that the user did not expect (fail closed).
pub fn find_subject_token(
    config: &Config,
    env: &dyn Env,
    http: &Http,
) -> Result<SubjectToken, Error> {
    let kind = match config.source {
        SourceChoice::Only(kind) => {
            if !kind.is_present(env) {
                return Err(Error::Source {
                    kind,
                    message: format!("not configured. Set {}.", kind.trigger()),
                });
            }
            kind
        }
        SourceChoice::Auto => SourceKind::AUTO_ORDER
            .into_iter()
            .find(|k| k.is_present(env))
            .ok_or_else(|| Error::NoSource {
                checked: SourceKind::AUTO_ORDER.to_vec(),
            })?,
    };

    let value = kind
        .fetch(env, &config.audience, http)
        .map_err(|message| Error::Source { kind, message })?;
    let token_type = kind.token_type();
    if token_type == TokenType::Jwt {
        jwt::check_shape(value.expose()).map_err(|message| Error::Source { kind, message })?;
    }
    Ok(SubjectToken {
        kind,
        token_type,
        value,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::MapEnv;

    const JWT: &str = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln";

    fn cfg(source: SourceChoice) -> Config {
        Config {
            tenant: "acme".into(),
            sts_url: crate::DEFAULT_STS_URL.into(),
            edge_code: Some("k7mq".into()),
            audience: crate::DEFAULT_AUDIENCE.into(),
            source,
            ca_file: None,
        }
    }

    fn http() -> Http {
        Http::new("test")
    }

    #[test]
    fn names_round_trip() {
        for k in SourceKind::AUTO_ORDER {
            assert_eq!(SourceKind::parse(k.name()), Some(k));
        }
        assert_eq!(SourceKind::parse("auto"), None);
    }

    #[test]
    fn auto_with_nothing_lists_all_sources() {
        let e = find_subject_token(&cfg(SourceChoice::Auto), &MapEnv::new(), &http()).unwrap_err();
        assert_eq!(
            e,
            Error::NoSource {
                checked: SourceKind::AUTO_ORDER.to_vec()
            }
        );
    }

    #[test]
    fn auto_picks_first_present_in_order() {
        let env = MapEnv::new()
            .with("PREGO_API_KEY", "prk_abc")
            .with("PREGO_ID_TOKEN", JWT);
        let t = find_subject_token(&cfg(SourceChoice::Auto), &env, &http()).unwrap();
        assert_eq!(t.kind, SourceKind::Gitlab);
        assert_eq!(t.token_type, TokenType::Jwt);
        assert_eq!(t.value.expose(), JWT);
    }

    #[test]
    fn auto_does_not_fall_through_on_failure() {
        let env = MapEnv::new()
            .with("PREGO_ID_TOKEN", "not-a-jwt")
            .with("PREGO_API_KEY", "prk_abc");
        let e = find_subject_token(&cfg(SourceChoice::Auto), &env, &http()).unwrap_err();
        assert!(
            matches!(
                e,
                Error::Source {
                    kind: SourceKind::Gitlab,
                    ..
                }
            ),
            "{e:?}"
        );
    }

    #[test]
    fn forced_source_must_be_present() {
        let env = MapEnv::new().with("PREGO_ID_TOKEN", JWT);
        let e = find_subject_token(&cfg(SourceChoice::Only(SourceKind::ApiKey)), &env, &http())
            .unwrap_err();
        assert!(e.to_string().contains("PREGO_API_KEY"), "{e}");
    }

    #[test]
    fn forced_source_skips_earlier_sources() {
        let env = MapEnv::new()
            .with("PREGO_ID_TOKEN", JWT)
            .with("PREGO_API_KEY", "prk_abc");
        let t = find_subject_token(&cfg(SourceChoice::Only(SourceKind::ApiKey)), &env, &http())
            .unwrap();
        assert_eq!(t.kind, SourceKind::ApiKey);
        assert_eq!(t.token_type.urn(), "urn:k8skill:prego:token-type:api-key");
    }

    #[test]
    fn gitlab_source() {
        let env = MapEnv::new().with("PREGO_ID_TOKEN", &format!(" {JWT}\n"));
        let t = find_subject_token(&cfg(SourceChoice::Only(SourceKind::Gitlab)), &env, &http())
            .unwrap();
        assert_eq!(t.value.expose(), JWT);
        assert_eq!(t.token_type.urn(), "urn:ietf:params:oauth:token-type:jwt");
    }

    #[test]
    fn github_needs_both_variables() {
        let env = MapEnv::new().with("ACTIONS_ID_TOKEN_REQUEST_URL", "https://example.test/x");
        assert!(!SourceKind::Github.is_present(&env));
        let env = env.with("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "t");
        assert!(SourceKind::Github.is_present(&env));
    }

    #[test]
    fn error_never_holds_token_value() {
        let secret = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0";
        let env = MapEnv::new().with("PREGO_ID_TOKEN", secret);
        let e = find_subject_token(&cfg(SourceChoice::Auto), &env, &http()).unwrap_err();
        assert!(!e.to_string().contains(secret));
        assert!(!format!("{e:?}").contains(secret));
    }
}
