//! The Cargo `Credential` implementation.

use cargo_credential::{
    Action, CacheControl, Credential, CredentialResponse, Error, RegistryInfo, Secret,
};
use prego_auth::{Config, Env, RegistryToken, TokenClient};
use time::OffsetDateTime;

const CONSOLE_HINT: &str =
    "cargo-credential-prego does not support `cargo login` or `cargo logout`. \
     Manage identities and API keys in the Prego console: https://app.prego.k8skill.com";

/// Gets Prego registry tokens for Cargo.
pub struct PregoCredential {
    client: TokenClient,
    env: Box<dyn Env>,
}

impl PregoCredential {
    /// Makes a provider that reads the given environment.
    pub fn new(env: Box<dyn Env>) -> Self {
        let ua = concat!("cargo-credential-prego/", env!("CARGO_PKG_VERSION"));
        PregoCredential {
            client: TokenClient::new(ua),
            env,
        }
    }
}

impl Credential for PregoCredential {
    fn perform(
        &self,
        registry: &RegistryInfo<'_>,
        action: &Action<'_>,
        args: &[&str],
    ) -> Result<CredentialResponse, Error> {
        match action {
            Action::Get(_) => {
                let config = Config::from_args(args, self.env.as_ref()).map_err(boxed)?;
                let resource = resource_for(registry.index_url);
                let now = prego_auth::now_unix();
                let token = self
                    .client
                    .registry_token_for(&config, self.env.as_ref(), resource.as_deref())
                    .map_err(boxed)?;
                Ok(get_response(token, now))
            }
            Action::Login(_) | Action::Logout => {
                eprintln!("{CONSOLE_HINT}");
                Err(Error::OperationNotSupported)
            }
            _ => Err(Error::OperationNotSupported),
        }
    }
}

fn boxed(e: prego_auth::Error) -> Error {
    Error::Other(Box::new(e))
}

/// The STS `resource` for a sparse index URL: `https://<host>/t/<tenant>/<namespace>/`. `None` for an index URL
/// without that path.
fn resource_for(index_url: &str) -> Option<String> {
    prego_auth::sts::resource_base(index_url).map(|b| format!("{b}/"))
}

/// Builds the `get` response. Cargo may cache the token until its expiry minus `min(60 s, lifetime / 4)`.
/// The expiry is the local time before the request plus `expires_in`, so it is never later than the real one.
fn get_response(token: RegistryToken, now: i64) -> CredentialResponse {
    let until = token.fresh_until();
    let cache = match OffsetDateTime::from_unix_timestamp(until) {
        Ok(expiration) if until > now => CacheControl::Expires { expiration },
        _ => CacheControl::Never,
    };
    CredentialResponse::Get {
        token: Secret::from(token.token.expose().to_string()),
        cache,
        operation_independent: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(received_at: i64, lifetime: i64) -> RegistryToken {
        RegistryToken::new(prego_auth::Secret::new("t"), received_at, lifetime)
    }

    fn expiration(r: CredentialResponse) -> Option<i64> {
        match r {
            CredentialResponse::Get {
                cache: CacheControl::Expires { expiration },
                operation_independent,
                ..
            } => {
                assert!(operation_independent);
                Some(expiration.unix_timestamp())
            }
            CredentialResponse::Get {
                cache: CacheControl::Never,
                ..
            } => None,
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn cache_hint_uses_the_lifetime_and_the_margin() {
        // 15 minutes: margin 60 s.
        assert_eq!(
            expiration(get_response(token(1_000, 900), 1_000)),
            Some(1_840)
        );
        // 5 minutes: margin 60 s.
        assert_eq!(
            expiration(get_response(token(1_000, 300), 1_000)),
            Some(1_240)
        );
        // 1 minute: margin 15 s, so Cargo still caches for 45 s.
        assert_eq!(
            expiration(get_response(token(1_000, 60), 1_000)),
            Some(1_045)
        );
        // 30 minutes: margin 60 s.
        assert_eq!(
            expiration(get_response(token(1_000, 1_800), 1_000)),
            Some(2_740)
        );
    }

    #[test]
    fn a_token_too_short_to_cache_is_not_cached() {
        assert_eq!(expiration(get_response(token(1_000, 0), 1_000)), None);
        assert_eq!(expiration(get_response(token(1_000, 60), 1_045)), None);
    }

    #[test]
    fn resource_from_the_index_url() {
        let want = Some("https://cargo.prego.k8skill.com/t/acme/default/".to_string());
        assert_eq!(
            resource_for("sparse+https://cargo.prego.k8skill.com/t/acme/default/index/"),
            want
        );
        assert_eq!(
            resource_for("sparse+https://cargo.prego.k8skill.com/t/acme/default/index"),
            want
        );
        assert_eq!(
            resource_for("sparse+https://cargo.prego.k8skill.com/t/vendor/rel/index/"),
            Some("https://cargo.prego.k8skill.com/t/vendor/rel/".into())
        );
        assert_eq!(resource_for("sparse+https://index.crates.io/"), None);
    }

    #[test]
    fn login_and_logout_are_not_supported() {
        let p = PregoCredential::new(Box::new(prego_auth::MapEnv::new()));
        let reg = RegistryInfo {
            index_url: "sparse+https://cargo.prego.k8skill.com/t/acme/default/index/",
            name: Some("acme"),
            headers: vec![],
        };
        assert!(matches!(
            p.perform(&reg, &Action::Logout, &[]),
            Err(Error::OperationNotSupported)
        ));
        assert!(matches!(
            p.perform(&reg, &Action::Unknown, &[]),
            Err(Error::OperationNotSupported)
        ));
    }
}
