//! Client configuration from arguments, with environment and settings-file fallbacks.

use crate::env::Env;
use crate::error::Error;
use crate::file_config::FileConfig;
use crate::sources::SourceKind;

/// The default STS endpoint.
pub const DEFAULT_STS_URL: &str = "https://sts.prego.k8skill.com/v1/sts/token";
/// The path of the token exchange on the STS host, without the edge code.
pub const STS_PATH: &str = "/v1/sts/token";
/// The default audience for SVIDs and CI tokens.
pub const DEFAULT_AUDIENCE: &str = "prego.k8skill.com";

/// Which identity source to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceChoice {
    /// Use the first source that is present, in [`SourceKind::AUTO_ORDER`].
    Auto,
    /// Use only this source.
    Only(SourceKind),
}

/// Settings for one token request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Tenant slug sent to the STS.
    pub tenant: String,
    /// STS endpoint URL without the edge code (`.../v1/sts/token`). Admin tokens use it as it is.
    pub sts_url: String,
    /// The tenant's edge code (4 characters, see [`check_edge_code`]). Registry tokens come from
    /// `<sts_url>/e/<edge code>` ([`Config::token_url`]).
    pub edge_code: Option<String>,
    /// Audience to request for SVIDs and CI tokens.
    pub audience: String,
    /// Identity source selection.
    pub source: SourceChoice,
    /// Optional PEM CA bundle (`PREGO_CA_FILE`), added to the built-in roots. For on-prem TLS proxies.
    pub ca_file: Option<String>,
}

impl Config {
    /// Parses arguments (`--tenant acme` or `--tenant=acme`) and fills gaps from the environment, then from
    /// the settings file ([`FileConfig`]).
    ///
    /// Order: argument, then `PREGO_*` variable, then the settings file, then the default.
    pub fn from_args(args: &[&str], env: &dyn Env) -> Result<Config, Error> {
        let file = FileConfig::load(env)?;
        Self::from_parts(args, env, &file)
    }

    /// Like [`Config::from_args`], with a settings file that is already loaded.
    pub fn from_parts(args: &[&str], env: &dyn Env, file: &FileConfig) -> Result<Config, Error> {
        let mut tenant = None;
        let mut sts_url = None;
        let mut audience = None;
        let mut source = None;
        let mut edge_code = None;

        let mut it = args.iter();
        while let Some(arg) = it.next() {
            let (name, inline) = match arg.split_once('=') {
                Some((n, v)) if n.starts_with("--") => (n, Some(v.to_string())),
                _ => (*arg, None),
            };
            let slot = match name {
                "--tenant" => &mut tenant,
                "--sts-url" => &mut sts_url,
                "--audience" => &mut audience,
                "--source" => &mut source,
                "--edge-code" => &mut edge_code,
                other => return Err(Error::Config(format!("unknown argument `{other}`"))),
            };
            let value = match inline {
                Some(v) => v,
                None => it
                    .next()
                    .map(|v| v.to_string())
                    .ok_or_else(|| Error::Config(format!("{name} needs a value")))?,
            };
            *slot = Some(value);
        }

        let tenant = tenant
            .or_else(|| env.var("PREGO_TENANT"))
            .or_else(|| file.tenant.clone())
            .ok_or_else(|| {
                Error::Config(
                    "tenant is not set. Use --tenant <slug>, PREGO_TENANT, or `tenant` in \
                     ~/.config/prego/config.toml."
                        .into(),
                )
            })?;
        validate_tenant(&tenant)?;

        let sts_url = sts_url
            .or_else(|| env.var("PREGO_STS_URL"))
            .or_else(|| file.sts_url.clone())
            .unwrap_or_else(|| DEFAULT_STS_URL.to_string());
        validate_sts_url(&sts_url)?;
        // A token URL from the console (`.../v1/sts/token/e/<code>`) also works as the STS URL.
        let (sts_url, url_code) = split_token_url(&sts_url)?;
        let edge_code = match edge_code
            .or_else(|| env.var("PREGO_EDGE_CODE"))
            .or_else(|| file.edge_code.clone())
        {
            Some(code) => {
                check_edge_code(&code)?;
                if let Some(u) = &url_code {
                    if *u != code {
                        return Err(Error::Config(format!(
                            "the edge code `{code}` is not the one in the STS URL (`{u}`). Set only one of them."
                        )));
                    }
                }
                Some(code)
            }
            None => url_code,
        };

        let audience = audience
            .or_else(|| env.var("PREGO_AUDIENCE"))
            .or_else(|| file.audience.clone())
            .unwrap_or_else(|| DEFAULT_AUDIENCE.to_string());
        if audience.trim().is_empty() || audience.chars().any(char::is_whitespace) {
            return Err(Error::Config(
                "audience must not be blank or hold spaces".into(),
            ));
        }

        let source = match source
            .or_else(|| env.var("PREGO_SOURCE"))
            .or_else(|| file.source.clone())
        {
            None => SourceChoice::Auto,
            Some(s) if s == "auto" => SourceChoice::Auto,
            Some(s) => SourceChoice::Only(SourceKind::parse(&s).ok_or_else(|| {
                Error::Config(format!(
                    "unknown source `{s}`. Use auto, spiffe, svid-file, gitlab, github, token-file, api-key or device."
                ))
            })?),
        };

        let ca_file = env.var("PREGO_CA_FILE");

        Ok(Config {
            tenant,
            sts_url,
            edge_code,
            audience,
            source,
            ca_file,
        })
    }

    /// The URL for registry token exchanges: `<sts_url>/e/<edge code>`. An error if the edge code is not
    /// set, because the STS refuses registry tokens on the URL without it.
    pub fn token_url(&self) -> Result<String, Error> {
        match &self.edge_code {
            Some(code) => Ok(format!("{}/e/{code}", self.sts_url)),
            None => Err(Error::Config(MISSING_EDGE_CODE.into())),
        }
    }
}

/// The message when a registry token needs the edge code and it is not set.
pub const MISSING_EDGE_CODE: &str = "the edge code of your tenant is not set. The Prego console shows it \
(4 characters, for example `k7mq`). Set PREGO_EDGE_CODE, `edge_code` in ~/.config/prego/config.toml, or \
--edge-code. The console's token URL (`.../v1/sts/token/e/<code>`) also works as the STS URL.";

/// Checks an edge code: 4 characters from `a-z` and `2-9`, without `i`, `l`, `0` and `1`. Lower case only.
pub fn check_edge_code(code: &str) -> Result<(), Error> {
    let ok = code.len() == 4
        && code
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'9') && b != b'i' && b != b'l');
    if ok {
        Ok(())
    } else {
        Err(Error::Config(format!(
            "bad edge code `{code}`: it has 4 characters from a-z and 2-9, without i, l, 0 and 1 (lower case)"
        )))
    }
}

/// Splits `.../v1/sts/token/e/<code>` into the STS URL and the code. Other URLs come back as they are.
fn split_token_url(url: &str) -> Result<(String, Option<String>), Error> {
    let marker = format!("{STS_PATH}/e/");
    match url.rfind(&marker) {
        Some(at) => {
            let code = &url[at + marker.len()..];
            check_edge_code(code)?;
            Ok((
                url[..at + STS_PATH.len()].to_string(),
                Some(code.to_string()),
            ))
        }
        None => Ok((url.to_string(), None)),
    }
}

fn validate_tenant(tenant: &str) -> Result<(), Error> {
    let ok = !tenant.is_empty()
        && tenant.len() <= 128
        && tenant
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');
    if ok {
        Ok(())
    } else {
        Err(Error::Config(format!("bad tenant slug `{tenant}`")))
    }
}

/// Subject tokens go only over https, or over http to a loopback host for local tests.
fn validate_sts_url(url: &str) -> Result<(), Error> {
    let uri: ureq::http::Uri = url
        .parse()
        .map_err(|_| Error::Config(format!("bad STS URL `{url}`")))?;
    let host = uri.host().unwrap_or("");
    match uri.scheme_str() {
        Some("https") if !host.is_empty() => Ok(()),
        Some("http") if matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1") => Ok(()),
        _ => Err(Error::Config(format!(
            "STS URL `{url}` must use https (http only for localhost)"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::MapEnv;

    #[test]
    fn defaults() {
        let c = Config::from_args(&["--tenant", "acme"], &MapEnv::new()).unwrap();
        assert_eq!(c.tenant, "acme");
        assert_eq!(c.sts_url, DEFAULT_STS_URL);
        assert_eq!(c.audience, DEFAULT_AUDIENCE);
        assert_eq!(c.source, SourceChoice::Auto);
        assert_eq!(c.ca_file, None);
        assert_eq!(c.edge_code, None);
        assert!(c
            .token_url()
            .unwrap_err()
            .to_string()
            .contains("PREGO_EDGE_CODE"));
    }

    #[test]
    fn edge_code_sources() {
        let file = FileConfig {
            tenant: Some("acme".into()),
            edge_code: Some("k7mq".into()),
            ..FileConfig::default()
        };
        let c = Config::from_parts(&[], &MapEnv::new(), &file).unwrap();
        assert_eq!(
            c.token_url().unwrap(),
            "https://sts.prego.k8skill.com/v1/sts/token/e/k7mq"
        );
        assert_eq!(c.sts_url, DEFAULT_STS_URL);
        let env = MapEnv::new().with("PREGO_EDGE_CODE", "ab2c");
        let c = Config::from_parts(&[], &env, &file).unwrap();
        assert_eq!(c.edge_code.as_deref(), Some("ab2c"));
        let c = Config::from_parts(&["--edge-code=zz99"], &env, &file).unwrap();
        assert_eq!(c.edge_code.as_deref(), Some("zz99"));
    }

    #[test]
    fn token_url_as_sts_url() {
        let env = MapEnv::new().with("PREGO_TENANT", "acme").with(
            "PREGO_STS_URL",
            "https://sts.example.test/v1/sts/token/e/k7mq",
        );
        let c = Config::from_args(&[], &env).unwrap();
        assert_eq!(c.sts_url, "https://sts.example.test/v1/sts/token");
        assert_eq!(c.edge_code.as_deref(), Some("k7mq"));
        assert_eq!(
            c.token_url().unwrap(),
            "https://sts.example.test/v1/sts/token/e/k7mq"
        );
        let same = Config::from_args(&["--edge-code", "k7mq"], &env).unwrap();
        assert_eq!(same, c);
        let e = Config::from_args(&["--edge-code", "ab2c"], &env).unwrap_err();
        assert!(e.to_string().contains("not the one in the STS URL"));
        let bad = MapEnv::new().with("PREGO_TENANT", "acme").with(
            "PREGO_STS_URL",
            "https://sts.example.test/v1/sts/token/e/K7MQ",
        );
        assert!(Config::from_args(&[], &bad).is_err());
    }

    #[test]
    fn edge_code_check() {
        for ok in ["k7mq", "abcd", "2345", "zz99", "hjkm"] {
            check_edge_code(ok).unwrap();
        }
        for bad in [
            "", "abc", "abcde", "K7MQ", "ab1c", "ab0c", "abic", "ablc", "ab-c", "ab%c", "ab c",
        ] {
            assert!(check_edge_code(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn args_win_over_env() {
        let env = MapEnv::new()
            .with("PREGO_TENANT", "envco")
            .with("PREGO_SOURCE", "gitlab");
        let c = Config::from_args(&["--tenant=acme", "--source", "api-key"], &env).unwrap();
        assert_eq!(c.tenant, "acme");
        assert_eq!(c.source, SourceChoice::Only(SourceKind::ApiKey));
    }

    #[test]
    fn env_fallbacks() {
        let env = MapEnv::new()
            .with("PREGO_TENANT", "acme")
            .with("PREGO_STS_URL", "http://127.0.0.1:8787/v1/sts/token")
            .with("PREGO_AUDIENCE", "example.test")
            .with("PREGO_SOURCE", "token-file")
            .with("PREGO_CA_FILE", "/etc/prego/ca.pem");
        let c = Config::from_args(&[], &env).unwrap();
        assert_eq!(c.sts_url, "http://127.0.0.1:8787/v1/sts/token");
        assert_eq!(c.audience, "example.test");
        assert_eq!(c.source, SourceChoice::Only(SourceKind::TokenFile));
        assert_eq!(c.ca_file.as_deref(), Some("/etc/prego/ca.pem"));
    }

    #[test]
    fn tenant_required() {
        let e = Config::from_args(&[], &MapEnv::new()).unwrap_err();
        assert!(e.to_string().contains("PREGO_TENANT"));
    }

    #[test]
    fn file_is_the_last_fallback() {
        let file = FileConfig {
            tenant: Some("fileco".into()),
            sts_url: Some("https://sts.example.test/v1/sts/token".into()),
            audience: Some("file.example.test".into()),
            source: Some("api-key".into()),
            ..FileConfig::default()
        };
        let c = Config::from_parts(&[], &MapEnv::new(), &file).unwrap();
        assert_eq!(c.tenant, "fileco");
        assert_eq!(c.sts_url, "https://sts.example.test/v1/sts/token");
        assert_eq!(c.audience, "file.example.test");
        assert_eq!(c.source, SourceChoice::Only(SourceKind::ApiKey));

        let env = MapEnv::new().with("PREGO_TENANT", "envco");
        let c = Config::from_parts(&[], &env, &file).unwrap();
        assert_eq!(c.tenant, "envco");
        let c = Config::from_parts(&["--tenant", "argco"], &env, &file).unwrap();
        assert_eq!(c.tenant, "argco");
    }

    #[test]
    fn file_values_are_checked() {
        let file = FileConfig {
            tenant: Some("bad slug".into()),
            ..FileConfig::default()
        };
        assert!(Config::from_parts(&[], &MapEnv::new(), &file).is_err());
    }

    #[test]
    fn no_cache_switch_is_gone() {
        assert!(Config::from_args(&["--tenant", "a", "--no-cache"], &MapEnv::new()).is_err());
    }

    #[test]
    fn rejects_unknown_arg_and_missing_value() {
        assert!(Config::from_args(&["--tenant", "a", "--bogus"], &MapEnv::new()).is_err());
        assert!(Config::from_args(&["--tenant"], &MapEnv::new()).is_err());
        assert!(Config::from_args(&["--tenant", "a b"], &MapEnv::new()).is_err());
    }

    #[test]
    fn rejects_plain_http_to_remote_host() {
        let e = Config::from_args(
            &[
                "--tenant",
                "a",
                "--sts-url",
                "http://sts.example.com/v1/sts/token",
            ],
            &MapEnv::new(),
        )
        .unwrap_err();
        assert!(e.to_string().contains("https"));
        for ok in [
            "http://localhost:8787/x",
            "http://[::1]:1/x",
            "https://sts.example.com/x",
        ] {
            Config::from_args(&["--tenant", "a", "--sts-url", ok], &MapEnv::new()).unwrap();
        }
    }

    #[test]
    fn rejects_unknown_source() {
        let e = Config::from_args(&["--tenant", "a", "--source", "kerberos"], &MapEnv::new())
            .unwrap_err();
        assert!(e.to_string().contains("unknown source"));
    }
}
