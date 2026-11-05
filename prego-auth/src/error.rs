use std::fmt;

use crate::sources::SourceKind;

/// Errors from configuration, identity sources and the STS exchange.
///
/// No variant holds a token value, so it is safe to show any error to the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A bad argument or environment value.
    Config(String),
    /// `auto` mode found no identity source.
    NoSource {
        /// The sources that were checked, with the variables that enable them.
        checked: Vec<SourceKind>,
    },
    /// An identity source is present but could not give a token.
    Source {
        /// The source that failed.
        kind: SourceKind,
        /// What went wrong.
        message: String,
    },
    /// The STS answered `invalid_grant`.
    Refused {
        /// The tenant slug that was sent.
        tenant: String,
    },
    /// The STS answered `429` after all waits: the tenant's budget of token exchanges per minute is used up.
    RateLimited {
        /// The tenant slug that was sent.
        tenant: String,
        /// The last `Retry-After` in seconds, if any.
        retry_after: Option<u64>,
    },
    /// The STS answered with another error.
    Sts {
        /// HTTP status.
        status: u16,
        /// The `error` field, if present.
        code: Option<String>,
        /// The `error_description` field, if present.
        description: Option<String>,
    },
    /// The STS could not be reached after all retries.
    Network(String),
    /// The STS answered `200` with a body that is not a valid token response.
    BadResponse(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Config(m) => write!(f, "prego: {m}"),
            Error::NoSource { checked } => {
                write!(f, "prego: no identity source found. Checked: ")?;
                for (i, k) in checked.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{} ({})", k.name(), k.trigger())?;
                }
                Ok(())
            }
            Error::Source { kind, message } => {
                let end = if message.ends_with('.') { "" } else { "." };
                write!(
                    f,
                    "prego: identity source `{}` failed: {message}{end} \
                     Fix it, or use --source <name> to choose another source.",
                    kind.name()
                )
            }
            Error::Refused { tenant } => write!(
                f,
                "Prego refused this identity for tenant {tenant}. \
                 Check the trust config and principal in the console."
            ),
            Error::Sts {
                status,
                code,
                description,
            } => {
                write!(f, "prego: the STS returned HTTP {status}")?;
                if let Some(c) = code {
                    write!(f, " ({c})")?;
                }
                if let Some(d) = description {
                    write!(f, ": {d}")?;
                }
                Ok(())
            }
            Error::RateLimited {
                tenant,
                retry_after,
            } => {
                write!(
                    f,
                    "prego: the STS refused more token exchanges for now (HTTP 429). The token exchange \
                     budget per minute of tenant {tenant} is used up, or this IP address sent too many \
                     refused requests."
                )?;
                if let Some(s) = retry_after {
                    write!(f, " Try again in {s} s.")?;
                }
                write!(
                    f,
                    " Many parallel jobs, or very short token lifetimes, use up the budget faster."
                )
            }
            Error::Network(m) => write!(f, "prego: cannot reach the STS: {m}"),
            Error::BadResponse(m) => write!(f, "prego: bad STS response: {m}"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refused_message_matches_spec() {
        let e = Error::Refused {
            tenant: "acme".into(),
        };
        assert_eq!(
            e.to_string(),
            "Prego refused this identity for tenant acme. Check the trust config and principal in the console."
        );
    }

    #[test]
    fn source_error_names_source_and_suggests_flag() {
        let e = Error::Source {
            kind: SourceKind::Gitlab,
            message: "value is not a JWT".into(),
        };
        assert_eq!(
            e.to_string(),
            "prego: identity source `gitlab` failed: value is not a JWT. \
             Fix it, or use --source <name> to choose another source."
        );
    }

    #[test]
    fn no_source_lists_checked_sources() {
        let e = Error::NoSource {
            checked: vec![SourceKind::Gitlab, SourceKind::ApiKey],
        };
        let s = e.to_string();
        assert!(s.contains("gitlab (PREGO_ID_TOKEN)"), "{s}");
        assert!(s.contains("api-key (PREGO_API_KEY)"), "{s}");
    }
}
