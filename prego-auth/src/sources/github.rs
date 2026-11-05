//! `github` source: request an OIDC token from the GitHub Actions runtime.

use serde::Deserialize;

use crate::http::Http;
use crate::secret::Secret;

#[derive(Deserialize)]
struct TokenBody {
    value: Option<String>,
}

/// Calls `GET $ACTIONS_ID_TOKEN_REQUEST_URL&audience=<aud>` with the request token, and reads `.value`.
pub(crate) fn fetch(
    http: &Http,
    request_url: &str,
    request_token: &str,
    audience: &str,
) -> Result<Secret, String> {
    let res = http
        .get_with_bearer(request_url, ("audience", audience), request_token)
        .map_err(|e| format!("cannot reach the GitHub Actions token service: {e}"))?;
    if res.status != 200 {
        return Err(format!(
            "the GitHub Actions token service returned HTTP {}. Does the workflow have `permissions: id-token: write`?",
            res.status
        ));
    }
    let body: TokenBody = serde_json::from_str(&res.body).map_err(|_| {
        "the GitHub Actions token service returned a body that is not JSON".to_string()
    })?;
    match body.value {
        Some(v) if !v.trim().is_empty() => Ok(Secret::new(v.trim())),
        _ => Err("the GitHub Actions token service returned no `value`".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{MockResponse, MockServer};

    #[test]
    fn requests_token_with_audience_and_bearer() {
        let server = MockServer::start(vec![MockResponse::json(
            200,
            r#"{"count":1,"value":"a.b.c"}"#,
        )]);
        let url = format!("{}/token?api-version=2.0", server.base_url());
        let t = fetch(&Http::new("test"), &url, "req-token", "prego.k8skill.com").unwrap();
        assert_eq!(t.expose(), "a.b.c");

        let reqs = server.requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, "GET");
        assert_eq!(
            reqs[0].target,
            "/token?api-version=2.0&audience=prego.k8skill.com"
        );
        assert_eq!(
            reqs[0].header("authorization").as_deref(),
            Some("bearer req-token")
        );
    }

    #[test]
    fn reports_http_errors_and_bad_bodies() {
        let server = MockServer::start(vec![
            MockResponse::json(403, r#"{"message":"no"}"#),
            MockResponse::json(200, "nope"),
            MockResponse::json(200, r#"{"value":""}"#),
        ]);
        let url = format!("{}/token?x=1", server.base_url());
        let http = Http::new("test");
        assert!(fetch(&http, &url, "t", "aud")
            .unwrap_err()
            .contains("id-token: write"));
        assert!(fetch(&http, &url, "t", "aud")
            .unwrap_err()
            .contains("not JSON"));
        assert!(fetch(&http, &url, "t", "aud")
            .unwrap_err()
            .contains("no `value`"));
    }
}
