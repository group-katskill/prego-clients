//! Read-only calls to the Prego admin API, for defaults that `prego setup` can find by itself.

use prego_auth::http::{Body, Http};
use prego_auth::sources::find_subject_token;
use prego_auth::{sts, Config, Env};

/// Gets `GET /v1/admin/tenants/<tenant><path>` with an `admin:read` admin token. Any refusal or error gives
/// `None`, with no message: the caller then asks the user for the value.
pub fn get(config: &Config, env: &dyn Env, path: &str) -> Option<serde_json::Value> {
    let http = Http::with_ca_file(crate::USER_AGENT, config.ca_file.as_deref()).ok()?;
    let subject = find_subject_token(config, env, &http).ok()?;
    let fields = [
        ("grant_type", sts::GRANT_TYPE),
        ("subject_token", subject.value.expose()),
        ("subject_token_type", subject.token_type.urn()),
        ("tenant", config.tenant.as_str()),
        ("audience", "prego-admin"),
        ("scope", "admin:read"),
    ];
    let res = http.post_form(&config.sts_url, &fields).ok()?;
    if res.status != 200 {
        return None;
    }
    let token: serde_json::Value = serde_json::from_str(&res.body).ok()?;
    let token = token["access_token"].as_str()?.to_string();
    let base = config.sts_url.strip_suffix("/v1/sts/token")?;
    let url = format!("{base}/v1/admin/tenants/{}{path}", config.tenant);
    let auth = format!("Bearer {token}");
    let res = http
        .send(
            "GET",
            &url,
            &[("Authorization", &auth), ("Accept", "application/json")],
            Body::Empty,
        )
        .ok()?;
    if res.status != 200 {
        return None;
    }
    serde_json::from_str(&res.body).ok()
}
