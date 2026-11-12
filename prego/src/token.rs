//! `prego token` and `prego whoami`.

use prego_auth::http::Http;
use prego_auth::sources::find_subject_token;
use prego_auth::{jwt, npm, oci, sts, Config, Env, FileConfig, RegistryToken, SourceKind};

/// Gets a registry token: from the STS, or from the OCI realm if `scopes` is not empty.
pub(crate) fn registry_token(
    config: &Config,
    scopes: &[String],
    resource: Option<&str>,
    env: &dyn Env,
) -> Result<(SourceKind, RegistryToken), String> {
    let http = Http::with_ca_file(crate::USER_AGENT, config.ca_file.as_deref())
        .map_err(|e| format!("prego: PREGO_CA_FILE: {e}"))?;
    let subject = find_subject_token(config, env, &http).map_err(|e| e.to_string())?;
    let now = prego_auth::now_unix();
    let sleep = std::thread::sleep;
    let token = if scopes.is_empty() {
        sts::exchange(&http, config, &subject, resource, now, &sleep)
    } else {
        oci::realm_token(
            &http,
            config,
            oci::DEFAULT_OCI_HOST,
            scopes,
            &subject,
            now,
            &sleep,
        )
    }
    .map_err(|e| e.to_string())?;
    Ok((subject.kind, token))
}

/// Checks a `--resource` value: a registry base URL `<scheme>://<host>/t/<tenant>/<namespace>[/...]`.
fn check_resource(resource: Option<&str>) -> Result<(), String> {
    match resource {
        Some(r) if sts::resource_base(r).is_none() => Err(format!(
            "prego: bad --resource `{r}`: give a registry base URL such as \
             https://cargo.prego.k8skill.com/t/<tenant>/<namespace>/"
        )),
        _ => Ok(()),
    }
}

/// The lifetime as text: `15 min`, or `1 min 30 s`.
pub(crate) fn minutes(secs: i64) -> String {
    match (secs / 60, secs % 60) {
        (m, 0) => format!("{m} min"),
        (0, s) => format!("{s} s"),
        (m, s) => format!("{m} min {s} s"),
    }
}

/// `prego token`: prints the registry token on stdout, and nothing else.
pub fn token(
    globals: &[&str],
    scopes: &[String],
    resource: Option<&str>,
    env: &dyn Env,
) -> Result<(), String> {
    check_resource(resource)?;
    for s in scopes {
        if s.is_empty() || s.chars().any(char::is_whitespace) {
            return Err(format!("prego: bad scope `{s}`"));
        }
    }
    let config = Config::from_args(globals, env).map_err(|e| e.to_string())?;
    let (_, token) = registry_token(&config, scopes, resource, env)?;
    println!("{}", token.token.expose());
    Ok(())
}

/// `prego whoami`: gets a token, and shows who it is for. It never shows the token.
pub fn whoami(
    globals: &[&str],
    namespace: &str,
    resource: Option<&str>,
    env: &dyn Env,
) -> Result<(), String> {
    crate::setup::check_slug("namespace", namespace)?;
    check_resource(resource)?;
    let file = FileConfig::load(env).map_err(|e| e.to_string())?;
    let config = Config::from_parts(globals, env, &file).map_err(|e| e.to_string())?;
    let (kind, token) = registry_token(&config, &[], resource, env)?;
    let claims = jwt::unverified_claims(token.token.expose()).unwrap_or_default();
    let claim = |name: &str| {
        claims
            .get(name)
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string()
    };
    let lifetime = minutes(token.lifetime);
    let scope = match resource {
        Some(r) => format!("for {r}"),
        None => "for all your grants".into(),
    };
    let t = &config.tenant;
    println!("tenant:     {t}");
    println!("source:     {}", kind.name());
    if let Ok(url) = config.token_url() {
        println!("token URL:  {url}");
    }
    // Read from the token without a signature check. Show only, never trust.
    println!("principal:  {} (not verified)", claim("sub"));
    // From the STS answer over TLS, for display only (registry 1.10.0 and later).
    match &token.principal_name {
        Some(name) => println!("name:       {name}"),
        None => println!("name:       unknown (the STS did not send it)"),
    }
    println!("tenant id:  {} (not verified)", claim("tid"));
    println!("token:      lifetime {lifetime} {scope} (not shown; use `prego token`)");
    println!("cargo:      sparse+https://cargo.prego.k8skill.com/t/{t}/{namespace}/index/");
    println!(
        "oci:        {}/{t}/{namespace}/<repo>",
        oci::DEFAULT_OCI_HOST
    );
    println!(
        "npm:        {} (scoped packages)",
        npm::registry_url(&npm::npm_host(&file, env), t, namespace)
    );
    Ok(())
}
