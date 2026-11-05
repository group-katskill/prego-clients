//! A small blocking HTTP client over `ureq` with `rustls`.

use std::fs::File;
use std::io::Read;
use std::time::Duration;

use ureq::tls::{parse_pem, Certificate, PemItem, RootCerts, TlsConfig};

/// Timeout for each HTTP request.
pub const TIMEOUT: Duration = Duration::from_secs(10);
/// Largest CA bundle that the client reads.
const MAX_CA_FILE: u64 = 1024 * 1024;
/// Largest response body that the client reads.
const MAX_BODY: u64 = 64 * 1024;
/// Timeout for one socket read or write of a transfer client ([`Http::for_transfers`]).
pub const TRANSFER_IO_TIMEOUT: Duration = Duration::from_secs(120);

/// A request body for [`Http::send`].
pub enum Body<'a> {
    /// No body.
    Empty,
    /// Bytes in memory.
    Bytes(&'a [u8]),
    /// `len` bytes from a reader. They are streamed, not read into memory. `Content-Length` is `len`.
    Reader(&'a mut dyn Read, u64),
}

/// A status, the response headers and the body (at most 64 KiB, as text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullResponse {
    /// HTTP status code.
    pub status: u16,
    /// Headers with lowercase names, in order.
    pub headers: Vec<(String, String)>,
    /// Response body as text.
    pub body: String,
}

impl FullResponse {
    /// Returns the first header with this name (any case).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// A status and body. Non-2xx statuses are not errors at this level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// HTTP status code.
    pub status: u16,
    /// Response body as text.
    pub body: String,
    /// The `Retry-After` header in seconds, if it is a number.
    pub retry_after: Option<u64>,
}

/// Blocking HTTP client. It never follows redirects, so a token never goes to another host.
#[derive(Debug, Clone)]
pub struct Http {
    agent: ureq::Agent,
}

impl Http {
    /// Makes a client with a 10 s timeout and the given `User-Agent`. It trusts the Mozilla root set.
    pub fn new(user_agent: &str) -> Self {
        Self::build(user_agent, TlsConfig::default())
    }

    /// Like [`Http::new`], and also trusts the CA certificates in the PEM file `ca_file`, if given.
    ///
    /// The extra roots are added to the Mozilla root set; they do not replace it. TLS certificate
    /// checks are always on. There is no way to turn them off.
    pub fn with_ca_file(user_agent: &str, ca_file: Option<&str>) -> Result<Self, String> {
        let Some(path) = ca_file else {
            return Ok(Self::new(user_agent));
        };
        let mut roots: Vec<Certificate<'static>> = webpki_root_certs::TLS_SERVER_ROOT_CERTS
            .iter()
            .map(|c| Certificate::from_der(c.as_ref()))
            .collect();
        roots.extend(load_pem_bundle(path)?);
        let tls = TlsConfig::builder()
            .root_certs(RootCerts::new_with_certs(&roots))
            .build();
        Ok(Self::build(user_agent, tls))
    }

    /// Like [`Http::with_ca_file`], for large uploads: no limit on the total time of a request, 10 s to
    /// connect, and [`TRANSFER_IO_TIMEOUT`] for each socket read or write.
    pub fn for_transfers(user_agent: &str, ca_file: Option<&str>) -> Result<Self, String> {
        let base = Self::with_ca_file(user_agent, ca_file)?;
        let tls = base.agent.config().tls_config().clone();
        let agent = ureq::Agent::config_builder()
            .timeout_global(None)
            .timeout_connect(Some(TIMEOUT))
            .timeout_per_read(Some(TRANSFER_IO_TIMEOUT))
            .timeout_per_write(Some(TRANSFER_IO_TIMEOUT))
            .http_status_as_error(false)
            .max_redirects(0)
            .max_redirects_will_error(false)
            .user_agent(user_agent)
            .tls_config(tls)
            .build()
            .new_agent();
        Ok(Http { agent })
    }

    fn build(user_agent: &str, tls: TlsConfig) -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(TIMEOUT))
            .http_status_as_error(false)
            .max_redirects(0)
            .max_redirects_will_error(false)
            .user_agent(user_agent)
            .tls_config(tls)
            .build()
            .new_agent();
        Http { agent }
    }

    /// Sends a form-encoded `POST`. An `Err` is a network or protocol error.
    pub fn post_form(&self, url: &str, fields: &[(&str, &str)]) -> Result<Response, String> {
        let res = self
            .agent
            .post(url)
            .header("Accept", "application/json")
            .send_form(fields.iter().copied());
        read(res)
    }

    /// Sends a `GET` with one query parameter and a bearer token.
    pub fn get_with_bearer(
        &self,
        url: &str,
        query: (&str, &str),
        bearer: &str,
    ) -> Result<Response, String> {
        let res = self
            .agent
            .get(url)
            .query(query.0, query.1)
            .header("Accept", "application/json")
            .header("Authorization", format!("bearer {bearer}"))
            .call();
        read(res)
    }

    /// Sends a `GET` with query parameters and HTTP Basic auth. `basic` is the base64 of `user:password`.
    pub fn get_with_basic(
        &self,
        url: &str,
        query: &[(&str, &str)],
        basic: &crate::Secret,
    ) -> Result<Response, String> {
        let res = self
            .agent
            .get(url)
            .query_pairs(query.iter().copied())
            .header("Accept", "application/json")
            .header("Authorization", format!("Basic {}", basic.expose()))
            .call();
        read(res)
    }
}

impl Http {
    /// Sends one request with the given headers and body, and returns the status, headers and body.
    /// Non-2xx statuses are not errors. An `Err` is a network or protocol error. Redirects are not followed.
    pub fn send(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Body<'_>,
    ) -> Result<FullResponse, String> {
        let mut builder = ureq::http::Request::builder().method(method).uri(url);
        for (n, v) in headers {
            builder = builder.header(*n, *v);
        }
        let res = match body {
            Body::Empty => {
                let builder = if matches!(method, "POST" | "PUT" | "PATCH") {
                    builder.header("Content-Length", "0")
                } else {
                    builder
                };
                let req = builder.body(()).map_err(|e| e.to_string())?;
                self.agent.run(req)
            }
            Body::Bytes(b) => {
                let req = builder
                    .header("Content-Length", b.len().to_string())
                    .body(b)
                    .map_err(|e| e.to_string())?;
                self.agent.run(req)
            }
            Body::Reader(r, len) => {
                let req = builder
                    .header("Content-Length", len.to_string())
                    .body(ureq::SendBody::from_reader(r))
                    .map_err(|e| e.to_string())?;
                self.agent.run(req)
            }
        };
        let mut res = res.map_err(|e| e.to_string())?;
        let status = res.status().as_u16();
        let headers = res
            .headers()
            .iter()
            .map(|(n, v)| {
                (
                    n.as_str().to_ascii_lowercase(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect();
        let body = if method == "HEAD" {
            String::new()
        } else {
            res.body_mut()
                .with_config()
                .limit(MAX_BODY)
                .read_to_string()
                .unwrap_or_default()
        };
        Ok(FullResponse {
            status,
            headers,
            body,
        })
    }
}

fn read(res: Result<ureq::http::Response<ureq::Body>, ureq::Error>) -> Result<Response, String> {
    let mut res = res.map_err(|e| e.to_string())?;
    let status = res.status().as_u16();
    let retry_after = res
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse().ok());
    let body = res
        .body_mut()
        .with_config()
        .limit(MAX_BODY)
        .read_to_string()
        .map_err(|e| e.to_string())?;
    Ok(Response {
        status,
        body,
        retry_after,
    })
}

/// Reads the CA certificates from a PEM file. Fails if the file has no certificate.
fn load_pem_bundle(path: &str) -> Result<Vec<Certificate<'static>>, String> {
    let file = File::open(path).map_err(|e| format!("cannot open CA file `{path}`: {e}"))?;
    let mut pem = Vec::new();
    file.take(MAX_CA_FILE + 1)
        .read_to_end(&mut pem)
        .map_err(|e| format!("cannot read CA file `{path}`: {e}"))?;
    if pem.len() as u64 > MAX_CA_FILE {
        return Err(format!(
            "CA file `{path}` is larger than {MAX_CA_FILE} bytes"
        ));
    }
    let mut certs = Vec::new();
    for item in parse_pem(&pem) {
        match item {
            Ok(PemItem::Certificate(c)) => certs.push(c),
            Ok(_) => {}
            Err(e) => return Err(format!("CA file `{path}` is not valid PEM: {e}")),
        }
    }
    if certs.is_empty() {
        return Err(format!("CA file `{path}` holds no PEM certificate"));
    }
    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file(name: &str, content: &str) -> String {
        let dir = std::env::temp_dir().join(format!("prego-auth-http-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, content).unwrap();
        path.to_string_lossy().into_owned()
    }

    // PEM framing with arbitrary DER bytes. The parser checks the framing; rustls checks the DER later.
    const PEM: &str =
        "-----BEGIN CERTIFICATE-----\nMIIBAAAAAAAAAAAAAAAAAAAAAAAA\n-----END CERTIFICATE-----\n";

    #[test]
    fn no_ca_file_is_the_default_client() {
        assert!(Http::with_ca_file("test", None).is_ok());
    }

    #[test]
    fn loads_pem_bundle() {
        let p = temp_file("two.pem", &format!("{PEM}{PEM}"));
        assert_eq!(load_pem_bundle(&p).unwrap().len(), 2);
        assert!(Http::with_ca_file("test", Some(&p)).is_ok());
    }

    #[test]
    fn refuses_bad_ca_files() {
        assert!(load_pem_bundle("/nonexistent/prego/ca.pem")
            .unwrap_err()
            .contains("cannot open"));
        let empty = temp_file("empty.pem", "no pem here\n");
        assert!(load_pem_bundle(&empty)
            .unwrap_err()
            .contains("no PEM certificate"));
    }
}
