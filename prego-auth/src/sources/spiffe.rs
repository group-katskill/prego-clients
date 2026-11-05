//! `spiffe` source: fetch a JWT-SVID from the SPIFFE Workload API.

use crate::secret::Secret;

/// Fetches a JWT-SVID for `audience` from the Workload API at `socket`.
#[cfg(feature = "spiffe")]
pub(crate) fn fetch(socket: &str, audience: &str) -> Result<Secret, String> {
    use spiffe::WorkloadApiClient;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("cannot start the async runtime: {e}"))?;
    let result = rt.block_on(async {
        tokio::time::timeout(crate::http::TIMEOUT, async {
            let client = WorkloadApiClient::connect_to(socket).await?;
            client.fetch_jwt_token([audience], None).await
        })
        .await
    });
    match result {
        Ok(Ok(token)) => Ok(Secret::new(token)),
        Ok(Err(e)) => Err(format!(
            "cannot get a JWT-SVID from the Workload API at `{socket}`: {e}"
        )),
        Err(_) => Err(format!(
            "the Workload API at `{socket}` did not answer in time"
        )),
    }
}

/// Without the `spiffe` feature this source is present but always fails.
#[cfg(not(feature = "spiffe"))]
pub(crate) fn fetch(_socket: &str, _audience: &str) -> Result<Secret, String> {
    Err("this build has no SPIFFE support (feature `spiffe` is off). Use PREGO_SVID_FILE.".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unreachable_socket_is_a_clear_error() {
        let e = fetch("unix:///nonexistent/prego/agent.sock", "prego.k8skill.com").unwrap_err();
        assert!(e.contains("Workload API") || e.contains("SPIFFE"), "{e}");
    }
}
