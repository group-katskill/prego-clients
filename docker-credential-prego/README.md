# docker-credential-prego

Docker credential helper for the **Prego by Katskill** OCI registry (`oci.prego.k8skill.com`).

Docker, Podman, BuildKit, crane and ORAS run it to sign in. The helper finds a machine identity (SPIFFE
JWT-SVID, GitLab or GitHub CI OIDC token, token file, or API key) and gives it to Docker for the Prego token
realm only. It never prints a token to stderr and never writes a token to disk. `docker login` stores nothing.

```sh
cargo install docker-credential-prego
```

In `~/.docker/config.json`:

```json
{ "credHelpers": { "oci.prego.k8skill.com": "prego" } }
```

```toml
# ~/.config/prego/config.toml
tenant = "acme"
```

```sh
docker pull oci.prego.k8skill.com/acme/default/api:1.0.0
```

Podman, crane, ORAS and Helm read the same `credHelpers` entry (for Podman set `REGISTRY_AUTH_FILE`, for Helm
set `HELM_REGISTRY_CONFIG` to the Docker config file).

Prego accepts at most 95 MiB in one request, and `docker push` sends each layer in one request. For an image
with a layer above 95 MiB, use `prego oci push` from the [`prego`](https://crates.io/crates/prego) crate. It
sends each layer in parts.

For any host that is not a Prego OCI host, the helper answers "credentials not found in native keychain", so
Docker uses its other credentials.

See the [OCI quickstart](https://github.com/group-katskill/prego-clients/blob/main/docs/oci-quickstart.md) for
each tool, and the repository `README.md` for the identity sources and the settings file, and `PROTOCOL.md` section 7
for the protocol.

License: `Apache-2.0`.
