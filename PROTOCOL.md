# Prego client protocol

Version 1.8.0. This is the public contract between a client and the Prego STS. Use it to write your own
client. A change that breaks this contract is a MAJOR version change for the registry and for the clients.

## Words

- **Subject token**: what the client brings to the STS. A SPIFFE JWT-SVID, an OIDC ID token, or an API key.
- **STS**: Security Token Service. The endpoint that exchanges a subject token for a registry token.
- **Registry token**: what the STS returns by default. A short-lived JWT signed by Prego. Send it on every
  registry request. Its lifetime is in `expires_in`: 15 minutes by default, and from registry 1.2.0 set per
  grant (section 2.1).
- **Admin token**: what the STS returns when the request asks for the `prego-admin` audience. A short-lived
  (15 min) JWT with admin scopes. Machines send it to the admin API. See section 4.
- **Tenant**: one organization. Identified by its slug, for example `acme`.
- **Edge code**: 4 characters, fixed per tenant, for example `k7mq`. The characters are `a` to `z` and `2` to
  `9`, without `i`, `l`, `0` and `1`, lower case only. It is not a secret and it does not name the caller (the
  subject token does). The console shows it. Registry token URLs carry it (sections 1 and 7).
- **Audience**: who a token is for. Subject tokens for Prego use `prego.k8skill.com`.
- **Device login**: `prego login`. A person approves a short code in the console with their own sign-in, and
  the client gets a device session (section 11). From registry 1.5.0.
- **Device session**: what a device login gives. It has a **refresh token** (opaque, kept only in secure
  storage, a new one on every use) that the client trades for registry tokens. It ends after 7 days without
  use, after 30 days in all, or when it is revoked.
- **User code**: the code that the person confirms in the console, 8 characters in two groups (`ABCD-EFGH`).

## 1. STS request

```
POST https://sts.prego.k8skill.com/v1/sts/token/e/<edge code>
Content-Type: application/x-www-form-urlencoded
```

A JSON body with the same fields is also accepted.

The path must be exactly `/v1/sts/token/e/<edge code>`: no `/` at the end, no upper case, no `%` escapes.
Other paths under `/v1/sts/token/` get `404`. Clients check the code with `^[a-hjkmnop-z2-9]{4}$` before they
send. A JWT without a `tenant` field uses the tenant of the edge code. The principal create answer of the
admin API has `edge_code` and `token_url` (this full URL), and the tenant object has `edge_code`. There is no
lookup without a credential.

Refusals for the token URL, all `400 invalid_request`:

| Request | `error_description` |
| --- | --- |
| Registry token on `POST /v1/sts/token` (no edge code), or on the old `/v1/sts/token/t/<tenant>` | `this client uses an old token URL; update prego-clients to 0.6.0 or later, which uses /v1/sts/token/e/<edge code> (the console shows your tenant's edge code)` |
| An edge code that no tenant has | `unknown token URL; ` and the text above |

Clients before 0.6.0 use the URL without the edge code. Upgrade them.

| Field | Required | Value |
| --- | --- | --- |
| `grant_type` | yes | `urn:ietf:params:oauth:grant-type:token-exchange` |
| `subject_token` | yes | the JWT or the API key |
| `subject_token_type` | yes | `urn:ietf:params:oauth:token-type:jwt` (SVID or OIDC) or `urn:k8skill:prego:token-type:api-key` |
| `tenant` | yes for JWTs | tenant slug, for example `acme`. Ignored for API keys (the key implies the tenant). |
| `audience` | no | Absent: a registry token. `prego-admin`: an admin token (section 4). Any other value: `invalid_target`. |
| `scope` | with `audience=prego-admin` | Space-separated admin scopes, for example `admin:read grants:write`. |
| `resource` | no | From registry 1.2.0. The registry base URL that the token is for: `https://<host>/t/<tenant>/<namespace>/`, for example `https://cargo.prego.k8skill.com/t/acme/default/` or `https://go.prego.k8skill.com/t/acme/default`. The STS then gives the lifetime of the grants for that tenant, namespace and package type (section 2.1). A value the STS cannot parse: `invalid_target`. An older STS ignores the field. |

Subject tokens that are JWTs must have `prego.k8skill.com` in `aud`, an `exp` claim, and a lifetime of at
most 3600 s. The maximum token size is 8 KiB.

## 2. STS response

Success, status `200`:

```json
{
  "access_token": "<registry token>",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 900
}
```

`expires_in` is the token lifetime in seconds. Use it, not the `exp` claim (section 6).

Errors (RFC 6749 style), status `400` or `401`:

```json
{ "error": "invalid_grant", "error_description": "subject token not accepted" }
```

| `error` | Status | Meaning |
| --- | --- | --- |
| `invalid_request` | 400 | A field is missing or bad. |
| `unsupported_grant_type` | 400 | `grant_type` is not token exchange. |
| `invalid_grant` | 400 or 401 | The STS does not accept this subject token for this tenant. The STS gives the same error for all causes. |
| `invalid_target` | 400 | `audience` is not `prego-admin`, or the STS cannot parse `resource`. |
| `invalid_scope` | 400 | The principal holds none of the requested admin scopes. |
| `rate_limited` | 429 | Too many requests. The response has `Retry-After` (section 2.2). |

### 2.1 Token lifetime (registry 1.2.0)

Each grant has a token lifetime in whole minutes. The STS gives a token the **shortest** lifetime of the
grants it can be used with:

- With `resource`: the principal's grants (own and cross-tenant) for that tenant, namespace and package type
  (or `any`).
- Without `resource`: all the principal's grants. This is always correct, but it can be shorter than needed.
- No grant in scope (for example a principal with admin scopes only): 15 minutes.
- Admin tokens: always 15 minutes.

The tenant's plan sets the range:

| Plan | Lifetime per grant | Default |
| --- | --- | --- |
| Trial | fixed 15 min | 15 min |
| Consumer | fixed 15 min | 15 min |
| Indie | 5 to 30 min | 15 min |
| Org | 5 to 30 min | 15 min |
| Publisher | 1 to 30 min | 15 min |

The registry also checks the token age on each request. If a grant matches the request but the token is
older than that grant's lifetime (plus 5 s), the registry answers `401` "token older than this grant allows;
get a new token", with the auth challenge of the host. Get a new token and send the request again. This
makes a shorter lifetime apply to tokens that were issued before the change.

### 2.2 Rate limits (registry 1.2.0)

- A refused or unauthenticated exchange counts against the caller's IP address (60 per minute).
- A successful exchange counts against the budget of the principal's home tenant (per minute, by plan), not
  against the IP address. Many CI jobs behind one NAT address are limited only by their tenant's budget.
- Over a limit: `429 rate_limited` with `Retry-After` (seconds).

The OCI realm (section 7) and the Go host follow the same rule.

## 3. Using the registry token

Send the registry token in the `Authorization` header of each registry request. The registry accepts
`Bearer <token>` and the raw token (Cargo sends the token as it is).

The registry token is a JWT. A client must not use its claims for any trust decision. Use `expires_in` for
the expiry (section 6).

Registry endpoints accept **only** registry tokens. They refuse API keys, JWT-SVIDs, OIDC ID tokens and admin
tokens with `401`.

## 4. Admin token (machines to the admin API)

A machine, for example a CI job or an OpenTofu or Ansible run, can manage objects in its own tenant through the
admin API (`https://sts.prego.k8skill.com/v1/admin/...`). It uses an admin token from the STS. It needs no stored
secret: it uses the same subject token as for registry access.

A human admin or owner of the tenant first gives the principal **admin scopes** in the Prego console. A machine
can never set admin scopes.

### 4.1 Request

`POST /v1/sts/token` (the URL without the edge code; `/v1/sts/token/e/<edge code>` also works), with the
fields of section 1 and two more:

```
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<CI ID token, JWT-SVID or API key>
subject_token_type=urn:ietf:params:oauth:token-type:jwt
tenant=acme
audience=prego-admin
scope=admin:read grants:write
```

The issued scope is the requested scope that the principal also holds. If the principal holds none of them, the
STS returns `invalid_scope`. The response is the same as section 2, plus a `scope` field with the issued scope:

```json
{
  "access_token": "<admin token>",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "admin:read grants:write"
}
```

The admin token is a JWT with `aud` = `prego-admin` and a `scope` claim. It is valid for 15 minutes and cannot
be refreshed. Exchange again when you need a new one.

### 4.2 Scopes

| Scope | Allows |
| --- | --- |
| `admin:read` | Every admin `GET` in the principal's own tenant, including the audit log. |
| `namespaces:write` | Create a namespace. |
| `trust_configs:write` | Create, delete and test trust configs. |
| `principals:write` | Create, change, revoke and delete principals, including API key principals. |
| `grants:write` | Create and delete grants. |

There is no wildcard scope. `grants:write` is powerful: a job with it can grant itself `publish`.

Which principals can hold admin scopes:

- `oidc` and `spiffe` principals: any scope.
- `api_key` principals: `admin:read` only.
- A write scope on a GitLab or GitHub OIDC principal needs a protected-ref pin in `claims_match`: GitLab
  `ref_protected: "true"` or an `environment` pin; GitHub an exact `ref` or an `environment` pin.

### 4.3 Using the admin token

Send `Authorization: Bearer <admin token>` to the admin API. The admin API checks on every request:

- The token is valid, has `aud` = `prego-admin`, and the principal is not revoked.
- The scope of the route is in the token's scope **and** in the principal's current admin scopes. If a human
  removes a scope, the change takes effect in about 60 seconds, also for live tokens.
- The `{tenant}` in the URL is the principal's own tenant. Any other tenant returns `404`.

Requests that an admin token can never make (`403`, whatever the scopes):

- `/v1/admin/me` and `POST /v1/admin/tenants`.
- Members, invites and owners; plan changes; deleting a namespace.
- Setting or changing admin scopes on any principal.
- Changing, revoking or deleting a principal that has admin scopes.
- Changing or deleting the trust config that the caller's own principal uses.

Each machine admin call is in the tenant's audit log, with the principal and the token ID.

The admin API refuses registry tokens, and the registry refuses admin tokens.

## 5. Identity sources

A client finds one subject token on the machine. `cargo-credential-prego` checks these sources in this order
and uses the first one that is present. `--source <name>` (or `PREGO_SOURCE`) selects one source only.

| Order | Name | Present when | How to get the token | `subject_token_type` |
| --- | --- | --- | --- | --- |
| 1 | `spiffe` | `SPIFFE_ENDPOINT_SOCKET` is set | Fetch a JWT-SVID for the audience from the SPIFFE Workload API. | `jwt` |
| 2 | `svid-file` | `PREGO_SVID_FILE` is set | Read the JWT from the file (spiffe-helper style setups). | `jwt` |
| 3 | `gitlab` | `PREGO_ID_TOKEN` is set | Use the value. GitLab CI makes it from `id_tokens` with `aud: prego.k8skill.com`. | `jwt` |
| 4 | `github` | `ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN` are set | `GET $ACTIONS_ID_TOKEN_REQUEST_URL&audience=prego.k8skill.com` with header `Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN`. Read `.value` from the JSON body. The workflow needs `permissions: id-token: write`. | `jwt` |
| 5 | `token-file` | `PREGO_TOKEN_FILE` is set | Read an OIDC JWT from the file (Kubernetes projected service account tokens, AWS/GCP workload identity files). | `jwt` |
| 6 | `api-key` | `PREGO_API_KEY` is set | Use the value. It starts with `prk_`. | `api-key` |
| 7 | `device` | No source above is present, and secure storage holds a device session for the tenant and STS | A session refresh (section 11.3). It is not a subject token: the client gets the registry token directly. | none |

`jwt` means `urn:ietf:params:oauth:token-type:jwt`. `api-key` means `urn:k8skill:prego:token-type:api-key`.

The audience is `prego.k8skill.com` unless the user sets another one (`--audience` or `PREGO_AUDIENCE`).

## 6. Client behavior

`cargo-credential-prego` does these things. Other clients should do the same.

- Timeout of 10 s for each HTTP request.
- Retry 2 times on network errors and on `5xx`, after 250 ms and then 1 s. No retry on `4xx`.
- Do not follow HTTP redirects. A redirect could send the subject token to another host.
- Send subject tokens only over `https`. Plain `http` only to `localhost`, `127.0.0.1` or `[::1]`, for
  local tests.
- Always check TLS certificates. Do not give an option to turn the checks off. To support on-prem TLS
  proxies, accept an extra PEM CA bundle (`PREGO_CA_FILE`) in addition to the built-in roots.
- Fail closed in auto mode. If the first present source fails, return its error and stop. Do not try the
  next source. The error names the source and tells the user to choose another one with
  `--source <name>`.
- Compute the expiry from `expires_in` and the local time of the request: `expiry = request time +
  expires_in`. Do not use the `exp` claim, so a wrong local clock does not matter. If `expires_in` is
  missing, use `exp - iat` from the token. If both are there, use the shorter one.
- The cache margin is `min(60 s, lifetime / 4)`. A cache gives out a token only until `expiry - margin`.
  For a 1-minute token the margin is 15 s.
- Send `resource` for the registry URL that the token is for. If the STS answers `400 invalid_target`, ask
  one more time without `resource`. Do not loop.
- On `429`, wait for `Retry-After` (at most 60 s) plus a small random time, and try again at most two times.
  Then fail with a message about the tenant's budget.
- Get a new token when the registry answers `401`, then send the request again one time.
- Keep no token cache in the client, except the private file cache of `prego go-auth` (section 9.1) and the
  registry tokens of a device session in secure storage (section 11.3). Cargo
  caches the token with the expiry hint below.
- On `invalid_grant`, tell the user: "Prego refused this identity for tenant <slug>. Check the trust config
  and principal in the console."
- Never print, log or write to disk a subject token or a registry token.
- For Cargo: return the token with `cache = expires` at `expiry - margin`, and
  `operation_independent = true`. A token with no time left after the margin gets `cache = never`. Return `operation-not-supported` for `login` and `logout`.

## 7. OCI registries (Docker token flow)

The OCI registry is `oci.prego.k8skill.com`. Image names are `oci.prego.k8skill.com/<tenant>/<namespace>/<repo>`.
The registry uses the Docker token flow:

1. A request without a registry token gets `401` with
   `WWW-Authenticate: Bearer realm="https://sts.prego.k8skill.com/v1/oci/token/e/<edge code>",service="oci.prego.k8skill.com",scope="..."`.
   Use the realm from the challenge of a repository path (for example `GET /v2/<name>/tags/list`) as it is.
   Its code is the code of the repository's tenant, which can be another tenant than the caller's. The
   challenge of `GET /v2/` names no repository and has the realm without a code. Do not make the realm URL yourself: the realm without the edge
   code refuses requests with a scope (`400 invalid_request`, "this token URL does not issue repository
   tokens"). It serves only the `docker login` check without a scope.
2. The client calls the realm, `GET https://sts.prego.k8skill.com/v1/oci/token/e/<edge code>?service=...&scope=...`, with HTTP
   Basic auth. `POST` with the form fields `grant_type=password`, `username`, `password`, `service` and `scope`
   is also accepted.
   - **username**: the tenant slug of the caller's principal. It is not used for API keys.
   - **password**: a subject token from section 5 (API key, JWT-SVID or OIDC ID token). The realm finds the
     type itself.
3. The realm does the exchange of section 1 and returns
   `200 {"token": "<registry token>", "access_token": "<same>", "expires_in": 900, "issued_at": "<RFC 3339>"}`.
   `expires_in` is the lifetime of section 2.1 for the grants that match the scopes. A missing
   `expires_in` means 60 s, and less than 60 s counts as 60 s (the distribution token spec).
   It never returns a `refresh_token`. Any failure is `401` with the same message.
4. The client sends `Authorization: Bearer <registry token>` to the registry.

Token reuse and pacing. The realm accepts at most 60 requests per minute from one IP address, and answers
`429 TOOMANYREQUESTS` above that. A client that pushes or pulls many blobs must:

- Keep one registry token for each set of scopes, and use it again until `expiry - margin` (section 6). Do
  not get a token for each request.
- Get a new token only when the kept one is near its expiry, or when the registry answers `401`.
- Send at most 60 realm requests in any 60 s window. Wait before the next request if needed.

`prego` does this (`prego-auth`, `oci::RealmTokens`).

A Docker credential helper (`docker-credential-prego`) gives Docker the subject token. It does not call the
STS itself:

- `get` reads a server URL on stdin. If its host is a Prego OCI host, it answers
  `{"ServerURL": "<as given>", "Username": "<tenant>", "Secret": "<subject token>"}`. With a device session
  (section 11), the Secret is a registry token from the session; the realm accepts it as the Basic password.
  It always comes from the session (the poll or a refresh), never from the realm: the realm marks its own
  tokens and never accepts them as a password again. The realm token ends no later than the Secret, and Docker
  keeps the Secret for the whole command, so the helper gives a stored token only while at least half of its
  lifetime is left; else it refreshes the session.
  The session refresh token never goes to Docker, and the Username is never `<token>` (Docker would then send
  the Secret as an OAuth refresh token). The Prego OCI hosts are
  `oci.prego.k8skill.com`, plus the hosts in `oci_hosts` (section 8) and in `PREGO_OCI_HOSTS`
  (comma-separated). A host compares equal after the scheme, the path and port 443 are removed, without case.
- For any other host, `get` reads no identity source. It writes `credentials not found in native keychain`
  on stdout and exits 1, so Docker uses its other credentials.
- `store` and `erase` do nothing and exit 0. The helper keeps no secret of its own (a device session is kept
  by `prego login`, section 11.4).
- `list` answers `{"https://<host>": "<tenant>"}` for each Prego OCI host, or `{}` if no tenant is set.
- An error is one line on stdout, with exit code 1. It never holds a token.

Chunked uploads. The registry accepts at most 95 MiB in one request. A client that pushes a larger blob sends it
in parts (`prego oci push` does this):

1. `HEAD /v2/<name>/blobs/<digest>`. `200` means that the repository has the blob. Send nothing.
2. Optional: `POST /v2/<name>/blobs/uploads/?mount=<digest>&from=<repo>` with a repository of the same tenant.
   `201` means mounted. `202` is a normal upload session: go on with step 4.
3. `POST /v2/<name>/blobs/uploads/`. The answer is `202` with `Location` and `OCI-Chunk-Min-Length`.
4. `PATCH <Location>` for each part, with `Content-Range: <first>-<last>` and `Content-Length`. Every part
   except the last has the same size: at least `OCI-Chunk-Min-Length`, at most 95 MiB. A different part size
   gets `416`. Use the `Location` of each answer for the next request.
5. After a network error, a `5xx` or a `416`: `GET <Location>` gives `204` with `Range: 0-<last>`. Go on from
   the next byte. If that byte is not on a part boundary, cancel with `DELETE <Location>` and start again.
6. `PUT <Location>&digest=<digest>` (or `?digest=` if the location has no query). `201` when the digest is
   correct, `400 DIGEST_INVALID` if not.
7. Push the manifests: each child manifest of an index by digest, then the top manifest by tag.

The `Location` is always on the registry host. Do not send the registry token to another host.

## 8. Settings file

All Prego client tools read the same settings file: `$XDG_CONFIG_HOME/prego/config.toml`, or
`$HOME/.config/prego/config.toml` if `XDG_CONFIG_HOME` is not set.

```toml
tenant = "acme"
# All keys are optional.
# sts_url = "https://sts.prego.k8skill.com/v1/sts/token"
# edge_code = "k7mq"
# audience = "prego.k8skill.com"
# source = "auto"
# oci_hosts = ["oci.example.internal"]
# go_hosts = ["go.example.internal"]
# go_prefixes = ["go.acme.com", "github.com/acme"]
# npm_host = "npm.example.internal"
```

- Order for each value: command-line argument, then the `PREGO_*` environment variable, then the file, then
  the default.
- `edge_code` (`--edge-code`, `PREGO_EDGE_CODE`): the tenant's edge code. `sts_url` can also be the console's
  token URL, `.../v1/sts/token/e/<edge code>`; the client then takes the code from it. Two different codes
  are an error.
- A missing file is not an error. A file that does not parse, an unknown key or a value of the wrong type is
  an error.
- The file never holds a secret. A key such as `api_key`, `token`, `secret` or `password` is an error. Put a
  token in a file and set `PREGO_TOKEN_FILE` or `PREGO_SVID_FILE`, or set `PREGO_API_KEY` in the environment.

## 9. Go modules (GOPROXY protocol)

From prego 0.4.0. The Go host is `go.prego.k8skill.com`. The GOPROXY base of one namespace is
`https://go.prego.k8skill.com/t/<tenant>/<namespace>`. More hosts come from `PREGO_GO_HOSTS`
(comma-separated) and `go_hosts` (section 8), in that order, before the default. The first host is the one
that `prego go publish`, `prego setup go` and `prego exec` use.

### 9.1 GOAUTH helper

`GOAUTH='prego go-auth'` (Go 1.24 or later). Go runs each `GOAUTH` entry that is not `off`, `netrc` or
`git <dir>` as a command line, so the entry is the command itself, with no word `command` in front.

- **First call** (no arguments): the helper reads `GOPROXY` (the environment, else `go env GOPROXY`). For
  each entry on a Prego Go host whose path starts with `/t/<tenant>/`, it prints the URL prefix
  `https://<host>/t/<tenant>/`. Then it prints a blank line, `Authorization: Bearer <registry token>` and a
  blank line. Go sends the header only to URLs under those prefixes. It never sends it to
  `proxy.golang.org` or to a download host.
- One registry token from one STS exchange covers all Prego prefixes. The registry checks the grants,
  cross-tenant grants included. If no tenant is set and `GOPROXY` has exactly one Prego tenant, the helper
  uses that tenant.
- **Retry calls** (Go gives the URL as an argument and the 4xx response on stdin): after a `401` for a Prego
  URL, the helper gets a new token. After any other status, or for a URL that is not a Prego URL, it prints
  the cached token again and makes no STS call.
- **Cache**: one file with mode 0600 in `$XDG_RUNTIME_DIR/prego/`, else in `$TMPDIR/prego-<uid>/`. The
  directory must be a real directory (not a symlink), owned by the user, with mode 0700; the helper makes it
  with mode 0700 if it is missing. If a check fails, the helper uses no cache. A cached token is used until
  its expiry minus the margin (`min(60 s, lifetime / 4)`), then the file is deleted.
- **Resource**: if the Prego entries of `GOPROXY` name one namespace, the helper sends that base URL as
  `resource`. With several namespaces or tenants, it sends none.
- With no Prego entry in `GOPROXY`, the helper prints nothing and makes no STS call.

### 9.2 `.netrc` for Go before 1.24

`prego exec -- <command>` writes `machine <host> login <tenant> password <registry token>` to a temporary
file with mode 0600, sets `NETRC` to its path for the command, and deletes the file when the command ends.
Go reads the file once, so the token in it cannot be renewed. `prego exec` prints the token lifetime on
stderr, and a warning when it is less than 10 minutes. From prego 0.6.0, the command also gets the same
token in `PREGO_NPM_TOKEN` and `PREGO_TOKEN` (section 10).
Go sends it as HTTP Basic auth. The Go host takes a registry token, or a read-only API key, as the Basic
password. A key that can publish or delete is refused.

### 9.3 Publish

`prego go publish` builds the zip from the git tree of the tag (`git ls-tree` and `git cat-file`), never from
the working directory, with the file rules of `golang.org/x/mod/zip`. If a module in a subdirectory has no
`LICENSE`, the root `LICENSE` is added, as the go command does. Then:

- Up to 95 MiB: `PUT /t/<tenant>/<ns>/-/publish/<module>/@v/<version>.zip` with `Content-Length`,
  `X-Prego-Go-H1: h1:<base64>` and `X-Prego-Go-Origin: {"VCS":"git","Hash":"<commit>","Ref":"refs/tags/<tag>",
  "Subdir":"<dir>"}` (`Subdir` only for a module in a subdirectory; no URL).
- Above 95 MiB: `POST .../-/publish/<module>/@v/<version>/uploads` with `{"size", "h1", "origin"}` gives
  `{"upload_id", "chunk_bytes"}`. Then `PATCH .../-/uploads/<id>?part=<n>` from 1, each part exactly
  `chunk_bytes` except the last. `204` has `X-Prego-Go-Received` (the bytes so far). A `409` means that part
  is already stored. Then `PUT .../-/uploads/<id>` to finish, or `DELETE` to abort. Before each request,
  the client gets a new token (for `resource` = the namespace base URL) if the current one has less than
  the margin left (section 6), so short tokens do not expire between parts.
- Limits: the zip is at most 300 MiB, compressed and uncompressed (Go itself allows 500 MiB). `go.mod` is at
  most 1 MiB, and the zip has at most 65535 files. The registry refuses a bigger zip. From prego 0.5.0, the
  client refuses it before any request.
- The module path and the version in the URL are case-encoded (`A` becomes `!a`).
- Success is `201 {"module", "version", "h1", "mod_h1"}`. The client fails if the registry's `h1` differs
  from its own. Errors are plain text, and the client shows them as they are.

## 10. npm packages (scoped)

From prego 0.6.0. The npm host is `npm.prego.k8skill.com` (`PREGO_NPM_HOST` or `npm_host` in the settings
file for another host). The registry URL of one namespace is `https://<host>/t/<tenant>/<ns>/`, with the `/`
at the end. Prego serves scoped packages only (`@scope/name`); a scope is registered by one tenant and is
unique across Prego.

### 10.1 Client files

`prego setup npm` writes the scope line and a **reference** to the variable `PREGO_NPM_TOKEN`, never a token:

- npm and pnpm, `.npmrc`: `@<scope>:registry=<registry URL>` and
  `//<host>/t/<tenant>/<ns>/:_authToken=${PREGO_NPM_TOKEN}`. Lines with the same keys are replaced; all other
  lines stay. A token value on the auth line is replaced.
- Yarn 4, `.yarnrc.yml`: `npmScopes.<scope>.npmRegistryServer` and `npmAuthToken: "${PREGO_NPM_TOKEN}"`.
- Bun, `bunfig.toml`: `[install.scopes]` `"@<scope>" = { url = "<registry URL>", token = "$PREGO_NPM_TOKEN" }`.
- The client adds a Yarn or Bun block only when the file has no scopes section. It never rewrites YAML or
  TOML.
- With no `--scope`, the client reads `GET /v1/admin/tenants/<tenant>/npm/scopes` with an `admin:read` admin
  token (section 4), and uses the scope if there is exactly one. A scope is accepted with or without `@`.

### 10.2 Tokens

- npm, pnpm, Yarn and Bun send `Authorization: Bearer <registry token>`. The npm host accepts only registry
  tokens. It answers `401` with `{"error": "..."}` for any other kind, and a special message when it gets the
  literal text `${PREGO_NPM_TOKEN}` (the variable was not set).
- `prego exec -- <command>` runs the command with a fresh registry token in `PREGO_NPM_TOKEN` and
  `PREGO_TOKEN`. `prego npm-env` prints `export PREGO_NPM_TOKEN='<token>'` on stdout and the lifetime on
  stderr. `prego token` prints the token only.
- The client sends no `resource` for the npm host yet. The lifetime is the one for all your grants.
- A single command that runs longer than the token lifetime gets `401` part way. The client does not renew
  the variable during a command.

### 10.3 Trusted publishing

npm 11.5.1 and later exchange a CI ID token on the npm host itself, with audience `npm:<npm host>`, and get a
normal registry token. The STS rules, rate limits and audit apply. On any failure npm uses the `.npmrc`
token. The Prego client has no part in this exchange.

## 11. Device login (`prego login`)

From registry 1.5.0. A person on a laptop logs in with the console sign-in. CI never uses it: CI uses a workload
identity or an API key (section 5). All paths carry the edge code, which picks the tenant.

### 11.1 Start

```
POST https://sts.prego.k8skill.com/v1/sts/device/e/<edge code>/start
Content-Type: application/json

{"client": "prego-cli/0.7.0", "access": [{"ecosystem": "any", "actions": ["read"]}]}
```

- Do not send `tenant`: a body with `tenant` gets `400 invalid_request`.
- `access` items: `ecosystem` (`any`, `cargo`, `oci`, `go`, `npm`), `namespace` (optional, default `default`)
  and `actions` (`read`, `publish`, `delete`; `delete` means yank and delete). `prego login` asks for read;
  `prego login --publish` asks for read and publish. The person can approve only access within their role.
  Publish and delete need a passkey check in the console.
- Answer `200`: `{"device_code", "user_code", "verification_uri", "verification_uri_complete", "expires_in":
  300, "interval": 5}`. Show `verification_uri` and `user_code`. Never show `device_code`.
- Too many pending requests (10 per IP address and per tenant): `429 {"error": "rate_limited"}` with
  `Retry-After`.

### 11.2 Poll

```
POST https://sts.prego.k8skill.com/v1/sts/device/e/<edge code>/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=<device code>
```

As RFC 8628: wait `interval` seconds between polls. `400` with `error`:

| `error` | Client action |
| --- | --- |
| `authorization_pending` | Poll again after `interval`. |
| `slow_down` | Add 5 s to `interval`, then poll again. |
| `expired_token` | Stop: the request expired. Tell the person to run `prego login` again. |
| `access_denied` | Stop: the person denied the request in the console. |

Answer `200`: the fields of section 2, plus `refresh_token` and `session`: `{"id": "dvs_...", "name",
"access": [{"ecosystem", "namespace", "actions"}], "idle_expires_at", "expires_at"}` (Unix seconds). Store
the refresh token and the session (section 11.4) before you use the registry token.

### 11.3 Refresh

```
POST https://sts.prego.k8skill.com/v1/sts/token/e/<edge code>
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=<refresh token>&resource=<registry base URL>
```

- `resource` is optional, as in section 1. `tenant` is not needed; if it is sent, it must be the session's
  tenant.
- Answer `200`: the fields of section 2, plus a new `refresh_token` and `session` (`id`, `idle_expires_at`,
  `expires_at`). The old refresh token stops working. Store the new one before you use the registry token.
- A refresh token that was used in the last 10 s gets the same answer as its first use (parallel processes).
  A use after that ends the whole session (a theft signal).
- An ended session (revoked, expired or reused): `400 {"error": "invalid_grant", "error_description": "the
  login session ended; run prego login again"}`. Delete the local session and show that text.
- An ended trial of the tenant: `401 invalid_grant` with the trial text of section 2. The session stays: keep
  it, and show the text. Delete the local session only on a `400 invalid_grant`.
- A rate limit or a full stop of the tenant stays `429 rate_limited`, as in section 2.2. A stop of the tenant
  (its usage limit) is not retried for long: show the text, and tell the person to try again after the reset
  or to ask the owner. The same applies to a stop during the poll (11.2).

Client behavior:

- Take an exclusive lock around a refresh (a lock file that holds no secret), so that parallel processes of
  one user do not use the same refresh token. Keep the registry tokens with the session in secure storage, and
  use a stored one while it is fresh (section 6, cache margin).
- Never write a registry token from a session to a plain file: no `.netrc` file (`prego exec`), and no
  `prego go-auth` file cache.

### 11.4 Storage

The client keeps the session only in secure storage: the macOS Keychain, the Windows Credential Manager, the
Secret Service on a Linux desktop, else the kernel keyring of the Linux user session (lost at logout or
reboot). There is no plain file fallback. Without secure storage, `prego login` stops and tells the person to
use `PREGO_API_KEY` or a workload identity.

### 11.5 Logout

```
POST https://sts.prego.k8skill.com/v1/sts/device/e/<edge code>/revoke
Content-Type: application/x-www-form-urlencoded

refresh_token=<refresh token>
```

Always `200 {}`, also for an unknown or revoked token. It ends the whole session. The client deletes the local
session also when the call fails, and says so.
