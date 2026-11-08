# Release Variables with `prego env`

**From prego 0.8.0.** Release Variables need `prego` 0.8.0 or later and Prego registry 1.8.0 or later.

Release Variables are plain settings that go with a release: an API base URL, feature flags, a schema version,
a list of regions. Prego keeps them next to the release. A machine that can pull `payments 1.4.0` can also
read the settings for it, with the same identity and no new credential.

> **Release Variables are plain text, readable by everyone who can pull the release. Do not store passwords,
> tokens or keys here.** Use a secrets manager for credentials. The registry refuses values that look like a
> credential (`422 looks_like_secret`).

This guide uses tenant `acme`, namespace `releases` and package `payments`. Replace them with your own.

## Sets, levels and the merge

A **set** is a flat map of keys to values on one **level**:

| Level | Attached to | Reference (`--level`) |
| --- | --- | --- |
| `tenant` | the tenant | `acme` |
| `namespace` | one namespace | `acme/releases` |
| `version` (default) | one package name and version in a namespace | `acme/releases/payments@1.4.0` |

- **Keys**: `A-Z`, `a-z`, `0-9` and `_`, not a digit first, at most 128 characters. So every set can be
  environment variables.
- **Values**: any JSON value. A JSON string is a string variable. An object, array, number, boolean or `null`
  is a JSON variable.
- **Merge** for a release: the most specific level wins, `version` over `namespace` over `tenant`, key by key.
  A JSON value at a higher level replaces the whole value below it.
- A `version` set binds by **name and version**, not to one artifact. One set serves a crate, an image, a Go
  module or an npm package with the same name and version. You can push it before the release is published.
- The version is compared exactly: `v1.4.0` and `1.4.0` are different.
- Caps: 64 KiB per value, 256 KiB per set, 1000 keys per set.

## References

- `acme/payments@1.4.0` is in namespace `default`.
- `acme/releases/payments@1.4.0` is in namespace `releases`. With three or more segments, the second is always
  the namespace.
- A nested name in `default` needs the long form: `acme/default/apps/web@1.0.0`. The same applies to an npm
  scoped package: `acme/default/@acme/core@1.2.0`.
- The version is after the last `@`.

## Access

`prego env` uses the same identity sources and grants as the other tools: GitLab or GitHub OIDC, SPIFFE, an
API key, or `prego login`. There is no new grant type.

- **Read** a `version` set: a grant with `read` whose glob matches the package (any `ecosystem`). Read a
  `namespace` or `tenant` set: any grant in that namespace or tenant.
- **Push** or **roll back** a `version` set: a grant with `publish` whose glob matches the package. A
  `namespace` set needs `publish` on `*` in that namespace, and a `tenant` set needs `publish` on `*` in every
  namespace.
- A tenant that you have a cross-tenant grant from shows you only its `version` sets (if the owner did not
  turn that off), never its `namespace` or `tenant` sets. For a cross-tenant pull, set your own tenant
  (`--tenant`, `PREGO_TENANT`): the reference names the other tenant. If no tenant is set, `prego` uses the
  tenant of the reference.
- No access gives `404`, also when the set exists.

## Pull

```sh
prego env pull acme/releases/payments@1.4.0                  # a table on a terminal
prego env pull acme/releases/payments@1.4.0 --out release.env
set -a; . ./release.env; set +a
```

- `--format env` (the default when stdout is not a terminal) gives `KEY='value'` lines, sorted by key. Every
  value is in single quotes, and a `'` in a value becomes `'\''`. A JSON value is its canonical JSON text.
  `#` lines at the top give the reference, the resolved hash, and the set ID, version and hash of each level.
- `--format json` gives the full answer: each key with the level it came from. `--format flat` gives
  `{key: value}` only.
- `--out FILE` writes the file in one step (a temporary file, then a rename).

### Pin the content with `--expect`

Each pull has a **resolved hash**: the SHA-256 of the merged `{key: value}` map in its RFC 8785 canonical form.
`prego` computes it again from the values it got, and stops if it is not the hash in the answer. Pin it in CI:

```sh
prego env pull acme/releases/payments@1.4.0 --expect sha256:9f2c...  --out release.env
```

If anything changed at any level, `prego` exits with code **3** and writes nothing. Other errors exit with
code 1.

## Push

```sh
prego env push acme/releases/payments@1.4.0 --file release-vars.json --message "$CI_COMMIT_SHORT_SHA"
prego env push acme/releases/payments@1.4.0 --env-file release.env
prego env push acme/releases --level namespace --set API_BASE_URL=https://api.acme.example \
  --set-json 'REGIONS=["eu-west","us-east"]'
```

- **A push replaces the whole set.** The new version is exactly what the command gives: the `--file` (a JSON
  object) or the `--env-file`, then `--set` and `--set-json` on top. Nothing is read from the server first.
- A `.env` file gives **strings only**: `PORT=8080` is the string `"8080"`. Use `--file` or `--set-json` for
  numbers, booleans and objects. The `.env` rules: `KEY=value`, `export KEY=value`, `#` comments, values in
  single quotes (literal) or double quotes (`\n`, `\t`, `\r`, `\"`, `\\`, `\$`).
- A push with the same content as the current version makes no new version (safe to repeat in CI).
- `--if-current sha256:...` refuses the push (`409 conflict`) if the current version has another hash.
- `--message` is at most 200 characters.
- The registry warns about key names that end with `_PASSWORD`, `_SECRET`, `_TOKEN` or `_PRIVATE_KEY`, and
  refuses values that look like a credential. Machines cannot override the refusal.

## History, rollback and diff

```sh
prego env history acme/releases/payments@1.4.0           # * marks the current version
prego env rollback acme/releases/payments@1.4.0 --to 2 --reason "flag broke checkout"
prego env diff acme/releases/payments@1.4.0 --from 2 --to 3
```

- Versions are immutable. A rollback moves the `current` pointer to an older version and makes no new version.
  Use the same command with a newer number to go forward again.
- `diff` shows `+` for an added key, `-` for a removed key and `~` for a changed key, with canonical JSON
  values.
- `--level tenant` or `--level namespace` works with all three.
- Prego keeps the last 50 versions of a set.

## Hash offline

```sh
prego env hash release-vars.json      # or - for stdin
```

It prints the `sha256:` hash of the JSON object in its RFC 8785 canonical form, the same value the registry
computes. Use it to know the hash of a set before you push it.

## CI

GitLab, with OIDC and no stored secret:

```yaml
deploy:
  id_tokens:
    PREGO_ID_TOKEN: { aud: prego.k8skill.com }
  variables:
    PREGO_TENANT: acme
    PREGO_EDGE_CODE: k7mq
  script:
    - prego env pull acme/releases/payments@${CI_COMMIT_TAG} --format env --out release.env
    - set -a; . ./release.env; set +a
    - ./deploy.sh
```

The publishing pipeline (needs `publish` on `payments`):

```yaml
release:
  id_tokens:
    PREGO_ID_TOKEN: { aud: prego.k8skill.com }
  script:
    - cargo publish --registry acme-releases
    - prego env push acme/releases/payments@${CI_COMMIT_TAG} --file release-vars.json --message "${CI_COMMIT_SHORT_SHA}"
```

GitHub Actions works the same with `permissions: id-token: write`. See the [CI guide](ci.md).

## Errors

| Message | Cause | Fix |
| --- | --- | --- |
| `not found, or you have no grant for it` (`404`) | No set at this level, or no grant that matches | Check the reference and the grant. |
| `exit code 3` with `the resolved hash is ...` | The content changed since you pinned it | Check the history, then update `--expect`. |
| `422 looks_like_secret (keys: ...)` | A value looks like a credential | Do not store it here. Use a secrets manager. |
| `409 conflict (current hash: ...)` | `--if-current` did not match, or a name that differs only by `-` or `_` | Pull again, or use the existing name. |
| `403 forbidden` | You can read the set but have no `publish` | Ask for a grant with `publish`. |
| `403 plan_limit` | Too many sets, or the storage quota is full | See the usage page in the console. |
| `413 value_too_large` / `set_too_large` | Over 64 KiB per value or 256 KiB per set | Make the set smaller. |
| `429` with `retry after` | The tenant reached its usage limit for this month, or the rate limit | Try again later. |

## FAQ

### Are Release Variables a secrets manager?

No. Release Variables and a secrets manager (for example Doppler) both give a value to a machine after the machine
proves its identity. But the two systems make different promises about the value.

- **Access follows the release.** Every identity that can pull a package can read its variables. A consumer in
  another tenant with a read grant can read the version-level set when its `cross_tenant` flag is on. The flag is on
  by default. A secret must not follow this path.
- **Versions stay, and each has a content hash.** Prego keeps the last 50 versions of a set. It also keeps the
  current version and every version that was current in the last 30 days. CI can pin a resolved hash with
  `--expect`. A secret needs rotation and revocation, not a long history.
- **Storage is plain text.** Prego encrypts the data at rest only (the Cloudflare default for D1 and R2). A secrets
  manager encrypts each value and limits who can see it.
- **Reads are counted, not audited.** Each resolve adds one to the tenant's monthly usage, the same as a download.
  Pushes, rollbacks, set changes and a refused push from a reader are audited. A read does not get an audit row. A
  secret needs an audit row for each read.
- **Values that look like credentials are refused.** A push with a value in a known credential format (for example a
  private key, a cloud access key or a GitHub token) gets `422 looks_like_secret`. Key names that end like
  `_PASSWORD` or `_TOKEN` give a warning. Only a person in the console can override the refusal, and the audit log
  records the override. Machines cannot override it. The check finds known formats only, so it is not a guarantee.

Use Release Variables for settings that belong to a release: API URLs, feature flags, schema versions, region lists.
Keep passwords, tokens and keys in a secrets manager. In Release Variables, store only the name or the path that
points to the secret.
