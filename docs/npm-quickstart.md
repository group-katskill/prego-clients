# Quickstart: npm packages with Prego

**From prego 0.6.0.** npm packages need `prego` 0.6.0 or later and a Prego registry with the npm host
(`npm.prego.k8skill.com`).

Prego serves **scoped** npm packages (`@acme/core`) from a private registry. All other packages still come
from registry.npmjs.org: npm sends only your scope to Prego. Prego does not proxy or cache public npm. npm 10
and 11, pnpm 9 and 10, Yarn 4 and Bun read the same registry. This guide uses tenant `acme`, namespace
`default` and scope `@acme`. Replace them with your own.

## What you need

- `prego` 0.6.0 or later: the [install script](../README.md#install).
- In the Prego console (<https://app.prego.k8skill.com>), a tenant admin:
  - registers the tenant's **npm scope**, for example `@acme`. A scope belongs to one tenant across all of
    Prego, first come, first served. Some names (for example `@npm`, `@types`, `@node`) are reserved.
  - gives a **grant** with `ecosystem = npm` (or `any`). The glob is on the full scoped name: `@acme/*`,
    `@acme/core-*` or `@acme/core`. The actions:

    | Action | npm commands |
    | --- | --- |
    | `read` | `npm install`, `npm view`, tarball download |
    | `publish` | `npm publish`, `npm dist-tag add` and `rm` |
    | `yank` | `npm deprecate` (the version can still be installed) |
    | `delete` | `npm unpublish @acme/core@1.2.0` (one version) |

    `publish`, `yank` and `delete` include `read`. `publish` does not include `delete`.

- Also create the free organization `@acme` on npmjs.com. See [Dependency confusion](#dependency-confusion).

## 1. Connect npm

In the project directory:

```sh
prego setup npm --scope @acme
```

It writes two lines to `.npmrc`, and keeps all other lines of the file:

```ini
@acme:registry=https://npm.prego.k8skill.com/t/acme/default/
//npm.prego.k8skill.com/t/acme/default/:_authToken=${PREGO_NPM_TOKEN}
```

- The file holds the **name** of a variable, never a token. Commit `.npmrc`. If the file had a token value
  on the Prego line, `prego setup npm` replaces it and tells you. Add `.npmrc` files with a literal token to
  your secret-scan rules.
- `--scope` is not necessary when the tenant has one scope and your identity can read it (`admin:read`).
- `--namespace rel` uses another namespace. The same package name can have different versions in two
  namespaces; the `.npmrc` chooses one.
- `--user` writes `~/.npmrc` in place of the project file. `--print` writes nothing and prints the lines.
- Do not set `registry=` to Prego. Prego serves scoped packages only, so all other packages would fail.
  `prego setup npm` warns when it finds such a line.

**pnpm** reads the same `.npmrc`: `prego setup npm --scope @acme --client pnpm` writes the same lines.

**Yarn 4:** `prego setup npm --scope @acme --client yarn` adds this to `.yarnrc.yml`:

```yaml
npmScopes:
  acme:
    npmRegistryServer: "https://npm.prego.k8skill.com/t/acme/default/"
    npmAuthToken: "${PREGO_NPM_TOKEN}"
```

**Bun:** `prego setup npm --scope @acme --client bun` adds this to `bunfig.toml`:

```toml
[install.scopes]
"@acme" = { url = "https://npm.prego.k8skill.com/t/acme/default/", token = "$PREGO_NPM_TOKEN" }
```

`prego` never changes YAML or TOML that is already there. If `.yarnrc.yml` already has `npmScopes`, or
`bunfig.toml` already has scopes, it prints the lines for you to add by hand.

Set your identity as for the other Prego tools, for example `PREGO_API_KEY` and `PREGO_TENANT` on a laptop.
See the [identity sources](../README.md#identity-sources).

## 2. Install

npm reads the token from `PREGO_NPM_TOKEN`. Use one of these:

```sh
prego exec -- npm install           # a fresh token for this one command
eval "$(prego npm-env)"             # export PREGO_NPM_TOKEN in this shell
npm install
```

`prego exec` works for npm, pnpm, Yarn, Bun and any other tool that reads the variable. It sets
`PREGO_NPM_TOKEN` and `PREGO_TOKEN`. The token is valid for 15 minutes by default (the grant sets 1 to 30
minutes). A single command that runs longer than that gets `401` part way. Run it again with `prego exec`.
`prego npm-env` prints the lifetime on stderr.

To check the connection, give the registry URL: `npm whoami` and `npm ping` do not use the scope line.

```sh
prego exec -- npm whoami --registry https://npm.prego.k8skill.com/t/acme/default/
prego exec -- npm ping --registry https://npm.prego.k8skill.com/t/acme/default/
```

`prego setup npm` prints the `whoami` line with your URL.

## 3. Publish

```sh
prego exec -- npm publish
```

- Only scoped names (`@acme/core`), in a scope that your tenant registered.
- A version number is used one time only. A second publish of `1.2.0` is refused, also after an unpublish.
  npm 11 refuses it itself, before it sends anything ("You cannot publish over the previously published
  versions"). npm 10 sends it, and shows Prego's `403`. Publish a new version.
- A tarball can be up to 50 MiB.
- No `--provenance`. Prego does not accept npm provenance yet.
- `npm dist-tag add @acme/core@1.3.0 beta` needs `publish`. `latest` cannot be removed.
- `npm deprecate` needs `yank`.
- `npm unpublish @acme/core@1.2.0` needs `delete`. The version is gone at once, and an admin can restore it
  in the console for 3 days. Delete a whole package in the console, not with `npm unpublish --force`.

## CI

**With the `prego` tool.** The job's ID token is the identity. Nothing is stored.

GitLab CI:

```yaml
install:
  image: node:24
  id_tokens:
    PREGO_ID_TOKEN:
      aud: prego.k8skill.com
  variables:
    PREGO_TENANT: acme
  script:
    - export PREGO_NPM_TOKEN="$(prego token)"   # install prego first (see the README)
    - npm ci
```

GitHub Actions: give the job `permissions: id-token: write` and run the same commands. `prego` requests the
OIDC token with audience `prego.k8skill.com`.

**Without the `prego` tool.** Exchange the CI ID token at the STS with curl:

```sh
export PREGO_NPM_TOKEN="$(curl -fsS https://sts.prego.k8skill.com/v1/sts/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token_type=urn:ietf:params:oauth:token-type:jwt \
  -d tenant=acme --data-urlencode "subject_token=$PREGO_ID_TOKEN" | jq -r .access_token)"
npm ci
```

`prego token` and the curl output are secrets. Put them in a variable, never in a log.

## Trusted publishing from CI

npm 11.5.1 and later can publish from CI with npm's own OIDC exchange: no Prego tool and no stored secret.
npm sends the CI ID token to the Prego npm host and gets a registry token back. If that fails, npm uses the
`.npmrc` token, so a project can have both.

In the console:

1. A **trust config** for the CI issuer, pinned to a protected branch or tag, or to an environment.
2. A **principal** for that trust config with a `publish` grant on `@acme/*`.

The committed `.npmrc` from `prego setup npm` stays as it is.

GitLab CI (npm reads the ID token from `NPM_ID_TOKEN`):

```yaml
publish:
  image: node:24
  id_tokens:
    NPM_ID_TOKEN:
      aud: npm:npm.prego.k8skill.com
  rules:
    - if: $CI_COMMIT_TAG
  script:
    - npm install --global npm@^11.5.1
    - npm publish
```

GitHub Actions:

```yaml
jobs:
  publish:
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-node@v5
        with:
          node-version: 24
      - run: npm install --global npm@^11.5.1
      - run: npm publish
```

The audience is always `npm:` and the npm host. The trust config's own audience setting does not apply here.
Pin the trust config to a protected ref: any job that can get an ID token with this audience from that
issuer, and that matches the pins, can publish.

## Dependency confusion

A machine whose `.npmrc` has no `@acme:registry` line asks registry.npmjs.org for `@acme/core`. If someone
else owns `@acme` there, npm installs their package. Prego cannot stop this on your machines. Do these
three things:

- Create the free organization `@acme` on npmjs.com, so that nobody else can publish `@acme` packages there.
- Always run `prego setup npm`, which writes the scope line, and commit `.npmrc`.
- Check the warning in the console: Prego shows when a package name that you publish also exists on
  registry.npmjs.org.

A scope on Prego does not prove that you own the same scope on npmjs.com, and the reverse is also true.

Install scripts in packages run on your machines. Prego stores packages; it does not scan them. Use
`npm install --ignore-scripts` where you can.

## Other hosts

For a self-hosted or test registry, set the npm host with `PREGO_NPM_HOST=npm.example.test`, or
`npm_host = "npm.example.test"` in `~/.config/prego/config.toml`. `prego whoami` shows the npm registry URL.

## Errors

npm shows a `401` as "Unable to authenticate". Prego's own message, from the table below, is on an
`npm notice` line near it. Look for that line.

| Message | Cause and fix |
| --- | --- |
| `401` `PREGO_NPM_TOKEN is not set in this shell` | npm sent the variable name, not a token. Use `prego exec -- npm ...` or `eval "$(prego npm-env)"`. |
| `401` `Prego needs a registry token from the STS` | The token is an API key, a CI ID token or an npm login. Use `prego exec`, `prego token` or the curl call. |
| `401` part way through a long command | The token expired. Run the command again with `prego exec`. |
| `404` for your own package | No `read` grant on it in this namespace, or the scope is not registered. Prego shows a missing grant as "not found". |
| `404` `Prego serves scoped packages only` | `.npmrc` sets `registry=` to Prego. Use only the `@scope:registry` line. |
| `403` `Prego does not issue npm logins or long-lived tokens` | `npm login`, `npm adduser` and `npm token` do not work with Prego. Use `prego setup npm`. |
| `403` `cannot publish over previously published version` (npm 10), or `You cannot publish over the previously published versions` (npm 11, before any request) | The version was used before. Publish a new version. |
| `403` on publish | No `publish` grant, or a plan or storage quota limit. |
| `400` `Prego does not accept npm provenance yet` | Publish without `--provenance`. |
| `413` | The tarball is larger than 50 MiB, or the package metadata is too large. |

## Not in this release

- Unscoped packages, and a proxy or cache of registry.npmjs.org.
- `npm login`, `npm token`, long-lived npm tokens, and `_auth` Basic credentials.
- npm provenance and signatures.
- `npm audit` (npm sends it to registry.npmjs.org, not to a scope registry), and search (empty).
- `npm access`, `owner`, `team` and `org`. Grants in the console replace them.
