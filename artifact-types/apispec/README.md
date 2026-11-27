# API specs (OpenAPI)

API specs holds versioned OpenAPI 3.0 and 3.1 documents. Each version is one document (JSON or YAML), with a SemVer
label, a body that does not change, a sha256 hash and a stable URL. Prego checks that a document is valid OpenAPI,
shows it as API docs in the console, and shows an informational diff between two versions at the API level.

**Prego never blocks a publish because of a breaking change, and it does not judge the data models.** The diff says
"added", "removed" or "changed"; it never says "breaking". Run your own compatibility tool in CI if you need a gate.

**Plans:** Trial, Indie, Org and Publisher can publish. Consumer reads through grants.

## Start

- [API specs quickstart](quickstart.md): publish, get, diff, tags, the checks and the errors.
- [API specs](../../README.md#api-specs-openapi) in the root README.

## Examples

- [`examples/payments-api.yaml`](examples/payments-api.yaml): a small OpenAPI 3.1 document.
- [`examples/github-actions.yml`](examples/github-actions.yml) and [`examples/gitlab-ci.yml`](examples/gitlab-ci.yml):
  publish the document of a release tag from CI.
