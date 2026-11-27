# API specs (OpenAPI, GraphQL)

API specs holds versioned OpenAPI 3.0 and 3.1 documents and GraphQL schemas (SDL). Each version is one document
(OpenAPI as JSON or YAML, GraphQL as SDL), with a SemVer label, a body that does not change, a sha256 hash and a
stable URL. A spec keeps the format of its first version. Prego checks the document, shows it in the console, and
shows an informational diff between two versions.

**Prego never blocks a publish because of a breaking change, and it does not judge the data models.** The diff says
"added", "removed" or "changed"; it never says "breaking". Run your own compatibility tool in CI if you need a gate.

**Plans:** Trial, Indie, Org and Publisher can publish. Consumer reads through grants.

## Start

- [API specs quickstart](quickstart.md): publish, get, diff, tags, the checks and the errors.
- [API specs](../../README.md#api-specs-openapi) in the root README.

## Examples

- [`examples/payments-api.yaml`](examples/payments-api.yaml): a small OpenAPI 3.1 document.
- [`examples/payments.graphql`](examples/payments.graphql): a small GraphQL schema.
- [`examples/github-actions.yml`](examples/github-actions.yml) and [`examples/gitlab-ci.yml`](examples/gitlab-ci.yml):
  publish the document of a release tag from CI.
