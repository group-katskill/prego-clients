# API specs (OpenAPI, GraphQL) with `prego apispec`

**From prego 1.4.0 and the registry with ADR-0067.**

An API spec is a name in a namespace, for example `payments-api`. Each version is one OpenAPI document or one
GraphQL schema (from ADR-0067 Amendment 1). This guide
uses tenant `acme`, namespace `default` and the spec `payments-api`. Replace them with your own.

## Plans and access

- Trial, Indie, Org and Publisher can publish API specs. Consumer reads through grants.
- Grants use the type "API specs" (`ecosystem = apispec`) with the actions `read`, `publish` and `delete`. An `any`
  grant also matches.
- With no grant, Prego answers as if the spec does not exist (`404`).

## Publish a version

```sh
prego apispec push ./openapi.yaml acme/payments-api@1.4.0 --message "add refunds" --tag stable
```

- The version is SemVer 2.0 with no leading `v`: `1.4.0`, `2.0.0-rc.1`. A version never changes. The same label with
  the same bytes again is "no change"; the same label with other bytes is refused (`409 conflict`).
- `prego` checks before the upload that the document is OpenAPI 3.0 or 3.1 and at most 4 MiB. Swagger 2.0 is
  refused, with nothing sent:

  ```text
  /swagger: Swagger 2.0 is not supported. Prego accepts OpenAPI 3.0 and 3.1. Convert the document to OpenAPI 3 (for
  example with swagger2openapi or the Swagger Editor), then publish it again.
  ```

- The registry does the full check: the required objects, and the shapes of the paths, operations, parameters,
  request bodies, responses, security and servers. An error names the place with a JSON pointer, for example
  `400 apispec_invalid /paths/~1refunds/post: the operation has no responses`.
- Prego does not follow an external `$ref` to another file or URL. Bundle the document before you publish (for
  example with `redocly bundle`).
- A document with a line that looks like a secret is refused (`422 looks_like_secret`, with the line numbers).
- Each publish gets an ADR-0065 publish attestation: who published the document, and from which pipeline.

## Get a version

```sh
prego apispec get acme/payments-api@1.4.0 --out openapi.yaml   # the bytes as published, checked against the hash
prego apispec get acme/payments-api --format json              # the highest version, as JSON
prego apispec get acme/payments-api@stable --expect sha256:<hex>
```

- With no version, `get` takes the highest version by SemVer.
- With no `--format`, you get the bytes as published, and `prego` checks them against the version hash.
- `--format json|yaml` gives the other format as a conversion of the parsed document.
- `--expect` stops with exit code 3 when the version has another hash.
- The stable URL of a version is `https://api.prego.k8skill.com/v1/apispec/acme/default/payments-api/1.4.0`. It needs
  a registry token and a `read` grant.

## GraphQL schemas

```sh
prego apispec push ./schema.graphql acme/payments-graph@1.0.0
prego apispec push ./schema acme/payments-graph@1.1.0          # every .graphql and .gql file, joined in path order
prego apispec get acme/payments-graph@1.1.0 --out schema.graphql
```

- A `.graphql` or `.gql` file, or a folder of them, is GraphQL SDL. `prego` joins the files of a folder in path
  order (subfolders too) and sends one document; the registry takes one file.
- An API spec holds the schema only. `prego` refuses a query, a mutation, a subscription, a shorthand `{ ... }` query
  or a fragment before the upload, with the line and column:

  ```text
  ops.graphql: line 2, column 1: `query` starts an executable definition (a query, mutation, subscription or
  fragment). An API spec holds the schema only ...
  ```

- The registry checks the schema: unique names, defined types, and extensions of defined types. An error names the
  schema coordinate, for example `400 apispec_invalid User.email: ...`.
- A spec keeps the format of its first version: an OpenAPI document to a GraphQL spec (or the other way) is refused
  with `400 format_mismatch`.
- `get` always gives the SDL as published. `--format json` or `yaml` applies to OpenAPI only.
- The diff names each change by its schema coordinate: `field Payment.currency added`,
  `argument Query.payment(id:) changed`, and types, enum values, union members, directives and deprecations.

## See what changed

```sh
prego apispec diff acme/payments-api@1.3.0 acme/payments-api@1.4.0
```

```text
acme/default/payments-api 1.3.0 (sha256:...) -> 1.4.0 (sha256:...)
~ info.version 1.3.0 -> 1.4.0
+ operation POST /refunds added
~ schema Payment changed
```

The diff comes from the registry, so the CLI and the console show the same list. It compares at the API level:
paths and operations, parameters (and a parameter that became required), request bodies, response codes, security
schemes and requirements, servers, `info.version` and `deprecated`. A change in `components.schemas` shows as
"schema `<name>` changed", with no deeper analysis. `--json` prints the answer as it is.

## Errors

| Message | What to do |
| --- | --- |
| `/swagger: Swagger 2.0 is not supported` | Convert the document to OpenAPI 3, then publish again. |
| `` `query` starts an executable definition `` | Remove the operations and fragments; publish the schema only. |
| `400 format_mismatch` | The spec has the other format. Use a new spec name for it. |
| `400 not_sdl` | The registry found an operation or a fragment in the GraphQL document. |
| `/openapi: ... is not 3.0.x or 3.1.x` | Set `openapi` to a 3.0 or 3.1 version. |
| `bad version ...: SemVer 2.0 with no leading v` | Use `1.4.0`, not `v1.4.0`. |
| `409 conflict` | The label has other bytes, is pending deletion, or was used before. Use a new label. |
| `403 plan_limit` | The namespace has the most specs of the plan, or the spec has 1,000 versions. |
| `not found, or you have no grant for it` | Ask an admin of the tenant for a grant on type API specs. |
