# A2A Agent Cards vectors (ADR-0062)

Shared test data for the A2A 1.0 card check, the 0.3 detection, card and set signatures, the version hash and
`prego a2a upgrade`. Data only: the registry (Prego-registry, Prego-admin-mcp) and `prego a2a` in prego-clients read
the same files. Copy the data, never code.

Test input only. There is no private key in this folder. The script makes the key pairs in memory and writes only the
public JWKs (`keys/TEST-ONLY-*.public.jwk.json`).

## Pinned A2A 1.0 source (ADR-0062 build decisions)

A2A 1.0 has no JSON schema in git. The normative source is `specification/a2a.proto`. The JSON schema is a generated
file of the A2A docs site. Prego pins both, from the same release:

| File | Source | SHA-256 |
| --- | --- | --- |
| `schema/a2a-1.0.1.proto` | <https://raw.githubusercontent.com/a2aproject/A2A/3303592588e388e62e0f69f701af531d2f4e3991/specification/a2a.proto> | `e195bf96ab630c69797851970203e1b2b6b19528f2e9803b7d904b91a5104016` |
| `schema/a2a-1.0.1.schema.json` | <https://a2a-protocol.org/v1.0.1/spec/a2a.json> | `ba4b702b5edbdcbfe972c272484eb38e1fcd72af3c0b7eaa114b50e97455d8dd` |

Tag `v1.0.1` of `a2aproject/A2A`, commit `3303592588e388e62e0f69f701af531d2f4e3991`, released 2026-05-28. Fetched on
2026-11-24. Do not edit these two files.

Notes on the generated schema:

- It has no `required` lists, so `{}` passes it. The REQUIRED fields come from the proto (`card-fields.json`).
- Its `$ref` values name files (`lf.a2a.v1.AgentSkill.jsonschema.json`) that are not in the bundle.
  `schema/ref-map.json` maps each `$ref` to its key in `definitions`.
- Every message has `additionalProperties: false`. The snake_case name of a field is allowed too (`patternProperties`).
- The sample card of the 1.0.1 spec (section 8.5) uses `security`, which is not a 1.0 field. The vectors follow the
  schema, so `security` is a 0.3 sign.

## The card rule ("passes the A2A 1.0 schema")

1. The card is a JSON object. Else: `card_invalid` with path `""` (`not valid JSON` or `expected object`).
2. The 0.3 detection runs first (see below).
3. Every field must be a field of its message in `card-fields.json`, by its `json` (lowerCamel) or `name` (snake_case)
   name. Else: `unknown field`. Both names of one field in one object: `duplicate field (<other name>)`.
4. Types: `string`, `bool`, `message:<Name>`, `map:string-><kind>`, repeated (an array). `any`
   (`google.protobuf.Struct`) is not checked inside.
5. REQUIRED (proto `field_behavior`): a string is present and not `""` (`required field is empty`); an array has at
   least one item (`required array is empty`); a message or map is present (a map can be empty). Missing: `required
   field is missing`, with the path of the missing field.
6. A oneof (`SecurityScheme.scheme`, `OAuthFlows.flow`) has exactly one member: `exactly one of <oneof> must be set`.
7. The path is an RFC 6901 JSON pointer (`/skills/0/tags`). The first error in document order wins.

`card-fields.json`: `{root, messages: {<Name>: {fields: [{name, json, kind, required, optional, repeated, oneof}]}},
not_in_schema}`. A script makes it from the pinned proto, and keeps only the fields that the pinned schema has.

## 0.3 detection

The first rule that matches gives the reason:

1. top-level `protocolVersion`: `has protocolVersion "<value>"` (the value as JSON);
2. top-level `url`: `has top-level url`;
3. `preferredTransport`: `has preferredTransport`;
4. `additionalInterfaces`: `has additionalInterfaces`;
5. `supportsAuthenticatedExtendedCard`: `has supportsAuthenticatedExtendedCard`;
6. top-level `security`: `has security, not securityRequirements`;
7. a `securitySchemes` entry with a `type` member: `security scheme <name> has type`.

The message (ADR-0062 section 2.3): "A2A 1.0 only. Card <file> looks like A2A 0.3 (<reason>). Run `prego a2a upgrade
<file>` to make a 1.0 card, then sign it again."

## Card signatures (A2A 1.0 section 8.4, ADR-0062 build decisions)

- Signing input: RFC 8785 of the card without `signatures` and without the fields at their default value. A field
  that is not REQUIRED and has no `optional` keyword in the proto is removed when its value is `""`, `false`, `0`,
  `[]` or an empty map. An `optional` field stays when it is present. A REQUIRED field always stays. Message fields
  stay. `any` content and map entries do not change. Field names stay as written (snake_case stays snake_case).
- Detached JWS: each entry of `signatures` is `{protected, signature[, header]}`; the payload is the signing input.
- Protected header: `{"alg", "typ": "JOSE", "kid": <RFC 7638 thumbprint>, "prego_key": "<tenant>/<namespace>/<name>"}`.
  The header rules of `../signing/README.md` apply.
- A card is valid when at least one signature verifies with a key of the tenant. A signature by an unknown key is
  ignored when another one verifies.
- Source extension (ADR-0062 section 2.9): an entry in `capabilities.extensions` with URI
  `https://prego.k8skill.com/ext/a2a-source/v1` and params `{"tenant", "namespace", "set"}`. When a card has it, the
  params must equal the push location. Else: `422 source_mismatch`.

## Files

- `cards/`: one file per card case. The bytes matter: do not reformat.
- `cases.json`:
  - `schema`: source, tag, commit and SHA-256 of the pinned files.
  - `valid[]`: `{name, file, note}`.
  - `invalid[]`: `{name, file, error: "card_invalid", path, reason}`.
  - `v03[]`: `{name, file, error: "card_invalid", reason, message}`.
  - `signed[]`: `{name, file, push, signing_input, keys, expect, error, reason, message}`. `signing_input` is the
    canonical text that the signatures cover (for `changed-after-signing`, the text before the change). `error` is
    `signature_required`, `signature_invalid` (with `reason`) or `source_mismatch`.
  - `sets[]`: `{name, dir, push, files, hash_input, hash, set_payload, set_jws, keys, expect, error, reason}`. `dir`
    has the card files and `.prego/set.jws.json`, as in the `.tar.gz` push of section 3a. `hash` is the Snippets hash
    (ADR-0057 item 6, mode `0644`) over the card files only. `set_payload` is the ADR-0061 section 3.1 payload. The
    case `one-card` also has `json_body`, the JSON push form of section 3a. The set JWS has its payload attached. The
    case `set-signed-for-other-set` has reason `payload_mismatch`; a verifier can report it as `payload_changed`
    (`../signing/README.md` rule 10).
  - `upgrade[]`: `{name, in, in_file, out, default_out_file, changes, error}`.
- `keys/`: the public JWKs. The cards name the key item `acme/default/release-keys`.

## `prego a2a upgrade` (0.3 to 1.0)

- `url` and `preferredTransport` (default `JSONRPC`) become `supportedInterfaces[0]`. Each `additionalInterfaces` entry
  becomes one more interface (`transport` becomes `protocolBinding`). An entry with the same URL and transport as the
  first one is removed.
- Each interface gets `protocolVersion: "0.3"`: the agent still serves A2A 0.3 at that URL. The card format is 1.0.
- `supportsAuthenticatedExtendedCard` becomes `capabilities.extendedAgentCard`. `stateTransitionHistory` is removed.
- 0.3 security schemes (`type` `http`, `apiKey`, `oauth2`, `openIdConnect`, `mutualTLS`) become the 1.0 oneof form
  (`apiKey` `in` becomes `location`). `security` becomes `securityRequirements` (`{schemes: {<name>: {list: [...]}}}`),
  for the card and for each skill.
- `signatures` is removed; the user signs the 1.0 card again. The output is not signed.
- The tool stops and names the field (`error.field`, a JSON pointer) when it cannot map a field with certainty: two or
  more OAuth flows in one scheme, a field that A2A 0.3 does not have, a card that is not 0.3, a scheme type with no 1.0
  form.
- `changes[]` lists each change as `{op, from, to, note}`, with `op` one of `move`, `remove`, `add`, `convert`. A client
  prints them; the exact text is free.
- The input name is free (the legacy `agent.json` too). With no `-o`, the output is `agent-card.json` next to the input.

## Make new vectors

Run `node apps/registry/test/vectors/a2a/make-vectors.mjs` from the repo root, in the capped container or in CI. Each
run makes new keys and signatures, so commit every file it writes. The script checks the valid and invalid cards
against the rule and the pinned schema, and the Snippets hash against `../snippets/`. Then
`scripts/vectors/test/keys-a2a.test.ts` checks the signatures and hashes again with its own code.

A change of this data is a change of the A2A Agent Cards contract. It needs an ADR change first.
