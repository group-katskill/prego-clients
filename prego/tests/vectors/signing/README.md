# Signing vectors (ADR-0061 section 3, signed sets)

Shared test data for signed sets. Data only: the registry (Prego-registry, Prego-admin-mcp) and `prego` in
prego-clients read the same files. Copy the data, never code. Write the rules from the ADR and from this file.

Test input only. There is no private key in this folder. The script makes the key pairs in memory and writes only the
public JWKs (`keys/TEST-ONLY-*.public.jwk.json`). A test that must make a signature makes its own key at test time.

## Files

- `jcs.json`: RFC 8785 cases. `[{name, input_text, input, canonical}]`. Parse `input_text` (the raw JSON text, with
  number forms such as `1E30`) and canonicalize it; the result must be `canonical`. `input` is the same value, parsed.
  Two cases are the examples of RFC 8785 sections 3.2.2 and 3.2.3.
- `thumbprint.json`: RFC 7638 cases. `[{name, jwk, thumbprint}]`. The thumbprint is the base64url (no padding) SHA-256
  of the RFC 8785 JSON of the required members only (`OKP`: crv, kty, x; `EC`: crv, kty, x, y; `RSA`: e, kty, n).
  Other members (`kid`, `use`, `alg`) and the member order do not change it. One case is RFC 8037 appendix A.3.
- `payload.json`: ADR-0061 section 3.1 payloads. `[{name, set, canonical, sha256}]`. `canonical` is the RFC 8785 JSON
  of `set`; `sha256` is the hex SHA-256 of its UTF-8 bytes. The `files` order is the order of the version: for
  Snippets and A2A Agent Cards, by the UTF-8 bytes of `path` (ADR-0057 item 6); for Keys and Certificates, by entry
  index (`entries/0`, `entries/1`, ...; ADR-0061 section 4a).
- `jws.json`: JWS JSON serialization cases. `[{name, alg, jws, payload, keys, expect, reason}]`.
  - `jws`: flattened (`{payload, protected, signature[, header]}`) or general (`{payload, signatures: [...]}`).
    `jws.payload` is the base64url of the payload bytes.
  - `payload`: the canonical payload text that the verifier expects (for example the payload of the version that
    the server computes).
  - `keys`: the public JWKs that the verifier can use (as the key items of Keys and Certificates).
  - `expect`: `valid` or `invalid`. `reason`: a stable code for an invalid case, else `null`. `alg` is `multi` when
    the case has signatures with different algorithms.

## Verify rules (ADR-0061 sections 3.2 and 3.4)

1. Every base64url value uses the URL-safe alphabet with no padding. Else: `bad_base64url`.
2. `alg`, `kid`, `prego_key`, `crit` and `b64` must be in the protected header only. One of them in the unprotected
   `header`: `header_unprotected`.
3. `b64: false`: `b64_false`. Any `crit`: `crit_present`.
4. `alg` must be `EdDSA` (Ed25519), `ES256`, `ES384`, `PS256` or `RS256`. Else (`none`, `HS256`, ...): `alg_not_allowed`.
5. `prego_key` must be present (`prego_key_missing`) and have the form `<tenant>/<namespace>/<name>`
   (`prego_key_invalid`).
6. `kid` must be an RFC 7638 thumbprint (43 base64url characters). Else: `kid_not_thumbprint`. No key in `keys` with
   that thumbprint: `key_not_found`. A verifier that finds the key by its thumbprint and does not check the `kid` form
   first can report `kid_not_thumbprint` as `key_not_found`. The answer is still `422 signature_invalid`.
7. The key type must fit `alg` (`EdDSA`: OKP Ed25519; `ES256`: EC P-256; `ES384`: EC P-384; `PS256`, `RS256`: RSA).
   Else: `alg_key_mismatch`.
8. ECDSA signatures are raw `r || s` (64 bytes for ES256, 96 for ES384). A DER signature: `ecdsa_der`. `PS256` uses
   a salt length of 32. The signing input is `ASCII(protected || "." || payload)`.
9. A signature that does not verify: `wrong_key` (signed by another key), `payload_changed` (the payload changed after
   signing) or `signature_truncated`. A verifier can report these three as one code (for example `bad_signature`).
10. The signature verifies, but the payload is not the expected `payload`: `payload_mismatch`. So a signature cannot
    move to another item, tenant or version. A verifier that compares the attached payload with the expected payload
    can report this as `payload_changed`. The answer is still `422 signature_invalid`.
11. A JWS with more than one signature is valid only when every signature verifies.
12. Other protected header members (for example `typ`) are allowed and ignored.

A2A card signatures (`a2a/`) use the same header rules, but a card is valid when at least one of its signatures
verifies (ADR-0062 section 2.4).

## Make new vectors

Run `node apps/registry/test/vectors/signing/make-vectors.mjs` from the repo root, in the capped container or in CI.
Each run makes new keys and new signatures, so commit every file it writes. `scripts/vectors/test/keys-a2a.test.ts`
checks the committed files again with its own code (`pnpm --filter @prego/registry run test:deploy`).

A change of this data is a change of the signing contract. It needs an ADR change first.
