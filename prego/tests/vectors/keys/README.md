# Keys and Certificates vectors (ADR-0061 sections 2.3 to 2.5 and 4a)

Shared test data for the entry parsers, the private-material check and the version hash. Data only: the registry
(Prego-registry, Prego-admin-mcp) and `prego keys` in prego-clients read the same `cases.json`. Copy the data, never
code.

**Test input only; not a key.** No case in this folder holds a usable private key. The private-material cases have the
real markers (PEM labels, the OpenSSH and OpenPGP armor, OpenPGP secret-key packet tags, JWK private members, a PKCS #12
structure) and a body that is not a key (the text `TEST-NOT-A-KEY`). A server or client must refuse on the marker or
the member alone, before any parse, so these inputs test the rule fully. The script makes the real key pairs in a
temporary folder and deletes it.

In `cases.json`, the first character of every PEM armor line is written as `-`, so that secret scanners do not
flag the file. A JSON parser gives the real text.

## Entries

Each case has `type`, `content` and `encoding` as in the `PUT` body of section 4a. `encoding` is `text` or `base64`
(DER, binary OpenPGP, PKCS #12). The entry bytes are the UTF-8 bytes of `content`, or the base64-decoded bytes.

## Files

- `cases.json`:
  - `valid[]`: `{name, type, content, encoding, entry}`. `entry` is the expected entry of `GET <k>/v/<v>` (section 4a)
    without `index` and `type`. A field that does not apply is `null`.
  - `invalid[]`: `{name, type, content, encoding, error: "key_invalid", index, reason}`.
  - `private_material[]`: `{name, type, content, encoding, entries, error: "private_key_material", index, kind,
    message}`. When `entries` is not `null`, the case is a push of several entries; `index` names the bad one.
  - `version_hashes[]`: `{name, entries, canonical, hash}` (section 4a).

## Rules that the vectors fix

- `index` is the 0-based entry index (as `entries/<index>`). The message says "Entry <index>" with the same number.
  "certificate 3 of the bundle" counts from 1 (the third certificate).
- The private-material check runs first, on the whole upload, also on text outside the declared entry, and for every
  declared type. So a JWK `oct` key gives `private_key_material` (member `k`), not `key_invalid`.
- `message`: "Keys and Certificates holds public keys and certificates only. Entry <index> holds a private key
  (<kind>). <hint>". The hint is per kind (see the cases).
- `alg` is one of `ed25519`, `ecdsa`, `rsa`, `x25519` (OpenPGP encryption subkey), `ed25519-sk` (FIDO),
  `ed25519-cert` (OpenSSH certificate). `curve` is `Ed25519`, `Curve25519`, `P-256`, `P-384`, `P-521` or `null`.
  `size_bits` is 256 for Ed25519 and Curve25519 (gpg shows 255).
- `fingerprint`:
  - `ssh`: `SHA256:<base64, no padding>` as `ssh-keygen -l -E sha256` shows it. For a certificate, this is the
    fingerprint of the certified key, as `ssh-keygen -l` shows it.
  - `openpgp`: the 40-character uppercase hex v4 fingerprint, as `gpg --with-colons` shows it. `subkeys[]` has the same
    fields per subkey. `user_ids[]` puts the primary user ID first, then the other user IDs in the order of the key
    packets. The primary user ID is the one whose newest self-signature has the primary flag (RFC 9580 section
    5.2.3.27); if no user ID has the flag, it is the user ID with the newest self-signature. This is the order of
    `gpg --with-colons`. In `openpgp-rsa3072-two-uids-no-expiry`, the second user ID is primary (it has the newer
    self-signature), so it comes first.
  - `x509`: `sha256:<hex>` of the DER of the certificate.
  - `jwk`, `pem-public-key`: the RFC 7638 thumbprint (also in `thumbprint`). `kid` is the `kid` of the JWK, else `null`.
- `x509`: the top-level fields describe the first certificate of the entry. A bundle also has `certs[]` (every
  certificate, in entry order) and `chain_in_order` (each certificate is issued by the next one; ADR-0061 sections 2.3
  and 4a).
  A single certificate has `certs: null` and `chain_in_order: null`. `subject` and `issuer` are RFC 4514 strings
  (`openssl -nameopt RFC2253`). `serial` is lowercase hex. `expired` is true when `not_after` is in the past.
- `jwk` with a JWK Set: the top-level fields are `null`, and `keys[]` has the fields per key (ADR-0061 section 4a).
- OpenPGP: v4 only in this release (ADR-0061 section 4a). A v6 key gets `400 key_invalid` "OpenPGP v6 keys are not
  supported yet". The case `openpgp-v6-binary` is a hand-made v6 public-key packet (the version byte is enough).
- Version hash: `sha256:` of the RFC 8785 JSON of `{"entries": [{"type", "sha256"}]}` in push order. The push order
  changes the hash (cases `mixed-push-order` and `same-entries-other-order`).

## Make new vectors

Run `node apps/registry/test/vectors/keys/make-vectors.mjs` from the repo root, in the capped container or in CI. It
needs `ssh-keygen`, `openssl` and `gpg`. Each run makes new keys, so commit every file it writes.
`scripts/vectors/test/keys-a2a.test.ts` checks the thumbprints, the fingerprints, the version hashes and the markers
again.

A change of this data is a change of the Keys and Certificates contract. It needs an ADR change first.
