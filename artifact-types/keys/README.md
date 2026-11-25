# Keys and Certificates

Keys and Certificates holds the public keys and certificates of your team: SSH keys and SSH certificates, OpenPGP
keys, JWKs, PEM public keys, and X.509 certificates and bundles. Prego checks each entry by its type, records its
fingerprint and validity, and keeps versions that do not change. A key item can be revoked, and signatures with a
revoked key then fail `--verify`.

**Public keys and certificates only; Prego never stores a private key.** `prego keys` checks every file before the
upload and stops if a file holds private key material.

**Plans:** Trial, Indie, Org and Publisher can publish. Consumer reads through grants.

## Start

- [Keys and Certificates quickstart](quickstart.md): the entry types, `prego keys new`, push, get, fingerprints,
  tags, rollback, revoke, and the errors.
- [Keys and Certificates](../../README.md#keys-and-certificates) in the root README.
- Sign A2A Agent Cards with a key from here: [A2A Agent Cards](../a2a/).

## Examples

- [`examples/push-and-fingerprint.sh`](examples/push-and-fingerprint.sh): make a signing key, push an SSH public
  key and a PEM certificate bundle, and print the fingerprints.
