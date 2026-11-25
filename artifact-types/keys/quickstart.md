# Keys and Certificates with `prego keys`

**From prego 1.3.0.** Keys and Certificates need `prego` 1.3.0 or later.

Keys and Certificates is a place for the public keys and certificates of your team: SSH deploy keys and SSH
certificate authorities, OpenPGP release keys, JWKs that sign A2A Agent Cards, and X.509 CA bundles and mTLS
chains. An item is a named set of entries with versions that do not change. Prego checks each entry by its type and
records its algorithm, size, fingerprint and validity dates.

> **Keys and Certificates holds public keys and certificates only; Prego never stores a private key.** `prego`
> checks every file before the upload. If a file holds private key material, `prego` stops and sends nothing:
>
> ```text
> Keys and Certificates holds public keys and certificates only. Entry <index> holds a private key (<kind>). <hint>
> ```
>
> The registry does the same check again and refuses the push with `422 private_key_material`. There is no
> override.

This guide uses tenant `acme`, namespace `release-keys` and the key items `signer` and `deploy`. Replace them with
your own.

## Plans and access

- Trial, Indie, Org and Publisher can push key items. Consumer reads through grants.
- Grants use the type "Keys and Certificates" (`ecosystem = key`) with the actions `read`, `publish` and `delete`.
  An `any` grant also matches.
- With no grant, Prego answers as if the item does not exist (`404`).
- A read from another namespace or another tenant needs an explicit grant. Grants to other tenants follow the plan
  rules: Indie cannot make them, Org can grant only to tenants with the same verified domain, and Publisher can
  grant to any tenant. A grant to another tenant gives `read` only.
- Prego does not serve keys in public. Every read needs a registry token.

## References

```text
<tenant>/<name>                        namespace default
<tenant>/<namespace>/<name>
<tenant>/<namespace>/<name>@<version>  a number, a tag, sha256:<hex> or current (the default)
```

A name is 1 to 128 characters: `[a-z0-9][a-z0-9._-]{0,127}`.

## Entry types

A version holds 1 to 100 entries, one for each file that you push. Without `--type`, `prego` finds the type of each
file from its content. Give `--type` to set the type of all files of the push.

| Type | What it accepts | Rules |
| --- | --- | --- |
| `ssh` | One OpenSSH public key line (`ssh-ed25519`, `ecdsa-sha2-nistp256/384/521`, `ssh-rsa`, `sk-ssh-ed25519@openssh.com`, `sk-ecdsa-sha2-nistp256@openssh.com`), or an OpenSSH certificate (`*-cert-v01@openssh.com`) | RSA at least 3072 bits. DSA is refused. |
| `openpgp` | An OpenPGP public key, ASCII armor or binary, v4 or v6 | Public key packets only. Prego records the primary fingerprint, the subkeys, the user IDs and the expiry. |
| `jwk` | One public JWK, or a JWK Set | `kty` `OKP` (Ed25519), `EC` (P-256, P-384) or `RSA` (at least 2048 bits). `oct` is refused. Prego keeps `kid` and records the RFC 7638 thumbprint. |
| `pem-public-key` | A PEM `PUBLIC KEY` (SubjectPublicKeyInfo) | The same algorithms and sizes as `jwk`. |
| `x509` | One certificate, or a bundle (a chain or a CA bundle), PEM or DER | At most 100 certificates in one entry. Prego records the subject, issuer, serial, SHA-256 fingerprint, `notBefore` and `notAfter`, and if the chain is in order. An expired certificate is accepted and marked `expired`. |

Make each file from your own keys with the usual tools. Run the commands on your computer; only the public part
goes into the file:

```sh
ssh-keygen -y -f ~/.ssh/deploy_ed25519 > deploy.pub         # ssh: one line, "ssh-ed25519 AAAA... deploy@acme"
gpg --armor --export release@acme.example > release.asc      # openpgp: "-----BEGIN PGP PUBLIC KEY BLOCK-----"
openssl pkey -in signer.pem -pubout -out signer.pub.pem     # pem-public-key: "-----BEGIN PUBLIC KEY-----"
cp /etc/ssl/acme/ca-bundle.pem ca-bundle.pem                # x509: one or more "-----BEGIN CERTIFICATE-----"
```

A public JWK looks like this (`d` and the other private members are not there):

```json
{"kty": "OKP", "crv": "Ed25519", "x": "<base64url public key>", "kid": "signer-2026", "use": "sig"}
```

These are refused, with the hint that tells you what to upload instead:

| Found | Kind in the message | Upload instead |
| --- | --- | --- |
| PEM `PRIVATE KEY`, `RSA PRIVATE KEY`, `EC PRIVATE KEY`, `ENCRYPTED PRIVATE KEY` | PEM `<label>` | `openssl pkey -in <key> -pubout` |
| PEM `OPENSSH PRIVATE KEY` | OpenSSH private key | `ssh-keygen -y -f <key>` |
| OpenPGP `PRIVATE KEY BLOCK` or a secret-key packet | OpenPGP private key block, OpenPGP secret-key packet | `gpg --armor --export <key id>` |
| A JWK with `d`, `p`, `q`, `dp`, `dq`, `qi`, `oth` or `k` | JWK private member `<name>` | the JWK without those members |
| PKCS #12 (`.p12`, `.pfx`), also with certificates only | PKCS #12 | `openssl pkcs12 -in <file> -nokeys`, then upload the PEM |

The check looks at the whole file, also at text outside the entry. The entry index counts from 0.

## Make a signing key

`prego keys new` makes a key pair on your computer and pushes only the public key:

```sh
prego keys new --alg ed25519 acme/release-keys/signer --out ./signer.private.pem
```

- `--alg` is `ed25519` or `es256` (ECDSA P-256).
- The private key goes to `--out` (default `./<name>.private.pem`) with mode `0600`. `prego` never replaces a file
  that exists, and never sends the private key.
- The public JWK goes to `./<name>.pub.jwk` (here `./signer.pub.jwk`) and to the key item. `kid` is the
  RFC 7638 thumbprint.
- The new key is added to the entries of the current version, so the old keys stay valid while you rotate.
- If the push fails, the key files stay. Fix the problem, then push the `.pub.jwk` file with `prego keys push`.

Keep the private key file safe: in a password manager, or in the secret store of your CI. Do not commit it. Use it
to sign A2A Agent Cards: see the [A2A Agent Cards quickstart](../a2a/quickstart.md).

## Push

```sh
prego keys push deploy.pub ci.pub acme/release-keys/deploy --message "deploy keys for the build hosts"
prego keys push ca-bundle.pem acme/release-keys/internal-ca --type x509 --not-after 2027-12-31T00:00:00Z
```

- A push makes a new version from the files that you give. It replaces the entry list: give all the files that
  the version must hold.
- `--tag <tag>` tags the new version. `--message <text>` records why.
- `--if-current <hash>` refuses the push if the current version hash is different.
- `--not-after <RFC 3339 time>` gives the item an end date.
- A push needs `publish`.

## Read

```sh
prego keys ls acme/release-keys                    # the key items that you can read
prego keys get acme/release-keys/deploy            # entries: type, algorithm, fingerprint, validity, revoke state
prego keys get acme/release-keys/deploy@3 --entry 0 > deploy.pub   # one entry, as pushed
prego keys get acme/release-keys/deploy@stable --expect sha256:... # exit 3 if the version hash is different
prego keys log acme/release-keys/deploy            # the versions, newest first
```

The fingerprint is `SHA256:<base64>` for `ssh` (as `ssh-keygen -l` shows), the hex fingerprint for `openpgp`,
`sha256:<hex>` of the DER for `x509`, and the RFC 7638 thumbprint for `jwk` and `pem-public-key`.

Compare a local file with the registry, offline:

```sh
prego keys fingerprint deploy.pub
prego keys fingerprint ca-bundle.pem --type x509
```

## Tags, rollback and revoke

```sh
prego keys tag acme/release-keys/deploy@3 stable
prego keys rollback acme/release-keys/deploy --to 2 --reason "host b was removed too early"
prego keys revoke acme/release-keys/signer --reason "laptop lost"
```

- A tag is written one time and never moves.
- A rollback makes another version the current one. It makes no new version.
- **A revoke is one-way.** It needs `delete`. The item stays readable, and every answer shows the revoke time
  and reason. After the revoke, signatures made with its keys fail `--verify`, also signatures made before the
  revoke. Make a new key with `prego keys new` and sign again.

## Missing grant

When you have no grant on an item, or the item does not exist, `prego` names the grant to ask for:

```text
read on key acme/release-keys/deploy (type Keys and Certificates) is missing, or the key item does not exist; ask an admin of acme for a grant
```

`prego a2a get --verify` needs `read` on the key item that signed the cards. Without it, `prego` stops with:

```text
verify needs read on key acme/release-keys/signer (type Keys and Certificates); ask an admin of acme for a grant
```

## Examples

[`examples/push-and-fingerprint.sh`](examples/push-and-fingerprint.sh) makes a signing key, pushes an SSH public
key and a PEM certificate bundle that you give, and prints the fingerprints.

## Errors

| Error | Cause | What to do |
| --- | --- | --- |
| `Keys and Certificates holds public keys and certificates only. Entry <index> holds a private key (<kind>). <hint>` | A file holds private key material. Nothing was sent. | Upload the public part, as the hint says. |
| `422 private_key_material` | The registry found private key material. | The same. |
| `400 key_invalid` | An entry does not parse as its type, or the key is too small (for example an SSH RSA key of 2048 bits). | Read the reason and the entry index. Fix the file or the `--type`. |
| `... is missing, or the key item does not exist; ask an admin of acme for a grant` | No grant, or no item with that name. | Check the reference. Ask an admin for the grant. |
| `403 plan_limit` | The plan's item count or storage is full, or the plan does not allow the action. | See the plan limits page. |
