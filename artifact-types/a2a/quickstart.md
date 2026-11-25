# A2A Agent Cards with `prego a2a`

**From prego 1.3.0.** A2A Agent Cards need `prego` 1.3.0 or later.

A2A (Agent2Agent) Agent Cards describe an agent: its name, endpoints, skills and security schemes. Prego keeps your
cards as card sets: one card or many cards, pushed as one signed version that does not change. Your teams and CI
jobs share, pin and check cards with the identity that they already have.

- **A2A 1.0 only.** For an A2A 0.3 card, use `prego a2a upgrade` first (see [Upgrade an A2A 0.3 card](#upgrade-an-a2a-03-card)).
- **Signed, always.** Every card and every set must be signed with a key from
  [Keys and Certificates](../keys/quickstart.md). Prego never gets the private key: `prego` signs on your computer.
- **No public serving.** Prego does not serve `/.well-known/agent-card.json`. Your agent serves its own card from
  its own host.

This guide uses tenant `acme`, namespace `agents`, the card set `support` and the signing key item
`acme/release-keys/signer`. Replace them with your own.

## Plans and access

- Trial, Indie, Org and Publisher can push card sets. Consumer reads through grants.
- Grants use the type "A2A Agent Cards" (`ecosystem = a2a`) with the actions `read`, `publish` and `delete`. An
  `any` grant also matches.
- To check signatures with `--verify`, a reader needs `read` on the card set **and** `read` on the key item that
  signed it.
- A push with `--sign` needs `publish` on the set and `read` on the key item. The key item must be in the tenant of
  the set.
- Grants to other tenants follow the plan rules: Indie cannot make them, so on Indie the cards stay in your tenant.
  Org can grant only to tenants with the same verified domain. Publisher can grant to any tenant. A grant to another
  tenant gives `read` only.

## References and files

```text
<tenant>/<set>                        namespace default
<tenant>/<namespace>/<set>
<tenant>/<namespace>/<set>@<version>  a number, a tag, sha256:<hex> or current (the default)
```

A card set is a folder with card files at the top level, or one card file:

- A card file name is `[a-z0-9][a-z0-9._-]{0,127}.json`. Dots are allowed, so a name can hold the agent name, for
  example `acme.support-bot.json`.
- At most 100 cards, 64 KiB each, 1 MiB together.
- The set signature is in `.prego/set.jws.json`. It is not a card file.
- Do not put a secret in a card. Security schemes describe the authentication; they do not hold a key. The registry
  refuses a value that looks like a secret (`422 looks_like_secret`) and names the file and the JSON path.

The example cards in [`examples/cards/`](examples/cards/) are valid A2A 1.0 cards.

## 1. Make a signing key (once)

```sh
prego keys new --alg ed25519 acme/release-keys/signer --out ./signer.private.pem
```

The private key stays in `./signer.private.pem` (mode `0600`). Only the public JWK goes to Prego. Keep the private
key file out of git. See [Make a signing key](../keys/quickstart.md#make-a-signing-key).

## 2. Check the cards (offline)

```sh
prego a2a check ./cards                                  # the A2A 1.0 schema of each card
prego a2a check ./cards --key-file ./signer.private.pem  # also the signatures, with a local key file
prego a2a check ./cards --key acme/release-keys/signer   # also the signatures, with the key from Prego
```

The schema check is offline. `--key-file` takes a private key file (its public part), a public JWK or a PEM
`PUBLIC KEY`. `--key` gets the public key from Keys and Certificates, so it needs `read` on the key item.

A card that looks like A2A 0.3 fails with:

```text
A2A 1.0 only. Card agent.json looks like A2A 0.3 (has protocolVersion "0.3.0"). Run `prego a2a upgrade agent.json` to make a 1.0 card, then sign it again.
```

## 3. Sign and push

```sh
prego a2a push ./cards acme/agents/support --sign ./signer.private.pem --key acme/release-keys/signer --tag stable
```

- `--sign <key file>` signs each card with an A2A 1.0 signature (a detached JWS over the RFC 8785 form of the card)
  and signs the set. The signing occurs on your computer. `--key <key ref>` is the key item that holds the public
  key.
- Before it signs, `--sign` adds the Prego source extension to each card, in `capabilities.extensions`: URI
  `https://prego.k8skill.com/ext/a2a-source/v1` with the params `tenant`, `namespace` and `set`. The signature
  covers it, so a card cannot claim to come from another tenant. `--no-source` leaves it out.
- Prego keeps the card's own `signatures` as they are, so a card stays a valid signed A2A card outside Prego.
- Without `--sign`, every card and `.prego/set.jws.json` must be signed already.
- `--tag <tag>`, `--message <text>` and `--if-current <hash>` work as for Snippets. The same cards give no new
  version.

If you forget to sign, the registry refuses the push:

```text
A2A Agent Cards must be signed. Sign with `prego a2a push --sign <key file> --key <key ref>`; make a key with `prego keys new`.
```

## 4. Get and verify

```sh
prego a2a get acme/agents/support@stable ./support-cards --verify
prego a2a get acme/agents/support --card acme.support-bot.json         # print one card
prego a2a get acme/agents/support@stable --expect sha256:...            # exit 3 if the version hash is different
```

- `get` writes the cards and `.prego/set.jws.json` to a new or empty folder (default `./<set>`).
- `--verify` checks the set signature and a signature on every card with the keys from Keys and Certificates. It
  uses your own grants, so it needs `read` on the key item too. A key that was revoked makes `--verify` fail, also
  for signatures made before the revoke.

When a grant is missing, `prego` names it:

```text
read on a2a set acme/agents/support (type A2A Agent Cards) is missing; ask an admin of acme for a grant
```

```text
verify needs read on key acme/release-keys/signer (type Keys and Certificates); ask an admin of acme for a grant
```

In the console, when an admin adds a `read` grant on a card set, the console offers to add `read` on the signing key
item in the same step.

## History

```sh
prego a2a ls acme/agents                       # the card sets that you can read
prego a2a log acme/agents/support              # the versions, newest first, with the signers
prego a2a diff acme/agents/support 3 stable    # the cards added, removed and changed
prego a2a tag acme/agents/support@4 stable     # a tag is written one time
prego a2a rollback acme/agents/support --to 3 --reason "billing bot endpoint is down"
```

## Upgrade an A2A 0.3 card

**`prego a2a upgrade` works offline and needs no Prego account.** It is open source (Apache-2.0) in this
repository. Install `prego` (Linux x86_64 binaries; elsewhere `cargo install prego`) and run it on any A2A
0.3 card, also a legacy `agent.json`:

```sh
prego a2a upgrade ./agent.json                     # writes ./agent-card.json next to the input
prego a2a upgrade ./agent.json -o ./cards/acme.legacy-bot.json
```

- It prints each change that it makes (for example `preferredTransport` and `additionalInterfaces` to
  `supportedInterfaces`, `type` security schemes to the 1.0 wrapper form, `security` to `securityRequirements`).
- Each interface gets `protocolVersion` `"0.3"`: the card format is 1.0, but the agent still serves A2A 0.3 at
  those URLs. Change it to `"1.0"` when the agent serves A2A 1.0.
- It removes the `signatures` of the 0.3 card. They sign the 0.3 card, not the new one.
- If it cannot map a field with certainty, it stops, writes nothing and names the field as a JSON pointer, for
  example `cannot upgrade /securitySchemes/oauth: ...`.
- With no `-o`, it writes `agent-card.json` next to the input. It does not replace a file that exists; give
  `--force` to replace it.
- **The output is unsigned.** Sign it with
  `prego a2a push --sign`, or with your own A2A tools.

[`examples/upgrade/`](examples/upgrade/) has a 0.3 card and its 1.0 output.

## CI

Push the card set from CI with the job's OIDC identity. The private signing key comes from a CI secret file. The CI
secret holds the private key; Prego never sees it.

- [`examples/gitlab-ci.yml`](examples/gitlab-ci.yml): GitLab CI with `id_tokens` and a file variable.
- [`examples/github-actions.yml`](examples/github-actions.yml): GitHub Actions with `id-token: write` and a secret.
- [`examples/sign-and-push.sh`](examples/sign-and-push.sh): the same steps on a laptop.

The CI principal needs `publish` on the card set and `read` on the key item. See the [CI guide](../../docs/ci.md)
for the trust config and the principal.

## Errors

| Error | Cause | What to do |
| --- | --- | --- |
| `400 card_invalid` "A2A 1.0 only. Card <file> looks like A2A 0.3 ..." | The card is A2A 0.3. | Run `prego a2a upgrade <file>`, then sign again. |
| `400 card_invalid` with a file and a JSON path | The card does not pass the A2A 1.0 schema. | Fix the field. `prego a2a check` shows the same error offline. |
| `422 signature_required` | A card or the set has no signature. | Push with `--sign <key file> --key <key ref>`. |
| `422 signature_invalid` | A signature does not verify, the key is revoked or past its end date, or the key is not in the item. | Read the reason. Push the public key with `prego keys push`, or make a new key with `prego keys new`. |
| `422 source_mismatch` | A card says it comes from another tenant, namespace or set. | Push to the set that the card names, or sign again with `--sign` (it writes the new source). |
| `422 looks_like_secret` | A card value looks like a secret. | Remove the secret from the card. |
| `... is missing; ask an admin of acme for a grant (... not found, or you have no grant for it ...)` | No grant, or no set with that name (the registry does not say which). | Check the reference. Ask an admin for the grant. |
| `verify needs read on key ...` | You can read the set but not the key item. | Ask an admin for `read` on the key item. |
