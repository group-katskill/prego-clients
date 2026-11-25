# A2A Agent Cards

A2A (Agent2Agent) Agent Cards describe an agent: its name, endpoints, skills and security schemes. Prego keeps one
card or a set of cards as one signed version that does not change. Every card and every set is signed with a key
from [Keys and Certificates](../keys/). A2A 1.0 only; `prego a2a upgrade` converts an A2A 0.3 card, offline and with
no Prego account.

**Plans:** Trial, Indie, Org and Publisher can publish. Consumer reads through grants. Indie cannot make grants to
other tenants, so on Indie the cards stay in your tenant.

## Start

- [A2A Agent Cards quickstart](quickstart.md): signing keys, check, sign and push, get and `--verify`, the
  missing-grant messages, upgrade from 0.3, CI, and the errors.
- [A2A Agent Cards](../../README.md#a2a-agent-cards) in the root README.

## Examples

See [`examples/`](examples/):

- [`examples/cards/`](examples/cards/): two valid A2A 1.0 cards.
- [`examples/sign-and-push.sh`](examples/sign-and-push.sh): make a key, check, sign, push, get and verify.
- [`examples/gitlab-ci.yml`](examples/gitlab-ci.yml) and [`examples/github-actions.yml`](examples/github-actions.yml):
  push from CI with the job's OIDC identity and a private key from a CI secret.
- [`examples/upgrade/`](examples/upgrade/): an A2A 0.3 card and its 1.0 output.
