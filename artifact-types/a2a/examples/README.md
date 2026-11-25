# A2A Agent Cards examples

Runnable examples for [A2A Agent Cards](../quickstart.md). No key is in this folder. The scripts make the keys at
run time, and [`.gitignore`](.gitignore) keeps key files out of git.

| File | What it shows |
| --- | --- |
| [`cards/`](cards/) | A card set of two valid A2A 1.0 cards: `acme.support-bot.json` and `acme.billing-bot.json`. Unsigned. |
| [`sign-and-push.sh`](sign-and-push.sh) | Make a signing key (first run only), check the cards, sign and push them, then get and verify them. |
| [`gitlab-ci.yml`](gitlab-ci.yml) | Push the card set from GitLab CI with `id_tokens`. The private key comes from a CI/CD file variable. |
| [`github-actions.yml`](github-actions.yml) | The same from GitHub Actions with `id-token: write`. The private key comes from a repository secret. |
| [`upgrade/`](upgrade/) | An A2A 0.3 card and the A2A 1.0 card that `prego a2a upgrade` makes from it. No account needed. |

Run the script:

```sh
export PREGO_TENANT=acme A2A_NAMESPACE=agents
prego login --publish --namespace agents
sh artifact-types/a2a/examples/sign-and-push.sh
```

In CI, the CI secret holds the private signing key. Prego never sees it: `prego` signs the cards in the job and sends
only the signatures. The job uses its own OIDC identity for Prego, so no Prego secret is stored.

Check the cards with no account:

```sh
prego a2a check artifact-types/a2a/examples/cards
```
