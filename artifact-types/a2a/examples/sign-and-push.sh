#!/bin/sh
# sign-and-push.sh: sign the example A2A card set and push it to Prego, then get it back and verify it.
#
# Run it on a laptop after `prego login --publish --namespace <namespace>`, or in CI with the job's identity.
#
#   export PREGO_TENANT=acme          # your tenant slug
#   export A2A_NAMESPACE=agents       # the namespace for the card set and the signing key
#   sh sign-and-push.sh
#
# Optional:
#   A2A_SET       the card set name (default: support)
#   A2A_CARDS     the folder with the cards (default: cards/ next to this script)
#   A2A_KEY_FILE  the private key file (default: ./release-keys.private.pem)
#
# The first run makes a key pair with `prego keys new`. The private key stays in A2A_KEY_FILE (mode 0600) and is
# never sent. Only the public key goes to the Keys and Certificates item <tenant>/<namespace>/release-keys.
# Do not commit the private key file.
set -eu

if [ -z "${PREGO_TENANT:-}" ]; then
  echo "sign-and-push.sh: PREGO_TENANT is not set. Set it to your tenant slug: export PREGO_TENANT=acme" >&2
  exit 1
fi
if [ -z "${A2A_NAMESPACE:-}" ]; then
  echo "sign-and-push.sh: A2A_NAMESPACE is not set. Set it to the namespace of the card set: export A2A_NAMESPACE=agents" >&2
  exit 1
fi

here="$(cd "$(dirname "$0")" && pwd)"
cards="${A2A_CARDS:-$here/cards}"
set_ref="$PREGO_TENANT/$A2A_NAMESPACE/${A2A_SET:-support}"
key_ref="$PREGO_TENANT/$A2A_NAMESPACE/release-keys"
key_file="${A2A_KEY_FILE:-./release-keys.private.pem}"

if [ ! -d "$cards" ]; then
  echo "sign-and-push.sh: $cards is not a folder. Set A2A_CARDS to the folder with the cards." >&2
  exit 1
fi

# 1. Make the signing key one time only. prego never replaces a key file that exists.
if [ -e "$key_file" ]; then
  echo "Using the signing key in $key_file"
else
  prego keys new --alg ed25519 "$key_ref" --out "$key_file"
fi

# 2. Check the cards offline: the A2A 1.0 schema of each card.
prego a2a check "$cards"

# 3. Sign each card and the set on this computer, and push. Prego gets the signatures, never the private key.
prego a2a push "$cards" "$set_ref" --sign "$key_file" --key "$key_ref" --message "sign-and-push.sh"

# 4. Get the current version into a new folder and check every signature with the key from Prego.
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
prego a2a get "$set_ref" "$out/cards" --verify
echo "Pushed and verified: $set_ref"
