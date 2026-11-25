#!/bin/sh
# push-and-fingerprint.sh: make a signing key, push an SSH public key and a PEM certificate bundle to Keys and
# Certificates, and print the fingerprints.
#
#   export PREGO_TENANT=acme          # your tenant slug
#   export KEYS_NAMESPACE=release-keys
#   prego login --publish --namespace "$KEYS_NAMESPACE"
#   sh push-and-fingerprint.sh ~/.ssh/deploy_ed25519.pub ./ca-bundle.pem
#
# Give public material only. prego checks each file first and stops, sends nothing, if a file holds a private
# key. The signing key that `prego keys new` makes stays in ./signer.private.pem (mode 0600); only its public JWK
# is sent. Do not commit the private key file.
set -eu

usage="usage: sh push-and-fingerprint.sh <SSH public key file> <PEM certificate bundle file>"
if [ "$#" -ne 2 ]; then
  echo "$usage" >&2
  exit 1
fi
if [ -z "${PREGO_TENANT:-}" ]; then
  echo "push-and-fingerprint.sh: PREGO_TENANT is not set. Set it to your tenant slug: export PREGO_TENANT=acme" >&2
  exit 1
fi
if [ -z "${KEYS_NAMESPACE:-}" ]; then
  echo "push-and-fingerprint.sh: KEYS_NAMESPACE is not set. Set it to the namespace for the key items: export KEYS_NAMESPACE=release-keys" >&2
  exit 1
fi

ssh_file="$1"
cert_file="$2"
for f in "$ssh_file" "$cert_file"; do
  if [ ! -f "$f" ]; then
    echo "push-and-fingerprint.sh: $f is not a file. $usage" >&2
    exit 1
  fi
done

base="$PREGO_TENANT/$KEYS_NAMESPACE"
key_file="${KEYS_SIGNER_FILE:-./signer.private.pem}"

# 1. Fingerprints of the local files, offline. This also stops on private key material.
echo "Local fingerprints:"
prego keys fingerprint "$ssh_file" --type ssh
prego keys fingerprint "$cert_file" --type x509

# 2. A signing key, one time only. prego never replaces a key file that exists.
if [ -e "$key_file" ]; then
  echo "Using the signing key in $key_file (not made again)"
else
  prego keys new --alg ed25519 "$base/signer" --out "$key_file"
fi

# 3. Push the SSH public key and the certificate bundle. Each push makes a new version of the item.
prego keys push "$ssh_file" "$base/deploy" --type ssh --message "push-and-fingerprint.sh"
prego keys push "$cert_file" "$base/ca-bundle" --type x509 --message "push-and-fingerprint.sh"

# 4. The entries as Prego recorded them: type, algorithm, fingerprint, validity and revoke state.
for item in signer deploy ca-bundle; do
  echo
  prego keys get "$base/$item"
done
