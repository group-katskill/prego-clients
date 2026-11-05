#!/bin/sh
# Print a Prego admin token on stdout. Use it in CI only, on a protected ref:
#
#   PREGO_ADMIN_TOKEN="$(sh prego-admin-token.sh)"
#   export PREGO_ADMIN_TOKEN
#
# Input (environment):
#   PREGO_TENANT         tenant slug, for example acme (required)
#   PREGO_ADMIN_SCOPE    space-separated admin scopes, for example "admin:read grants:write" (required)
#   PREGO_ID_TOKEN       the CI OIDC token (GitLab id_tokens). Or set PREGO_SUBJECT_TOKEN.
#   PREGO_STS_URL        default https://sts.prego.k8skill.com/v1/sts/token
#
# The subject token goes to curl on stdin, so it does not show in the process list.
# The script never prints the subject token. On error it prints the STS error code only.
# Needs: curl, jq.

set -eu

: "${PREGO_TENANT:?set PREGO_TENANT}"
: "${PREGO_ADMIN_SCOPE:?set PREGO_ADMIN_SCOPE}"
subject="${PREGO_SUBJECT_TOKEN:-${PREGO_ID_TOKEN:-}}"
if [ -z "$subject" ]; then
  echo "prego-admin-token: set PREGO_ID_TOKEN or PREGO_SUBJECT_TOKEN" >&2
  exit 1
fi
sts_url="${PREGO_STS_URL:-https://sts.prego.k8skill.com/v1/sts/token}"
case "$sts_url" in
  https://*) ;;
  *) echo "prego-admin-token: PREGO_STS_URL must use https" >&2; exit 1 ;;
esac

body="$(mktemp)"
trap 'rm -f "$body"' EXIT

status="$(printf '%s' "$subject" | curl -sS --max-time 10 --proto '=https' \
  -o "$body" -w '%{http_code}' \
  --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
  --data-urlencode 'subject_token@-' \
  --data-urlencode 'subject_token_type=urn:ietf:params:oauth:token-type:jwt' \
  --data-urlencode "tenant=${PREGO_TENANT}" \
  --data-urlencode 'audience=prego-admin' \
  --data-urlencode "scope=${PREGO_ADMIN_SCOPE}" \
  "$sts_url")"

if [ "$status" != "200" ]; then
  code="$(jq -r '.error // "unknown"' "$body" 2>/dev/null || echo unknown)"
  echo "prego-admin-token: the STS returned HTTP ${status} (${code})" >&2
  exit 1
fi

issued="$(jq -r '.scope // ""' "$body")"
echo "prego-admin-token: issued scope: ${issued}" >&2
jq -r '.access_token' "$body"
