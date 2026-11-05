#!/bin/sh
# Installs the Prego client tools: cargo-credential-prego, docker-credential-prego and prego.
#
#   curl -fsSLO https://github.com/group-katskill/prego-clients/releases/latest/download/install.sh
#   sh install.sh [--version X.Y.Z] [--dir DIR]
#
# It downloads the release archive for this machine from GitHub, checks its SHA-256 sum, and copies the
# three binaries to DIR (default: $PREGO_INSTALL_DIR, else ~/.local/bin). It needs curl, tar, and
# sha256sum or shasum. It never uses sudo. Targets: Linux x86_64 and aarch64, macOS arm64.
#
# The SHA-256 check shows that the download is complete, not who made it. To check the origin too (0.3.0 and
# later), check install.sh itself before you run it. Download SHA256SUMS and SHA256SUMS.sigstore.json from
# the same release, then:
#   cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
#     --certificate-identity "https://github.com/group-katskill/prego-clients/.github/workflows/release.yml@refs/tags/prego-clients-vX.Y.Z" \
#     --certificate-oidc-issuer https://token.actions.githubusercontent.com
#   sha256sum --ignore-missing -c SHA256SUMS
# SHA256SUMS lists install.sh and all archives. See "Verify a release" in the README.
set -eu

REPO="https://github.com/group-katskill/prego-clients"
BINARIES="cargo-credential-prego docker-credential-prego prego"

version="${PREGO_VERSION:-}"
dir="${PREGO_INSTALL_DIR:-${HOME:-}/.local/bin}"

fail() {
  echo "install.sh: $*" >&2
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --version) [ $# -ge 2 ] || fail "--version needs a value"; version="$2"; shift 2 ;;
    --version=*) version="${1#--version=}"; shift ;;
    --dir) [ $# -ge 2 ] || fail "--dir needs a value"; dir="$2"; shift 2 ;;
    --dir=*) dir="${1#--dir=}"; shift ;;
    -h | --help) sed -n '2,9p' "$0"; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
done

if [ -z "$dir" ] || [ "$dir" = "/.local/bin" ]; then
  fail "HOME is not set. Use --dir DIR."
fi
case "$version" in
  "" | [0-9]*.[0-9]*.[0-9]*) ;;
  *) fail "bad version: $version (use X.Y.Z)" ;;
esac

os="$(uname -s)"
arch="$(uname -m)"
case "$os/$arch" in
  Linux/x86_64 | Linux/amd64) target="x86_64-unknown-linux-musl" ;;
  Linux/aarch64 | Linux/arm64) target="aarch64-unknown-linux-musl" ;;
  Darwin/arm64 | Darwin/aarch64) target="aarch64-apple-darwin" ;;
  *) fail "no prebuilt binaries for $os $arch. Use: cargo install $BINARIES" ;;
esac

if [ -n "$version" ]; then
  base="$REPO/releases/download/prego-clients-v$version"
else
  base="$REPO/releases/latest/download"
fi
archive="prego-clients-$target.tar.gz"

command -v curl >/dev/null 2>&1 || fail "curl is not installed"
if command -v sha256sum >/dev/null 2>&1; then
  check="sha256sum -c"
elif command -v shasum >/dev/null 2>&1; then
  check="shasum -a 256 -c"
else
  fail "sha256sum or shasum is necessary to check the download"
fi

tmp="$(mktemp -d "${TMPDIR:-/tmp}/prego-install.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT INT TERM

echo "Downloading $archive (${version:-latest})"
curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/$archive" "$base/$archive" ||
  fail "cannot download $base/$archive"
curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/$archive.sha256" "$base/$archive.sha256" ||
  fail "cannot download $base/$archive.sha256"

(cd "$tmp" && $check "$archive.sha256" >/dev/null) || fail "SHA-256 check failed for $archive. Nothing installed."
echo "SHA-256 sum is correct"

mkdir -p "$tmp/x"
# shellcheck disable=SC2086 # BINARIES is a word list
tar -xzf "$tmp/$archive" -C "$tmp/x" $BINARIES

mkdir -p "$dir"
for bin in $BINARIES; do
  [ -f "$tmp/x/$bin" ] || fail "$bin is not in $archive"
  cp "$tmp/x/$bin" "$dir/$bin.tmp.$$"
  chmod 0755 "$dir/$bin.tmp.$$"
  mv -f "$dir/$bin.tmp.$$" "$dir/$bin"
  echo "Installed $dir/$bin"
done

case ":${PATH:-}:" in
  *":$dir:"*) ;;
  *) echo "Add $dir to PATH, for example: export PATH=\"$dir:\$PATH\"" ;;
esac
"$dir/prego" --version
echo "To check who made this release (0.3.0 and later), see \"Verify a release\" in the README."
