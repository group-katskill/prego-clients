#!/usr/bin/env bash
# Publishes the crate `prego-cli`, an alias of the crate `prego`: the same source, the same version and the
# same binary `prego`. Only the package name, the description and the README are different.
#
# Usage: tools/publish-prego-cli.sh <tag> [--publish] [--keep]
#
#   <tag>       A signed release tag, for example prego-clients-v0.9.0.
#   --publish   Publish to crates.io. Without it, the script does a dry run only.
#   --keep      Keep the temporary directory (the package and the build) for inspection.
#
# The script:
#   1. Verifies the GPG signature of the tag (git verify-tag).
#   2. Extracts the tree of the tag into a temporary directory (git archive). It does not use the working tree.
#   3. Changes the package name of prego/Cargo.toml to `prego-cli`, adds `[[bin]] name = "prego"`, sets the
#      description and the README (tools/prego-cli/README.md), and renames the package in Cargo.lock.
#   4. Lists the package files, runs `cargo publish --dry-run --locked`, and checks that the built binary
#      prints `prego <version>`.
#   5. With --publish only: runs `cargo publish -p prego-cli --locked`.
#
# Publish `prego-auth` at the same version first (`cargo publish --workspace --locked`), because `prego-cli`
# depends on it from crates.io. Cargo reads the token from CARGO_REGISTRY_TOKEN. This script never prints it.

set -euo pipefail

usage() {
    sed -n '4,9p' "$0" | sed 's/^# \{0,1\}//' >&2
    exit 2
}

tag=""
publish=0
keep=0
for arg in "$@"; do
    case "$arg" in
        --publish) publish=1 ;;
        --keep) keep=1 ;;
        -h | --help) usage ;;
        -*) echo "publish-prego-cli: unknown option: $arg" >&2; usage ;;
        *)
            if [ -n "$tag" ]; then
                echo "publish-prego-cli: give one tag only" >&2
                usage
            fi
            tag="$arg"
            ;;
    esac
done
[ -n "$tag" ] || usage

case "$tag" in
    prego-clients-v[0-9]*) ;;
    *) echo "publish-prego-cli: the tag must have the form prego-clients-vX.Y.Z: $tag" >&2; exit 2 ;;
esac
version="${tag#prego-clients-v}"

script_dir="$(cd "$(dirname "$0")" && pwd)"
repo="$(git -C "$script_dir" rev-parse --show-toplevel)"
readme="$script_dir/prego-cli/README.md"
[ -f "$readme" ] || { echo "publish-prego-cli: not found: $readme" >&2; exit 1; }

if [ "$publish" -eq 1 ] && [ -z "${CARGO_REGISTRY_TOKEN:-}" ]; then
    echo "publish-prego-cli: --publish needs CARGO_REGISTRY_TOKEN in the environment" >&2
    exit 1
fi

# 1. The tag must have a good signature.
echo "==> Verify the signature of $tag"
git -C "$repo" verify-tag "$tag"
commit="$(git -C "$repo" rev-parse --short=12 "$tag^{commit}")"

# 2. A clean tree of the tag, outside the repository.
work="$(mktemp -d "${TMPDIR:-/tmp}/prego-cli.XXXXXX")"
if [ "$keep" -eq 1 ]; then
    echo "==> Work directory (kept): $work"
else
    trap 'rm -rf "$work"' EXIT
fi
src="$work/src"
mkdir -p "$src"
git -C "$repo" archive --format=tar "$tag" | tar -x -C "$src"

manifest="$src/prego/Cargo.toml"
lock="$src/Cargo.lock"

tag_version="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$manifest" | head -n 1)"
if [ "$tag_version" != "$version" ]; then
    echo "publish-prego-cli: prego/Cargo.toml at $tag has version $tag_version, not $version" >&2
    exit 1
fi

# 3. Rename the package. Each change must hit exactly one line.
count_lines() { grep -c -x -F -- "$1" "$2" || true; }

[ "$(count_lines 'name = "prego"' "$manifest")" -eq 1 ] \
    || { echo "publish-prego-cli: prego/Cargo.toml must have one line name = \"prego\"" >&2; exit 1; }
[ "$(grep -c '^description = ' "$manifest" || true)" -eq 1 ] \
    || { echo "publish-prego-cli: prego/Cargo.toml must have one description line" >&2; exit 1; }
[ "$(count_lines 'readme = "README.md"' "$manifest")" -eq 1 ] \
    || { echo "publish-prego-cli: prego/Cargo.toml must have readme = \"README.md\"" >&2; exit 1; }
if grep -q '^\[\[bin\]\]' "$manifest"; then
    echo "publish-prego-cli: prego/Cargo.toml already has a [[bin]] table; update this script" >&2
    exit 1
fi

sed -i.bak \
    -e 's/^name = "prego"$/name = "prego-cli"/' \
    -e 's/^description = .*$/description = "Alias of the crate prego, the command-line tool for Prego by Katskill. Installs the same prego binary, from the same source and version."/' \
    "$manifest"
rm -f "$manifest.bak"
printf '\n# prego-cli is an alias of prego: the binary keeps the name prego.\n[[bin]]\nname = "prego"\npath = "src/main.rs"\n' >> "$manifest"
cp "$readme" "$src/prego/README.md"

# In Cargo.lock, the workspace package `prego` has a line name = "prego" and no other package depends on it.
[ "$(count_lines 'name = "prego"' "$lock")" -eq 1 ] \
    || { echo "publish-prego-cli: Cargo.lock must have one package prego" >&2; exit 1; }
if grep -q -E '^ "prego( [0-9][^"]*)?",?$' "$lock"; then
    echo "publish-prego-cli: a package in Cargo.lock depends on prego; update this script" >&2
    exit 1
fi
sed -i.bak 's/^name = "prego"$/name = "prego-cli"/' "$lock"
rm -f "$lock.bak"

export CARGO_TARGET_DIR="$work/target"
# The tree has no .git, so build.rs cannot find the commit. Give it the commit of the tag.
export PREGO_GIT_COMMIT="$commit"

cd "$src"
# --locked: fail if Cargo.lock does not match the renamed package.
cargo metadata --locked --format-version 1 > /dev/null

echo "==> Changes to the tree of $tag"
diff -u <(git -C "$repo" show "$tag:prego/Cargo.toml") "$manifest" || true

# 4. Dry run. --allow-dirty: the tree comes from git archive, so a VCS check has nothing to compare.
echo "==> Files in prego-cli $version"
cargo package --list -p prego-cli --locked --allow-dirty

echo "==> cargo publish --dry-run -p prego-cli --locked"
cargo publish --dry-run -p prego-cli --locked --allow-dirty

# The verify step of the dry run builds the packaged crate into the target directory.
bin="$CARGO_TARGET_DIR/debug/prego"
[ -x "$bin" ] || { echo "publish-prego-cli: the dry run built no prego binary" >&2; exit 1; }
printed="$("$bin" --version)"
echo "==> $bin --version: $printed"
case "$printed" in
    "prego $version "*) ;;
    *) echo "publish-prego-cli: expected prego $version, got: $printed" >&2; exit 1 ;;
esac

if [ "$publish" -eq 0 ]; then
    echo "==> Dry run OK. To publish: $0 $tag --publish"
    exit 0
fi

# 5. Publish. Cargo reads CARGO_REGISTRY_TOKEN from the environment.
echo "==> cargo publish -p prego-cli --locked"
cargo publish -p prego-cli --locked --allow-dirty
echo "==> Published prego-cli $version"
