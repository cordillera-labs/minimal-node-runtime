#!/usr/bin/env bash
# Inspect an unstarted image without assuming it has a shell, find, or tar.
# Keep the existing fail-closed policy for .env, .env.*, and .npmrc files.
set -euo pipefail

if [[ $# -ne 1 || ! "$1" =~ ^[a-zA-Z0-9._:/@-]+$ ]]; then
    echo "usage: container-image-filesystem-check.sh IMAGE_REFERENCE" >&2
    exit 64
fi

image="$1"
tmp="$(mktemp -d)"
cid=""
cleanup() {
    if [[ -n "$cid" ]]; then docker rm -f "$cid" >/dev/null 2>&1 || true; fi
    rm -rf "$tmp"
}
trap cleanup EXIT

# docker create never executes the image's entrypoint. Inherit the image
# configuration, not an executable path from a particular release.
cid="$(docker create "$image")"
docker export "$cid" | tar -tf - > "$tmp/files"
docker rm "$cid" > /dev/null
cid=""

if grep -E '(^|/)\.env(\.[^/]*)?$|(^|/)\.npmrc$' "$tmp/files" > "$tmp/forbidden"; then
    echo "::error title=Environment file in app image::Forbidden files in $image:" >&2
    cat "$tmp/forbidden" >&2
    exit 1
fi

echo "container-image-filesystem-check: $image contains no .env, .env.* or .npmrc files"
