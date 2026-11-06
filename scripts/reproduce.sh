#!/bin/bash
# Builds a lock twice, in two fresh BuildKit builders that share no cache, and
# fails unless both builds give the same image digest. When the lock records
# PUBLISHED_DIGEST, the digest must also equal it.
#
#   reproduce.sh <lock> <out-dir>
#
# Writes <out-dir>/a and <out-dir>/b (see build.sh) and <out-dir>/digest.
# With KEEP_BUILDER=1, builder A stays up for a push that reuses its cache, and
# its name is written to <out-dir>/builder. Otherwise both builders are removed.
set -euo pipefail
lock=$1
out=$2
root="$(cd "$(dirname "$0")/.." && pwd)"
buildkit_image=$(sed -n 's/^BUILDKIT_IMAGE=//p' "$root/toolchain.env")
suffix="${GITHUB_RUN_ID:-local}-$$"
builder_a="mnr-a-$suffix"
builder_b="mnr-b-$suffix"
mkdir -p "$out"

cleanup() {
    docker buildx rm --force "$builder_b" >/dev/null 2>&1 || true
    if [ "${KEEP_BUILDER:-0}" != 1 ]; then
        docker buildx rm --force "$builder_a" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

for builder in "$builder_a" "$builder_b"; do
    docker buildx create --name "$builder" --driver docker-container \
        --driver-opt "image=$buildkit_image" --bootstrap >/dev/null
done

BUILDER=$builder_a "$root/scripts/build.sh" "$lock" "$out/a"
BUILDER=$builder_b "$root/scripts/build.sh" "$lock" "$out/b"
digest_a=$(cat "$out/a/digest")
digest_b=$(cat "$out/b/digest")
echo "builder A: $digest_a"
echo "builder B: $digest_b"

if [ "$digest_a" != "$digest_b" ]; then
    echo "reproduce: FAIL the two builds differ" >&2
    for side in a b; do
        mkdir -p "$out/$side/layout"
        tar -xf "$out/$side/image.tar" -C "$out/$side/layout"
    done
    diff -r "$out/a/layout" "$out/b/layout" >&2 || true
    exit 1
fi
if ! cmp -s "$out/a/rootfs.manifest" "$out/b/rootfs.manifest"; then
    echo "reproduce: FAIL the two rootfs manifests differ" >&2
    exit 1
fi
echo "$digest_a" > "$out/digest"

published=$(python3 "$root/scripts/lock.py" get "$lock" PUBLISHED_DIGEST)
if [ -n "$published" ]; then
    if [ "$digest_a" != "$published" ]; then
        echo "reproduce: FAIL the build gives $digest_a, the lock records the published $published" >&2
        exit 1
    fi
    echo "reproduce: matches the published digest $published"
fi
if [ "${KEEP_BUILDER:-0}" = 1 ]; then
    echo "$builder_a" > "$out/builder"
fi
echo "reproduce: pass"
