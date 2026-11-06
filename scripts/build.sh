#!/bin/bash
# Builds the image from a lock file into an OCI archive, without pushing.
#
#   build.sh <lock> <out-dir>
#
# Writes <out-dir>/image.tar (an OCI archive), <out-dir>/oci (the same OCI
# layout unpacked, which Trivy reads), <out-dir>/digest (the manifest digest),
# <out-dir>/rootfs.manifest and <out-dir>/ldd.txt.
# BUILDER selects the buildx builder; it must be a docker-container builder
# for rewrite-timestamp.
set -euo pipefail
lock=$1
out=$2
root="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$out"

build_args=()
while IFS= read -r arg; do
    build_args+=(--build-arg "$arg")
done < <(python3 "$root/scripts/lock.py" build-args "$lock")
python3 "$root/scripts/lock.py" check "$lock"

builder=()
[ -n "${BUILDER:-}" ] && builder=(--builder "$BUILDER")
common=(buildx build "${builder[@]}" --platform linux/amd64 --provenance=false --sbom=false "${build_args[@]}")

docker "${common[@]}" --target manifest --output "type=local,dest=$out/manifest" "$root"
mv "$out/manifest/rootfs.manifest" "$out/manifest/ldd.txt" "$out/"
rmdir "$out/manifest"
docker "${common[@]}" --target runtime \
    --output "type=oci,dest=$out/image.tar,name=minimal-node-runtime:build,rewrite-timestamp=true" "$root"
mkdir -p "$out/oci"
tar -xf "$out/image.tar" -C "$out/oci"
jq -r '.manifests[0].digest' "$out/oci/index.json" > "$out/digest"
echo "build: $(cat "$out/digest")"
