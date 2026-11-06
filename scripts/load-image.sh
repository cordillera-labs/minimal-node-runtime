#!/usr/bin/env bash
# Load an OCI-layout archive into a Docker engine that uses the classic image
# store, which cannot load OCI layouts directly. The OCI blobs are repackaged
# as a docker-archive whose manifest names the same config and layer blobs. The
# script then checks that the loaded image's layer diff IDs equal the OCI
# config's rootfs.diff_ids, which proves the loaded filesystem is the gated one.
# (The image ID cannot be compared: the classic store reports the config digest
# and the containerd store reports a manifest digest.) Usage: load-image.sh <oci-archive.tar> <tag>
set -euo pipefail
archive=$1
tag=$2
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tar -xf "$archive" -C "$work"
manifest_digest=$(jq -r '.manifests[0].digest' "$work/index.json")
manifest="$work/blobs/${manifest_digest/://}"
config_digest=$(jq -r '.config.digest' "$manifest")
jq -n --arg tag "$tag" --slurpfile m "$manifest" '[{
    Config: ("blobs/" + ($m[0].config.digest | sub(":"; "/"))),
    RepoTags: [$tag],
    Layers: [$m[0].layers[].digest | "blobs/" + sub(":"; "/")]
}]' > "$work/manifest.json"
tar -C "$work" -cf "$work/docker-archive.tar" manifest.json blobs
docker load -q -i "$work/docker-archive.tar" >/dev/null
expected=$(jq -c '.rootfs.diff_ids' "$work/blobs/${config_digest/://}")
loaded=$(docker image inspect --format '{{json .RootFS.Layers}}' "$tag" | jq -c '.')
if [ "$loaded" != "$expected" ]; then
    echo "load-image: loaded layers $loaded differ from the OCI diff_ids $expected" >&2
    exit 1
fi
echo "load-image: $tag = $config_digest (manifest $manifest_digest)"
