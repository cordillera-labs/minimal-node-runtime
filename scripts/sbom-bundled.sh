#!/bin/bash
# Merges the components bundled into node into a Trivy CycloneDX SBOM, then
# checks the result against the image's own node.
#
#   sbom-bundled.sh <image> <trivy.cdx.json> <lock> <digest> <out.cdx.json>
#
# <image> is a local image reference, such as minimal-node-runtime:build.
set -euo pipefail
image=$1
trivy_sbom=$2
lock=$3
digest=$4
out=$5
root="$(cd "$(dirname "$0")/.." && pwd)"
repository=$(sed -n 's/^IMAGE_REPOSITORY=//p' "$root/toolchain.env")
versions=$(mktemp)
trap 'rm -f "$versions"' EXIT

docker run --rm --network none "$image" -p 'JSON.stringify(process.versions)' > "$versions"
python3 -I "$root/scripts/sbom-merge.py" --sbom "$trivy_sbom" --versions "$versions" --image "$repository" \
    --digest "$digest" --epoch "$(python3 "$root/scripts/lock.py" get "$lock" SOURCE_DATE_EPOCH)" --out "$out"

# The check: openssl, zlib and icu are nested in the node component with the
# versions that node reports, and the document is one actions/attest reads.
jq -e '.bomFormat == "CycloneDX" and (.specVersion | length > 0) and (.serialNumber | startswith("urn:uuid:"))' \
    "$out" > /dev/null || { echo "sbom-bundled: $out is not a CycloneDX document actions/attest accepts"; exit 1; }
for name in openssl zlib icu; do
    want=$(jq -r --arg n "$name" '.[$n]' "$versions")
    got=$(jq -r --arg n "$name" '.components[] | select(.name == "node") | .components[] | select(.name == $n) | .version' "$out")
    if [ "$want" = null ] || [ "$got" != "$want" ]; then
        echo "sbom-bundled: $name is '$got' in the SBOM, '$want' in process.versions"
        exit 1
    fi
    echo "ok   $name $got"
done
echo "sbom-bundled: $(jq '[.components[] | select(.name == "node") | .components[]] | length' "$out") bundled components"
