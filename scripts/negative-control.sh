#!/bin/bash
# Proves that the gates can fail.
#
#   negative-control.sh build <image.tar> <lock> <out-dir>
#       Builds three variants of the image as <out-dir>/<variant>.tar, each
#       also unpacked as the OCI layout <out-dir>/<variant>.oci for Trivy.
#   negative-control.sh check <out-dir> <lock>
#       Reads <out-dir>/<variant>.json (Trivy JSON with --list-all-pkgs, one
#       per variant) and fails unless every variant is rejected.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
VARIANTS="no-debian-version old-libc6 zlib-entry"

build() {
    local image_tar=$1 lock=$2 out=$3
    mkdir -p "$out/layout"
    tar -xf "$image_tar" -C "$out/layout"
    local digest
    digest=$(jq -r '.manifests[0].digest' "$out/layout/index.json")
    local helper
    helper=$(python3 "$root/scripts/lock.py" get "$lock" HELPER_IMAGE)
    local buildkit_image
    buildkit_image=$(sed -n 's/^BUILDKIT_IMAGE=//p' "$root/toolchain.env")
    local builder="mnr-neg-${GITHUB_RUN_ID:-local}-$$"
    docker buildx create --name "$builder" --driver docker-container \
        --driver-opt "image=$buildkit_image" --bootstrap >/dev/null
    trap 'docker buildx rm --force '"$builder"' >/dev/null 2>&1 || true' RETURN
    for variant in $VARIANTS; do
        docker buildx build --builder "$builder" --platform linux/amd64 --provenance=false --sbom=false \
            --build-context "image=oci-layout://$out/layout@$digest" \
            --build-arg "HELPER_IMAGE=$helper" \
            -f "$root/tests/negative-control.Dockerfile" --target "$variant" \
            --output "type=oci,dest=$out/$variant.tar" "$root/tests"
        mkdir -p "$out/$variant.oci"
        tar -xf "$out/$variant.tar" -C "$out/$variant.oci"
    done
    rm -rf "$out/layout"
}

check() {
    local out=$1 lock=$2 failures=0
    for variant in no-debian-version zlib-entry; do
        if "$root/scripts/gate.sh" "$out/$variant.json" "$lock" > "$out/$variant.gate.txt"; then
            echo "FAIL the gate passed the $variant variant"
            failures=$((failures + 1))
        else
            echo "ok   the gate rejects the $variant variant: $(grep '^FAIL' "$out/$variant.gate.txt" | head -1)"
        fi
    done
    if [ "$(jq -r '.Metadata.OS.Family // "none"' "$out/no-debian-version.json")" = debian ]; then
        echo "FAIL Trivy still detected Debian without /etc/debian_version; the control no longer tests the false pass"
        failures=$((failures + 1))
    fi
    local libc_findings
    libc_findings=$(jq '[.Results[]? | .Vulnerabilities[]? | select(.PkgName == "libc6"
        and (.Severity == "HIGH" or .Severity == "CRITICAL") and (.FixedVersion // "") != "")] | length' \
        "$out/old-libc6.json")
    if [ "$libc_findings" -gt 0 ] && ! "$root/scripts/vuln-policy.sh" "$out/old-libc6.json" "$out/old-libc6.unfixed.json" >/dev/null; then
        echo "ok   Trivy reports $libc_findings fixable HIGH/CRITICAL findings for the old libc6, and the policy blocks it"
    else
        echo "FAIL the old libc6 variant was not blocked ($libc_findings fixable HIGH/CRITICAL libc6 findings)"
        failures=$((failures + 1))
    fi
    [ "$failures" -eq 0 ] || { echo "negative-control: $failures control(s) failed"; exit 1; }
    echo "negative-control: pass"
}

case "${1:-}" in
    build) build "$2" "$3" "$4" ;;
    check) check "$2" "$3" ;;
    *) echo "usage: negative-control.sh build <image.tar> <lock> <out-dir> | check <out-dir> <lock>" >&2; exit 2 ;;
esac
