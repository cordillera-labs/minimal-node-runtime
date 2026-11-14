#!/usr/bin/env bash
#
# trivy-image-scan.sh — install a pinned, hash-checked Trivy and scan a local
# Docker image for High and Critical vulnerabilities.
#
# WHY NOT aquasecurity/trivy-action. Its installer downloads the binary through
# get.trivy.dev, a domain that serves whatever Aqua points it at (it served the
# malicious v0.69.4 in the March 2026 compromise, GHSA-69fq-xp46-6x23) and that
# stopped resolving on 2026-11-03. This script downloads from the immutable
# GitHub release and checks the tarball against a sha256 recorded here, so a
# changed binary fails closed instead of running on the shared runners.
#
# UPGRADING. Pick a release at least 7 days old (malicious releases have been
# caught within hours, so waiting is the defence against a poisoned release
# pipeline), then verify the tarball's sigstore bundle, and update both lines:
#
#   cosign verify-blob --bundle trivy_X_Linux-64bit.tar.gz.sigstore.json \
#       --certificate-identity-regexp '^https://github.com/aquasecurity/trivy/' \
#       --certificate-oidc-issuer https://token.actions.githubusercontent.com \
#       trivy_X_Linux-64bit.tar.gz
#
# The vulnerability DB is fetched fresh into a per-run cache, so a DB written
# by another repository's job on the shared runner is never read.
#
# USAGE
#   bash trivy-image-scan.sh IMAGE_REFERENCE
#
# EXIT
#   0   no High or Critical vulnerability
#   1   at least one finding (Trivy prints the table)
#   64  usage error
#   69  download, checksum or scanner fault
set -euo pipefail

TRIVY_VERSION=0.74.0
TRIVY_SHA256_LINUX_64BIT=2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a

if [[ $# -ne 1 || ! "$1" =~ ^[a-zA-Z0-9._:/@-]+$ ]]; then
    echo "usage: trivy-image-scan.sh IMAGE_REFERENCE" >&2
    exit 64
fi
image="$1"

if [[ "$(uname -s)/$(uname -m)" != "Linux/x86_64" ]]; then
    echo "::error::trivy-image-scan.sh pins only the Linux x86_64 binary; got $(uname -s)/$(uname -m)" >&2
    exit 69
fi

work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/trivy.XXXXXX")"
trap 'rm -rf "$work"' EXIT

tarball="trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
url="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${tarball}"
if ! curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
        --max-time 300 --output "$work/$tarball" "$url"; then
    echo "::error::Failed to download $url" >&2
    exit 69
fi
if ! echo "${TRIVY_SHA256_LINUX_64BIT}  $work/$tarball" | sha256sum --check --status; then
    echo "::error::$tarball does not match the pinned sha256; refusing to run it" >&2
    exit 69
fi
tar -xzf "$work/$tarball" -C "$work" trivy
echo "trivy-image-scan: verified Trivy ${TRIVY_VERSION} (sha256 ${TRIVY_SHA256_LINUX_64BIT})"

# --image-src docker: scan the local image only, never a same-named remote one.
set +e
"$work/trivy" image \
    --cache-dir "$work/cache" \
    --image-src docker \
    --scanners vuln \
    --pkg-types os,library \
    --severity CRITICAL,HIGH \
    --exit-code 1 \
    --timeout 10m \
    --format table \
    "$image"
status=$?
set -e
case "$status" in
    0 | 1) exit "$status" ;;
    *) echo "::error::Trivy failed with exit $status (a scanner fault, not a finding)" >&2; exit 69 ;;
esac
