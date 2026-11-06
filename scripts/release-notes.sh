#!/bin/bash
# Writes the release notes for one published digest.
#
#   release-notes.sh <lock> <previous-lock> <decision.json> <scan.json> <digest> <tag> <channel> <sources.json>
set -euo pipefail
lock=$1
previous=$2
decision=$3
scan=$4
digest=$5
tag=$6
channel=$7
sources=$8
image=$(sed -n 's/^IMAGE_REPOSITORY=//p' "$(dirname "$0")/../toolchain.env")
repo=${GITHUB_REPOSITORY:-cordillera-labs/minimal-node-runtime}

line=$(python3 "$(dirname "$0")/lock.py" line "$lock")
case "$channel" in
    stable) tags="\`$line\`, \`$line-trixie\`, \`$tag\`" ;;
    candidate) tags="\`$line-candidate\`, \`$tag\`" ;;
esac

cat <<NOTES
Channel: **$channel** (tags $tags)

Digest: \`$image@$digest\`

$(jq -r '.message' "$decision")

## Inputs

Evaluated at $(sed -n 's/^EVALUATED_AT=//p' "$lock"). Each line shows the input, its release date, and why it was accepted.

| Input | Value | Released | Accepted |
|---|---|---|---|
$(python3 - "$lock" "$(dirname "$0")" <<'PY'
import sys
sys.path.insert(0, sys.argv[2])
import lock as lockfile
lock = dict(line.split("=", 1) for line in open(sys.argv[1]).read().splitlines() if "=" in line and not line.startswith("#"))
rows = [("Node.js", lock["NODE_VERSION"], lock.get("NODE_RELEASED", ""), lock.get("NODE_ACCEPTED", "")),
        ("helper image", lock["HELPER_IMAGE"].split("@")[1][:19], lock.get("HELPER_IMAGE_RELEASED", ""),
         lock.get("HELPER_IMAGE_ACCEPTED", ""))]
for package in lockfile.read_packages():
    prefix = f"DEB_{lockfile.package_key(package)}_"
    rows.append((package, lock[prefix + "VERSION"], lock.get(prefix + "RELEASED", ""), lock.get(prefix + "ACCEPTED", "")))
for row in rows:
    print("| " + " | ".join(row) + " |")
PY
)

## Changes from the previous $channel release

\`\`\`diff
$(diff <(grep -E '^(NODE|HELPER|DEB|BUILD_DEFINITION)_?[A-Z0-9_]*(VERSION|SHA256|IMAGE)=' "$previous" 2>/dev/null || true) \
       <(grep -E '^(NODE|HELPER|DEB|BUILD_DEFINITION)_?[A-Z0-9_]*(VERSION|SHA256|IMAGE)=' "$lock") || true)
\`\`\`

## Scan

Trivy, HIGH and CRITICAL: $(jq '[.Results[]? | .Vulnerabilities[]? | select(.Severity == "HIGH" or .Severity == "CRITICAL")] | length' "$scan") findings, of which $(jq '[.Results[]? | .Vulnerabilities[]? | select((.Severity == "HIGH" or .Severity == "CRITICAL") and (.FixedVersion // "") == "")] | length' "$scan") have no fix. All severities: $(jq '[.Results[]? | .Vulnerabilities[]?] | length' "$scan").

## Source code

| Source package | Version | Binary packages | Carried by |
|---|---|---|---|
$(jq -r --arg tag "$tag" 'to_entries | sort_by(.key)[] | .value
    | "| \(.source) | \(.version) | \(.binaries | join(", ")) | \(if .release == $tag then "this release" else "[\(.release)](\(.release_url))" end) |"' "$sources")

The Debian source packages above are release assets (\`*.dsc\`, \`*.orig.tar.*\`, \`*.debian.tar.*\`, or a native \`*.tar.xz\`). GitHub rewrites \`+\` in asset names; \`debian-sources.txt\` in the carrying release maps each asset to its Debian file name and SHA-256. The Node.js source is at https://nodejs.org/dist/v$(sed -n 's/^NODE_VERSION=//p' "$lock")/node-v$(sed -n 's/^NODE_VERSION=//p' "$lock").tar.gz.

The assets hold the lock (\`inputs.lock\`), the six \`.deb\` files the image was built from, the CycloneDX SBOM (with the components bundled into node), the full Trivy report, the rootfs manifest and the upstream state the decision used.

## Verify

\`\`\`sh
cosign verify $image@$digest \\
  --certificate-identity-regexp '^https://github\\.com/$repo/\\.github/workflows/publish\\.yml@refs/heads/main\$' \\
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://$image@$digest --repo $repo
\`\`\`

Reproduce it with \`scripts/reproduce.sh\`, as README.md describes.

Run: ${RUN_URL:-}
NOTES
