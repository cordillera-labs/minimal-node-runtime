#!/bin/bash
# Runs the smoke checks against an image.
#
#   smoke-test.sh <image-ref> <expected-node-version>
#
# Needs network access: the DNS and HTTPS checks reach nodejs.org.
set -euo pipefail
image=$1
expected=$2
tests_dir="$(cd "$(dirname "$0")/../tests" && pwd)"

docker run --rm --pull never \
    -e EXPECTED_NODE_VERSION="$expected" -e TZ=America/Vancouver \
    -v "$tests_dir:/smoke:ro" "$image" /smoke/smoke.mjs

# Prove the default Node startup actually removes a baked DER fingerprint,
# even though the underlying Node binary still contains that Mozilla root.
denied_hash=$(docker run --rm --pull never "$image" -e '
    const tls = require("node:tls");
    const {createHash, X509Certificate} = require("node:crypto");
    const der = new X509Certificate(tls.rootCertificates[0]).raw;
    console.log(createHash("sha256").update(der).digest("hex"));
')
[[ "$denied_hash" =~ ^[0-9a-f]{64}$ ]] || { echo 'invalid baked CA probe hash' >&2; exit 1; }
denyfile=$(mktemp)
trap 'rm -f "$denyfile"' EXIT
printf '%s\n' "$denied_hash" > "$denyfile"
chmod 0644 "$denyfile"
docker run --rm --pull never \
    --mount "type=bind,src=$denyfile,dst=/nodejs/lib/ca-image-exclusions.txt,readonly" \
    -e EXPECTED_BAKED_EXCLUDED_SHA="$denied_hash" \
    "$image" -e '
      const tls = require("node:tls");
      const {createHash, X509Certificate} = require("node:crypto");
      const ids = new Set(tls.getCACertificates("default").map(pem => {
        return createHash("sha256").update(new X509Certificate(pem).raw).digest("hex");
      }));
      if (ids.has(process.env.EXPECTED_BAKED_EXCLUDED_SHA)) {
        console.error("FAIL: baked CA exclusion did not affect Node default TLS trust");
        process.exit(1);
      }
    '
echo "ok   baked CA exclusion removes a Node default trust anchor"

# The image has no shell and no package manager.
for binary in /bin/sh /usr/bin/apt-get /usr/bin/dpkg; do
    if docker run --rm --pull never --entrypoint "$binary" "$image" -c true >/dev/null 2>&1; then
        echo "FAIL the image runs $binary" >&2
        exit 1
    fi
    echo "ok   $binary is absent"
done
echo "smoke-test: pass"
