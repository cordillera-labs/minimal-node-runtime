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

# The image has no shell and no package manager.
for binary in /bin/sh /usr/bin/apt-get /usr/bin/dpkg; do
    if docker run --rm --pull never --entrypoint "$binary" "$image" -c true >/dev/null 2>&1; then
        echo "FAIL the image runs $binary" >&2
        exit 1
    fi
    echo "ok   $binary is absent"
done
echo "smoke-test: pass"
