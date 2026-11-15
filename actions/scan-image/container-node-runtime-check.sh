#!/usr/bin/env bash
# Verify the Node executable shipped by the built app image.
# Trivy scans OS and language packages, but a standalone official Node binary
# may not be attributed a Node-core CVE by the image vulnerability cataloger.
#
# The caller names the minimum safe Node version; raise it only after reviewing
# official Node security advisories. The major must match exactly, so a series
# change is a deliberate edit to the caller, never silent drift.
#
# USAGE
#   container-node-runtime-check.sh IMAGE_REFERENCE MIN_VERSION   (MIN_VERSION like 24.22.2)
set -euo pipefail

if [[ $# -ne 2 || ! "$1" =~ ^[a-zA-Z0-9._:/@-]+$ || ! "$2" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "usage: container-node-runtime-check.sh IMAGE_REFERENCE MIN_VERSION (e.g. 24.22.2)" >&2
    exit 64
fi

image="$1"
IFS=. read -r expected_major min_minor min_patch <<< "$2"
min_safe="$2"
# The runtime image has no shell and declares an absolute Node executable as its
# entrypoint. Derive its path instead of assuming one location.
if ! entrypoint="$(docker image inspect "$image" --format '{{json .Config.Entrypoint}}')"; then
    echo "::error::Failed to inspect the Node image $image" >&2
    exit 69
fi
if [[ "$entrypoint" =~ ^\[\"(/[^\"[:space:]]+/node)\"\]$ ]]; then
    node_executable="${BASH_REMATCH[1]}"
else
    node_executable=node
fi
if ! actual="$(docker run --rm --network none --entrypoint "$node_executable" "$image" --version)"; then
    echo "::error::Failed to execute Node in built image $image ($node_executable)" >&2
    exit 69
fi
if [[ ! "$actual" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
    echo "::error::Invalid Node version reported by $image: $actual" >&2
    exit 69
fi

major="${BASH_REMATCH[1]}"
minor="${BASH_REMATCH[2]}"
patch="${BASH_REMATCH[3]}"
if (( 10#$major != expected_major )); then
    echo "::error::Unexpected Node major $major; review and update the runtime security baseline before changing series" >&2
    exit 1
fi
if (( 10#$minor < min_minor || (10#$minor == min_minor && 10#$patch < min_patch) )); then
    echo "::error::Node v$major.$minor.$patch is older than security baseline v$min_safe" >&2
    exit 1
fi
echo "Node runtime $actual meets the checked security baseline v$min_safe"
