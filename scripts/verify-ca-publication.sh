#!/usr/bin/env bash
# verify-ca-publication.sh <update-run-id> <root-trust-report.json>
set -euo pipefail
update_run=${1:?update workflow run ID required}
report=${2:?root trust report required}
[[ "$update_run" =~ ^[0-9]+$ ]] || { echo 'invalid update run ID' >&2; exit 1; }
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
mapfile -t excluded < <(jq -er '.auto_excluded[]' "$report")
(( ${#excluded[@]} > 0 )) || { echo 'nothing new to verify' >&2; exit 1; }
for hash in "${excluded[@]}"; do
    [[ "$hash" =~ ^[0-9a-f]{64}$ ]] || { echo 'invalid exclusion fingerprint' >&2; exit 1; }
done
image_repository=$(sed -n 's/^IMAGE_REPOSITORY=//p' toolchain.env)
[[ "$image_repository" == ghcr.io/* ]] || exit 1
git fetch --quiet origin main
mkdir -p "$RUNNER_TEMP/ca-publication"
for line in $(python3 scripts/lock.py lines | jq -r '.[]'); do
    lock="$RUNNER_TEMP/ca-publication/$line.lock"
    git show "origin/main:state/$line/stable.lock" > "$lock"
    published=$(python3 scripts/lock.py get "$lock" PUBLISHED_RUN)
    digest=$(python3 scripts/lock.py get "$lock" PUBLISHED_DIGEST)
    accepted_hash=$(python3 scripts/lock.py get "$lock" BUILD_DEFINITION_SHA256)
    expected_hash=$(python3 scripts/lock.py build-definition)
    case "$published" in
        "${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${update_run}"*) ;;
        *) echo "node $line stable lock not published by update run $update_run: $published" >&2; exit 1 ;;
    esac
    [ "$accepted_hash" = "$expected_hash" ] || {
        echo "node $line stable lock does not contain the new exclusion build definition" >&2; exit 1;
    }
    [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || exit 1
    tag="$image_repository:$line"
    remote=$(docker buildx imagetools inspect "$tag" --format '{{json .Manifest}}' | jq -r .digest)
    [ "$remote" = "$digest" ] || {
        echo "node $line stable GHCR tag still names $remote instead of $digest" >&2; exit 1;
    }
    docker pull "$image_repository@$digest"
    expected_exclusions=$(printf '%s\n' "${excluded[@]}")
    docker run --rm --pull never -e EXPECTED_EXCLUSIONS="$expected_exclusions" \
        "$image_repository@$digest" -e '
        const fs = require("node:fs");
        const tls = require("node:tls");
        const { createHash, X509Certificate } = require("node:crypto");
        const expected = process.env.EXPECTED_EXCLUSIONS.trim().split(/\s+/);
        const baked = new Set(fs.readFileSync("/nodejs/lib/ca-image-exclusions.txt", "utf8").split(/\s+/));
        const trusted = new Set(tls.getCACertificates("default").map(pem =>
          createHash("sha256").update(new X509Certificate(pem).raw).digest("hex")));
        for (const hash of expected) {
          if (!baked.has(hash)) throw Error("exclusion not baked: " + hash);
          if (trusted.has(hash)) throw Error("excluded CA still trusted: " + hash);
        }
        console.log("pass: " + expected.length + " root distrust exclusions active");
      '
    echo "Verified node $line stable publication: $tag -> $digest"
done
