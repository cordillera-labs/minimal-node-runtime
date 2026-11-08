#!/usr/bin/env bash
# Prove a synthetic Mozilla root distrust causes a real, local image rebuild.
# Usage: root-trust-integration.sh <baseline-image> <ci-lock> <work-dir>
# No GitHub publishing, workflow dispatch, or production source modification.
set -euo pipefail
image=${1:?baseline image required}
lock=${2:?CI lock required}
work=${3:?CI work directory required}
root=$(cd "$(dirname "$0")/.." && pwd)
overlay="$root/certificates.auto.exclude"
original="$work/original.auto.exclude"
integration="$work/ca-rebuild-integration"
mkdir -p "$integration"
cp "$overlay" "$original"
trap 'cp "$original" "$overlay"' EXIT

# Pick a certificate actually trusted by the baseline's default Node TLS set.
# Export its real DER encoding so the fixture exercises fingerprint identity.
docker run --rm --pull never "$image" -e '
  const tls = require("node:tls");
  const { X509Certificate, createHash } = require("node:crypto");
  const hash = pem => createHash("sha256").update(new X509Certificate(pem).raw).digest("hex");
  const trusted = new Set(tls.getCACertificates("default").map(hash));
  const candidate = tls.rootCertificates.find(pem => trusted.has(hash(pem)));
  if (!candidate) throw Error("baseline has no bundled trusted CA to test");
  console.log(new X509Certificate(candidate).raw.toString("base64"));
' > "$integration/root.der.b64"

baseline_digest=$(cat "$work/out/digest")
python3 "$root/scripts/root-trust-integration.py" \
    --der-b64-file "$integration/root.der.b64" \
    --baseline-lock "$lock" --baseline-digest "$baseline_digest" \
    --output-dir "$integration"
python3 "$root/scripts/lock.py" check "$integration/variant.lock"

# The reproducibility step retained one already-warmed pinned builder. This
# uses the actual production Dockerfile, Debian packages and build.sh path.
builder=$(cat "$work/out/builder")
BUILDER="$builder" DEBS_FROM="$work/out/a/debs" \
    "$root/scripts/build.sh" "$integration/variant.lock" "$integration/image"
variant_digest=$(cat "$integration/image/digest")
if [[ "$baseline_digest" == "$variant_digest" ]]; then
    echo 'FAIL: accepted distrust produced an unchanged image digest' >&2
    exit 1
fi
# A removal changes contents but must not introduce/remove paths in the image.
cmp "$work/out/a/rootfs.manifest" "$integration/image/rootfs.manifest"
"$root/scripts/load-image.sh" "$integration/image/image.tar" minimal-node-runtime:revoked

# Compare the effective *default* Node trust sets, not merely the system CA
# bundle. The only difference must be the one synthetic distrust anchor.
for entry in "baseline:$image" 'revoked:minimal-node-runtime:revoked'; do
    name=$(cut -d: -f1 <<< "$entry")
    ref=$(cut -d: -f2- <<< "$entry")
    docker run --rm --pull never "$ref" -e '
      const tls = require("node:tls");
      const { X509Certificate, createHash } = require("node:crypto");
      const hashes = tls.getCACertificates("default").map(pem =>
        createHash("sha256").update(new X509Certificate(pem).raw).digest("hex"));
      console.log(JSON.stringify(hashes.sort()));
    ' > "$integration/$name-roots.json"
done
python3 - "$integration" <<'PY'
import json
from pathlib import Path
import sys
work = Path(sys.argv[1])
expected = json.loads((work / 'integration-result.json').read_text())['fingerprint']
before = set(json.loads((work / 'baseline-roots.json').read_text()))
after = set(json.loads((work / 'revoked-roots.json').read_text()))
assert before - after == {expected}, f'wrong removed TLS roots: {before - after}'
assert after - before == set(), f'new TLS roots were introduced: {after - before}'
print(f'PASS: rebuilt Node distrusts {expected} and retains all other roots')
PY
printf 'PASS: build digest changed from %s to %s\n' "$baseline_digest" "$variant_digest"
