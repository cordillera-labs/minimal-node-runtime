#!/bin/bash
# Wraps a Trivy JSON report in the cosign "vuln" predicate, for
# `cosign attest --type vuln`.
#
#   vuln-predicate.sh <scan.json> <trivy-version> <db-version> <scan-started> <scan-finished>
set -euo pipefail
jq --arg version "$2" --arg db "$3" --arg started "$4" --arg finished "$5" \
   --arg run "${RUN_URL:-}" --arg builder "${BUILDER_ID:-}" '{
    invocation: {parameters: ["--scanners", "vuln", "--pkg-types", "os,library", "--list-all-pkgs"],
                 uri: $run, event_id: "", "builder.id": $builder},
    scanner: {uri: "https://github.com/aquasecurity/trivy", version: $version,
              db: {uri: "https://github.com/aquasecurity/trivy-db", version: $db},
              result: .},
    metadata: {scanStartedOn: $started, scanFinishedOn: $finished}
}' "$1"
