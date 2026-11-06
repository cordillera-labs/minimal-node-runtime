#!/bin/bash
# Applies the vulnerability policy to a Trivy JSON report.
#
#   vuln-policy.sh <trivy-report.json> <unfixed-out.json>
#
# A HIGH or CRITICAL finding with a fixed version blocks publishing: exit 1.
# A HIGH or CRITICAL finding with no fixed version does not block. It is
# written to <unfixed-out.json> for the issue step, and no VEX statement is
# generated for it.
set -euo pipefail
report=$1
unfixed_out=$2

findings='[.Results[]? | .Vulnerabilities[]? | select(.Severity == "HIGH" or .Severity == "CRITICAL")
    | {id: .VulnerabilityID, package: .PkgName, installed: .InstalledVersion,
       fixed: (.FixedVersion // ""), severity: .Severity, status: (.Status // ""), title: (.Title // "")}]'
jq "$findings | map(select(.fixed == \"\")) | unique_by(.id + .package)" "$report" > "$unfixed_out"
fixable=$(jq "$findings | map(select(.fixed != \"\")) | unique_by(.id + .package)" "$report")

echo "unfixed HIGH/CRITICAL: $(jq length "$unfixed_out")"
jq -r '.[] | "  \(.severity) \(.id) \(.package) \(.installed) (no fix)"' "$unfixed_out"
count=$(jq length <<<"$fixable")
echo "fixable HIGH/CRITICAL: $count"
jq -r '.[] | "  \(.severity) \(.id) \(.package) \(.installed) fixed in \(.fixed)"' <<<"$fixable"
if [ "$count" -ne 0 ]; then
    echo "vuln-policy: a fix exists for a HIGH or CRITICAL finding; nothing is published"
    exit 1
fi
echo "vuln-policy: pass"
