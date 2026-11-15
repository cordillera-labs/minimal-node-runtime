#!/usr/bin/env bash
# Network-free tests for report-issue.sh, with gh stubbed.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
dir="$(mktemp -d)"
trap 'rm -rf "$dir"' EXIT
mkdir -p "$dir/bin"
cat > "$dir/bin/gh" <<'MOCK'
#!/usr/bin/env bash
echo "gh $*" >> "$MOCK_LOG"
if [[ "$1 $2" == "issue list" ]]; then
    printf '%s\n' "${MOCK_ISSUES:-[]}"
fi
MOCK
chmod +x "$dir/bin/gh"
export PATH="$dir/bin:$PATH" MOCK_LOG="$dir/log"
export GITHUB_SERVER_URL=https://github.example GITHUB_REPOSITORY=o/r GITHUB_RUN_ID=7
export TITLE='Scan failed' GH_REPO=o/r

run() { : > "$MOCK_LOG"; SCAN_RESULT="$1" MOCK_ISSUES="$2" bash "$here/report-issue.sh" > /dev/null; }
expect() { # expect LABEL PATTERN  — the call log must contain PATTERN
    grep -q -- "$2" "$MOCK_LOG" || { echo "FAIL $1: no '$2' in:" >&2; cat "$MOCK_LOG" >&2; exit 1; }
}
refute() {
    ! grep -q -- "$2" "$MOCK_LOG" || { echo "FAIL $1: unexpected '$2' in:" >&2; cat "$MOCK_LOG" >&2; exit 1; }
}
open='[{"number":5,"title":"Scan failed"},{"number":6,"title":"Other"}]'

run failure '[]';  expect "failure opens" 'issue create --title Scan failed'; refute "failure opens" 'issue comment'
run failure "$open"; expect "failure comments" 'issue comment 5'; refute "failure comments" 'issue create'
run success "$open"; expect "success closes" 'issue close 5'
run success '[]';  refute "success, none open" 'issue close'; refute "success, none open" 'issue create'
run success '[{"number":6,"title":"Other"}]'; refute "other issues untouched" 'issue close'
run cancelled "$open"; [[ ! -s "$MOCK_LOG" ]] || { echo "FAIL cancelled touched gh" >&2; exit 1; }
if SCAN_RESULT=bogus bash "$here/report-issue.sh" > /dev/null 2>&1; then echo "FAIL unknown result accepted" >&2; exit 1; fi
echo "[container-security] report-issue checks passed"
