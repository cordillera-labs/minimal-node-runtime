#!/usr/bin/env bash
#
# report-issue.sh — keep one GitHub issue in step with a scheduled scan.
#
# A failed scan opens the issue, or comments on it when it is already open; a
# passing scan closes it, so an open issue always means the latest scan failed.
# A cancelled run changes nothing. The message links the run and names no
# findings: the job log holds those, and it cannot tell a vulnerability from a
# scanner fault, so it says so.
#
# USAGE (environment, so nothing is interpolated into a shell)
#   SCAN_RESULT   success | failure | cancelled
#   TITLE         issue title; also how the open issue is found
#   GH_TOKEN      token with issues:write; GH_REPO the owner/name repository
#   GITHUB_SERVER_URL, GITHUB_REPOSITORY, GITHUB_RUN_ID   (set by Actions)
set -euo pipefail

: "${SCAN_RESULT:?}" "${TITLE:?}"
case "$SCAN_RESULT" in
    success | failure) ;;
    cancelled) echo "report-issue: run cancelled; issue left as it is"; exit 0 ;;
    *) echo "::error::report-issue: unknown scan result '$SCAN_RESULT'" >&2; exit 64 ;;
esac

run_url="$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID"
existing="$(gh issue list --state open --limit 100 --json number,title \
    | jq -r --arg t "$TITLE" '.[] | select(.title == $t) | .number' | head -n 1)"

if [[ "$SCAN_RESULT" == success ]]; then
    if [[ -n "$existing" ]]; then
        gh issue close "$existing" --comment "The scan passed. Run: $run_url"
    fi
    exit 0
fi

message="The scheduled scan failed. This may be a High/Critical advisory, a vulnerable Node runtime, or a scanner or infrastructure fault; read the job log before treating it as a confirmed vulnerability. Run: $run_url"
if [[ -n "$existing" ]]; then
    gh issue comment "$existing" --body "$message"
else
    gh issue create --title "$TITLE" --body "$message"
fi
