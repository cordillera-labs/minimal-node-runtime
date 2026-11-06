#!/bin/bash
# Opens, updates and closes the issues the workflows report through. Needs the
# gh CLI with GH_TOKEN and GH_REPO set. One open issue exists per title; an
# update edits its body, which sends no notification, rather than commenting.
#
#   issue.sh ensure <label> <title> <body-file>
#   issue.sh close <label> <title> <comment>
#   issue.sh sync-unfixed <unfixed.json> <image-ref> <source> <line>
#       Ensures one "unfixed-cve" issue per line and HIGH or CRITICAL finding
#       without a fix. With <source> "published-stable", it also closes the
#       line's open unfixed-cve issues whose finding is gone from that scan.
set -euo pipefail

find_issue() {
    gh issue list --state open --label "$1" --limit 200 --json number,title \
        | jq -r --arg t "$2" '.[] | select(.title == $t) | .number' | head -1
}

ensure() {
    local label=$1 title=$2 body=$3 number
    gh label create "$label" --force --description "Opened by the update workflows" >/dev/null
    number=$(find_issue "$label" "$title")
    if [ -n "$number" ]; then
        gh issue edit "$number" --body-file "$body" >/dev/null
        echo "updated #$number: $title"
    else
        gh issue create --label "$label" --title "$title" --body-file "$body"
    fi
}

close() {
    local label=$1 title=$2 comment=$3 number
    number=$(find_issue "$label" "$title" || true)
    if [ -n "$number" ]; then
        gh issue close "$number" --comment "$comment" >/dev/null
        echo "closed #$number: $title"
    fi
}

sync_unfixed() {
    local findings=$1 image=$2 source=$3 line=$4 body titles suffix
    body=$(mktemp)
    titles=$(mktemp)
    # Each line has its own issues, so one line's scan never closes another's.
    suffix=" on node $line"
    jq -r --arg s "$suffix" '.[] | "Unfixed \(.severity) \(.id) in \(.package)\($s)"' "$findings" | sort -u > "$titles"
    jq -c '.[]' "$findings" | while read -r finding; do
        title=$(jq -r --arg s "$suffix" '"Unfixed \(.severity) \(.id) in \(.package)\($s)"' <<<"$finding")
        {
            echo "Trivy reports a ${title#Unfixed } with no fixed version available."
            echo
            jq -r '"- Package: `\(.package)` \(.installed)\n- Status: \(.status)\n- Title: \(.title)"' <<<"$finding"
            echo "- Image: \`$image\`"
            echo "- Seen by: $source, run $RUN_URL"
            echo
            echo "Policy: the image is still published, because no fixed package exists to"
            echo "build from. No VEX statement is generated. This issue closes when the"
            echo "hourly scan of the line's published stable image no longer reports the finding."
        } > "$body"
        ensure unfixed-cve "$title" "$body"
    done
    if [ "$source" = published-stable ]; then
        gh issue list --state open --label unfixed-cve --limit 200 --json number,title \
            | jq -r --arg s "$suffix" '.[] | select(.title | endswith($s)) | "\(.number)\t\(.title)"' \
            | while IFS=$'\t' read -r number title; do
                if ! grep -qxF "$title" "$titles"; then
                    gh issue close "$number" --comment "The hourly scan of the published stable image no longer reports this finding ($RUN_URL)." >/dev/null
                    echo "closed #$number: $title"
                fi
            done
    fi
}

: "${RUN_URL:=unknown run}"
case "${1:-}" in
    ensure) ensure "$2" "$3" "$4" ;;
    close) close "$2" "$3" "$4" ;;
    sync-unfixed) sync_unfixed "$2" "$3" "$4" "$5" ;;
    *) echo "usage: issue.sh ensure|close|sync-unfixed ..." >&2; exit 2 ;;
esac
