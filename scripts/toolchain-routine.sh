#!/usr/bin/env bash
# Advance existing routine PRs, then propose at most one new eligible pin.
# Called by the existing hourly toolchain observer, not a separate schedule.
set -euo pipefail

report=${1:?usage: toolchain-routine.sh <monitor-report>}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

failure() {
    {
        echo "Automatic routine toolchain updating requires attention."
        echo
        echo "- Reason: $1"
        echo "- Run: $RUN_URL"
        echo
        echo "No pin was merged without a successful exact-head full CI run."
    } > "$work/failure.md"
    scripts/issue.sh ensure toolchain-routine-failure \
        'Automated routine toolchain update did not finish' "$work/failure.md"
    echo "::error::$1"
    exit 1
}

# The emergency advisory-backed lane takes priority. Both jobs also share a
# concurrency group so they cannot mutate the repo at exactly the same time.
security_pr=$(gh pr list --state open --label toolchain-security-auto \
    --json number --jq '.[0].number // empty')
if [[ -n "$security_pr" ]]; then
    echo "Security PR #$security_pr is pending; routine adoption yields priority."
    exit 0
fi

gh label create toolchain-routine-auto --force \
    --description 'Cooldown-eligible routine toolchain pin upgrade' >/dev/null
open=$(gh pr list --state open --label toolchain-routine-auto --limit 100 \
    --json number,headRefName,headRefOid,baseRefName,author,isDraft)
skip=''
blocked=false

# Major upgrades stay open for human review. Same-major PRs are serialized to
# avoid flooding the reproducibility CI with simultaneous builder changes.
while IFS= read -r item; do
    [[ -n "$item" ]] || continue
    number=$(jq -er .number <<<"$item")
    branch=$(jq -er .headRefName <<<"$item")
    head=$(jq -er .headRefOid <<<"$item")
    author=$(jq -er '.author.login' <<<"$item")
    base=$(jq -er .baseRefName <<<"$item")
    draft=$(jq -r .isDraft <<<"$item")
    if [[ ! "$branch" =~ ^routine/toolchain-(buildkit|buildx|cosign|trivy)-(v[0-9]+\.[0-9]+\.[0-9]+)-[0-9]+$ ]]; then
        failure "Unexpected PR #$number head branch $branch has the routine bot label."
    fi
    tool=${BASH_REMATCH[1]}
    if [[ "$author" != 'github-actions[bot]' || "$base" != main ]]; then
        failure "Unexpected PR #$number author $author or base $base."
    fi
    skip="${skip:+$skip,}$tool"
    if [[ "$(gh pr diff "$number" --name-only)" != toolchain.env ]]; then
        failure "PR #$number modifies files other than toolchain.env."
    fi
    gh api "repos/$GH_REPO/contents/toolchain.env?ref=$head" \
        --jq .content | base64 --decode > "$work/proposed.env" ||
        failure "Cannot read PR #$number's pinned toolchain.env."
    # Verify against the exact parent, not against a potentially newer main.
    parent=$(gh api "repos/$GH_REPO/commits/$head" \
        --jq 'if (.parents | length) == 1 then .parents[0].sha else "" end')
    [[ "$parent" =~ ^[0-9a-f]{40}$ ]] || failure "PR #$number is not a single-parent commit."
    gh api "repos/$GH_REPO/contents/toolchain.env?ref=$parent" \
        --jq .content | base64 --decode > "$work/base.env" ||
        failure "Cannot read PR #$number's original pin file."
    python3 scripts/toolchain_routine.py verify --tool "$tool" \
        --base "$work/base.env" --candidate "$work/proposed.env" > "$work/verify.json" ||
        failure "PR #$number no longer contains exactly one valid pin upgrade."
    major=$(jq -r .major_change "$work/verify.json")
    [[ "$draft" == false ]] || { echo "Draft routine PR #$number: awaiting review."; blocked=true; continue; }

    runs=$(gh run list --workflow ci.yml --branch "$branch" \
        --event workflow_dispatch --limit 100 \
        --json databaseId,headSha,status,conclusion)
    matched=$(jq -c --arg sha "$head" \
        '[.[] | select(.headSha == $sha)] | .[0] // empty' <<<"$runs")
    [[ -n "$matched" ]] || failure "PR #$number has no dispatched full CI on head $head."
    status=$(jq -r .status <<<"$matched")
    conclusion=$(jq -r '.conclusion // ""' <<<"$matched")
    if [[ "$status" != completed ]]; then
        echo "PR #$number exact-head full CI is $status."
        if [[ "$major" == false ]]; then blocked=true; fi
        continue
    fi
    if [[ "$conclusion" != success ]]; then
        if [[ "$major" == true ]]; then
            echo "::warning::Major-version PR #$number CI finished with $conclusion; manual review required."
            continue  # Do not starve unrelated tool updates behind a manual major.
        fi
        failure "PR #$number exact-head full CI finished with $conclusion."
    fi
    if [[ "$major" == true ]]; then
        echo "PR #$number passed CI but crosses a major version; manual review required."
        continue
    fi

    # Reject CI performed against an obsolete main, including an intervening
    # emergency toolchain update. The PR stays open rather than silently using
    # tests from a different build definition.
    current_main=$(gh api "repos/$GH_REPO/branches/main" --jq .commit.sha)
    [[ "$parent" == "$current_main" ]] ||
        failure "PR #$number CI passed against obsolete main ($parent, now $current_main). Rebase and rerun CI."
    actual=$(gh pr view "$number" --json headRefOid --jq .headRefOid)
    [[ "$actual" == "$head" ]] || failure "PR #$number head changed after validation."
    gh pr merge "$number" --squash --delete-branch --match-head-commit "$head" ||
        failure "PR #$number passed CI but branch protection or merge failed."
    gh workflow run update.yml --ref main ||
        failure "PR #$number merged but publication dispatch failed."
    echo "Merged verified routine PR #$number and dispatched publication."
    scripts/issue.sh close toolchain-routine-failure \
        'Automated routine toolchain update did not finish' "Routine PR #$number merged successfully."
    # The earlier release report was generated on the old main. Recheck next run.
    exit 0
done < <(jq -c '.[]' <<<"$open")

if [[ "$blocked" == true ]]; then
    echo 'An automatic same-major PR is awaiting CI or review; not starting another.'
    exit 0
fi

python3 scripts/toolchain_routine.py plan --report "$report" \
    --skip "$skip" --out "$work/choice.json" ||
    failure 'Could not validate routine release eligibility.'
if jq -e '. == null' "$work/choice.json" >/dev/null; then
    echo 'No unclaimed cooldown-eligible routine pin updates.'
    exit 0
fi

tool=$(jq -er .tool "$work/choice.json")
old=$(jq -er .from "$work/choice.json")
new=$(jq -er .to "$work/choice.json")
major=$(jq -r .major_change "$work/choice.json")
git fetch --quiet origin main
git switch -c "routine/toolchain-$tool-$new-$GITHUB_RUN_ID" origin/main
branch=$(git branch --show-current)
digest=''
case "$tool" in
    buildkit) reference="moby/buildkit:$new" ;;
    cosign) reference="gcr.io/projectsigstore/cosign:$new" ;;
    *) reference='' ;;
esac
if [[ -n "$reference" ]]; then
    digest=$(docker buildx imagetools inspect "$reference" \
        --format '{{json .Manifest}}' | jq -er .digest) ||
        failure "Registry digest lookup failed for $reference."
fi
args=()
if [[ -n "$digest" ]]; then args=(--digest "$digest"); fi
python3 scripts/toolchain_routine.py apply \
    --plan "$work/choice.json" --toolchain toolchain.env "${args[@]}" ||
    failure "Failed to apply the single $tool pin change."
[[ "$(git diff --name-only)" == toolchain.env ]] ||
    failure "Routine proposal changed something other than toolchain.env."
git config user.name 'github-actions[bot]'
git config user.email '41898282+github-actions[bot]@users.noreply.github.com'
git add -- toolchain.env
git commit -m "Routine: pin $tool $old to $new"
git push --set-upstream origin "$branch" ||
    failure "Cannot push routine $tool branch."

{
    echo "Automatic seven-day cooldown toolchain upgrade for **$tool**: \`$old\` → \`$new\`."
    echo
    jq -r '"Release: " + .release_url + "\nReleased: " + .released_at' "$work/choice.json"
    echo
    if [[ "$major" == true ]]; then
        echo '**Major upgrade — manual review and merge required.**'
    else
        echo 'Same-major upgrade — the next hourly observer may merge only after exact-head full CI passes.'
    fi
    echo 'Full CI exercises both Node lines, reproducibility, vulnerability gates, and negative controls.'
    echo 'Only toolchain.env changes; immutable registry digests are included for image pins.'
    echo "Monitor: $RUN_URL"
} > "$work/pr.md"
gh pr create --base main --head "$branch" \
    --title "Routine: upgrade $tool to $new" \
    --body-file "$work/pr.md" --label toolchain-routine-auto ||
    failure "GitHub could not create the $tool PR (check Actions create-PR setting)."
gh workflow run ci.yml --ref "$branch" ||
    failure "Created the $tool PR but full CI dispatch failed."
echo "Created routine $tool $new PR and explicitly dispatched full CI."
