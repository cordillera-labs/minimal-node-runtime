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

# The exact-head CI gate remains the only merge authority, but making the
# scheduled observer wait for its own dispatched read-only CI allows the same
# update run to adopt a successful pin and trigger publication. Otherwise an
# hourly schedule (or one manually dispatched run) only launches CI and stops.
#
# Bound the wait so queued runners cannot hold the publish concurrency group
# indefinitely. If CI is still queued, keep the PR and allow the next observer
# to adopt the exact validated head. One re-entry is enough; if main changes
# materially again during CI the safe replay/retest fallback stays in force.
adopt_when_ci_finishes() {
    local branch=$1 head=$2 child='' attempt rc
    if [[ "${ROUTINE_CI_REENTRY:-0}" == 1 ]]; then
        echo "CI re-entry already used; leaving any additional refresh for the next observer."
        return 0
    fi
    for attempt in $(seq 1 40); do
        child=$(gh run list --workflow ci.yml --branch "$branch" \
            --event workflow_dispatch --limit 100 --json databaseId,headSha \
            --jq ".[] | select(.headSha == \"$head\") | .databaseId" | head -1) ||
            failure "Cannot locate exact-head CI for $branch."
        if [[ "$child" =~ ^[0-9]+$ ]]; then break; fi
        sleep 5
    done
    if [[ ! "$child" =~ ^[0-9]+$ ]]; then
        echo "::warning::No exact-head CI run observed for $head; the next observer will retry."
        return 0
    fi
    echo "Watching exact-head CI $child for $head before guarded adoption."
    if timeout --kill-after=30s 660 gh run watch "$child" --exit-status; then
        # Re-run every existing trusted PR/head/base/diff/major-version check.
        # Never merge merely because the watcher succeeded.
        ROUTINE_CI_REENTRY=1 bash "$0" "$report"
        return 0
    else
        rc=$?
        if [[ "$rc" == 124 ]]; then
            echo "::warning::Exact-head CI $child exceeded the wait budget; the next observer will adopt it if green."
            return 0
        fi
        failure "Exact-head full CI run $child for $branch failed or could not be watched (exit $rc)."
    fi
}

# The emergency advisory-backed lane takes priority. Both jobs also share a
# concurrency group so they cannot mutate the repo at exactly the same time.
security_pr=$(gh pr list --state open --label toolchain-security-auto \
    --json number --jq '.[0].number // empty')
if [[ -n "$security_pr" ]]; then
    echo "Security PR #$security_pr is pending; routine adoption yields priority."
    exit 0
fi

# The App token is used only for PR authoring/merge. The job token retains
# issue maintenance, CI dispatch, and read-only metadata permissions.
pr_token=${ROUTINE_APP_TOKEN:-$GH_TOKEN}
if [[ -n "${ROUTINE_APP_TOKEN:-}" ]]; then
    [[ "${ROUTINE_APP_SLUG:-}" =~ ^[a-z0-9][a-z0-9-]*$ ]] ||
        failure "Invalid GitHub App slug from token creation."
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
    # GitHub GraphQL reports app/<slug>, while REST reports <slug>[bot].
    # Preserve the legacy Actions-owned PR #39 during the migration; future
    # PRs must match the installed, narrowly scoped GitHub App's exact slug.
    if [[ "$author" != 'github-actions[bot]' && "$author" != 'app/github-actions' &&
          "$author" != "app/${ROUTINE_APP_SLUG:-}" &&
          "$author" != "${ROUTINE_APP_SLUG:-}[bot]" ]] ||
            [[ "$base" != main ]]; then
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

    # Require the exact tested PR head and successful full CI. When main
    # advances, accept only explicitly build-inert observation-state commits;
    # those cannot alter the image build definition, pinned line inputs, CI,
    # or the trust exclusions baked into the image. All other main drift
    # requires replaying the verified one-pin commit and re-running full CI.
    current_main=$(gh api "repos/$GH_REPO/branches/main" --jq .commit.sha)
    needs_refresh=false
    if [[ "$parent" != "$current_main" ]]; then
        git fetch --quiet origin main "$branch" ||
            failure "Cannot fetch current main or routine PR #$number."
        if [[ "$(git rev-parse --is-shallow-repository)" == true ]]; then
            git fetch --quiet --unshallow origin main ||
                failure "Cannot inspect the full git ancestry for PR #$number."
        fi
        fetched_main=$(git rev-parse refs/remotes/origin/main)
        [[ "$fetched_main" == "$current_main" ]] ||
            failure "Main advanced while examining PR #$number; retry on next run."
        if python3 scripts/toolchain_observation_drift.py "$parent" "$current_main"; then
            echo "PR #$number has only build-inert observation drift; preserving green exact-head CI."
        else
            needs_refresh=true
        fi
    fi
    if [[ "$needs_refresh" == true ]]; then
        echo "PR #$number has build-relevant or unverified drift from $parent to $current_main; refresh and retest."
        old_version=$(jq -er .from "$work/verify.json")
        new_version=$(jq -er .to "$work/verify.json")
        git fetch --quiet origin main "$branch" ||
            failure "Cannot fetch current main or routine PR #$number."
        git switch --detach origin/main ||
            failure "Cannot switch to current main for PR #$number."
        git cherry-pick --no-commit "$head" ||
            failure "PR #$number pin conflicts with newer main; cannot refresh automatically."
        [[ "$(git diff --cached --name-only)" == toolchain.env ]] ||
            failure "Refreshed PR #$number changes files other than toolchain.env."
        git show HEAD:toolchain.env > "$work/refreshed-base.env" ||
            failure "Cannot read refreshed base for PR #$number."
        git show :toolchain.env > "$work/refreshed-proposed.env" ||
            failure "Cannot read refreshed pin for PR #$number."
        python3 scripts/toolchain_routine.py verify --tool "$tool" \
            --base "$work/refreshed-base.env" \
            --candidate "$work/refreshed-proposed.env" > "$work/refreshed-verify.json" ||
            failure "Refreshed PR #$number is not the same single-pin upgrade."
        if [[ "$(jq -r .from "$work/refreshed-verify.json")" != "$old_version" ||
                "$(jq -r .to "$work/refreshed-verify.json")" != "$new_version" ]]; then
            failure "Refreshed PR #$number would change the approved pin upgrade."
        fi
        # Preserve bot authorship and only replace the branch if nobody has
        # touched its exact previously validated head (force-with-lease).
        git config user.name 'github-actions[bot]'
        git config user.email '41898282+github-actions[bot]@users.noreply.github.com'
        git commit -m "Routine: pin $tool $old_version to $new_version" ||
            failure "Cannot commit refreshed routine pin for PR #$number."
        git push --force-with-lease="refs/heads/$branch:$head" \
            origin "HEAD:refs/heads/$branch" ||
            failure "Routine PR #$number branch changed during refresh."
        gh workflow run ci.yml --ref "$branch" ||
            failure "Refreshed PR #$number but could not dispatch fresh CI."
        echo "Refreshed PR #$number and dispatched fresh full CI."
        adopt_when_ci_finishes "$branch" "$(git rev-parse HEAD)"
        exit 0
    fi
    # Confirm main did not move during our drift inspection. The PR head
    # match protects the CI result; the main match protects our drift verdict.
    merge_main=$(gh api "repos/$GH_REPO/branches/main" --jq .commit.sha)
    [[ "$merge_main" == "$current_main" ]] ||
        failure "Main moved during PR #$number validation; retry without merging."
    actual=$(gh pr view "$number" --json headRefOid --jq .headRefOid)
    [[ "$actual" == "$head" ]] || failure "PR #$number head changed after validation."
    GH_TOKEN="$pr_token" gh pr merge "$number" --squash --delete-branch --match-head-commit "$head" ||
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
GH_TOKEN="$pr_token" gh pr create --base main --head "$branch" \
    --title "Routine: upgrade $tool to $new" \
    --body-file "$work/pr.md" --label toolchain-routine-auto ||
    failure "GitHub could not create the $tool PR (check Actions create-PR setting)."
gh workflow run ci.yml --ref "$branch" ||
    failure "Created the $tool PR but full CI dispatch failed."
echo "Created routine $tool $new PR and explicitly dispatched full CI."
if [[ "$major" == false ]]; then
    adopt_when_ci_finishes "$branch" "$(git rev-parse HEAD)"
fi
