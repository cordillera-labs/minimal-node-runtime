"""Static guardrails for the GitHub App-based toolchain automation wiring.

The full workflow is integration-tested by Actions. These tests catch accidental
reversion to GITHUB_TOKEN for PR authoring and overbroad App permissions.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
ACTION = "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1"


class ToolchainGitHubAppWiring(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.update = (ROOT / ".github/workflows/update.yml").read_text(encoding="utf-8")
        cls.security = (ROOT / ".github/workflows/toolchain-security.yml").read_text(encoding="utf-8")
        cls.routine = (ROOT / "scripts/toolchain-routine.sh").read_text(encoding="utf-8")
        cls.ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    def test_app_token_is_scoped_to_one_repo_and_two_permissions(self):
        for content in (self.update, self.security):
            with self.subTest(workflow="update" if content == self.update else "security"):
                self.assertIn(ACTION, content)
                self.assertIn("vars.TOOLCHAIN_APP_CLIENT_ID", content)
                self.assertIn("secrets.TOOLCHAIN_APP_PRIVATE_KEY", content)
                self.assertIn("permission-contents: write", content)
                self.assertIn("permission-pull-requests: write", content)
                self.assertNotIn("permission-workflows:", content)
                self.assertNotIn("permission-actions:", content)
                self.assertNotIn("permission-issues:", content)
                self.assertNotIn("          repositories:", content)
                self.assertNotIn("          owner:", content)
                self.assertIn("steps.toolchain-app.outputs.token || github.token", content)

    def test_routine_only_uses_app_for_pr_mutations(self):
        self.assertIn("ROUTINE_APP_TOKEN: ${{ steps.toolchain-app.outputs.token }}", self.update)
        self.assertIn("ROUTINE_APP_SLUG: ${{ steps.toolchain-app.outputs.app-slug }}", self.update)
        self.assertIn('GH_TOKEN="$pr_token" gh pr create', self.routine)
        self.assertIn('GH_TOKEN="$pr_token" gh pr merge', self.routine)
        self.assertIn('gh workflow run ci.yml --ref "$branch"', self.routine)
        self.assertIn('app/${ROUTINE_APP_SLUG:-}', self.routine)
        self.assertIn('${ROUTINE_APP_SLUG:-}[bot]', self.routine)
        self.assertIn("'github-actions[bot]'", self.routine)

    def test_routine_waits_for_exact_head_ci_before_automatic_adoption(self):
        # Creating/refreshing a pin must not require a *second* scheduled run
        # to notice that its own CI passed. The re-entry still executes every
        # existing PR/head/diff/major and main-drift validation.
        self.assertIn('adopt_when_ci_finishes() {', self.routine)
        self.assertIn('--event workflow_dispatch --limit 100 --json databaseId,headSha', self.routine)
        self.assertIn('select(.headSha ==', self.routine)
        self.assertIn('timeout --kill-after=30s 660 gh run watch "$child" --exit-status', self.routine)
        self.assertIn('ROUTINE_CI_REENTRY=1 bash "$0" "$report"', self.routine)
        self.assertEqual(self.routine.count('adopt_when_ci_finishes "$branch" "$(git rev-parse HEAD)"'), 2)
        self.assertIn('GH_TOKEN="$pr_token" gh pr merge "$number"', self.routine)
        self.assertIn('--match-head-commit "$head"', self.routine)

    def test_major_toolchain_upgrade_adopts_only_after_exact_head_ci(self):
        # A semantic major bump is not an automatic blocker for build tooling.
        # Every release, including major, must retain exact-head CI and strict
        # single pin/immutable registry digest verification before merge.
        self.assertNotIn('if [[ "$major" == true ]]', self.routine)
        self.assertNotIn('if [[ "$major" == false ]]', self.routine)
        self.assertIn('python3 scripts/toolchain_routine.py verify --tool "$tool"', self.routine)
        self.assertIn('--match-head-commit "$head"', self.routine)
        self.assertIn('if [[ "$conclusion" != success ]]', self.routine)
        self.assertTrue(self.routine.rstrip().endswith(
            'adopt_when_ci_finishes "$branch" "$(git rev-parse HEAD)"'))

    def test_cosign_contract_is_part_of_required_full_ci(self):
        self.assertIn('  cosign-contract:', self.ci)
        self.assertIn('    needs: [unit, workflow-lint, build, cosign-contract]', self.ci)
        self.assertIn('COSIGN: ${{ needs.cosign-contract.result }}', self.ci)
        self.assertIn('[ "$COSIGN" = success ]', self.ci)
        self.assertIn('permissions:\n      contents: read\n      packages: read', self.ci)
        self.assertIn('scripts/verify-published.sh signature', self.ci)
        self.assertIn('scripts/verify-published.sh vuln', self.ci)
        self.assertIn('state/22/stable.lock PUBLISHED_DIGEST', self.ci)
        self.assertIn('COSIGN_IMAGE="$(sed -n', self.ci)

    def test_toolchain_pin_push_publishes_without_recursive_record_commits(self):
        self.assertIn('  push:\n    branches: [main]\n    paths:\n      - toolchain.env\n      - .github/workflows/update.yml', self.update)
        self.assertIn('    - cron:', self.update)
        self.assertIn('      - scripts/toolchain-routine.sh', self.update)
        self.assertIn('  workflow_dispatch:', self.update)
        self.assertIn('gh workflow run update.yml --ref main', self.routine)

    def test_app_merges_only_dispatch_publication_once(self):
        # App-authored merges already produce update.yml push events.
        # A second explicit dispatch can cancel one queued run because GitHub
        # only retains a single pending run per concurrency group.
        routine_after_merge = self.routine.split('GH_TOKEN="$pr_token" gh pr merge', 1)[1]
        self.assertIn('if [[ -n "${ROUTINE_APP_TOKEN:-}" ]]; then', routine_after_merge)
        self.assertIn('else\n        # GITHUB_TOKEN', routine_after_merge)
        self.assertIn('gh workflow run update.yml --ref main', routine_after_merge)

        security_after_merge = self.security.split('gh pr merge "$PR" --squash --delete-branch', 1)[1]
        self.assertIn('if [[ -n "${TOOLCHAIN_APP_TOKEN:-}" ]]; then', security_after_merge)
        self.assertIn('gh workflow run update.yml --ref main', security_after_merge)

    def test_line_recording_finishes_before_routine_ci_adoption(self):
        # The publish jobs write state/<line>/stable.lock on main. Starting
        # routine CI concurrently invalidates the tested base while it runs,
        # forcing another rebase and another CI instead of adopting the PR.
        # Do not disable the updater if a line job fails.
        toolchain_job = self.update.split('  toolchain:\n', 1)[1].split('  keepalive:', 1)[0]
        self.assertIn('    needs: [line]\n', toolchain_job)
        self.assertIn("    if: always() && github.ref == 'refs/heads/main'", toolchain_job)
        self.assertIn('      group: toolchain-security', toolchain_job)
        self.assertIn('Advance routine toolchain PRs after the release cooldown', toolchain_job)

    def test_security_refreshes_app_token_after_ci(self):
        self.assertIn('GH_TOKEN="${TOOLCHAIN_APP_TOKEN:-$GH_TOKEN}" gh pr create', self.security)
        self.assertIn('GH_TOKEN="${TOOLCHAIN_APP_TOKEN:-$GH_TOKEN}" gh pr merge', self.security)
        self.assertIn('steps.merge-app.outputs.token', self.security)
        self.assertLess(
            self.security.index("- name: Explicitly dispatch exact-head full CI"),
            self.security.index("- name: Refresh scoped App token for post-CI merge"))
        self.assertLess(
            self.security.index("- name: Refresh scoped App token for post-CI merge"),
            self.security.index("- name: Merge only after full CI passes"))


if __name__ == "__main__":
    unittest.main()
