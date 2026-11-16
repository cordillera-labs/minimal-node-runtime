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

    def test_toolchain_pin_push_publishes_without_recursive_record_commits(self):
        self.assertIn('  push:\\n    branches: [main]\\n    paths:\\n      - toolchain.env', self.update)
        self.assertIn('    - cron:', self.update)
        self.assertIn('  workflow_dispatch:', self.update)
        self.assertIn('gh workflow run update.yml --ref main', self.routine)

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
