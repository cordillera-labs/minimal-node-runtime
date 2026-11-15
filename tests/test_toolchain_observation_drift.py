"""Regression tests for safe main drift while routine toolchain CI is pending."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from toolchain_observation_drift import is_observation_only  # noqa: E402


class ObservationDriftTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)
        self.git("init", "-q")
        self.git("config", "user.name", "Test")
        self.git("config", "user.email", "test@example.invalid")
        self.commit("toolchain.env", "BUILDX_VERSION=v0.37.2\n")
        self.base = self.sha()

    def git(self, *args):
        result = subprocess.run(
            ["git", *args], cwd=self.repo, capture_output=True, text=True,
        )
        if result.returncode:
            self.fail(f"git {args!r} failed: {result.stderr}")
        return result.stdout.strip()

    def sha(self):
        return self.git("rev-parse", "HEAD")

    def commit(self, path, data):
        dest = self.repo / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(data, encoding="utf-8")
        self.git("add", "--", path)
        self.git("commit", "-q", "-m", f"change {path}")

    def test_identical_main_is_safe(self):
        self.assertTrue(is_observation_only(self.repo, self.base, self.base))

    def test_chrome_observation_is_safe(self):
        self.commit("state/trust/chrome.json", '{"commit":"1"}\n')
        self.assertTrue(is_observation_only(self.repo, self.base, self.sha()))

    def test_both_observations_and_heartbeat_are_safe(self):
        self.commit("state/trust/chrome.json", '{"commit":"1"}\n')
        self.commit("state/trust/mozilla.json", '{"commit":"2"}\n')
        self.commit("state/heartbeat", "heartbeat\n")
        self.assertTrue(is_observation_only(self.repo, self.base, self.sha()))

    def test_toolchain_pin_change_is_not_safe(self):
        self.commit("toolchain.env", "BUILDX_VERSION=v0.38.2\n")
        self.assertFalse(is_observation_only(self.repo, self.base, self.sha()))

    def test_automated_certificate_exclusions_are_not_safe(self):
        self.commit("state/trust/chrome.json", '{"commit":"1"}\n')
        self.commit("certificates.auto.exclude", "untrusted-cert\n")
        self.assertFalse(is_observation_only(self.repo, self.base, self.sha()))

    def test_lock_change_is_not_safe(self):
        self.commit("state/22/stable.lock", "changed lock\n")
        self.assertFalse(is_observation_only(self.repo, self.base, self.sha()))

    def test_workflow_change_is_not_safe(self):
        self.commit(".github/workflows/ci.yml", "name: changed\n")
        self.assertFalse(is_observation_only(self.repo, self.base, self.sha()))

    def test_new_snapshot_name_is_not_implicitly_allowlisted(self):
        self.commit("state/trust/other.json", "{}\n")
        self.assertFalse(is_observation_only(self.repo, self.base, self.sha()))

    def test_rename_cannot_hide_unrelated_file_change(self):
        self.commit("scripts/security.py", "print('hello')\n")
        before = self.sha()
        self.git("mv", "scripts/security.py", "state/trust/chrome.json")
        self.git("commit", "-q", "-m", "rename unrelated file")
        self.assertFalse(is_observation_only(self.repo, before, self.sha()))

    def test_non_descendant_main_requires_refresh(self):
        self.commit("state/trust/chrome.json", '{"commit":"1"}\n')
        first_branch = self.sha()
        self.git("checkout", "-q", "-b", "separate", self.base)
        self.commit("state/trust/chrome.json", '{"commit":"2"}\n')
        self.assertFalse(is_observation_only(self.repo, first_branch, self.sha()))

    def test_invalid_commit_fails_closed(self):
        with self.assertRaises(ValueError):
            is_observation_only(self.repo, "0" * 40, self.sha())


if __name__ == "__main__":
    unittest.main()
