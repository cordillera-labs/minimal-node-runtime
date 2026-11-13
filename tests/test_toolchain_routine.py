"""Offline regression tests for cooldown-eligible routine pin PR automation."""
import datetime
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import toolchain_routine as routine  # noqa: E402

NOW = datetime.datetime(2026, 11, 13, 12, tzinfo=datetime.timezone.utc)
OLD = {
    "BUILDKIT_IMAGE": "moby/buildkit:v0.33.1@sha256:" + "a" * 64,
    "BUILDX_VERSION": "v0.37.2",
    "COSIGN_IMAGE": "gcr.io/projectsigstore/cosign:v2.6.1@sha256:" + "b" * 64,
    "TRIVY_VERSION": "v0.74.0",
    "IMAGE_REPOSITORY": "ghcr.io/example/runtime",
}
ORDER = (("buildkit", "BUILDKIT_IMAGE", "moby/buildkit", "v0.34.2"),
         ("buildx", "BUILDX_VERSION", "docker/buildx", "v0.38.2"),
         ("cosign", "COSIGN_IMAGE", "sigstore/cosign", "v3.1.4"),
         ("trivy", "TRIVY_VERSION", "aquasecurity/trivy", "v0.76.2"))


def monitor(pins=None, release_at="2026-11-03T12:00:00Z"):
    pins = pins or OLD
    rows = []
    for name, key, repo, target in ORDER:
        rows.append({
            "tool": name, "pinned": routine.toolchain.TOOLS[key][2](pins[key]),
            "state": "update", "eligible": {
                "tag": target, "published_at": release_at,
                "url": f"https://github.com/{repo}/releases/tag/{target}",
            },
        })
    return {"checked_at": NOW.isoformat(), "tools": rows}


def contents(pins=None):
    pins = pins or OLD
    return "# Pinned tools\n" + "".join(f"{k}={v}\n" for k, v in pins.items())


class RoutinePlanning(unittest.TestCase):
    def test_order_and_skip_pending_prs(self):
        report = monitor()
        selected = routine.plan(report, OLD, now=NOW)
        self.assertEqual((selected["tool"], selected["to"]), ("buildkit", "v0.34.2"))
        selected = routine.plan(report, OLD, skip=["buildkit", "buildx"], now=NOW)
        self.assertEqual(selected["tool"], "cosign")
        self.assertTrue(selected["major_change"])
        self.assertEqual(routine.plan(report, OLD, skip=[r[0] for r in ORDER], now=NOW), None)

    def test_never_propose_pending_current_or_fault(self):
        report = monitor()
        for row in report["tools"]:
            row["state"] = "pending"
        self.assertIsNone(routine.plan(report, OLD, now=NOW))
        report["tools"][0]["state"] = "fault"
        report["tools"][1]["state"] = "current"
        self.assertIsNone(routine.plan(report, OLD, now=NOW))

    def test_cooldown_cannot_be_shortened_by_report_state(self):
        report = monitor(release_at="2026-11-09T12:00:00Z")
        with self.assertRaisesRegex(ValueError, "cooldown"):
            routine.plan(report, OLD, now=NOW)
        report = monitor(release_at="2026-11-06T12:00:01Z")
        with self.assertRaisesRegex(ValueError, "cooldown"):
            routine.plan(report, OLD, now=NOW)
        self.assertEqual(routine.plan(monitor(release_at="2026-11-06T12:00:00Z"),
                                      OLD, now=NOW)["tool"], "buildkit")

    def test_reject_stale_or_forged_eligible_release(self):
        report = monitor()
        report["tools"][0]["pinned"] = "v99.0.0"
        with self.assertRaisesRegex(ValueError, "disagree"):
            routine.plan(report, OLD, now=NOW)
        report = monitor()
        report["tools"][0]["eligible"]["url"] = "https://attacker.test/release"
        with self.assertRaisesRegex(ValueError, "metadata"):
            routine.plan(report, OLD, now=NOW)
        report = monitor()
        report["tools"].append(dict(report["tools"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            routine.plan(report, OLD, now=NOW)
        with self.assertRaisesRegex(ValueError, "unknown skipped"):
            routine.plan(monitor(), OLD, skip=["unknown"], now=NOW)


class PinChange(unittest.TestCase):
    def test_binary_upgrade_only_changes_one_line(self):
        before = contents()
        after = before.replace("BUILDX_VERSION=v0.37.2", "BUILDX_VERSION=v0.38.2")
        info = routine.changed_pin(before, after, "buildx")
        self.assertEqual(info["to"], "v0.38.2")
        self.assertFalse(info["major_change"])
        with self.assertRaisesRegex(ValueError, "unrelated changes"):
            routine.changed_pin(before, after + "# surprise\n", "buildx")
        with self.assertRaisesRegex(ValueError, "exactly one"):
            routine.changed_pin(before, before, "buildx")

    def test_digest_and_registry_must_be_pinned(self):
        before = contents()
        for bad in ("moby/buildkit:v0.34.2",
                    "evil/buildkit:v0.34.2@sha256:" + "c" * 64,
                    "moby/buildkit:v0.34.2@sha256:abcd"):
            after = before.replace(OLD["BUILDKIT_IMAGE"], bad)
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                routine.changed_pin(before, after, "buildkit")
        good = before.replace(OLD["BUILDKIT_IMAGE"],
                              "moby/buildkit:v0.34.2@sha256:" + "c" * 64)
        self.assertFalse(routine.changed_pin(before, good, "buildkit")["major_change"])

    def test_major_is_proposed_but_not_treated_as_auto_merge(self):
        before = contents()
        after = before.replace(OLD["COSIGN_IMAGE"],
                               "gcr.io/projectsigstore/cosign:v3.1.4@sha256:" + "c" * 64)
        self.assertTrue(routine.changed_pin(before, after, "cosign")["major_change"])

    def test_apply_checks_current_pin_digest_and_plan(self):
        choice = routine.plan(monitor(), OLD, now=NOW)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "toolchain.env"
            path.write_text(contents(), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "digest"):
                routine.apply(choice, str(path))
            digest = "sha256:" + "c" * 64
            result = routine.apply(choice, str(path), digest)
            self.assertEqual(result, f"moby/buildkit:v0.34.2@{digest}")
            self.assertEqual(routine.changed_pin(contents(), path.read_text(), "buildkit")["to"],
                             "v0.34.2")
            with self.assertRaisesRegex(ValueError, "pin changed"):
                routine.apply(choice, str(path), digest)
            self.assertEqual(path.read_text().count("BUILDKIT_IMAGE="), 1)

    def test_apply_rejects_boolean_mismatch_and_forged_major(self):
        choice = routine.plan(monitor(), OLD, skip=["buildkit", "buildx"], now=NOW)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "toolchain.env"
            path.write_text(contents(), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "classification"):
                routine.apply(dict(choice, major_change=False), str(path), "sha256:" + "c" * 64)
            with self.assertRaisesRegex(ValueError, "digest"):
                routine.apply(choice, str(path), "not-a-digest")
            self.assertEqual(path.read_text(), contents())


if __name__ == "__main__":
    unittest.main()
