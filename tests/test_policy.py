"""Unit tests for scripts/policy.py and scripts/lock.py.

Run: python3 -m unittest discover -s tests
They need `dpkg` for version comparison, as the workflows do.
"""

import datetime
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))
import lock as lockfile  # noqa: E402
import policy  # noqa: E402
import upstream  # noqa: E402

NOW = datetime.datetime(2026, 11, 6, 3, 0, 0, tzinfo=datetime.timezone.utc)
SHA = "a" * 64
SHA_B = "b" * 64
URL = "https://snapshot.debian.org/file/" + "1" * 40
URL_B = "https://snapshot.debian.org/file/" + "2" * 40
HELPER = "docker.io/library/debian:trixie-slim@sha256:" + "c" * 64
HELPER_B = "docker.io/library/debian:trixie-slim@sha256:" + "d" * 64


def days_ago(days):
    return (NOW - datetime.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def base_lock():
    lock = {
        "BUILD_DEFINITION_SHA256": SHA,
        "HELPER_IMAGE": HELPER, "HELPER_IMAGE_RELEASED": days_ago(40),
        "NODE_VERSION": "22.23.4", "NODE_SHA256": SHA, "NODE_RELEASED": "2026-10-20",
        "PUBLISHED_DIGEST": "sha256:" + "e" * 64,
    }
    for package in lockfile.read_packages():
        prefix = f"DEB_{lockfile.package_key(package)}_"
        lock.update({prefix + "VERSION": "1.0-1", prefix + "SUITE": "trixie", prefix + "URL": URL,
                     prefix + "SHA256": SHA, prefix + "RELEASED": days_ago(60)})
    lock["SOURCE_DATE_EPOCH"] = lockfile.derived_epoch(lock)
    return lock


def upstream_same(lock):
    return {
        "build_definition": lock["BUILD_DEFINITION_SHA256"],
        "helper": {"image": lock["HELPER_IMAGE"], "created": None},
        "node": {"releases": [{"version": "22.23.4", "date": "2026-10-20", "security": True, "sha256": SHA}]},
        "debian": {package: {"version": "1.0-1", "suite": "trixie", "archive": "debian",
                             "filename": "x", "sha256": SHA}
                   for package in lockfile.read_packages()},
        "faults": [], "warnings": [],
    }


def scan_with(package, cve, fixed):
    return {"Results": [{"Vulnerabilities": [
        {"PkgName": package, "VulnerabilityID": cve, "FixedVersion": fixed, "Severity": "HIGH"}]}]}


class NodeDecision(unittest.TestCase):
    def releases(self, *entries):
        return [{"version": v, "date": d, "security": s, "sha256": SHA_B} for v, d, s in entries]

    def test_holds_a_release_inside_the_cooldown(self):
        changes, pending = policy.decide_node(base_lock(), self.releases(("22.24.0", "2026-11-03", False)), NOW)
        self.assertEqual(changes, {})
        self.assertIn("22.24.0", pending[0])
        self.assertIn("eligible 2026-11-10", pending[0])

    def test_accepts_a_release_after_the_cooldown(self):
        changes, _ = policy.decide_node(base_lock(), self.releases(("22.24.0", "2026-10-30", False)), NOW)
        self.assertEqual(changes["NODE_VERSION"], "22.24.0")
        self.assertTrue(changes["NODE_ACCEPTED"].startswith("cooldown elapsed"))

    def test_cooldown_boundary_is_exactly_seven_days(self):
        exactly = (NOW - datetime.timedelta(days=policy.COOLDOWN_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.assertTrue(policy.aged(exactly, NOW))
        just_short = (NOW - datetime.timedelta(days=policy.COOLDOWN_DAYS) + datetime.timedelta(seconds=1))
        self.assertFalse(policy.aged(just_short.strftime("%Y-%m-%dT%H:%M:%SZ"), NOW))

    def test_security_release_skips_the_cooldown(self):
        changes, _ = policy.decide_node(base_lock(), self.releases(("22.24.0", "2026-11-05", True)), NOW)
        self.assertEqual(changes["NODE_VERSION"], "22.24.0")
        self.assertTrue(changes["NODE_ACCEPTED"].startswith("security"))

    def test_takes_the_newest_eligible_and_keeps_newer_pending(self):
        changes, pending = policy.decide_node(base_lock(), self.releases(
            ("22.24.0", "2026-10-25", False), ("22.24.1", "2026-11-05", True), ("22.25.0", "2026-11-06", False)), NOW)
        self.assertEqual(changes["NODE_VERSION"], "22.24.1")
        self.assertEqual(len(pending), 1)
        self.assertIn("22.25.0", pending[0])

    def test_older_releases_are_ignored(self):
        changes, pending = policy.decide_node(base_lock(), self.releases(("22.23.4", "2026-10-20", True)), NOW)
        self.assertEqual((changes, pending), ({}, []))


class HelperDecision(unittest.TestCase):
    def test_unchanged(self):
        self.assertEqual(policy.decide_helper(base_lock(), {"image": HELPER, "created": None}, NOW), ({}, []))

    def test_holds_a_new_image_inside_the_cooldown(self):
        changes, pending = policy.decide_helper(base_lock(), {"image": HELPER_B, "created": days_ago(2)}, NOW)
        self.assertEqual(changes, {})
        self.assertEqual(len(pending), 1)

    def test_holds_an_image_with_no_date(self):
        changes, pending = policy.decide_helper(base_lock(), {"image": HELPER_B, "created": None}, NOW)
        self.assertEqual(changes, {})
        self.assertIn("release date unknown", pending[0])

    def test_accepts_after_the_cooldown(self):
        changes, _ = policy.decide_helper(base_lock(), {"image": HELPER_B, "created": days_ago(8)}, NOW)
        self.assertEqual(changes["HELPER_IMAGE"], HELPER_B)


class DebianDecision(unittest.TestCase):
    def entry(self, **overrides):
        entry = {"version": "1.0-2", "suite": "trixie-security", "archive": "debian-security",
                 "filename": "x", "sha256": SHA_B, "url": URL_B, "released": days_ago(1)}
        entry.update(overrides)
        return entry

    def decide(self, entry, scan=None):
        debian = upstream_same(base_lock())["debian"]
        debian["libc6"] = entry
        return policy.decide_debian(base_lock(), debian, policy.security_fixes(scan), NOW)

    def test_holds_inside_the_cooldown(self):
        changes, pending, _ = self.decide(self.entry())
        self.assertEqual(changes, {})
        self.assertIn("libc6 1.0-2", pending[0])

    def test_accepts_after_the_cooldown(self):
        changes, _, _ = self.decide(self.entry(released=days_ago(8)))
        self.assertEqual(changes["DEB_LIBC6_VERSION"], "1.0-2")
        self.assertEqual(changes["DEB_LIBC6_RELEASED"], days_ago(8))
        self.assertTrue(changes["DEB_LIBC6_ACCEPTED"].startswith("cooldown elapsed"))

    def test_security_fix_skips_the_cooldown(self):
        changes, pending, _ = self.decide(self.entry(), scan_with("libc6", "CVE-2026-1", "1.0-2"))
        self.assertEqual(pending, [])
        self.assertEqual(changes["DEB_LIBC6_ACCEPTED"], "security (fixes CVE-2026-1)")

    def test_a_fix_above_the_new_version_is_not_security(self):
        changes, pending, _ = self.decide(self.entry(), scan_with("libc6", "CVE-2026-1", "1.0-3"))
        self.assertEqual(changes, {})
        self.assertEqual(len(pending), 1)

    def test_a_fix_for_another_package_is_not_security(self):
        changes, _, _ = self.decide(self.entry(), scan_with("libstdc++6", "CVE-2026-1", "1.0-2"))
        self.assertEqual(changes, {})

    def test_holds_without_a_snapshot_url(self):
        changes, pending, _ = self.decide(self.entry(url=None), scan_with("libc6", "CVE-2026-1", "1.0-2"))
        self.assertEqual(changes, {})
        self.assertIn("not on snapshot", pending[0])

    def test_holds_without_a_release_date_even_for_security(self):
        changes, pending, _ = self.decide(self.entry(released=None), scan_with("libc6", "CVE-2026-1", "1.0-2"))
        self.assertEqual(changes, {})
        self.assertIn("no release date", pending[0])

    def test_never_downgrades(self):
        changes, pending, warnings = self.decide(self.entry(version="0.9-1", released=days_ago(30)))
        self.assertEqual((changes, pending), ({}, []))
        self.assertIn("older", warnings[0])


class Plan(unittest.TestCase):
    def test_no_change(self):
        lock = base_lock()
        result, nextlock = policy.plan(lock, {}, upstream_same(lock), None, NOW)
        self.assertEqual(result["action"], "none")
        self.assertIsNone(nextlock)

    def test_first_publish_builds_the_lock_as_is(self):
        lock = base_lock()
        del lock["PUBLISHED_DIGEST"]
        result, nextlock = policy.plan(lock, {}, upstream_same(lock), None, NOW)
        self.assertEqual(result["action"], "build")
        self.assertTrue(policy.same_inputs(nextlock, lock, ignore_epoch=False))

    def test_eligible_change_builds_and_records_the_evaluation(self):
        lock = base_lock()
        upstream = upstream_same(lock)
        upstream["node"]["releases"].append({"version": "22.24.0", "date": "2026-10-28", "security": False,
                                             "sha256": SHA_B})
        result, nextlock = policy.plan(lock, {}, upstream, None, NOW)
        self.assertEqual(result["action"], "build")
        self.assertEqual(nextlock["NODE_VERSION"], "22.24.0")
        self.assertEqual(nextlock["EVALUATED_AT"], "2026-11-06T03:00:00Z")
        self.assertNotIn("PUBLISHED_DIGEST", nextlock)

    def test_same_upstream_and_time_give_the_same_decision(self):
        lock = base_lock()
        upstream = upstream_same(lock)
        upstream["node"]["releases"].append({"version": "22.24.0", "date": "2026-10-28", "security": False,
                                             "sha256": SHA_B})
        first = policy.plan(lock, {}, upstream, None, NOW)
        second = policy.plan(lock, {}, upstream, None, NOW)
        self.assertEqual(first, second)

    def test_a_repository_change_builds(self):
        lock = base_lock()
        upstream = upstream_same(lock)
        upstream["build_definition"] = SHA_B
        result, nextlock = policy.plan(lock, {}, upstream, None, NOW)
        self.assertEqual(result["action"], "build")
        self.assertEqual(nextlock["BUILD_DEFINITION_ACCEPTED"], "repository change")

    def test_upstream_fault_builds_nothing(self):
        lock = base_lock()
        upstream = upstream_same(lock)
        upstream["faults"] = [{"kind": "upstream", "input": "debian", "message": "x"}]
        result, nextlock = policy.plan(lock, {}, upstream, None, NOW)
        self.assertEqual(result["action"], "none")
        self.assertIsNone(nextlock)

    def test_signature_fault_keeps_other_inputs_moving(self):
        lock = base_lock()
        upstream = upstream_same(lock)
        upstream["node"]["releases"] = []
        upstream["faults"] = [{"kind": "signature", "input": "node", "message": "bad"}]
        upstream["helper"] = {"image": HELPER_B, "created": days_ago(9)}
        result, nextlock = policy.plan(lock, {}, upstream, None, NOW)
        self.assertEqual(result["action"], "build")
        self.assertEqual(nextlock["NODE_VERSION"], "22.23.4")
        self.assertEqual(result["faults"][0]["kind"], "signature")

    def test_pending_candidate_without_a_stable_subset_waits(self):
        lock = base_lock()
        upstream = upstream_same(lock)
        upstream["debian"]["libc6"].update(version="1.0-2", url=URL_B, sha256=SHA_B, released=days_ago(9))
        _, nextlock = policy.plan(lock, {}, upstream, None, NOW)
        candidate = dict(nextlock, PUBLISHED_DIGEST="sha256:" + "f" * 64, BREAKING_PACKAGES="libc6")
        result, again = policy.plan(lock, candidate, upstream, None, NOW)
        self.assertEqual(result["action"], "none")
        self.assertIn("awaits promotion", result["summary"])
        self.assertIsNone(again)

    def test_pending_candidate_with_a_stable_subset_builds_it(self):
        lock = base_lock()
        upstream = upstream_same(lock)
        upstream["debian"]["libc6"].update(version="1.0-2", url=URL_B, sha256=SHA_B, released=days_ago(9))
        upstream["helper"] = {"image": HELPER_B, "created": days_ago(9)}
        _, nextlock = policy.plan(lock, {}, upstream, None, NOW)
        candidate = dict(nextlock, PUBLISHED_DIGEST="sha256:" + "f" * 64, BREAKING_PACKAGES="libc6")
        result, subset = policy.plan(lock, candidate, upstream, None, NOW)
        self.assertEqual((result["action"], result["policy"]), ("build", "stable-only"))
        self.assertEqual(subset["DEB_LIBC6_VERSION"], "1.0-1")
        self.assertEqual(subset["HELPER_IMAGE"], HELPER_B)


class Epoch(unittest.TestCase):
    def test_is_the_newest_release_time(self):
        lock = base_lock()
        lock["DEB_LIBC6_RELEASED"] = "2026-11-01T06:00:00Z"
        self.assertEqual(lockfile.derived_epoch(lock), str(int(datetime.datetime(
            2026, 11, 1, 6, tzinfo=datetime.timezone.utc).timestamp())))

    def test_a_date_counts_as_midnight_utc(self):
        lock = {"NODE_RELEASED": "2026-10-20"}
        self.assertEqual(lockfile.derived_epoch(lock), "1792454400")

    def test_fractional_seconds_are_truncated(self):
        lock = {"DEB_LIBC6_RELEASED": "2026-11-04T21:23:39.987654321Z"}
        self.assertEqual(lockfile.derived_epoch(lock), "1793827419")

    def test_the_helper_image_does_not_move_the_epoch(self):
        lock = base_lock()
        newer_helper = dict(lock, HELPER_IMAGE=HELPER_B, HELPER_IMAGE_RELEASED=days_ago(0))
        self.assertEqual(lockfile.derived_epoch(newer_helper), lockfile.derived_epoch(lock))

    def test_no_release_time_is_a_fault(self):
        with self.assertRaises(lockfile.LockError):
            lockfile.derived_epoch({})


class Channel(unittest.TestCase):
    MANIFEST = {"usr/lib/x86_64-linux-gnu/libc.so.6": ("libc6", "file"),
                "var/lib/dpkg/status.d/libc6": ("dpkg-metadata", "file"),
                "etc/passwd": ("generated", "file")}

    def test_equal_manifest_is_stable(self):
        decision, subset = policy.channel(base_lock(), base_lock(), dict(self.MANIFEST), dict(self.MANIFEST),
                                          "auto", NOW)
        self.assertEqual((decision["channel"], decision["breaking"], subset), ("stable", [], None))

    def test_first_publish_is_stable(self):
        decision, _ = policy.channel(base_lock(), base_lock(), None, dict(self.MANIFEST), "auto", NOW)
        self.assertEqual(decision["channel"], "stable")

    def test_status_metadata_changes_count_against_their_package(self):
        new = dict(self.MANIFEST)
        new["var/lib/dpkg/status.d/libc6.md5sums"] = ("dpkg-metadata", "file")
        self.assertEqual(policy.breaking_owners(self.MANIFEST, new), ["libc6"])

    def test_a_type_change_is_breaking(self):
        new = dict(self.MANIFEST)
        new["usr/lib/x86_64-linux-gnu/libc.so.6"] = ("libc6", "link:libc-2.42.so")
        self.assertEqual(policy.breaking_owners(self.MANIFEST, new), ["libc6"])

    def breaking_lock(self, accepted):
        lock = base_lock()
        lock.update(DEB_LIBC6_VERSION="1.0-2", DEB_LIBC6_URL=URL_B, DEB_LIBC6_ACCEPTED=accepted,
                    DEB_LIBSTDCXX6_VERSION="1.0-2", DEB_LIBSTDCXX6_URL=URL_B,
                    DEB_LIBSTDCXX6_ACCEPTED="cooldown elapsed (x)")
        return lock

    def soname_change(self):
        new = dict(self.MANIFEST)
        del new["usr/lib/x86_64-linux-gnu/libc.so.6"]
        new["usr/lib/x86_64-linux-gnu/libc.so.7"] = ("libc6", "file")
        return new

    def test_breaking_non_security_goes_to_candidate_with_a_stable_subset(self):
        lock = self.breaking_lock("cooldown elapsed (x)")
        decision, subset = policy.channel(lock, base_lock(), dict(self.MANIFEST), self.soname_change(), "auto", NOW)
        self.assertEqual((decision["channel"], decision["breaking"]), ("candidate", ["libc6"]))
        self.assertTrue(decision["split"])
        self.assertEqual(subset["DEB_LIBC6_VERSION"], "1.0-1")
        self.assertEqual(subset["DEB_LIBSTDCXX6_VERSION"], "1.0-2")

    def test_breaking_security_goes_to_stable_and_flags_it(self):
        lock = self.breaking_lock("security (fixes CVE-2026-1)")
        decision, subset = policy.channel(lock, base_lock(), dict(self.MANIFEST), self.soname_change(), "auto", NOW)
        self.assertEqual(decision["channel"], "stable")
        self.assertTrue(decision["security_breaking"])
        self.assertIsNone(subset)

    def test_stable_only_policy_fails_on_a_non_security_break(self):
        lock = self.breaking_lock("cooldown elapsed (x)")
        decision, _ = policy.channel(lock, base_lock(), dict(self.MANIFEST), self.soname_change(), "stable-only", NOW)
        self.assertEqual(decision["channel"], "fail")

    def test_a_breaking_repository_change_never_splits(self):
        lock = self.breaking_lock("security (fixes CVE-2026-1)")
        lock["BUILD_DEFINITION_SHA256"] = SHA_B
        decision, subset = policy.channel(lock, base_lock(), dict(self.MANIFEST), self.soname_change(), "auto", NOW)
        self.assertEqual(decision["channel"], "candidate")
        self.assertFalse(decision["split"])
        self.assertIsNone(subset)

    def test_a_generated_file_change_never_splits(self):
        lock = self.breaking_lock("cooldown elapsed (x)")
        new = dict(self.MANIFEST)
        new["etc/hosts"] = ("generated", "file")
        decision, subset = policy.channel(lock, base_lock(), dict(self.MANIFEST), new, "auto", NOW)
        self.assertEqual(decision["channel"], "candidate")
        self.assertIsNone(subset)


class LockFile(unittest.TestCase):
    def test_rejects_an_unknown_key(self):
        with self.assertRaises(lockfile.LockError):
            lockfile.parse("SOMETHING=1\n")

    def test_rejects_a_value_outside_its_pattern(self):
        with self.assertRaises(lockfile.LockError):
            lockfile.parse("NODE_VERSION=24.0\n")
        with self.assertRaises(lockfile.LockError):
            lockfile.parse("DEB_LIBC6_URL=https://deb.debian.org/x.deb\n")
        with self.assertRaises(lockfile.LockError):
            lockfile.parse("HELPER_IMAGE=docker.io/library/debian:trixie-slim\n")

    def test_rejects_shell_metacharacters_in_a_version(self):
        with self.assertRaises(lockfile.LockError):
            lockfile.parse("DEB_LIBC6_VERSION=1.0;rm\n")

    def test_inputs_hash_ignores_records_and_publication(self):
        lock = base_lock()
        recorded = dict(lock, NODE_ACCEPTED="initial", PUBLISHED_RUN="https://github.com/o/r/actions/runs/1")
        self.assertEqual(lockfile.inputs_hash(lock), lockfile.inputs_hash(recorded))

    def test_inputs_hash_tracks_inputs(self):
        lock = base_lock()
        self.assertNotEqual(lockfile.inputs_hash(lock), lockfile.inputs_hash(dict(lock, NODE_SHA256=SHA_B)))

    def test_render_round_trips(self):
        lock = base_lock()
        text = lockfile.render(lock, "stable", lockfile.read_packages())
        self.assertEqual(lockfile.parse(text), lock)

    def test_package_keys(self):
        self.assertEqual(lockfile.package_key("libstdc++6"), "LIBSTDCXX6")
        self.assertEqual(lockfile.package_key("gcc-14-base"), "GCC_14_BASE")

    def test_a_toolchain_change_changes_the_build_definition(self):
        self.assertIn("toolchain.env", lockfile.BUILD_DEFINITION_FILES)
        with tempfile.TemporaryDirectory() as root:
            for name in lockfile.BUILD_DEFINITION_FILES:
                os.makedirs(os.path.join(root, os.path.dirname(name)), exist_ok=True)
                shutil.copy(os.path.join(lockfile.REPO_ROOT, name), os.path.join(root, name))
            before = lockfile.build_definition_hash(root)
            self.assertEqual(before, lockfile.build_definition_hash())
            with open(os.path.join(root, "toolchain.env"), "a", encoding="utf-8") as handle:
                handle.write("BUILDX_VERSION=v0.0.0\n")
            self.assertNotEqual(lockfile.build_definition_hash(root), before)

    def test_every_committed_lock_is_valid_and_on_its_line(self):
        lines = lockfile.lines()
        self.assertIn("22", lines)
        self.assertIn("24", lines)
        for line in lines:
            for channel in ("stable", "candidate"):
                path = os.path.join(lockfile.REPO_ROOT, "state", line, f"{channel}.lock")
                if channel == "candidate" and not os.path.exists(path):
                    continue
                with self.subTest(line=line, channel=channel):
                    lock = lockfile.load(path)
                    lockfile.require_complete(lock, lockfile.read_packages())
                    self.assertEqual(lock["SOURCE_DATE_EPOCH"], lockfile.derived_epoch(lock))
                    self.assertEqual(lockfile.line_of(lock), line)


class Lines(unittest.TestCase):
    def test_the_line_is_the_node_major(self):
        lock = base_lock()
        self.assertEqual(lockfile.line_of(lock), "22")
        lock["NODE_VERSION"] = "24.22.2"
        self.assertEqual(lockfile.line_of(lock), "24")

    def test_the_immutable_tag_carries_the_line(self):
        lock = base_lock()
        lock["NODE_VERSION"] = "24.22.2"
        self.assertTrue(lockfile.image_tag(lock).startswith("24.22.2-trixie-"))
        lockfile.validate("PUBLISHED_TAG", lockfile.image_tag(lock))

    def test_rejects_a_malformed_major(self):
        for version in ("024.1.0", "v24.1.0", "24.1", "1234.0.0"):
            with self.assertRaises(lockfile.LockError, msg=version):
                lockfile.validate("NODE_VERSION", version)

    def test_lines_are_the_state_directories_with_a_stable_lock(self):
        with tempfile.TemporaryDirectory() as root:
            for name, lock in (("22", True), ("24", True), ("26", False), ("notes", True)):
                os.makedirs(os.path.join(root, "state", name))
                if lock:
                    open(os.path.join(root, "state", name, "stable.lock"), "w").close()
            self.assertEqual(lockfile.lines(root), ["22", "24"])

    def test_upstream_offers_only_releases_of_the_lock_major(self):
        index = [{"version": v, "files": ["linux-x64"]} for v in
                 ("v26.0.0", "v24.22.2", "v24.22.1", "v22.24.0", "v22.23.4", "v22.23.3", "v2.4.0", "v222.0.0")]
        index.append({"version": "v22.25.0", "files": ["linux-arm64"]})
        self.assertEqual([v for v, _ in upstream.line_entries(index, "22.23.4")], ["22.24.0", "22.23.4"])
        self.assertEqual([v for v, _ in upstream.line_entries(index, "24.22.1")], ["24.22.2", "24.22.1"])

if __name__ == "__main__":
    unittest.main()
