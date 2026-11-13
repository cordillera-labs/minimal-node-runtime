"""Unit tests for scripts/toolchain.py.

Run: python3 -m unittest discover -s tests
The GitHub release lists are fixtures; no test reaches the network.
"""

import datetime
import json
import os
import sys
import unittest
from unittest.mock import patch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import toolchain  # noqa: E402

NOW = datetime.datetime(2026, 11, 6, 3, 0, 0, tzinfo=datetime.timezone.utc)

with open(os.path.join(ROOT, "tests", "fixtures", "github", "trivy-releases.json"), encoding="utf-8") as handle:
    TRIVY_RELEASES = json.load(handle)


def release(tag, published_at, **flags):
    return {"tag_name": tag, "draft": False, "prerelease": False, "published_at": published_at,
            "html_url": f"https://example.test/{tag}", **flags}


class StableReleases(unittest.TestCase):
    def test_skips_prereleases_drafts_and_odd_tags(self):
        tags = [entry[1] for entry in toolchain.stable_releases(TRIVY_RELEASES)]
        self.assertEqual(tags, ["v0.76.2", "v0.76.1", "v0.76.0", "v0.74.0"])

    def test_orders_numerically_not_by_text(self):
        releases = [release("v0.9.0", "2026-01-01T00:00:00Z"), release("v0.10.0", "2025-01-01T00:00:00Z")]
        self.assertEqual(toolchain.stable_releases(releases)[0][1], "v0.10.0")


class Evaluate(unittest.TestCase):
    def test_newest_eligible_release_with_a_newer_one_in_the_cooldown(self):
        result = toolchain.evaluate("trivy", "aquasecurity/trivy", "v0.74.0", TRIVY_RELEASES, NOW)
        self.assertEqual(result["state"], "update")
        self.assertEqual(result["eligible"]["tag"], "v0.76.1")
        self.assertEqual(result["pending"]["tag"], "v0.76.2")
        self.assertEqual(result["pending"]["cooldown_ends"], "2026-11-12")

    def test_a_release_at_exactly_seven_days_is_eligible(self):
        releases = [release("v1.1.0", "2026-10-30T03:00:00Z")]
        self.assertEqual(toolchain.evaluate("t", "o/t", "v1.0.0", releases, NOW)["state"], "update")
        releases = [release("v1.1.0", "2026-10-30T03:00:01Z")]
        self.assertEqual(toolchain.evaluate("t", "o/t", "v1.0.0", releases, NOW)["state"], "pending")

    def test_pending_only(self):
        result = toolchain.evaluate("trivy", "aquasecurity/trivy", "v0.76.1", TRIVY_RELEASES, NOW)
        self.assertEqual(result["state"], "pending")
        self.assertIsNone(result["eligible"])
        self.assertEqual(result["pending"]["tag"], "v0.76.2")

    def test_current_when_the_pin_is_the_newest_or_newer(self):
        for pinned in ("v0.76.2", "v0.80.0"):
            result = toolchain.evaluate("trivy", "aquasecurity/trivy", pinned, TRIVY_RELEASES, NOW)
            self.assertEqual(result["state"], "current", pinned)

    def test_a_prerelease_never_counts(self):
        releases = [release("v2.0.0", "2026-01-01T00:00:00Z", prerelease=True)]
        self.assertEqual(toolchain.evaluate("t", "o/t", "v1.0.0", releases, NOW)["state"], "current")

    def test_an_eligible_release_hides_no_newer_pending_release_of_the_same_age_class(self):
        releases = [release("v1.2.0", "2026-10-01T00:00:00Z"), release("v1.1.0", "2026-09-01T00:00:00Z")]
        result = toolchain.evaluate("t", "o/t", "v1.0.0", releases, NOW)
        self.assertEqual(result["eligible"]["tag"], "v1.2.0")
        self.assertIsNone(result["pending"])


class PinReaders(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(toolchain.version_pin("v0.74.0"), "v0.74.0")
        self.assertIsNone(toolchain.version_pin("0.74.0"))
        self.assertIsNone(toolchain.version_pin("latest"))

    def test_image_pin_reads_the_tag_before_the_digest(self):
        sha = "a" * 64
        self.assertEqual(toolchain.image_pin(f"moby/buildkit:v0.33.1@sha256:{sha}"), "v0.33.1")
        self.assertEqual(toolchain.image_pin(f"gcr.io/projectsigstore/cosign:v2.6.1@sha256:{sha}"), "v2.6.1")
        self.assertIsNone(toolchain.image_pin(f"moby/buildkit@sha256:{sha}"))


class Check(unittest.TestCase):
    PINS = {
        "TRIVY_VERSION": "v0.74.0",
        "BUILDX_VERSION": "v0.37.2",
        "BUILDKIT_IMAGE": "moby/buildkit:v0.33.1@sha256:" + "a" * 64,
        "COSIGN_IMAGE": "gcr.io/projectsigstore/cosign:v2.6.1@sha256:" + "b" * 64,
        "IMAGE_REPOSITORY": "ghcr.io/example/image",
    }

    def by_tool(self, results):
        return {result["tool"]: result for result in results}

    def test_one_result_per_tool(self):
        calls = []

        def fetch(repo):
            calls.append(repo)
            return TRIVY_RELEASES if repo == "aquasecurity/trivy" else [release("v9.0.0", "2026-01-01T00:00:00Z")]

        results = self.by_tool(toolchain.check(self.PINS, fetch, NOW))
        self.assertEqual(set(results), {"trivy", "buildkit", "buildx", "cosign"})
        self.assertEqual(sorted(calls), sorted(repo for _, repo, _ in toolchain.TOOLS.values()))
        self.assertEqual(results["buildkit"]["eligible"]["tag"], "v9.0.0")

    def test_an_unreachable_tool_is_a_fault_and_the_others_still_report(self):
        def fetch(repo):
            if repo == "moby/buildkit":
                raise ConnectionError("HTTP 403")
            return TRIVY_RELEASES

        results = self.by_tool(toolchain.check(self.PINS, fetch, NOW))
        self.assertEqual(results["buildkit"]["state"], "fault")
        self.assertIn("HTTP 403", results["buildkit"]["message"])
        self.assertEqual(results["trivy"]["state"], "update")

    def test_an_empty_or_prerelease_only_list_is_a_fault_not_current(self):
        for releases in ([], [release("v2.0.0", "2026-01-01T00:00:00Z", prerelease=True)]):
            results = self.by_tool(toolchain.check(self.PINS, lambda repo, r=releases: r, NOW))
            self.assertEqual(results["trivy"]["state"], "fault")

    def test_an_unreadable_pin_is_a_fault(self):
        pins = dict(self.PINS, TRIVY_VERSION="latest")
        results = self.by_tool(toolchain.check(pins, lambda repo: TRIVY_RELEASES, NOW))
        self.assertEqual(results["trivy"]["state"], "fault")

    def test_a_new_pin_without_a_checker_is_a_fault(self):
        pins = dict(self.PINS, SYFT_VERSION="v1.0.0")
        results = toolchain.check(pins, lambda repo: TRIVY_RELEASES, NOW)
        self.assertTrue(any(r["state"] == "fault" and r["tool"] == "SYFT_VERSION" for r in results))

    def test_the_committed_toolchain_env_is_fully_covered_and_readable(self):
        pins = toolchain.read_pins(os.path.join(ROOT, "toolchain.env"))
        self.assertEqual(set(pins) - toolchain.NOT_A_TOOL, set(toolchain.TOOLS))
        for key, (_, _, read_pin) in toolchain.TOOLS.items():
            self.assertIsNotNone(read_pin(pins[key]), key)


class GithubPublicFallback(unittest.TestCase):
    def test_403_scoped_token_retries_public_release_endpoint(self):
        with patch.dict(os.environ, {"GH_TOKEN": "restricted-token"}):
            with patch.object(toolchain.upstream, "get", side_effect=[
                ConnectionError("HTTP 403: Forbidden"),
                json.dumps([release("v0.76.2", "2026-11-05T00:00:00Z")]).encode(),
            ]) as get:
                found = toolchain.github_releases("aquasecurity/trivy")
        self.assertEqual(found[0]["tag_name"], "v0.76.2")
        self.assertIn("Authorization", get.call_args_list[0].kwargs["headers"])
        self.assertNotIn("Authorization", get.call_args_list[1].kwargs["headers"])

    def test_404_is_not_mistaken_for_an_authentication_issue(self):
        with patch.dict(os.environ, {"GH_TOKEN": "restricted-token"}):
            with patch.object(toolchain.upstream, "get",
                              side_effect=ConnectionError("HTTP 404")) as get:
                with self.assertRaises(ConnectionError):
                    toolchain.github_releases("aquasecurity/trivy")
                get.assert_called_once()


class TrivyAtomFallback(unittest.TestCase):
    """The GitHub API 403 and the authenticated/release-feed path are distinct."""

    @classmethod
    def setUpClass(cls):
        path = os.path.join(ROOT, "tests", "fixtures", "github", "trivy-releases.atom")
        with open(path, "rb") as handle:
            cls.atom = handle.read()

    def test_feed_includes_only_stable_and_uses_later_updated_date(self):
        releases = toolchain.trivy_atom_releases(self.atom, NOW)
        self.assertEqual([item["tag_name"] for item in releases], ["v0.76.2", "v0.76.1"])
        self.assertEqual(releases[1]["published_at"], "2026-10-23T17:34:44Z")
        result = toolchain.evaluate("trivy", "aquasecurity/trivy", "v0.74.0", releases, NOW)
        self.assertEqual(result["eligible"]["tag"], "v0.76.1")
        self.assertEqual(result["pending"]["tag"], "v0.76.2")

    def test_real_failure_pattern_authenticated_and_public_api_403(self):
        with patch.dict(os.environ, {"GH_TOKEN": "restricted-token"}):
            with patch.object(toolchain.upstream, "get", side_effect=[
                ConnectionError("GET Trivy API: HTTP Error 403: Forbidden"),
                ConnectionError("GET Trivy API: HTTP Error 403: Forbidden"),
                self.atom,
            ]) as get:
                releases = toolchain.github_releases("aquasecurity/trivy")
        self.assertEqual(releases[0]["tag_name"], "v0.76.2")
        self.assertEqual(get.call_count, 3)
        self.assertIn("?per_page=10", get.call_args_list[0].args[0])
        self.assertIn("Authorization", get.call_args_list[0].kwargs["headers"])
        self.assertNotIn("Authorization", get.call_args_list[1].kwargs["headers"])
        self.assertEqual(get.call_args_list[2].args[0], toolchain.TRIVY_ATOM_URL)
        self.assertNotIn("Authorization", get.call_args_list[2].kwargs["headers"])

    def test_public_api_rate_limit_without_token_also_recovers(self):
        with patch.dict(os.environ, {"GH_TOKEN": "", "GITHUB_TOKEN": ""}):
            with patch.object(toolchain.upstream, "get", side_effect=[
                ConnectionError("HTTP 429: Too Many Requests"), self.atom
            ]) as get:
                result = toolchain.github_releases("aquasecurity/trivy")
        self.assertEqual(get.call_count, 2)
        self.assertEqual(result[0]["tag_name"], "v0.76.2")

    def test_trivy_api_success_does_not_call_feed(self):
        expected = [release("v0.76.2", "2026-11-05T12:50:25Z")]
        with patch.object(toolchain.upstream, "get", return_value=json.dumps(expected).encode()) as get:
            actual = toolchain.github_releases("aquasecurity/trivy")
        self.assertEqual(actual, expected)
        get.assert_called_once()

    def test_fallback_not_allowed_on_404_or_for_other_repositories(self):
        with patch.dict(os.environ, {"GH_TOKEN": "restricted-token"}):
            with patch.object(toolchain.upstream, "get", side_effect=ConnectionError("HTTP 404")) as get:
                with self.assertRaises(ConnectionError):
                    toolchain.github_releases("aquasecurity/trivy")
                get.assert_called_once()
            with patch.object(toolchain.upstream, "get", side_effect=ConnectionError("HTTP 403")) as get:
                with self.assertRaises(ConnectionError):
                    toolchain.github_releases("docker/buildx")
                self.assertEqual(get.call_count, 2)

    def test_both_sources_fail_reports_fault_not_current(self):
        with patch.dict(os.environ, {"GH_TOKEN": "restricted-token"}):
            with patch.object(toolchain.upstream, "get", side_effect=[
                ConnectionError("HTTP 403"), ConnectionError("HTTP 403"),
                ConnectionError("HTTP 403"),
            ]):
                def fetch(repo):
                    if repo == "aquasecurity/trivy":
                        return toolchain.github_releases(repo)
                    return [release("v9.0.0", "2026-10-01T00:00:00Z")]
                results = toolchain.check(dict(Check.PINS), fetch, NOW)
        trivy = next(item for item in results if item["tool"] == "trivy")
        self.assertEqual(trivy["state"], "fault")
        self.assertIn("Atom fallback also failed", trivy["message"])

    def test_identity_bad_links_and_bad_timestamps_fail_closed(self):
        variants = [
            self.atom.replace(b"/aquasecurity/trivy/releases</id>", b"/foreign/repo/releases</id>"),
            self.atom.replace(b"releases.atom", b"tags.atom"),
            self.atom.replace(b"aquasecurity/trivy/releases/tag/v0.76.2",
                              b"another/repository/releases/tag/v0.76.2"),
            self.atom.replace(b"2026-11-05T12:50:25Z", b"3000-01-01T00:00:00Z"),
            self.atom.replace(b"2026-11-05T12:50:25Z", b"not-a-timestamp"),
            self.atom.replace(b"</feed>", b""),
            b"<html><body>403</body></html>",
            b"<!DOCTYPE feed [<!ENTITY test 'x'>]><feed></feed>",
        ]
        for raw in variants:
            with self.subTest(raw=raw[:90]):
                with self.assertRaises(ValueError):
                    toolchain.trivy_atom_releases(raw, NOW)

    def test_feed_must_contain_a_stable_release(self):
        data = self.atom.replace(b"/releases/tag/v0.76.2", b"/releases/tag/nightly-1")
        data = data.replace(b"/releases/tag/v0.76.1", b"/releases/tag/nightly-2")
        self.assertRaises(ValueError, toolchain.trivy_atom_releases, data, NOW)


class Rendering(unittest.TestCase):
    def test_issue_text_names_the_tool_pin_and_release(self):
        result = toolchain.evaluate("trivy", "aquasecurity/trivy", "v0.74.0", TRIVY_RELEASES, NOW)
        self.assertEqual(toolchain.issue_title(result), "Toolchain pin update available: trivy")
        body = toolchain.issue_body(result)
        for text in ("v0.74.0", "v0.76.1", "v0.76.2", "2026-11-12", "routine updater proposes"):
            self.assertIn(text, body)

    def test_summary_keeps_a_fault_apart_from_current(self):
        results = [toolchain.fault("cosign", "sigstore/cosign", "boom"),
                   toolchain.evaluate("trivy", "aquasecurity/trivy", "v0.76.2", TRIVY_RELEASES, NOW)]
        text = toolchain.summary(results)
        self.assertIn("- fault: cosign: boom", text)
        self.assertIn("- trivy: v0.76.2 is current", text)


if __name__ == "__main__":
    unittest.main()
