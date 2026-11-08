"""Offline tests for published-advisory-only toolchain security automation."""
import datetime
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import toolchain_security as sec  # noqa: E402


def release(v, date="2026-11-07T12:00:00Z", **other):
    return {"tag_name":v, "published_at":date, "html_url":f"https://example.test/{v}",
            "draft":False, "prerelease":False, **other}


def advisory(tool, low, high, fixed, ghsa="GHSA-abcd-1234-efgh", **overrides):
    return {
        "ghsa_id": ghsa, "state": "published", "published_at": "2026-11-07T00:00:00Z",
        "withdrawn_at": None,
        "html_url": f"https://github.com/{tool}/security/advisories/{ghsa}",
        "vulnerabilities": [{"package": {"ecosystem": "go", "name": tool},
                             "vulnerable_version_range": f">= {low}, < {high}",
                             "patched_versions": fixed}],
        **overrides,
    }


class Ranges(unittest.TestCase):
    def test_all_comparators_and_unknowns(self):
        self.assertTrue(sec.affected((0, 33, 1), ">= 0.26.0, < 0.34.2"))
        self.assertFalse(sec.affected((0, 34, 2), ">= 0.26.0, < 0.34.2"))
        self.assertTrue(sec.affected((0, 34, 1), "> 0.34.0, <= 0.34.1"))
        self.assertTrue(sec.affected((0, 33, 1), "v0.26.0 - v0.34.1"))
        self.assertFalse(sec.affected((0, 34, 2), "v0.26.0 - v0.34.1"))
        self.assertIsNone(sec.affected((0, 33, 1), "v0.35.1 - v0.34.1"))
        self.assertTrue(sec.affected((2, 6, 5), "= 2.6.5"))
        for bad in ("", "*", "^2.6", "<= v2.6.x", "<2.6.5; rm -rf ~", "2.6.5", None,
                    "> 9.0.0, UNKNOWN"):
            self.assertIsNone(sec.affected((2, 6, 4), bad))

    def test_empty_unsupported_or_withdrawn_advisory_no_fast_path(self):
        direct = advisory("github.com/moby/buildkit", "0.20.0", "0.34.2", "0.34.2")
        release_list = [release("v0.34.2")]
        for ignored in (
            dict(direct, withdrawn_at="2026-11-07"),
            dict(direct, state="draft"),
            dict(direct, ghsa_id="not-ghsa"),
            dict(direct, vulnerabilities=[dict(direct["vulnerabilities"][0],
                                              package={"ecosystem":"go","name":"another/dependency"})]),
            dict(direct, vulnerabilities=[dict(direct["vulnerabilities"][0],
                                              package={"ecosystem":"npm","name":"github.com/moby/buildkit"})]),
        ):
            self.assertIsNone(sec.pick("buildkit", "moby/buildkit", "v0.33.1",release_list,[ignored]))


class Selection(unittest.TestCase):
    def test_security_fix_bypasses_cooldown_but_is_not_major_upgrade(self):
        releases = [release("v0.34.1", "2026-10-20T00:00:00Z"),
                    release("v0.34.2", "2026-11-07T00:00:00Z"),
                    release("v0.35.0-rc1", "2026-11-08T00:00:00Z", prerelease=True)]
        data = [advisory("github.com/moby/buildkit","0.26.0","0.34.2","0.34.2")]
        result = sec.pick("buildkit","moby/buildkit","v0.33.1",releases,data)
        self.assertEqual(result["to"],"v0.34.2")
        self.assertTrue(result["cooldown_bypassed"])
        self.assertEqual(result["advisories"],["GHSA-abcd-1234-efgh"])

    def test_untyped_buildkit_cve_advisory_with_version_span(self):
        entry=advisory("github.com/moby/buildkit","0.26.0","0.34.2","v0.34.2+",
                       cve_id="CVE-2026-121522")
        item=entry["vulnerabilities"][0]
        item["package"]={"ecosystem":"other","name":None}
        item["vulnerable_version_range"]="v0.26.0 - v0.34.1"
        result=sec.pick("buildkit","moby/buildkit","v0.33.1",
                        [release("v0.34.1"),release("v0.34.2")],[entry])
        self.assertEqual(result["to"],"v0.34.2")

    def test_untyped_buildx_cve_with_comparison_range(self):
        entry=advisory("github.com/docker/buildx","0.19.0","0.38.1","v0.38.1+",
                       cve_id="CVE-2026-121541")
        item=entry["vulnerabilities"][0]
        item["package"]=None
        item["vulnerable_version_range"]="<=v0.38.0"
        result=sec.pick("buildx","docker/buildx","v0.37.2",
                        [release("v0.38.1"),release("v0.38.2")],[entry])
        self.assertEqual(result["to"],"v0.38.1")

    def test_untyped_advisory_without_cve_cannot_upgrade(self):
        entry=advisory("github.com/moby/buildkit","0.26.0","0.34.2","v0.34.2+")
        entry["vulnerabilities"][0]["package"]={"ecosystem":"other","name":None}
        self.assertIsNone(sec.pick("buildkit","moby/buildkit","v0.33.1",
                                   [release("v0.34.2")],[entry]))

    def test_cosign_uses_patched_major_2_not_major_3(self):
        releases=[release("v3.1.4"),release("v2.6.5"),release("v2.6.4")]
        entries=[advisory("github.com/sigstore/cosign/v2","2.6.0","2.6.5","2.6.5")]
        target=sec.pick("cosign","sigstore/cosign","v2.6.1",releases,entries)
        self.assertEqual(target["to"],"v2.6.5")

    def test_not_related_dependency_or_release_notes_claim(self):
        releases=[release("v0.76.2")]
        data=[advisory("golang.org/x/net","0.1.0","0.62.0","0.62.0")]
        self.assertIsNone(sec.pick("trivy","aquasecurity/trivy","v0.74.0",releases,data))

    def test_global_advisory_format_is_supported_without_weakening_repo_format(self):
        data=advisory("github.com/sigstore/cosign/v2","2.6.0","2.6.5","2.6.5")
        entry=data["vulnerabilities"][0]
        entry.pop("patched_versions")
        entry["first_patched_version"]={"identifier":"2.6.5"}
        target=sec.pick("cosign","sigstore/cosign","v2.6.1",[release("v2.6.5")],[data])
        self.assertEqual(target["to"],"v2.6.5")

    def test_only_major_fix_requires_human_review(self):
        releases=[release("v3.1.4")]
        data=[advisory("github.com/sigstore/cosign/v2","2.6.0","3.0.0","3.0.0")]
        self.assertIsNone(sec.pick("cosign","sigstore/cosign","v2.6.1",releases,data))

    def test_all_advisories_must_be_resolved(self):
        releases=[release("v0.34.1"),release("v0.34.2")]
        old=advisory("github.com/moby/buildkit","0.22.0","0.34.1","0.34.1")
        newer=advisory("github.com/moby/buildkit","0.26.0","0.34.2","0.34.2",
                       ghsa="GHSA-aaaa-bbbb-cccc")
        self.assertEqual(sec.pick("buildkit","moby/buildkit","v0.33.1",
                                  releases,[old,newer])["to"],"v0.34.2")

    def test_unparseable_direct_advisory_blocks_automation(self):
        bad=advisory("github.com/moby/buildkit","0.20.0","0.34.2","0.34.2")
        bad["vulnerabilities"][0]["vulnerable_version_range"]=">= 0.1.0 || < 0.34.2"
        with self.assertRaisesRegex(ValueError,"unparseable"):
            sec.pick("buildkit","moby/buildkit","v0.33.1",[release("v0.34.2")],[bad])

    def test_missing_fixed_version_blocks_automation(self):
        bad=advisory("github.com/moby/buildkit","0.20.0","0.34.2","0.34.2")
        bad["vulnerabilities"][0]["patched_versions"]=None
        with self.assertRaisesRegex(ValueError,"patched version"):
            sec.pick("buildkit","moby/buildkit","v0.33.1",[release("v0.34.2")],[bad])


class Plan(unittest.TestCase):
    PINS = {
        "TRIVY_VERSION":"v0.74.0","BUILDX_VERSION":"v0.37.2",
        "BUILDKIT_IMAGE":"moby/buildkit:v0.33.1@sha256:"+"a"*64,
        "COSIGN_IMAGE":"gcr.io/projectsigstore/cosign:v2.6.1@sha256:"+"b"*64,
    }

    def test_one_tool_per_run_builder_first(self):
        def adv(repo):
            if repo=="moby/buildkit":
                return [advisory("github.com/moby/buildkit","0.20.0","0.34.2","0.34.2")]
            if repo=="docker/buildx":
                return [advisory("github.com/docker/buildx","0.20.0","0.38.2","0.38.2")]
            return []
        def releases(repo):
            return [release("v0.34.2") if repo=="moby/buildkit" else
                    release("v0.38.2") if repo=="docker/buildx" else release("v3.1.4")]
        result=sec.plan(self.PINS,releases,adv)
        self.assertEqual(result["selected"]["tool"],"buildkit")
        self.assertEqual([x["tool"] for x in result["queued"]],["buildx"])

    def test_fault_is_visible_and_no_guess_when_api_unavailable(self):
        def adv(repo):
            if repo=="moby/buildkit":
                raise ConnectionError("HTTP 403")
            return []
        result=sec.plan(self.PINS,lambda repo:[release("v0.99.9")],adv)
        self.assertIsNone(result["selected"])
        self.assertTrue(any("buildkit" in fault and "403" in fault for fault in result["faults"]))


class LiveFeedValidation(unittest.TestCase):
    def test_public_403_fallback(self):
        data=[release("v0.34.2")]
        with patch.dict(os.environ, {"GH_TOKEN":"scoped-token"}):
            with patch.object(sec.upstream, "get", side_effect=[
                ConnectionError("HTTP 403"),json.dumps(data).encode()]) as get:
                result=sec.github_list("https://api.github.com/repos/moby/buildkit/releases?per_page=50")
        self.assertEqual(result, data)
        self.assertIn("Authorization", get.call_args_list[0].kwargs["headers"])
        self.assertNotIn("Authorization", get.call_args_list[1].kwargs["headers"])

    def test_truncated_advisory_feed_fails_closed(self):
        with patch.object(sec.upstream, "get", return_value=json.dumps([{}]*100).encode()):
            with self.assertRaisesRegex(ValueError,"truncated"):
                sec.github_list("https://api.github.com/repos/moby/buildkit/security-advisories?state=published&per_page=100")


class Apply(unittest.TestCase):
    def test_exactly_one_image_pin_changes_with_digest(self):
        with tempfile.TemporaryDirectory() as dirname:
            file=Path(dirname)/"toolchain.env"
            file.write_text("BUILDKIT_IMAGE=moby/buildkit:v0.33.1@sha256:"+"a"*64+"\nBUILDX_VERSION=v0.37.2\n")
            upgrade={"tool":"buildkit","key":"BUILDKIT_IMAGE","from":"v0.33.1","to":"v0.34.2",
                     "advisories":["GHSA-abcd-1234-efgh"],"cooldown_bypassed":True}
            new=sec.apply(upgrade,file,"sha256:"+"b"*64)
            self.assertEqual(new,"moby/buildkit:v0.34.2@sha256:"+"b"*64)
            self.assertIn("BUILDX_VERSION=v0.37.2",file.read_text())
            with self.assertRaisesRegex(ValueError,"pin changed"):
                sec.apply(upgrade,file,"sha256:"+"c"*64)

    def test_major_upgrade_and_no_advisory_are_rejected(self):
        with tempfile.TemporaryDirectory() as dirname:
            file=Path(dirname)/"toolchain.env"
            file.write_text("COSIGN_IMAGE=gcr.io/projectsigstore/cosign:v2.6.1@sha256:"+"a"*64+"\n")
            upgrade={"tool":"cosign","key":"COSIGN_IMAGE","from":"v2.6.1","to":"v3.1.4",
                     "advisories":["GHSA-abcd-1234-efgh"],"cooldown_bypassed":True}
            with self.assertRaisesRegex(ValueError,"major"):
                sec.apply(upgrade,file,"sha256:"+"b"*64)
            upgrade["to"]="v2.6.5"
            upgrade["advisories"]=[]
            with self.assertRaisesRegex(ValueError,"unverified"):
                sec.apply(upgrade,file,"sha256:"+"b"*64)
            self.assertIn("v2.6.1",file.read_text())

    def test_digest_is_mandatory_for_image_pin(self):
        with tempfile.TemporaryDirectory() as dirname:
            file=Path(dirname)/"toolchain.env"
            file.write_text("BUILDKIT_IMAGE=moby/buildkit:v0.33.1@sha256:"+"a"*64+"\n")
            upgrade={"tool":"buildkit","key":"BUILDKIT_IMAGE","from":"v0.33.1","to":"v0.34.2",
                     "advisories":["GHSA-abcd-1234-efgh"],"cooldown_bypassed":True}
            with self.assertRaisesRegex(ValueError,"registry-verified"):
                sec.apply(upgrade,file)

if __name__=="__main__":
    unittest.main()
