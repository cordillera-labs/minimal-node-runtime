"""Go vulnerability database: direct, reviewed, exact Trivy-module auto-update evidence."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import trivy_go_advisories as vdb  # noqa: E402
import toolchain_security as sec  # noqa: E402


def report(status="REVIEWED", fixed="0.76.2", introduced="0", module=vdb.MODULE,
           aliases=None, rid="GO-2026-7777"):
    return {"id":rid, "published":"2026-11-07T00:00:00Z",
            "database_specific":{"review_status":status},
            "aliases":aliases or ["CVE-2026-12345","GHSA-aaaa-bbbb-cccc"],
            "affected":[{"package":{"ecosystem":"Go","name":module},
                         "ranges":[{"type":"SEMVER","events":[
                             {"introduced":introduced},{"fixed":fixed}]}]}]}


def fake_index(ids):
    items=[{"path":f"example.com/module-{n}","vulns":[]} for n in range(100)]
    items[0]={"path":vdb.MODULE,"vulns":[{"id":i,"modified":"2026-11-07T00:00:00Z"} for i in ids]}
    return json.dumps(items).encode()


class Normalization(unittest.TestCase):
    def test_reviewed_direct_module_cve_and_ghsa(self):
        data=vdb.normalize(report())
        self.assertEqual(data["ghsa_id"],"GHSA-aaaa-bbbb-cccc")
        self.assertEqual(data["vulnerabilities"][0]["vulnerable_version_range"],
                         ">= 0.0.0, < 0.76.2")
        self.assertEqual(data["vulnerabilities"][0]["patched_versions"],"v0.76.2")
        result=sec.pick("trivy","aquasecurity/trivy","v0.74.0",
                        [{"tag_name":"v0.76.2","draft":False,"prerelease":False,
                          "published_at":"2026-11-07T00:00:00Z","html_url":"https://example.test"}],
                        [data])
        self.assertEqual(result["to"],"v0.76.2")

    def test_go_narrowness_cannot_grant_unreviewed_or_unlinked_upgrade(self):
        self.assertIsNone(vdb.normalize(report(status="UNREVIEWED")))
        self.assertIsNone(vdb.normalize(report(aliases=["CVE-2026-12345"])))
        self.assertIsNone(vdb.normalize(dict(report(),withdrawn="2026-11-08T00:00:00Z")))

    def test_other_module_is_rejected(self):
        with self.assertRaisesRegex(ValueError,"no exact Trivy"):
            vdb.normalize(report(module="github.com/evil/trivy"))

    def test_invalid_or_open_ended_ranges_fail_closed(self):
        cases=[
            dict(introduced="future"),
            dict(fixed="0.0.0"),
            dict(fixed="1.0.0-rc1"),
        ]
        for kwargs in cases:
            with self.subTest(**kwargs),self.assertRaises(ValueError):
                vdb.normalize(report(**kwargs))
        item=report()
        item["affected"][0]["ranges"][0]["events"].append({"introduced":"0.75.0"})
        with self.assertRaisesRegex(ValueError,"ambiguous"):
            vdb.normalize(item)

    def test_bad_review_status_does_not_approve(self):
        with self.assertRaisesRegex(ValueError,"review status"):
            vdb.normalize(report(status="UNKNOWN"))


class OfficialDbTransport(unittest.TestCase):
    def test_index_then_each_osv_detail_and_reviewed_only(self):
        ids=["GO-2026-7777","GO-2026-8888"]
        payload={
            vdb.INDEX:fake_index(ids),
            vdb.GO_URL+ids[0]+".json":json.dumps(report()).encode(),
            vdb.GO_URL+ids[1]+".json":json.dumps(
                report(status="UNREVIEWED",rid=ids[1])).encode(),
        }
        calls=[]
        def get(url):
            calls.append(url)
            return payload[url]
        found=vdb.fetch_advisories(get)
        self.assertEqual(len(found),1)
        self.assertEqual(calls,[vdb.INDEX, vdb.GO_URL+ids[0]+".json",
                                vdb.GO_URL+ids[1]+".json"])

    def test_fail_closed_on_wrong_osv_id(self):
        ids=["GO-2026-7777"]
        def get(url):
            if url==vdb.INDEX:return fake_index(ids)
            return json.dumps(report(rid="GO-2026-6666")).encode()
        with self.assertRaisesRegex(ValueError,"ID does not match"):
            vdb.fetch_advisories(get)

    def test_valid_full_index_without_trivy_has_no_direct_go_advisories(self):
        index=json.loads(fake_index([]))
        index[0]["path"]="example.org/none"
        self.assertEqual(vdb.fetch_advisories(lambda url:json.dumps(index).encode()),[])

    def test_errors_are_not_no_vulnerabilities(self):
        for broken in (b"",b"[]",b"{",b"<html>403</html>"):
            with self.subTest(broken=broken),self.assertRaises(ValueError):
                vdb.fetch_advisories(lambda url, raw=broken:raw)

    def test_security_planner_uses_go_vulndb_only_for_trivy(self):
        data=vdb.normalize(report())
        with patch.object(sec.trivy_go_advisories,"fetch_advisories",return_value=[data]) as fetch:
            found=sec.tool_advisories("aquasecurity/trivy")
            self.assertEqual(found,[data])
            fetch.assert_called_once_with(sec.upstream.get)
        with patch.object(sec,"github_list",return_value=[]) as other:
            sec.tool_advisories("docker/buildx")
            other.assert_called_once_with(sec.ADVISORIES_URL.format(repo="docker/buildx"))


if __name__=="__main__":
    unittest.main()
