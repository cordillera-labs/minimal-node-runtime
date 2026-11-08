"""Deterministic CA selection from the extracted Debian ca-certificates tree."""

import base64
import hashlib
import pathlib
import subprocess
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "select-ca-certificates.sh"


def certificate(name, newline=True):
    payload = base64.b64encode(name.encode()).decode()
    return (f"-----BEGIN CERTIFICATE-----\n{payload}\n-----END CERTIFICATE-----"
            + ("\n" if newline else "")).encode()


class CertificateSelection(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.certs = self.root / "certs"
        (self.certs / "mozilla").mkdir(parents=True)
        self.exclusions = self.root / "certificates.exclude"
        self.exclusions.write_text("# No exclusions by default\n", encoding="utf-8")
        self.bundle = self.root / "bundle.crt"
        self.auto = self.root / "certificates.auto.exclude"
        self.auto.write_text("# empty\n", encoding="ascii")
        self.denied = self.root / "denied.txt"
        self.put("mozilla/B.crt", certificate("B", newline=False))
        self.put("mozilla/A.crt", certificate("A"))
        self.put("mozilla/C.crt", certificate("C"))

    def put(self, name, data):
        path = self.certs / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def select(self, config=None):
        if config is not None:
            self.exclusions.write_text(config, encoding="utf-8")
        return subprocess.run(["bash", str(SCRIPT), str(self.certs), str(self.exclusions),
                               str(self.bundle), str(self.auto), str(self.denied)],
                              capture_output=True, text=True, check=False)

    def test_default_selects_all_in_deterministic_order(self):
        result = self.select()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.bundle.read_bytes(), certificate("A") + certificate("B") + certificate("C"))

    def test_exclusion_omits_only_the_named_root(self):
        result = self.select("# reviewed distrust\nmozilla/B.crt\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.bundle.read_bytes(), certificate("A") + certificate("C"))
        self.assertNotIn(b"\nB\n", self.bundle.read_bytes())

    def test_comments_and_blank_lines(self):
        result = self.select("\n# comment\nmozilla/C.crt\n\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.bundle.read_bytes(), certificate("A") + certificate("B"))

    def test_invalid_or_duplicate_exclusions_fail_closed(self):
        for config in ("../A.crt\n", "/mozilla/A.crt\n", "mozilla/./A.crt\n",
                       "mozilla//A.crt\n", "mozilla/missing.crt\n", "mozilla/A.crt\nmozilla/A.crt\n",
                       "mozilla/A.crt # typo\n", "mozilla/A.pem\n"):
            with self.subTest(config=config):
                result = self.select(config)
                self.assertNotEqual(result.returncode, 0, config)

    def test_empty_selected_set_is_rejected(self):
        result = self.select("mozilla/A.crt\nmozilla/B.crt\nmozilla/C.crt\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no selected certificates", result.stderr)

    def test_bad_pem_is_rejected(self):
        self.put("mozilla/B.crt", b"not a certificate\n")
        result = self.select()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not one PEM certificate", result.stderr)

    def test_automatic_fingerprint_excludes_bundled_and_system_cas(self):
        digest = hashlib.sha256(b"B").hexdigest()
        self.auto.write_text(digest + "\n")
        result = self.select()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.bundle.read_bytes(), certificate("A") + certificate("C"))
        self.assertEqual(self.denied.read_text().splitlines(), [digest])

    def test_manual_exclusions_are_also_emitted_for_node_preload(self):
        result = self.select("mozilla/B.crt\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.denied.read_text().splitlines(), [hashlib.sha256(b"B").hexdigest()])

    def test_invalid_auto_fingerprint_rejected(self):
        for bad in ("BAD\n", "a"*64+"\n"+"a"*64+"\n", "B"*64+"\n"):
            with self.subTest(bad=bad):
                self.auto.write_text(bad)
                result = self.select()
                self.assertNotEqual(result.returncode, 0)

    def test_exclusion_config_is_required(self):
        self.exclusions.unlink()
        result = self.select()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing exclusions file", result.stderr)


if __name__ == "__main__":
    unittest.main()
