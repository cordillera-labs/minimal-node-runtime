"""Deterministic CA selection from the extracted Debian ca-certificates tree."""

import pathlib
import subprocess
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "select-ca-certificates.sh"


def certificate(name, newline=True):
    return (f"-----BEGIN CERTIFICATE-----\n{name}\n-----END CERTIFICATE-----"
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
                               str(self.bundle)], capture_output=True, text=True, check=False)

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

    def test_exclusion_config_is_required(self):
        self.exclusions.unlink()
        result = self.select()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing exclusions file", result.stderr)


if __name__ == "__main__":
    unittest.main()
