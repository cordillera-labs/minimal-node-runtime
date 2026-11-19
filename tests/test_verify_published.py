"""Verify Cosign legacy compatibility is explicit, never a silent downgrade."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/verify-published.sh"
REFERENCE = "ghcr.io/cordillera-labs/minimal-node-runtime@sha256:" + "a" * 64


class PublishedVerificationCommands(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        path = Path(self.tmp.name)
        (path / "bin").mkdir()
        (path / ".docker").mkdir()
        self.log = path / "docker-args.txt"
        docker = path / "bin/docker"
        docker.write_text(
            '#!/bin/sh\n'
            'printf "%s\\n" "$@" > "$MOCK_DOCKER_ARGS"\n',
            encoding="utf-8",
        )
        docker.chmod(0o755)
        self.env = dict(os.environ, HOME=str(path),
                        PATH=f"{path / 'bin'}:{os.environ['PATH']}",
                        MOCK_DOCKER_ARGS=str(self.log),
                        COSIGN_IMAGE="gcr.io/projectsigstore/cosign:v3.1.4@sha256:" + "b" * 64,
                        GITHUB_REPOSITORY="cordillera-labs/minimal-node-runtime",
                        GH_TOKEN="fake-readonly-token")

    def verify(self, mode):
        return subprocess.run(["bash", str(SCRIPT), mode, REFERENCE],
                              env=self.env, capture_output=True, text=True)

    def arguments(self):
        return self.log.read_text(encoding="utf-8").splitlines()

    def test_legacy_vulnerability_attestation_selects_old_format(self):
        result = self.verify("legacy-vuln")
        self.assertEqual(result.returncode, 0, result.stderr)
        args = self.arguments()
        self.assertIn("verify-attestation", args)
        self.assertIn("--type", args)
        self.assertIn("vuln", args)
        self.assertIn("--new-bundle-format=false", args)
        self.assertIn(REFERENCE, args)
        self.assertIn("--certificate-identity-regexp", args)
        self.assertIn("--certificate-oidc-issuer", args)
        self.assertIn("https://token.actions.githubusercontent.com", args)

    def test_normal_vulnerability_verification_uses_modern_default(self):
        result = self.verify("vuln")
        self.assertEqual(result.returncode, 0, result.stderr)
        args = self.arguments()
        self.assertIn("verify-attestation", args)
        self.assertIn("vuln", args)
        self.assertNotIn("--new-bundle-format=false", args)

    def test_signature_still_uses_exact_identity(self):
        result = self.verify("signature")
        self.assertEqual(result.returncode, 0, result.stderr)
        args = self.arguments()
        self.assertIn("verify", args)
        self.assertNotIn("verify-attestation", args)
        self.assertIn("--certificate-identity-regexp", args)

    def test_unknown_verification_type_is_rejected(self):
        result = self.verify("legacy-unknown")
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
