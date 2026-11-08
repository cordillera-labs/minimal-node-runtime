"""Proof-run isolation and production root-monitor transition regression tests."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/ca-deployment-canary.py'
spec = importlib.util.spec_from_file_location('ca_deployment_canary', SCRIPT)
proof = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proof)


class TestProofCanary(unittest.TestCase):
    def test_transition_is_exact_and_preserves_other_exclusions(self):
        der = bytes(range(256)) * 3
        expected = hashlib.sha256(der).hexdigest()
        prior = '0'*64
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            overlay = temp/'certificates.auto.exclude'
            overlay.write_text('# retained\n'+prior+'\n')
            left, right = temp/'base-22.json', temp/'base-24.json'
            for file in [left, right]:
                file.write_text(json.dumps([expected, 'f'*64]))
            output = temp/'proof'
            fingerprint = proof.prepare(der, output, overlay=overlay,
                                        main_sha='a'*40, trigger_run='12345',
                                        base_roots=[left, right])
            self.assertEqual(fingerprint, expected)
            self.assertEqual(proof.monitor.read_overlay(overlay), {expected, prior})
            marker = json.loads((output/'canary.json').read_text())
            self.assertTrue(marker['test_only'])
            self.assertEqual(marker['source_run'], '12345')
            self.assertEqual(marker['excluded_cert_der_sha256'], expected)
            self.assertEqual(json.loads((output/'transition-report.json').read_text())['auto_excluded'], [expected])

    def test_rejects_root_not_trusted_by_both_images(self):
        der = bytes(range(128)) * 6
        expected = hashlib.sha256(der).hexdigest()
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            overlay = temp/'certificates.auto.exclude'
            overlay.write_text('# unchanged\n')
            left, right = temp/'base-22.json', temp/'base-24.json'
            left.write_text(json.dumps([expected]))
            right.write_text(json.dumps([]))
            with self.assertRaisesRegex(ValueError,'not in both'):
                proof.prepare(der, temp/'proof', overlay=overlay,
                              main_sha='a'*40, trigger_run='1', base_roots=[left,right])
            self.assertEqual(overlay.read_text(),'# unchanged\n')

    def test_rejects_previously_excluded_root(self):
        der = bytes(range(128)) * 6
        expected = hashlib.sha256(der).hexdigest()
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            overlay = temp/'certificates.auto.exclude'
            overlay.write_text('# retained\n'+expected+'\n')
            left, right = temp/'base-22.json', temp/'base-24.json'
            for file in [left,right]:
                file.write_text(json.dumps([expected]))
            with self.assertRaisesRegex(ValueError,'already excluded'):
                proof.prepare(der,temp/'proof',overlay=overlay,
                              main_sha='a'*40,trigger_run='1',base_roots=[left,right])
            self.assertEqual(proof.monitor.read_overlay(overlay), {expected})


if __name__ == '__main__':
    unittest.main()
