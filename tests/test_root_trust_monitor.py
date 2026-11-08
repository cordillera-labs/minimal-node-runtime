"""Offline fixtures for source parsing, policy transitions and failure containment."""
import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / 'scripts/root_trust_monitor.py'
spec = importlib.util.spec_from_file_location('root_trust_monitor', SCRIPT)
monitor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(monitor)


def octal(content):
    return ''.join(f'\\{c:03o}' for c in content)


def nss(count=105, *, revoked=(), missing=(), restricted=()):
    blocks = ['# generated test fixture\nBEGINDATA\n']
    for number in range(count):
        if number in missing:
            continue
        der = f'cert-{number:04d}'.encode()
        sha1 = hashlib.sha1(der).digest()
        status = 'CKT_NSS_MUST_VERIFY_TRUST' if number in revoked else 'CKT_NSS_TRUSTED_DELEGATOR'
        blocks.append('\n'.join([
            'CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE',
            'CKA_VALUE MULTILINE_OCTAL', octal(der), 'END',
        ]))
        blocks.append('\n'.join([
            'CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST',
            'CKA_CERT_SHA1_HASH MULTILINE_OCTAL', octal(sha1), 'END',
            f'CKA_TRUST_SERVER_AUTH CK_TRUST {status}',
            *(['CKA_NSS_SERVER_DISTRUST_AFTER MULTILINE_OCTAL', octal(b'260101000000Z'), 'END']
              if number in restricted else []),
        ]))
    return ('\n\n'.join(blocks) + '\n').encode()


def chrome(count=105, *, missing=(), restrictions=()):
    parts = ['version_major: 10']
    for number in range(count):
        if number in missing:
            continue
        hash_ = hashlib.sha256(f'chrome-{number}'.encode()).hexdigest()
        constraint = 'constraints: { sct_not_after_sec: 1820966399 }' if number in restrictions else ''
        parts.append(f'trust_anchors {{\n sha256_hex: "{hash_}"\n crs_root_id: {number+1}\n {constraint}\n}}')
    return ('\n'.join(parts) + '\n').encode()


def observe_moz(revoked=(), missing=(), restricted=()):
    return {'repository': 'mozilla-firefox/firefox',
            'roots': monitor.parse_mozilla(nss(revoked=revoked, missing=missing,
                                              restricted=restricted))}


class RootTrustMonitorTests(unittest.TestCase):
    def test_parser_identifies_certificate_der_and_server_trust(self):
        entries = monitor.parse_mozilla(nss(revoked={104}))
        self.assertEqual(len(entries), 105)
        bad = hashlib.sha256(b'cert-0104').hexdigest()
        self.assertEqual(entries[bad]['status'], 'explicitly-untrusted')
        self.assertEqual(entries[bad]['distrust_after'], '')

    def test_explicit_tls_distrust_automatically_excludes(self):
        old = observe_moz()
        new = observe_moz(revoked={104})
        fingerprint = hashlib.sha256(b'cert-0104').hexdigest()
        auto, review = monitor.diff_trust(old, new, set())
        self.assertEqual(auto, [fingerprint])
        self.assertEqual(review, [])
        self.assertEqual(monitor.diff_trust(old, new, {fingerprint})[0], [])

    def test_missing_root_and_restriction_are_reported_not_excluded(self):
        old = observe_moz()
        for changed in (observe_moz(missing={104}), observe_moz(restricted={104})):
            auto, review = monitor.diff_trust(old, changed, set())
            self.assertEqual(auto, [])
            self.assertEqual(len(review), 1)

    def test_new_roots_and_renames_do_not_create_exclusions(self):
        original = observe_moz()
        old = {'repository': original['repository'], 'roots': dict(list(original['roots'].items())[:-1])}
        self.assertEqual(monitor.diff_trust(old, original, set()), ([], []))

    def test_mass_distrust_fails_safe(self):
        with self.assertRaisesRegex(monitor.SourceError, 'manual review'):
            monitor.diff_trust(
                {'roots': monitor.parse_mozilla(nss(count=125))},
                {'roots': monitor.parse_mozilla(nss(count=125, revoked=range(20)))}, set())

    def test_unrecognized_or_truncated_source_is_not_empty_trust_store(self):
        with self.assertRaises(monitor.SourceError):
            monitor.parse_mozilla(b'not a certdata file')
        with self.assertRaises(monitor.SourceError):
            monitor.parse_chrome(b'version_major: 1')
        with self.assertRaises(monitor.SourceError):
            monitor.parse_mozilla(nss(missing=range(10)))

    def test_chrome_removal_and_constraints_are_review_only(self):
        old = {'roots': monitor.parse_chrome(chrome())}
        new = {'roots': monitor.parse_chrome(chrome(missing={104}, restrictions={103}))}
        events = monitor.diff_chrome(old, new)
        self.assertEqual({x['kind'] for x in events}, {'root-removed', 'constraints-changed'})

    def test_malformed_exclusion_overlay_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            file = pathlib.Path(directory) / 'overlay'
            file.write_text('f'*64+'\n'+'f'*64+'\n')
            with self.assertRaises(monitor.SourceError):
                monitor.read_overlay(file)

    def test_two_source_transaction_does_not_modify_state_on_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            state = pathlib.Path(directory)/'state'
            overlay = pathlib.Path(directory)/'overlay'
            report = pathlib.Path(directory)/'report'
            overlay.write_text('# empty\n')
            def fetch(url, **kwargs):
                if '/git/ref/heads/' in url:
                    return json.dumps({'object': {'sha': 'a'*40}}).encode()
                if 'mozilla-firefox' in url:
                    return nss() + b'# pad\n' * 100_000
                raise monitor.SourceError('Chrome upstream unavailable')
            with self.assertRaises(monitor.SourceError):
                monitor.run(state, overlay, report, getter=fetch)
            self.assertFalse(state.exists())
            self.assertEqual(overlay.read_text(), '# empty\n')
            self.assertFalse(report.exists())

    def test_baseline_then_distrust_produces_monotonic_overlay(self):
        with tempfile.TemporaryDirectory() as directory:
            state = pathlib.Path(directory)/'state'
            overlay = pathlib.Path(directory)/'overlay'
            report = pathlib.Path(directory)/'report'
            overlay.write_text('# initial\n')
            current = {'mozilla': nss(), 'chrome': chrome()}
            def fetch(url, **kwargs):
                if '/git/ref/heads/' in url:
                    return json.dumps({'object': {'sha': 'a'*40}}).encode()
                return ((current['mozilla'] + b'# pad\n' * 100_000)
                        if 'mozilla-firefox' in url else current['chrome'])
            first = monitor.run(state, overlay, report, getter=fetch)
            self.assertEqual(first['auto_excluded'], [])
            current['mozilla'] = nss(revoked={104})
            second = monitor.run(state, overlay, report, getter=fetch)
            h = hashlib.sha256(b'cert-0104').hexdigest()
            self.assertEqual(second['auto_excluded'], [h])
            self.assertIn(h, overlay.read_text())
            third = monitor.run(state, overlay, report, getter=fetch)
            self.assertEqual(third['auto_excluded'], [])
            self.assertEqual(monitor.read_overlay(overlay), {h})

if __name__ == '__main__':
    unittest.main()
