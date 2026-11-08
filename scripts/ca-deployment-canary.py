#!/usr/bin/env python3
"""Create a synthetic NSS TLS distrust only for an isolated proof branch."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import root_trust_monitor as monitor


def octal(data):
    return ''.join(f'\\{c:03o}' for c in data)


def nss(target_der, withdrawn):
    blocks = ['BEGINDATA']
    for idx in range(105):
        der = target_der if idx == 104 else f'canary-fixture-{idx:04d}'.encode()
        sha1 = hashlib.sha1(der).digest()
        status = ('CKT_NSS_NOT_TRUSTED' if withdrawn and idx == 104
                  else 'CKT_NSS_TRUSTED_DELEGATOR')
        blocks += [
            '\n'.join(['CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE',
                       'CKA_VALUE MULTILINE_OCTAL', octal(der), 'END']),
            '\n'.join(['CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST',
                       'CKA_CERT_SHA1_HASH MULTILINE_OCTAL', octal(sha1), 'END',
                       f'CKA_TRUST_SERVER_AUTH CK_TRUST {status}']),
        ]
    return ('\n\n'.join(blocks) + '\n' + '# padding\n' * 50_000).encode()


def chrome():
    parts = ['version_major: 10']
    for idx in range(105):
        hash_ = hashlib.sha256(f'canary-chrome-{idx}'.encode()).hexdigest()
        parts.append(f'trust_anchors {{\n sha256_hex: "{hash_}"\n crs_root_id: {idx+1}\n}}')
    return ('\n'.join(parts) + '\n').encode()


def prepare(der, output_dir, *, overlay, main_sha, trigger_run, base_roots):
    output_dir.mkdir(parents=True, exist_ok=True)
    expected = hashlib.sha256(der).hexdigest()
    trusted = [set(json.loads(path.read_text())) for path in base_roots]
    if any(expected not in roots for roots in trusted):
        raise ValueError('canary root is not in both published baseline trust stores')
    previous = monitor.read_overlay(overlay)
    if expected in previous:
        raise ValueError('target root is already excluded by production policy')
    initial_overlay = overlay.read_bytes()
    fixture = {'mozilla': nss(der, False), 'chrome': chrome()}
    revisions = {'mozilla': 'a'*40, 'chrome': 'c'*40}

    def getter(url, *, token=None):
        for name, (repo, ref, path) in monitor.SOURCES.items():
            if url == f'https://api.github.com/repos/{repo}/git/ref/heads/{ref}':
                return json.dumps({'object': {'sha': revisions[name]}}).encode()
            if url == f'https://raw.githubusercontent.com/{repo}/{revisions[name]}/{path}':
                return fixture[name]
        raise ValueError('unexpected source URL: ' + url)

    snapshots = output_dir / 'source-state'
    report = output_dir / 'transition-report.json'
    first = monitor.run(snapshots, overlay, report, getter=getter)
    if first['auto_excluded'] or overlay.read_bytes() != initial_overlay:
        raise ValueError('baseline attempted to change production exclusion policy')
    fixture['mozilla'] = nss(der, True)
    revisions['mozilla'] = 'b'*40
    second = monitor.run(snapshots, overlay, report, getter=getter)
    if second['auto_excluded'] != [expected] or second['review']:
        raise ValueError('test transition did not yield precisely one exclusion')
    if monitor.read_overlay(overlay) != previous | {expected}:
        raise ValueError('exclusions did not monotonically accumulate')
    marker = {
        'test_only': True,
        'source_run': trigger_run,
        'source_main_commit': main_sha,
        'excluded_cert_der_sha256': expected,
        'reason': 'synthetic Mozilla explicit TLS distrust; test-only branch and registry tags',
        'baseline_node_roots': [p.name for p in base_roots],
        'upstream_source': 'synthetic fixture, not Mozilla production',
    }
    (output_dir / 'canary.json').write_text(json.dumps(marker, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'expected_hash': expected, 'sources': list(monitor.SOURCES),
                      'accepted': second['auto_excluded'], 'report': str(report)}))
    return expected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--der-b64-file', required=True, type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--overlay', default=ROOT/'certificates.auto.exclude', type=Path)
    parser.add_argument('--main-sha', required=True)
    parser.add_argument('--source-run', required=True)
    parser.add_argument('--base-22', required=True, type=Path)
    parser.add_argument('--base-24', required=True, type=Path)
    args = parser.parse_args()
    der = base64.b64decode(args.der_b64_file.read_text().strip(), validate=True)
    if len(der) < 500 or len(der) > 20000:
        parser.error('selected X.509 root DER size is implausible')
    prepare(der, args.output_dir, overlay=args.overlay,
            main_sha=args.main_sha, trigger_run=args.source_run,
            base_roots=(args.base_22, args.base_24))


if __name__ == '__main__':
    main()
