#!/usr/bin/env python3
"""Exercise a fake Mozilla TLS distrust through observation and rebuild planning.

Run only in a disposable CI checkout. This deliberately changes the checkout's
certificates.auto.exclude; the shell harness backs it up and restores it.
No upstream connection, Git push, workflow dispatch, or publication occurs.
"""

import argparse
import base64
import datetime
import hashlib
import json
from pathlib import Path

import lock as lockfile
import policy
import root_trust_monitor as monitor

REPO = Path(__file__).resolve().parents[1]


def octal(data):
    return "".join(f"\\{byte:03o}" for byte in data)


def mozilla_fixture(target_der, *, withdrawn):
    # Include a real Node-bundled root from the base image so that the rebuilt
    # image has a trust anchor whose removal can be verified, not just a dummy
    # fingerprint that was never trusted. All other roots are synthetic.
    blocks = ["BEGINDATA"]
    for number in range(105):
        der = target_der if number == 104 else f"integration-fixture-{number:04d}".encode()
        sha1 = hashlib.sha1(der).digest()
        status = ("CKT_NSS_NOT_TRUSTED" if withdrawn and number == 104
                  else "CKT_NSS_TRUSTED_DELEGATOR")
        blocks.append("\n".join((
            "CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE",
            "CKA_VALUE MULTILINE_OCTAL", octal(der), "END",
        )))
        blocks.append("\n".join((
            "CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST",
            "CKA_CERT_SHA1_HASH MULTILINE_OCTAL", octal(sha1), "END",
            f"CKA_TRUST_SERVER_AUTH CK_TRUST {status}",
        )))
    # Mimics the substantial size of the real NSS file without downloading it.
    return ("\n\n".join(blocks) + "\n" + "# padding\n" * 50_000).encode()


def chrome_fixture():
    roots = ["version_major: 1"]
    for number in range(105):
        digest = hashlib.sha256(f"chrome-fixture-{number}".encode()).hexdigest()
        roots.append(f'trust_anchors {{\n sha256_hex: "{digest}"\n crs_root_id: {number+1}\n}}')
    raw = ("\n".join(roots) + "\n").encode()
    if len(raw) < 10_000:
        raise AssertionError("Chrome fixture unexpectedly below source-size floor")
    return raw


def run(target_der, baseline_lock, baseline_digest, output_dir):
    output_dir.mkdir(parents=True, exist_ok=True)
    overlay = REPO / "certificates.auto.exclude"
    original_policy = overlay.read_bytes()
    wanted = hashlib.sha256(target_der).hexdigest()
    previous_exclusions = monitor.read_overlay(overlay)
    if wanted in previous_exclusions:
        raise AssertionError("chosen Node root is already excluded")

    stable = lockfile.load(str(baseline_lock))
    baseline_hash = lockfile.build_definition_hash()
    if stable["BUILD_DEFINITION_SHA256"] != baseline_hash:
        raise AssertionError("CI baseline lock does not describe the tested checkout")
    stable["PUBLISHED_DIGEST"] = baseline_digest  # Model a previously published baseline.
    no_updates = {"faults": [], "build_definition": baseline_hash,
                  "node": {"releases": []},
                  "helper": {"image": stable["HELPER_IMAGE"]}, "debian": {}}
    now = datetime.datetime.now(datetime.timezone.utc)
    initial_plan, _ = policy.plan(stable, None, no_updates, None, now)
    if initial_plan["action"] != "none":
        raise AssertionError(f"unchanged inputs unexpectedly rebuild: {initial_plan}")

    source_data = {"mozilla": mozilla_fixture(target_der, withdrawn=False),
                   "chrome": chrome_fixture()}
    versions = {"mozilla": "a" * 40, "chrome": "c" * 40}

    def get_source(url, *, token=None):
        for name, (repository, branch, path) in monitor.SOURCES.items():
            if url == f"https://api.github.com/repos/{repository}/git/ref/heads/{branch}":
                return json.dumps({"object": {"sha": versions[name]}}).encode()
            if url == f"https://raw.githubusercontent.com/{repository}/{versions[name]}/{path}":
                return source_data[name]
        raise AssertionError(f"unexpected source URL: {url}")

    state = output_dir / "source-state"
    report = output_dir / "source-report.json"
    first = monitor.run(state, overlay, report, getter=get_source)
    if first["auto_excluded"] or first["review"] or overlay.read_bytes() != original_policy:
        raise AssertionError("initial source baseline must never change image trust")
    for source in monitor.SOURCES:
        if not (state / f"{source}.json").is_file():
            raise AssertionError(f"missing {source} source baseline")

    source_data["mozilla"] = mozilla_fixture(target_der, withdrawn=True)
    versions["mozilla"] = "b" * 40
    second = monitor.run(state, overlay, report, getter=get_source)
    if second["auto_excluded"] != [wanted] or second["review"]:
        raise AssertionError(f"explicit Mozilla distrust was not accepted: {second}")
    accepted = monitor.read_overlay(overlay)
    if accepted != previous_exclusions | {wanted}:
        raise AssertionError("the overlay did not preserve exactly the cumulative exclusions")
    third = monitor.run(state, overlay, report, getter=get_source)
    if third["auto_excluded"] or monitor.read_overlay(overlay) != accepted:
        raise AssertionError("a repeated observation should not alter the exclusion overlay")

    changed_hash = lockfile.build_definition_hash()
    if changed_hash == baseline_hash:
        raise AssertionError("new exclusion did not change the image build definition")
    updates = dict(no_updates, build_definition=changed_hash)
    planned, variant = policy.plan(stable, None, updates, None, now)
    if planned["action"] != "build" or planned["policy"] != "auto" or variant is None:
        raise AssertionError(f"the real update policy did not request a rebuild: {planned}")
    if variant["BUILD_DEFINITION_SHA256"] != changed_hash:
        raise AssertionError("updated build-definition hash missing from planned lock")
    for key in lockfile.inputs(stable):
        if key != "BUILD_DEFINITION_SHA256" and stable[key] != variant[key]:
            raise AssertionError(f"unrelated package/Node input changed: {key}")

    variant_path = output_dir / "variant.lock"
    variant_path.write_text(lockfile.render(variant, "stable", lockfile.read_packages()))
    metadata = {"fingerprint": wanted, "baseline_build_definition": baseline_hash,
                "variant_build_definition": changed_hash, "policy": planned["policy"],
                "action": planned["action"], "baseline_digest": baseline_digest}
    (output_dir / "integration-result.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(f"Mozilla baseline -> explicit TLS distrust: {wanted}")
    print("Rebuild decision: build (immediate, without changing Debian or Node pins)")
    print(f"Variant lock: {variant_path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--der-b64-file", type=Path, required=True)
    parser.add_argument("--baseline-lock", type=Path, required=True)
    parser.add_argument("--baseline-digest", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    der = base64.b64decode(args.der_b64_file.read_text().strip(), validate=True)
    if not der or not args.baseline_digest.startswith("sha256:"):
        parser.error("expected a DER-encoded Node root and a baseline OCI digest")
    run(der, args.baseline_lock, args.baseline_digest, args.output_dir)


if __name__ == "__main__":
    main()
