#!/usr/bin/env python3
"""Observe Mozilla and Chrome root stores; only automate explicit TLS trust loss.

This is a build-time observer, not an updater installed in the final image.
State snapshots are committed to git to provide a durable comparison baseline.
External sources are resolved to GitHub commit SHA and fetched at that SHA.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import urllib.request

SOURCES = {
    "mozilla": ("mozilla-firefox/firefox", "release", "security/nss/lib/ckfw/builtins/certdata.txt"),
    "chrome": ("chromium/chromium", "main", "net/data/ssl/chrome_root_store/root_store.textproto"),
}
SHA = re.compile(r"[a-f0-9]{64}\Z")
OCTAL = re.compile(r"\\([0-7]{3})")
TRUSTED = "CKT_NSS_TRUSTED_DELEGATOR"
NO_TLS_TRUST = {"CKT_NSS_MUST_VERIFY_TRUST", "CKT_NSS_NOT_TRUSTED"}
MAX_FETCH = 3_000_000


class SourceError(ValueError):
    pass


def get_bytes(url, *, limit=MAX_FETCH, token=None):
    headers = {"User-Agent": "minimal-node-runtime-root-monitor/1",
               "Accept": "application/vnd.github+json"}
    if token and url.startswith("https://api.github.com/"):
        headers["Authorization"] = "Bearer " + token
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=45) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise SourceError("upstream exceeds size limit")
    return data


def observe_source(name, getter=get_bytes, token=None):
    owner, branch, path = SOURCES[name]
    ref = json.loads(getter(f"https://api.github.com/repos/{owner}/git/ref/heads/{branch}", token=token))
    sha = ref.get("object", {}).get("sha", "")
    if not re.fullmatch(r"[a-f0-9]{40}", sha):
        raise SourceError(f"{name}: invalid upstream commit SHA")
    url = f"https://raw.githubusercontent.com/{owner}/{sha}/{path}"
    raw = getter(url, token=token)
    if len(raw) < (400_000 if name == "mozilla" else 10_000):
        raise SourceError(f"{name}: implausibly small upstream source")
    return {"repository": owner, "commit": sha,
            "source_sha256": hashlib.sha256(raw).hexdigest(),
            "roots": parse_mozilla(raw) if name == "mozilla" else parse_chrome(raw)}


def objects(data):
    for block in re.split(r"\r?\n[ \t]*\r?\n", data.decode("utf-8")):
        lines = [line.strip() for line in block.splitlines()
                 if line.strip() and not line.lstrip().startswith("#")]
        if lines:
            yield lines


def octal_attribute(lines, attribute):
    header = attribute + " MULTILINE_OCTAL"
    if header not in lines:
        return None
    start = lines.index(header) + 1
    try:
        end = lines.index("END", start)
    except ValueError as error:
        raise SourceError(f"unterminated {attribute}") from error
    result = bytearray()
    for line in lines[start:end]:
        seq = OCTAL.findall(line)
        if not seq or "".join("\\" + part for part in seq) != line:
            raise SourceError(f"malformed octal {attribute}")
        result.extend(int(x, 8) for x in seq)
    if not result:
        raise SourceError(f"empty {attribute}")
    return bytes(result)


def parse_mozilla(raw, *, minimum=100):
    certs = {}
    trusts = {}
    for lines in objects(raw):
        if "CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE" in lines:
            der = octal_attribute(lines, "CKA_VALUE")
            if der is None:
                raise SourceError("NSS certificate missing CKA_VALUE")
            sha1 = hashlib.sha1(der).hexdigest()  # NSS trust-object identifier.
            sha256 = hashlib.sha256(der).hexdigest()
            if sha1 in certs and certs[sha1] != sha256:
                raise SourceError("duplicate NSS SHA-1 certificate identifier")
            certs[sha1] = sha256
        elif "CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST" in lines:
            key = octal_attribute(lines, "CKA_CERT_SHA1_HASH")
            if key is None or len(key) != 20:
                raise SourceError("NSS trust block missing SHA-1 identifier")
            trust_key = key.hex()
            server = [line.split()[-1] for line in lines
                      if line.startswith("CKA_TRUST_SERVER_AUTH CK_TRUST ")]
            if len(server) != 1 or trust_key in trusts:
                raise SourceError("duplicate or malformed NSS server trust")
            trusts[trust_key] = {
                "status": "trusted" if server[0] == TRUSTED else
                          "explicitly-untrusted" if server[0] in NO_TLS_TRUST else "unknown",
                "distrust_after": (
                    octal_attribute(lines, "CKA_NSS_SERVER_DISTRUST_AFTER") or b""
                ).decode("ascii"),
            }
    result = {}
    for sha1, sha256 in certs.items():
        if sha1 not in trusts:
            raise SourceError("NSS certificate missing corresponding trust object")
        result[sha256] = trusts[sha1]
    if len(result) < minimum or sum(v["status"] == "trusted" for v in result.values()) < minimum:
        raise SourceError("NSS certificate inventory too small to be trusted")
    if len(set(certs.values())) != len(certs):
        raise SourceError("duplicate NSS certificate DER fingerprint")
    return dict(sorted(result.items()))


def parse_chrome(raw, *, minimum=75):
    source = raw.decode("utf-8")
    if not re.search(r"(?m)^version_major: [1-9][0-9]*\s*$", source):
        raise SourceError("Chrome Root Store missing version")
    result = {}
    for match in re.finditer(r"\btrust_anchors\s*\{", source):
        depth, pos = 1, match.end()
        while depth and pos < len(source):
            if source[pos] == "{":
                depth += 1
            if source[pos] == "}":
                depth -= 1
            pos += 1
        if depth:
            raise SourceError("unclosed Chrome trust anchor")
        body = source[match.end():pos - 1]
        hashes = re.findall(r'\bsha256_hex:\s*"([0-9a-f]{64})"', body)
        if len(hashes) != 1 or hashes[0] in result:
            raise SourceError("invalid or duplicated Chrome root fingerprint")
        restrictions = re.findall(r"\bconstraints\s*:\s*\{[^{}]*\}", body)
        result[hashes[0]] = {"constraints": sorted(" ".join(r.split()) for r in restrictions)}
    if len(result) < minimum or len(result) > 1000:
        raise SourceError("Chrome Root Store inventory too small or too large")
    return dict(sorted(result.items()))


def diff_trust(previous, current, exclusions, *, max_automatic=10):
    previous = previous or {}
    auto, review = set(), []
    old = previous.get("roots", {})
    new = current["roots"]
    for hash_, before in old.items():
        if before == new.get(hash_):
            continue
        if hash_ not in new:
            review.append({"source": "mozilla", "kind": "root-removed", "sha256": hash_})
            continue
        after = new[hash_]
        if (before["status"] == "trusted" and after["status"] == "explicitly-untrusted"
                and before["distrust_after"] == after["distrust_after"]):
            auto.add(hash_)
        else:
            review.append({"source": "mozilla", "kind": "conditional-or-ambiguous-change",
                           "sha256": hash_})
    if len(auto) > max_automatic:
        raise SourceError(f"{len(auto)} simultaneous Mozilla distrust events require manual review")
    return sorted(auto - exclusions), review


def diff_chrome(previous, current):
    if previous is None:
        return []
    old, new = previous["roots"], current["roots"]
    return [{"source": "chrome",
             "kind": "root-removed" if key not in new else "constraints-changed",
             "sha256": key} for key in sorted(old) if key not in new or old[key] != new[key]]


def read_overlay(path):
    if not path.is_file():
        raise SourceError(f"missing committed exclusion overlay: {path}")
    entries = set()
    for line in path.read_text(encoding="ascii").splitlines():
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        if not SHA.fullmatch(entry) or entry in entries:
            raise SourceError("invalid or duplicated auto-excluded certificate fingerprint")
        entries.add(entry)
    return entries


def run(state_dir, overlay, report, *, getter=get_bytes, token=None):
    existing = read_overlay(overlay)
    states = {}
    for source in SOURCES:
        path = state_dir / f"{source}.json"
        prior = json.loads(path.read_text()) if path.exists() else None
        if prior is not None and (prior.get("repository") != SOURCES[source][0] or
                                  not isinstance(prior.get("roots"), dict) or
                                  len(prior["roots"]) < (100 if source == "mozilla" else 75)):
            raise SourceError(f"{source} snapshot is malformed or from another source")
        current = observe_source(source, getter=getter, token=token)
        states[source] = (prior, current)
    auto, review = diff_trust(*states["mozilla"], existing)
    review.extend(diff_chrome(*states["chrome"]))
    # Do not modify any persistent file unless *both* sources verified.
    state_dir.mkdir(parents=True, exist_ok=True)
    for name, (_, current) in states.items():
        (state_dir / f"{name}.json").write_text(json.dumps(current, indent=2, sort_keys=True) + "\n")
    if auto:
        overlay.write_text("# Cumulative, removal-only SHA-256 fingerprints of DER roots.\n" +
                           "".join(f"{entry}\n" for entry in sorted(existing | set(auto))))
    data = {"auto_excluded": auto, "review": review,
            "sources": {name: {k: v for k, v in state[1].items() if k != "roots"}
                        for name, state in states.items()}}
    report.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=Path("state/trust"))
    parser.add_argument("--overlay", type=Path, default=Path("certificates.auto.exclude"))
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = run(args.state_dir, args.overlay, args.report,
                     token=os.environ.get("GITHUB_TOKEN"))
    except (OSError, ValueError, UnicodeError, KeyError, TypeError) as error:
        print(f"root_trust_monitor: {error}", file=sys.stderr)
        return 1
    print(f"Mozilla and Chrome verified. {len(result['auto_excluded'])} new exclusions; "
          f"{len(result['review'])} decisions for review.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
