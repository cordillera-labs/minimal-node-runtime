"""Reviewed first-party Go vulnerability database fallback for Trivy.

GitHub's release and security-advisory API endpoints return 403 for this
public repository in GitHub Actions. The canonical Go vulnerability database
(vuln.go.dev) provides reviewed, OSV-formatted direct-module vulnerabilities.
It is narrower than GitHub's repository advisories: it does not certify
security of Trivy binaries, supply-chain releases or dependencies.
"""

import json
import re

MODULE = "github.com/aquasecurity/trivy"
INDEX = "https://vuln.go.dev/index/modules.json"
GO_URL = "https://vuln.go.dev/ID/"
GHSA = re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$")
CVE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
GO_ID = re.compile(r"^GO-[0-9]{4}-[0-9]{4,6}$")
VERSION = re.compile(r"^v?[0-9]+\.[0-9]+\.[0-9]+$")


def _read(fetch, url, max_bytes):
    raw = fetch(url)
    if not isinstance(raw, bytes) or len(raw) > max_bytes:
        raise ValueError("Go vulnerability database response oversized or invalid")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("Invalid JSON from Go vulnerability database") from exc


def normalize(report):
    """One reviewed direct-module OSV record -> one advisory-like object.

    Return None for withdrawn/unreviewed records. Unknown affected/fix shapes
    fail closed; they must never count as evidence of a safe automatic update.
    """
    if not isinstance(report, dict):
        raise ValueError("OSV report must be an object")
    ident = report.get("id")
    if not isinstance(ident, str) or not GO_ID.fullmatch(ident):
        raise ValueError("OSV record has invalid GO vulnerability ID")
    if report.get("withdrawn"):
        return None
    review_meta = report.get("database_specific") or {}
    if not isinstance(review_meta, dict):
        raise ValueError(f"{ident} review metadata invalid")
    review = review_meta.get("review_status", "REVIEWED")
    if review not in ("REVIEWED", "UNREVIEWED"):
        raise ValueError(f"{ident} unknown review status")
    if review == "UNREVIEWED":
        return None
    published = report.get("published")
    if not isinstance(published, str) or not published.endswith("Z"):
        raise ValueError(f"{ident} missing publication timestamp")
    aliases = report.get("aliases")
    if not isinstance(aliases, list):
        raise ValueError(f"{ident} missing aliases")
    ghsas = sorted({item for item in aliases if isinstance(item, str) and GHSA.fullmatch(item)})
    if not ghsas:
        return None  # No GHSA evidence permits no automatic patch adoption.
    affected = report.get("affected")
    if not isinstance(affected, list) or not affected:
        raise ValueError(f"{ident} has no affected package records")
    rows = []
    for entry in affected:
        if not isinstance(entry, dict) or not isinstance(entry.get("package"), dict):
            raise ValueError(f"{ident} malformed affected package")
        pkg = entry["package"]
        if pkg.get("ecosystem") != "Go" or pkg.get("name") != MODULE:
            continue
        ranges = entry.get("ranges")
        if not isinstance(ranges, list) or not ranges:
            raise ValueError(f"{ident} missing affected version ranges")
        for rng in ranges:
            if not isinstance(rng, dict) or rng.get("type") != "SEMVER":
                raise ValueError(f"{ident} unsupported OSV range type")
            events = rng.get("events")
            if not isinstance(events, list) or len(events) != 2:
                raise ValueError(f"{ident} ambiguous OSV version events")
            first, last = events
            if not isinstance(first, dict) or not isinstance(last, dict):
                raise ValueError(f"{ident} invalid OSV version events")
            if set(first) != {"introduced"} or set(last) != {"fixed"}:
                raise ValueError(f"{ident} unsupported OSV event order")
            lower = "0.0.0" if first["introduced"] == "0" else first["introduced"]
            upper = last["fixed"]
            if not isinstance(lower, str) or not isinstance(upper, str):
                raise ValueError(f"{ident} missing fixed version")
            if not VERSION.fullmatch(lower) or not VERSION.fullmatch(upper):
                raise ValueError(f"{ident} unsupported version format")
            parse = lambda x: tuple(map(int, x.lstrip("v").split(".")))
            if parse(lower) >= parse(upper):
                raise ValueError(f"{ident} fixed version precedes introduction")
            rows.append({
                "package": {"ecosystem": "go", "name": MODULE},
                "vulnerable_version_range": f">= {lower}, < {upper}",
                "patched_versions": f"v{upper.lstrip('v')}",
            })
    if not rows:
        raise ValueError(f"{ident} has no exact Trivy module range")
    return {
        "ghsa_id": ghsas[0],
        "cve_id": next((a for a in aliases if isinstance(a, str) and CVE.fullmatch(a)), None),
        "state": "published",
        "published_at": published,
        "withdrawn_at": None,
        "html_url": f"https://pkg.go.dev/vuln/{ident}",
        "source": "reviewed Go vulnerability database",
        "vulnerabilities": rows,
    }


def fetch_advisories(fetch):
    """Use the complete official Go module index and exact OSV reports."""
    index = _read(fetch, INDEX, 16 * 1024 * 1024)
    if not isinstance(index, list) or not 100 <= len(index) <= 100000:
        raise ValueError("Go vulnerability module index has implausible size")
    matching = [item for item in index if isinstance(item, dict) and item.get("path") == MODULE]
    if len(matching) > 1:
        raise ValueError("Duplicate Trivy module in official Go index")
    if not matching:
        return []
    items = matching[0].get("vulns")
    if not isinstance(items, list) or len(items) > 100:
        raise ValueError("Trivy module vulnerability inventory malformed")
    results = []
    seen = set()
    for meta in items:
        ident = meta.get("id") if isinstance(meta, dict) else None
        if not isinstance(ident, str) or not GO_ID.fullmatch(ident) or ident in seen:
            raise ValueError("Invalid/duplicate GO vulnerability ID")
        seen.add(ident)
        report = _read(fetch, GO_URL + ident + ".json", 1024 * 1024)
        if not isinstance(report, dict) or report.get("id") != ident:
            raise ValueError("Go vulnerability record ID does not match module index")
        converted = normalize(report)
        if converted is not None:
            results.append(converted)
    return results
