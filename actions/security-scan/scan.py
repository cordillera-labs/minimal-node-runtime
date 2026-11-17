#!/usr/bin/env python3
"""SBOM-driven security assessment. Only reads metadata; never executes packages."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

SEVERITIES = {"unknown": 0, "info": 0, "low": 1, "middle": 2, "medium": 2,
              "moderate": 2, "high": 3, "critical": 4}
SOCKET_ENDPOINT = "https://api.socket.dev/v0/orgs/{org}/purl?alerts=true&compact=true&poll=false"
BQ_TABLE = "ossf-malware-analysis.packages.analysis"


def load_json(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


def npm_identity(purl):
    if not isinstance(purl, str) or not purl.startswith("pkg:npm/"):
        return None
    unqualified = purl.split("?", 1)[0].split("#", 1)[0][8:]
    if "@" not in unqualified:
        return None
    name, sep, version = unqualified.rpartition("@")
    name, version = urllib.parse.unquote(name), urllib.parse.unquote(version)
    if not sep or not name or not version or any(c.isspace() for c in name + version):
        return None
    return name, version


def inventory(sbom):
    if not isinstance(sbom, dict) or sbom.get("bomFormat") != "CycloneDX":
        raise ValueError("expected a CycloneDX JSON SBOM")
    if not isinstance(sbom.get("components"), list):
        raise ValueError("CycloneDX SBOM must contain a components array")
    packages = {}
    def visit(components, inherited):
        for component in components:
            if not isinstance(component, dict):
                raise ValueError("invalid CycloneDX component")
            purl = component.get("purl")
            identity = npm_identity(purl)
            if identity:
                normalized = "pkg:npm/" + identity[0] + "@" + identity[1]
                packages.setdefault(normalized, {
                    "purl": normalized, "name": identity[0], "version": identity[1],
                    "origin": "bundled-upstream" if inherited else "sbom-component",
                })
            children = component.get("components", [])
            if children:
                if not isinstance(children, list):
                    raise ValueError("invalid nested CycloneDX components")
                visit(children, True)
    visit(sbom["components"], False)
    return [packages[k] for k in sorted(packages)]


def finding(provider, pkg, kind, severity, detail, blocking=False, evidence=None):
    item = {"provider": provider, "purl": pkg["purl"], "type": str(kind)[:100],
            "severity": severity, "detail": str(detail)[:400], "blocking": blocking}
    if evidence:
        item["evidence"] = evidence
    return item


def from_trivy(report, only_fixable=True):
    if (not isinstance(report, dict) or not isinstance(report.get("Results"), list)
            or not report["Results"]):
        raise ValueError("Trivy report must have nonempty Results array")
    observations = []
    for result in report["Results"]:
        for vuln in result.get("Vulnerabilities") or []:
            severity = str(vuln.get("Severity", "UNKNOWN")).lower()
            fixed = str(vuln.get("FixedVersion") or "")
            pkg = {"purl": "pkg:trivy/" + str(vuln.get("PkgName", "unknown"))}
            blocking = SEVERITIES.get(severity, 0) >= 3 and (bool(fixed) or not only_fixable)
            observations.append(finding("trivy", pkg, vuln.get("VulnerabilityID", "vulnerability"),
                                        severity, vuln.get("Title") or "Known vulnerability",
                                        blocking, {"installed": vuln.get("InstalledVersion"),
                                                   "fixed": fixed, "class": result.get("Class")}))
    return {"status": "complete", "covered": len(report["Results"]),
            "findings": observations}


def parse_socket_rows(raw):
    """The purl API can return JSON, NDJSON, or a JSON list of artifacts."""
    decoded = raw.decode("utf-8")
    try:
        obj = json.loads(decoded)
    except json.JSONDecodeError:
        obj = [json.loads(line) for line in decoded.splitlines() if line.strip()]
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict):
        for field in ("results", "components", "packages", "data"):
            if isinstance(obj.get(field), list):
                return obj[field]
        if "name" in obj or "inputPurl" in obj:
            return [obj]
    raise ValueError("Socket returned an unrecognized response schema")


def socket_purl(row):
    explicit = row.get("inputPurl") or row.get("purl")
    if isinstance(explicit, str) and npm_identity(explicit):
        name, version = npm_identity(explicit)
        return "pkg:npm/" + name + "@" + version
    if row.get("type") == "npm" and row.get("name") and row.get("version"):
        return "pkg:npm/" + str(row["name"]) + "@" + str(row["version"])
    return None


def socket_result(packages, rows):
    expected = {p["purl"]: p for p in packages}
    mapped = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Socket artifact is not an object")
        key = socket_purl(row)
        if key in expected:
            if key in mapped:
                raise ValueError("duplicate Socket artifact for " + key)
            mapped[key] = row
    out = []
    missing = []
    for key, pkg in expected.items():
        row = mapped.get(key)
        if row is None or not isinstance(row.get("alerts"), (list, dict)):
            missing.append(key)
            continue
        alerts = row["alerts"]
        if isinstance(alerts, dict):
            alerts = [{"type": kind, **(value if isinstance(value, dict) else {})}
                      for kind, value in alerts.items()]
        if not all(isinstance(alert, dict) for alert in alerts):
            raise ValueError("invalid Socket alerts collection for " + key)
        unknown = any(a.get("type") in ("pendingScan", "notFound") for a in alerts)
        if unknown:
            missing.append(key)
            continue
        for alert in alerts:
            raw_severity = str(alert.get("severity", "unknown")).lower()
            severity = {"0": "low", "1": "medium", "2": "high", "3": "critical"}.get(
                raw_severity, raw_severity)
            action = str(alert.get("action", ""))
            kind = str(alert.get("type", "unknown"))
            block = action == "error" or severity in ("critical", "high")
            out.append(finding("socket", pkg, kind, severity,
                               "Socket alert" + (": " + action if action else ""),
                               block, {"action": action}))
    covered = len(expected) - len(missing)
    return {"status": "complete" if not missing else "partial", "covered": covered,
            "missing": missing, "findings": out}


def fetch_socket(packages, org, token, timeout=20):
    if not packages:
        return {"status": "not_applicable", "covered": 0, "findings": []}
    if not org or not token:
        return {"status": "unavailable", "reason": "Socket organization/token not configured",
                "covered": 0, "findings": []}
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", org):
        return {"status": "unavailable", "reason": "invalid Socket organization slug",
                "covered": 0, "findings": []}
    all_rows = []
    try:
        for start in range(0, len(packages), 100):
            body = json.dumps({"components": [{"purl": p["purl"]}
                                              for p in packages[start:start + 100]]}).encode()
            url = SOCKET_ENDPOINT.format(org=urllib.parse.quote(org))
            request = urllib.request.Request(
                url, data=body, method="POST",
                headers={"Authorization": "Bearer " + token,
                         "Accept": "application/x-ndjson",
                         "Content-Type": "application/json"})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                all_rows.extend(parse_socket_rows(response.read(10_000_000)))
        return socket_result(packages, all_rows)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        # Do not echo provider response bodies, tokens, or arbitrary URLs in logs.
        return {"status": "unavailable", "reason": type(exc).__name__,
                "covered": 0, "findings": []}


def collect_tree(value, key):
    """Find observations in OpenSSF analysis output without assuming phase depth."""
    if isinstance(value, dict):
        for k, val in value.items():
            if k.lower() == key.lower():
                yield val
            yield from collect_tree(val, key)
    elif isinstance(value, list):
        for entry in value:
            yield from collect_tree(entry, key)


def openssf_result(packages, rows):
    expected = {(p["name"], p["version"]): p for p in packages}
    matched = set()
    findings = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("OpenSSF row is not an object")
        name = row.get("name") or (row.get("Package") or {}).get("Name")
        version = row.get("version") or (row.get("Package") or {}).get("Version")
        key = (name, version)
        if key not in expected:
            continue
        pkg = expected[key]
        raw = row.get("install")
        if raw is None:
            raw = (row.get("Analysis") or {}).get("install")
        # A result without an install phase is not evidence of clean behavior.
        if raw is None:
            continue
        if isinstance(raw, str):
            raw = json.loads(raw)
        if not isinstance(raw, dict):
            raise ValueError("invalid OpenSSF install analysis")
        matched.add(key)
        commands = []
        for group in collect_tree(raw, "Command"):
            if isinstance(group, list) and group:
                commands.append(" ".join(str(x) for x in group)[:200])
        hosts = []
        for host in collect_tree(raw, "Hostname"):
            if isinstance(host, str):
                hosts.append(host[:200])
        for cmd in sorted(set(commands))[:25]:
            findings.append(finding("openssf", pkg, "install-command", "info",
                                    "Command observed in isolated package install",
                                    evidence={"command": cmd, "created": row.get("created")}))
        for host in sorted(set(hosts))[:25]:
            findings.append(finding("openssf", pkg, "install-dns", "info",
                                    "DNS lookup observed in isolated package install",
                                    evidence={"hostname": host, "created": row.get("created")}))
    missing = [p["purl"] for p in packages
               if (p["name"], p["version"]) not in matched]
    return {"status": "complete" if not missing else "partial",
            "covered": len(matched), "missing": missing, "findings": findings}


def query_openssf(packages, billing_project, max_bytes=100_000_000_000, timeout=50):
    if not packages:
        return {"status": "not_applicable", "covered": 0, "findings": []}
    if not billing_project:
        return {"status": "unavailable", "reason": "OpenSSF BigQuery billing project not configured",
                "covered": 0, "findings": []}
    if not re.fullmatch(r"[a-z][a-z0-9:-]{3,100}", billing_project):
        return {"status": "unavailable", "reason": "invalid BigQuery billing project",
                "covered": 0, "findings": []}
    sql = """
WITH requested AS (
  SELECT JSON_VALUE(x, '$.name') AS name, JSON_VALUE(x, '$.version') AS version
  FROM UNNEST(JSON_QUERY_ARRAY(@requested)) AS x
)
SELECT T.Package.Name AS name, T.Package.Version AS version,
       CAST(T.CreatedTimestamp AS STRING) AS created,
       TO_JSON_STRING(T.Analysis.install) AS install
FROM __TABLE__ AS T
JOIN requested AS r ON T.Package.Name = r.name AND T.Package.Version = r.version
WHERE T.Package.Ecosystem = 'npm'
QUALIFY ROW_NUMBER() OVER (
  PARTITION BY T.Package.Name, T.Package.Version ORDER BY T.CreatedTimestamp DESC
) = 1
""".replace("__TABLE__", chr(96) + BQ_TABLE + chr(96))
    req = json.dumps([{"name": p["name"], "version": p["version"]} for p in packages],
                     separators=(",", ":"))
    args = ["bq", "query", "--format=json", "--use_legacy_sql=false",
            "--project_id=" + billing_project,
            "--maximum_bytes_billed=" + str(max_bytes),
            "--parameter=requested:STRING:" + req, sql]
    try:
        proc = subprocess.run(args, capture_output=True, text=True,
                              timeout=timeout, check=False)
        if proc.returncode:
            return {"status": "unavailable", "reason": "BigQuery query failed",
                    "covered": 0, "findings": []}
        rows = json.loads(proc.stdout)
        if not isinstance(rows, list):
            raise ValueError("BigQuery did not return an array")
        return openssf_result(packages, rows)
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired, ValueError):
        return {"status": "unavailable", "reason": "OpenSSF BigQuery unavailable or invalid response",
                "covered": 0, "findings": []}


def run(args):
    sbom_bytes = Path(args.sbom).read_bytes()
    packages = inventory(json.loads(sbom_bytes))
    selected = [p.strip().lower() for p in args.providers.split(",") if p.strip()]
    if not selected or len(selected) != len(set(selected)) or set(selected) - {"trivy", "socket", "openssf"}:
        raise ValueError("providers must be unique values from trivy,socket,openssf")
    assessments = {}
    if "trivy" in selected:
        try:
            if args.trivy_report:
                trivy = load_json(args.trivy_report)
            elif args.image:
                cmd = ["trivy", "image", "--scanners", "vuln", "--format", "json",
                       "--exit-code", "0", args.image]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if proc.returncode:
                    raise RuntimeError("Trivy scan failed")
                trivy = json.loads(proc.stdout)
            else:
                raise ValueError("provide trivy-report or image for Trivy")
            assessments["trivy"] = from_trivy(trivy, only_fixable=args.trivy_fixable_only)
        except (ValueError, OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
            assessments["trivy"] = {"status": "unavailable", "covered": 0,
                                    "reason": type(exc).__name__, "findings": []}
    if "socket" in selected:
        assessments["socket"] = fetch_socket(packages, args.socket_org, args.socket_token,
                                             timeout=args.timeout)
    if "openssf" in selected:
        try:
            if args.openssf_json:
                rows = load_json(args.openssf_json)
                if not isinstance(rows, list):
                    raise ValueError("OpenSSF JSON export must be an array")
                assessments["openssf"] = openssf_result(packages, rows)
            else:
                assessments["openssf"] = query_openssf(packages, args.openssf_project,
                                                       timeout=args.timeout)
        except (ValueError, OSError, json.JSONDecodeError) as exc:
            assessments["openssf"] = {"status": "unavailable", "covered": 0,
                                      "reason": type(exc).__name__, "findings": []}
    findings = sorted((item for data in assessments.values() for item in data["findings"]),
                      key=lambda f: (f["provider"], f["purl"], f["type"]))
    incomplete = any(data["status"] not in ("complete", "not_applicable")
                     for data in assessments.values())
    blocked = any(item["blocking"] for item in findings)
    verdict = "block" if blocked else "incomplete" if incomplete else "pass"
    return {
        "schema": "cordillera-security-assessment/v1",
        "evaluated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "input": {"image": args.image or None,
                  "sbom_sha256": hashlib.sha256(sbom_bytes).hexdigest(),
                  "npm_components": packages},
        "providers": assessments,
        "findings": findings,
        "verdict": verdict,
        "mode": args.mode,
        "limitations": [
            "Behavior observations describe published package releases, not verified bytes inside a vendored Node binary.",
            "SBOM-only scanning cannot see build-only dependencies missing from the SBOM.",
            "No provider finding is proof of absence of malicious behavior.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sbom", required=True)
    parser.add_argument("--image", default="")
    parser.add_argument("--trivy-report", default="")
    parser.add_argument("--providers", default="trivy,socket,openssf")
    parser.add_argument("--mode", choices=("report", "enforce"), default="report")
    parser.add_argument("--trivy-fixable-only", action="store_true", default=False)
    parser.add_argument("--socket-org", default="")
    parser.add_argument("--socket-token", default=os.getenv("SOCKET_SECURITY_TOKEN", ""))
    parser.add_argument("--openssf-json", default="")
    parser.add_argument("--openssf-project", default="")
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if not 1 <= args.timeout <= 120:
        parser.error("timeout must be between 1 and 120 seconds")
    try:
        report = run(args)
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        for p, assessment in report["providers"].items():
            print(p + ": " + assessment["status"] +
                  " (covered " + str(assessment["covered"]) +
                  ", findings " + str(len(assessment["findings"])) + ")")
        print("security-scan verdict: " + report["verdict"])
        if os.getenv("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as outputs:
                outputs.write("report=" + str(output.absolute()) + "\n")
                outputs.write("verdict=" + report["verdict"] + "\n")
        if os.getenv("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
                summary.write("### Security scan\n\n")
                summary.write("| Provider | Coverage | Findings |\n|---|---|---|\n")
                for name, data in report["providers"].items():
                    summary.write("| " + name + " | " + data["status"] + " (" +
                                  str(data["covered"]) + ") | " +
                                  str(len(data["findings"])) + " |\n")
                summary.write("\n**Verdict:** " + report["verdict"] + "\n")
        return 1 if args.mode == "enforce" and report["verdict"] != "pass" else 0
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print("security-scan input error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
