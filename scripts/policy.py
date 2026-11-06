#!/usr/bin/env python3
"""The update policy: which upstream changes are eligible, and which channel a
build publishes to. This module makes no network calls.

  policy.py plan --stable <lock> --candidate <lock> --upstream <upstream.json>
                 [--scan <trivy.json>] --out-dir <dir>
      Writes <dir>/plan.json and, when a build is due, <dir>/next.lock.

  policy.py channel --lock <lock> --stable <lock> --stable-manifest <file>
                    --manifest <file> --policy auto|stable-only --out-dir <dir>
      Writes <dir>/decision.json and, when a stable subset exists,
      <dir>/split.lock.

Eligibility (README.md "Update policy" states the same rules for users):
  - A change that fixes no CVE is eligible COOLDOWN_DAYS after its upstream
    release.
  - A security change is eligible at once. A change counts as security when
    Trivy reports a CVE against the published stable image whose fixed version
    is at or below the new version, or, for Node.js, when dist/index.json marks
    a release in the update range with "security": true.
  - Each line stays on its Node.js major (state/22/ on 22.x, state/24/ on
    24.x) and Debian stays on trixie. Neither moves here.

Channels:
  - A build whose rootfs manifest equals the stable manifest is non-breaking
    and publishes to stable.
  - A breaking build publishes to the candidate channel. When the breaking
    part is only security-accepted package changes, it publishes to stable and
    the run opens an issue labelled breaking.
"""

import argparse
import datetime
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lock as lockfile  # noqa: E402

# Days a non-security update waits after its upstream release.
COOLDOWN_DAYS = 7

DEB_FIELDS = ("VERSION", "SUITE", "URL", "SHA256", "RELEASED", "ACCEPTED")
NODE_FIELDS = ("NODE_VERSION", "NODE_SHA256", "NODE_RELEASED", "NODE_ACCEPTED")
# Manifest owners that are not packages. A change to them cannot be split off.
UNSPLITTABLE_OWNERS = {"generated", "layout"}


def dpkg_compare(left, operator, right):
    return subprocess.run(["dpkg", "--compare-versions", left, operator, right], check=False).returncode == 0


def parse_time(text):
    if len(text) == 10:
        return datetime.datetime.strptime(text, "%Y-%m-%d").replace(tzinfo=datetime.timezone.utc)
    trimmed = text.rstrip("Z")
    if "." in trimmed:
        head, fraction = trimmed.split(".", 1)
        trimmed = f"{head}.{fraction[:6]}"
        moment = datetime.datetime.strptime(trimmed, "%Y-%m-%dT%H:%M:%S.%f")
    else:
        moment = datetime.datetime.strptime(trimmed, "%Y-%m-%dT%H:%M:%S")
    return moment.replace(tzinfo=datetime.timezone.utc)


def aged(released, now):
    return now - parse_time(released) >= datetime.timedelta(days=COOLDOWN_DAYS)


def version_tuple(version):
    return tuple(int(part) for part in version.split("."))


def security_fixes(scan):
    """{package: [(cve, [fixed versions])]} for findings that name a fix."""
    fixes = {}
    for result in (scan or {}).get("Results") or []:
        for finding in result.get("Vulnerabilities") or []:
            fixed = [part.strip() for part in (finding.get("FixedVersion") or "").split(",") if part.strip()]
            if fixed:
                fixes.setdefault(finding["PkgName"], []).append((finding["VulnerabilityID"], fixed))
    return fixes


def same_inputs(left, right, ignore_epoch=True):
    def picked(lock):
        values = lockfile.inputs(lock)
        if ignore_epoch:
            values.pop("SOURCE_DATE_EPOCH", None)
        return values
    return picked(left) == picked(right)


# ---- per-input decisions ---------------------------------------------------------------

def decide_node(stable, releases, now):
    current = version_tuple(stable["NODE_VERSION"])
    newer = [r for r in releases if version_tuple(r["version"]) > current]
    eligible = [r for r in newer if r["security"] or aged(r["date"], now)]
    pending = [f"node {r['version']} (released {r['date']}, eligible {cooldown_end(r['date'])})"
               for r in newer if r not in eligible]
    if not eligible:
        return {}, pending
    pick = max(eligible, key=lambda r: version_tuple(r["version"]))
    in_range = [r for r in newer if version_tuple(r["version"]) <= version_tuple(pick["version"])]
    security = [r["version"] for r in in_range if r["security"]]
    if security:
        reason = "security (nodejs.org marks " + ", ".join(security) + " as security releases)"
    else:
        reason = f"cooldown elapsed (released {pick['date']})"
    pending = [p for p in pending if version_tuple(p.split()[1]) > version_tuple(pick["version"])]
    return {"NODE_VERSION": pick["version"], "NODE_SHA256": pick["sha256"],
            "NODE_RELEASED": pick["date"], "NODE_ACCEPTED": reason}, pending


def cooldown_end(released):
    return (parse_time(released) + datetime.timedelta(days=COOLDOWN_DAYS)).strftime("%Y-%m-%d")


def decide_helper(stable, helper, now):
    if helper["image"] == stable.get("HELPER_IMAGE"):
        return {}, []
    created = helper.get("created")
    if not created:
        return {}, [f"helper {helper['image']} (release date unknown)"]
    if not aged(created, now):
        return {}, [f"helper {helper['image']} (created {created}, eligible {cooldown_end(created)})"]
    return {"HELPER_IMAGE": helper["image"], "HELPER_IMAGE_RELEASED": created,
            "HELPER_IMAGE_ACCEPTED": f"cooldown elapsed (image created {created})"}, []


def decide_debian(stable, debian, fixes, now, compare=dpkg_compare):
    changes, pending, warnings = {}, [], []
    for package in sorted(debian):
        entry = debian[package]
        prefix = f"DEB_{lockfile.package_key(package)}_"
        current = stable.get(prefix + "VERSION", "")
        if entry["version"] == current:
            continue
        if current and compare(entry["version"], "lt", current):
            warnings.append(f"{package}: upstream {entry['version']} is older than the lock's {current}")
            continue
        if not entry.get("url"):
            pending.append(f"{package} {entry['version']} (not on snapshot.debian.org yet)")
            continue
        released = entry.get("released")
        cves = sorted({cve for cve, fixed in fixes.get(package, [])
                       if any(compare(version, "le", entry["version"]) for version in fixed)})
        if not released:
            # Without a release date there is no SOURCE_DATE_EPOCH, so the
            # version waits for snapshot.debian.org, even as a security fix.
            pending.append(f"{package} {entry['version']} (no release date from snapshot.debian.org yet)")
            continue
        if cves:
            reason = "security (fixes " + ", ".join(cves) + ")"
        elif aged(released, now):
            reason = f"cooldown elapsed (first listed in {entry['suite']} by {released})"
        else:
            pending.append(f"{package} {entry['version']} (first listed in {entry['suite']} by {released}, "
                           f"eligible {cooldown_end(released)})")
            continue
        changes.update({prefix + "VERSION": entry["version"], prefix + "SUITE": entry["suite"],
                        prefix + "URL": entry["url"], prefix + "SHA256": entry["sha256"],
                        prefix + "RELEASED": released, prefix + "ACCEPTED": reason})
    return changes, pending, warnings


def unpublished(lock):
    return {key: value for key, value in lock.items()
            if not key.startswith("PUBLISHED_") and key not in ("CHANNEL", "BREAKING_PACKAGES")}


def plan(stable, candidate, upstream, scan, now, compare=dpkg_compare):
    result = {"action": "none", "policy": "auto", "summary": "", "pending": [], "warnings": [],
              "faults": list(upstream.get("faults", []))}
    if any(fault["kind"] != "signature" for fault in result["faults"]):
        result["summary"] = "upstream resolution failed; no build"
        return result, None
    nextlock = unpublished(stable)

    if upstream["build_definition"] != stable.get("BUILD_DEFINITION_SHA256"):
        nextlock["BUILD_DEFINITION_SHA256"] = upstream["build_definition"]
        nextlock["BUILD_DEFINITION_ACCEPTED"] = "repository change"

    node_changes, node_pending = decide_node(stable, upstream["node"]["releases"], now)
    helper_changes, helper_pending = decide_helper(stable, upstream["helper"], now)
    deb_changes, deb_pending, deb_warnings = decide_debian(stable, upstream["debian"], security_fixes(scan), now, compare)
    for changes in (node_changes, helper_changes, deb_changes):
        nextlock.update(changes)
    result["pending"] = node_pending + helper_pending + deb_pending
    result["warnings"] = deb_warnings + list(upstream.get("warnings", []))

    nextlock["SOURCE_DATE_EPOCH"] = lockfile.derived_epoch(nextlock)
    nextlock["EVALUATED_AT"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    candidate_published = bool(candidate and candidate.get("PUBLISHED_DIGEST"))

    if same_inputs(nextlock, stable, ignore_epoch=False):
        if stable.get("PUBLISHED_DIGEST"):
            result["summary"] = "no eligible change"
            return result, None
        result.update(action="build", summary="first publish of the stable lock")
        return result, nextlock
    if candidate_published and same_inputs(nextlock, candidate, ignore_epoch=False):
        breaking = [name for name in candidate.get("BREAKING_PACKAGES", "").split(",") if name.strip()]
        subset = split(nextlock, stable, [name.strip() for name in breaking], now)
        if subset is None:
            result["summary"] = f"candidate {candidate['PUBLISHED_DIGEST']} awaits promotion"
            return result, None
        result.update(action="build", policy="stable-only",
                      summary="stable subset of the pending candidate")
        return result, subset
    result["summary"] = "eligible change"
    result["action"] = "build"
    return result, nextlock


# ---- channel -----------------------------------------------------------------------------

def read_manifest(path):
    entries = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            owner, rel, kind = line.rstrip("\n").split("\t")
            entries[rel] = (owner, kind)
    return entries


def breaking_owners(old, new):
    owners = set()
    for rel in set(old) | set(new):
        if old.get(rel) != new.get(rel):
            for side in (old.get(rel), new.get(rel)):
                if side:
                    owner = side[0]
                    if owner == "dpkg-metadata":
                        # status.d/<package> and status.d/<package>.md5sums
                        owner = os.path.basename(rel).removesuffix(".md5sums")
                    owners.add(owner)
    return sorted(owners)


def split(lock, stable, breaking, now):
    """The lock with every breaking change reverted that was not accepted for
    security, or None when no stable subset differs from stable."""
    if lock.get("BUILD_DEFINITION_SHA256") != stable.get("BUILD_DEFINITION_SHA256"):
        return None  # the repository itself changed; only promotion moves stable
    if UNSPLITTABLE_OWNERS & set(breaking):
        return None
    subset = dict(lock)
    for owner in breaking:
        if owner == "node":
            if not lock.get("NODE_ACCEPTED", "").startswith("security"):
                for key in NODE_FIELDS:
                    if key in stable:
                        subset[key] = stable[key]
            continue
        prefix = f"DEB_{lockfile.package_key(owner)}_"
        if lock.get(prefix + "ACCEPTED", "").startswith("security"):
            continue
        for field in DEB_FIELDS:
            if prefix + field in stable:
                subset[prefix + field] = stable[prefix + field]
            else:
                subset.pop(prefix + field, None)
    subset["SOURCE_DATE_EPOCH"] = lockfile.derived_epoch(subset)
    if same_inputs(subset, stable, ignore_epoch=False):
        return None
    return subset


def security_only(lock, stable, breaking):
    if not breaking or lock.get("BUILD_DEFINITION_SHA256") != stable.get("BUILD_DEFINITION_SHA256"):
        return False
    for owner in breaking:
        if owner == "node":
            key = "NODE_ACCEPTED"
        else:
            key = f"DEB_{lockfile.package_key(owner)}_ACCEPTED"
        if not lock.get(key, "").startswith("security"):
            return False
    return True


def channel(lock, stable, stable_manifest, manifest, policy, now):
    decision = {"channel": "stable", "breaking": [], "security_breaking": False, "split": False, "message": ""}
    if stable_manifest is None:
        decision["message"] = "first publish: no stable manifest to compare"
        return decision, None
    breaking = breaking_owners(stable_manifest, manifest)
    decision["breaking"] = breaking
    if not breaking:
        decision["message"] = "non-breaking: the rootfs manifest equals stable"
        return decision, None
    if security_only(lock, stable, breaking):
        decision.update(security_breaking=True,
                        message="breaking, and every breaking change was accepted for security: publish to stable")
        return decision, None
    if policy == "stable-only":
        decision.update(channel="fail",
                        message="the stable subset is still breaking: " + ", ".join(breaking))
        return decision, None
    subset = split(lock, stable, breaking, now)
    decision.update(channel="candidate", split=subset is not None,
                    message="breaking: " + ", ".join(breaking) + "; publish to the candidate channel")
    return decision, subset


# ---- CLI ----------------------------------------------------------------------------------

def load_optional_lock(path):
    if path and os.path.exists(path):
        return lockfile.load(path)
    return {}


def write_lock(path, lock, channel_name):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(lockfile.render(lock, channel_name, lockfile.read_packages()))


def main(argv):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    plan_parser = sub.add_parser("plan")
    plan_parser.add_argument("--stable", required=True)
    plan_parser.add_argument("--candidate", required=True)
    plan_parser.add_argument("--upstream", required=True)
    plan_parser.add_argument("--scan")
    plan_parser.add_argument("--out-dir", required=True)
    plan_parser.add_argument("--now", help="evaluation time, YYYY-MM-DDTHH:MM:SSZ; default: the clock")
    channel_parser = sub.add_parser("channel")
    channel_parser.add_argument("--lock", required=True)
    channel_parser.add_argument("--stable", required=True)
    channel_parser.add_argument("--stable-manifest", required=True)
    channel_parser.add_argument("--manifest", required=True)
    channel_parser.add_argument("--policy", choices=("auto", "stable-only"), required=True)
    channel_parser.add_argument("--out-dir", required=True)
    args = parser.parse_args(argv[1:])
    os.makedirs(args.out_dir, exist_ok=True)
    if getattr(args, "now", None):
        now = parse_time(args.now)
    else:
        now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)

    if args.command == "plan":
        with open(args.upstream, encoding="utf-8") as handle:
            upstream = json.load(handle)
        scan = None
        if args.scan and os.path.exists(args.scan):
            with open(args.scan, encoding="utf-8") as handle:
                scan = json.load(handle)
        result, nextlock = plan(lockfile.load(args.stable), load_optional_lock(args.candidate),
                                upstream, scan, now)
        if nextlock is not None:
            write_lock(os.path.join(args.out_dir, "next.lock"), nextlock, "stable")
        with open(os.path.join(args.out_dir, "plan.json"), "w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2)
            handle.write("\n")
        print(json.dumps(result, indent=2))
        return 0

    stable_manifest = read_manifest(args.stable_manifest) if os.path.exists(args.stable_manifest) else None
    decision, subset = channel(lockfile.load(args.lock), lockfile.load(args.stable), stable_manifest,
                               read_manifest(args.manifest), args.policy, now)
    if subset is not None:
        write_lock(os.path.join(args.out_dir, "split.lock"), subset, "stable")
    with open(os.path.join(args.out_dir, "decision.json"), "w", encoding="utf-8") as handle:
        json.dump(decision, handle, indent=2)
        handle.write("\n")
    print(json.dumps(decision, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
