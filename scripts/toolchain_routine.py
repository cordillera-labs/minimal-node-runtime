#!/usr/bin/env python3
"""Plan, apply and verify one cooldown-eligible routine toolchain pin update.

Pure plan/verify operations are deliberately separate from the GitHub Actions
orchestrator. No release or registry metadata is fetched by this module.
"""
import argparse
import datetime
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import policy  # noqa: E402
import toolchain  # noqa: E402

ORDER = ("buildkit", "buildx", "cosign", "trivy")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
IMAGES = {
    "buildkit": "moby/buildkit",
    "cosign": "gcr.io/projectsigstore/cosign",
}


def version(tag):
    return toolchain.version_tuple(tag) if isinstance(tag, str) else None


def plan(report, pins, skip=(), now=None):
    """Select one eligible release, excluding tools with existing routine PRs."""
    if not isinstance(report, dict) or not isinstance(report.get("tools"), list):
        raise ValueError("missing toolchain monitor report")
    now = now or datetime.datetime.now(datetime.timezone.utc)
    skip = frozenset(skip)
    if any(name not in ORDER for name in skip):
        raise ValueError("unknown skipped tool")
    rows = [r for r in report["tools"] if isinstance(r, dict) and r.get("tool") in ORDER]
    if len(rows) != len(set(r["tool"] for r in rows)):
        raise ValueError("duplicate tool in monitor report")
    by_tool = {r["tool"]: r for r in rows}
    for name in ORDER:
        if name in skip:
            continue
        row = by_tool.get(name)
        if row is None:
            raise ValueError(f"monitor report is missing {name}")
        if row.get("state") != "update":
            continue  # current, pending, and fault never authorize a pin change
        key = next(k for k, (tool, _, _) in toolchain.TOOLS.items() if tool == name)
        pinned = toolchain.TOOLS[key][2](pins.get(key, ""))
        eligible = row.get("eligible")
        if pinned is None or row.get("pinned") != pinned or not isinstance(eligible, dict):
            raise ValueError(f"{name}: report and current pin disagree")
        target = eligible.get("tag")
        old, new = version(pinned), version(target)
        released = eligible.get("published_at")
        url = eligible.get("url")
        repo = toolchain.TOOLS[key][1]
        if (old is None or new is None or new <= old or
                not isinstance(released, str) or
                not isinstance(url, str) or
                url != f"https://github.com/{repo}/releases/tag/{target}"):
            raise ValueError(f"{name}: invalid eligible release metadata")
        try:
            aged = policy.aged(released, now)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"{name}: invalid release timestamp") from exc
        if not aged:
            raise ValueError(f"{name}: release has not completed cooldown")
        return {
            "tool": name, "key": key, "from": pinned, "to": target,
            "released_at": released, "release_url": url,
            "major_change": old[0] != new[0],
        }
    return None


def changed_pin(base, candidate, name):
    """Reject every change except a single, syntactically valid pin upgrade."""
    if name not in ORDER:
        raise ValueError("tool not allowlisted")
    key = next(k for k, (tool, _, _) in toolchain.TOOLS.items() if tool == name)
    base_pins = parse_pins(base)
    new_pins = parse_pins(candidate)
    if set(base_pins) != set(new_pins):
        raise ValueError("pin keys changed")
    if [k for k in base_pins if base_pins[k] != new_pins[k]] != [key]:
        raise ValueError("exactly one tool pin must change")
    old_raw, new_raw = base_pins[key], new_pins[key]
    read_pin = toolchain.TOOLS[key][2]
    old, new = read_pin(old_raw), read_pin(new_raw)
    if not old or not new or version(new) <= version(old):
        raise ValueError("pin change is not a valid upgrade")
    if name in IMAGES:
        prefix = IMAGES[name] + ":"
        if (not new_raw.startswith(prefix) or "@sha256:" not in new_raw or
                not DIGEST.fullmatch(new_raw.split("@", 1)[1])):
            raise ValueError("image must retain its registry and a full immutable digest")
    elif new_raw != new:
        raise ValueError("binary pin must only contain the version")
    if candidate != base.replace(f"{key}={old_raw}\n", f"{key}={new_raw}\n", 1):
        raise ValueError("toolchain.env has unrelated changes")
    return {"tool": name, "from": old, "to": new,
            "major_change": version(old)[0] != version(new)[0]}


def parse_pins(data):
    pins = {}
    for line in data.splitlines():
        if not line or line.startswith("#"):
            continue
        if line.count("=") != 1:
            raise ValueError("malformed pin line")
        key, value = line.split("=", 1)
        if key in pins:
            raise ValueError("duplicate pin key")
        pins[key] = value
    return pins


def apply(choice, path, digest=None):
    if not isinstance(choice, dict) or choice.get("tool") not in ORDER:
        raise ValueError("missing routine update plan")
    name = choice["tool"]
    key = next(k for k, (tool, _, _) in toolchain.TOOLS.items() if tool == name)
    old, new = choice.get("from"), choice.get("to")
    if key != choice.get("key") or not version(old) or not version(new) or version(new) <= version(old):
        raise ValueError("invalid or stale routine pin upgrade")
    if choice.get("major_change") != (version(old)[0] != version(new)[0]):
        raise ValueError("major-change classification mismatch")
    if name in IMAGES:
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
            raise ValueError("image update requires verified sha256 digest")
        replacement = f"{IMAGES[name]}:{new}@{digest}"
    else:
        if digest is not None:
            raise ValueError("binary version must not specify a digest")
        replacement = new
    with open(path, encoding="utf-8") as handle:
        original = handle.read()
    current = parse_pins(original)
    read_pin = toolchain.TOOLS[key][2]
    if read_pin(current.get(key, "")) != old:
        raise ValueError("pin changed since the monitor ran")
    candidate = original.replace(f"{key}={current[key]}\n", f"{key}={replacement}\n", 1)
    changed_pin(original, candidate, name)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(candidate)
    return replacement


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    subs = parser.add_subparsers(dest="command", required=True)
    p = subs.add_parser("plan")
    p.add_argument("--report", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--skip", default="", help="comma-separated tools with open routine PRs")
    p.add_argument("--toolchain", default=os.path.join(toolchain.lockfile.REPO_ROOT, "toolchain.env"))
    a = subs.add_parser("apply")
    a.add_argument("--plan", required=True)
    a.add_argument("--toolchain", default=os.path.join(toolchain.lockfile.REPO_ROOT, "toolchain.env"))
    a.add_argument("--digest")
    v = subs.add_parser("verify")
    v.add_argument("--base", required=True)
    v.add_argument("--candidate", required=True)
    v.add_argument("--tool", choices=ORDER, required=True)
    args = parser.parse_args(argv[1:])
    try:
        if args.command == "plan":
            with open(args.report, encoding="utf-8") as handle:
                report = json.load(handle)
            choice = plan(report, toolchain.read_pins(args.toolchain), filter(None, args.skip.split(",")))
            with open(args.out, "w", encoding="utf-8") as handle:
                json.dump(choice, handle, indent=2)
                handle.write("\n")
            print(json.dumps(choice))
        elif args.command == "apply":
            with open(args.plan, encoding="utf-8") as handle:
                print(apply(json.load(handle), args.toolchain, args.digest))
        else:
            with open(args.base, encoding="utf-8") as handle:
                base = handle.read()
            with open(args.candidate, encoding="utf-8") as handle:
                candidate = handle.read()
            print(json.dumps(changed_pin(base, candidate, args.tool)))
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print(f"toolchain-routine: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
