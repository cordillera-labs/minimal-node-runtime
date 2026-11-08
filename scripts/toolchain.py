#!/usr/bin/env python3
"""Check the tool pins in toolchain.env against the latest stable upstream release.

  toolchain.py check --toolchain toolchain.env --out toolchain.json [--summary summary.md]

Dependabot does not read toolchain.env, so a pin goes stale without a signal.
This script reads each pin and the GitHub releases of its tool, and writes one
result per tool to --out. It decides nothing about the pins: it never edits
toolchain.env and publishes nothing. A person reviews the change and merges it.

A newer stable release is eligible once it is COOLDOWN_DAYS old
(scripts/policy.py), the same cooldown the update policy applies to every other
input. A security update has no fast path here, because a tool is part of the
build definition and a person reviews every change to it.

Each result has a state:
  current   the pin is at or above the newest stable release.
  pending   a newer stable release exists, and it is still inside the cooldown.
  update    a newer stable release is eligible.
  fault     the pin or the upstream release list could not be read. This is not
            "no update": the workflow leaves the tool's issue as it is.
"""

import argparse
import datetime
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lock as lockfile  # noqa: E402  (REPO_ROOT)
import policy  # noqa: E402
import upstream  # noqa: E402

RELEASES_URL = "https://api.github.com/repos/{repo}/releases?per_page=50"
STABLE_TAG = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
IMAGE_TAG = re.compile(r"^[a-z0-9./_-]+:(v\d+\.\d+\.\d+)(?:@sha256:[0-9a-f]{64})?$")
VERSION_PIN = re.compile(r"^v\d+\.\d+\.\d+$")
LABEL = "toolchain-update"

# Pins that name no tool release.
NOT_A_TOOL = {"IMAGE_REPOSITORY"}


def version_pin(value):
    return value if VERSION_PIN.match(value) else None


def image_pin(value):
    match = IMAGE_TAG.match(value)
    return match.group(1) if match else None


# key in toolchain.env -> (tool, GitHub repository of its releases, reader of the pinned version)
TOOLS = {
    "TRIVY_VERSION": ("trivy", "aquasecurity/trivy", version_pin),
    "BUILDKIT_IMAGE": ("buildkit", "moby/buildkit", image_pin),
    "BUILDX_VERSION": ("buildx", "docker/buildx", version_pin),
    "COSIGN_IMAGE": ("cosign", "sigstore/cosign", image_pin),
}


def read_pins(path):
    pins = {}
    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                pins[key] = value
    return pins


def version_tuple(tag):
    match = STABLE_TAG.match(tag)
    return tuple(int(part) for part in match.groups()) if match else None


def stable_releases(releases):
    """(version tuple, tag, published_at, url) of each stable release, newest first.
    A draft, a prerelease and a tag that is not vMAJOR.MINOR.PATCH are skipped."""
    found = []
    for release in releases:
        tag = release.get("tag_name", "")
        parsed = version_tuple(tag)
        if release.get("draft") or release.get("prerelease") or parsed is None or not release.get("published_at"):
            continue
        found.append((parsed, tag, release["published_at"], release.get("html_url", "")))
    found.sort(reverse=True)
    return found


def evaluate(tool, repo, pinned, releases, now):
    """The result for one tool from its pinned tag and the GitHub release list."""
    result = {"tool": tool, "repo": repo, "pinned": pinned, "state": "current", "eligible": None, "pending": None}
    pinned_version = version_tuple(pinned)
    newer = [release for release in stable_releases(releases) if release[0] > pinned_version]
    # The newest release that has passed the cooldown. A newer one still inside it is pending.
    eligible = next((release for release in newer if policy.aged(release[2], now)), None)
    pending = next((release for release in newer if not policy.aged(release[2], now)), None)
    if eligible:
        result["state"] = "update"
        result["eligible"] = {"tag": eligible[1], "published_at": eligible[2], "url": eligible[3]}
    elif pending:
        result["state"] = "pending"
    if pending and (not eligible or pending[0] > eligible[0]):
        result["pending"] = {"tag": pending[1], "published_at": pending[2], "cooldown_ends": policy.cooldown_end(pending[2])}
    return result


def fault(tool, repo, message):
    return {"tool": tool, "repo": repo, "pinned": None, "state": "fault", "eligible": None, "pending": None,
            "message": message}


def check(pins, fetch_releases, now):
    results = []
    unknown = sorted(set(pins) - set(TOOLS) - NOT_A_TOOL)
    for key in unknown:
        results.append(fault(key, "", f"{key} in toolchain.env has no entry in scripts/toolchain.py TOOLS"))
    for key, (tool, repo, read_pin) in TOOLS.items():
        pinned = read_pin(pins[key]) if key in pins else None
        if pinned is None:
            results.append(fault(tool, repo, f"{key} in toolchain.env is missing or is not a vMAJOR.MINOR.PATCH pin"))
            continue
        try:
            releases = fetch_releases(repo)
        except (ConnectionError, ValueError) as error:
            results.append(fault(tool, repo, f"the releases of {repo} could not be read: {error}"))
            continue
        if not stable_releases(releases):
            results.append(dict(fault(tool, repo, f"{repo} lists no stable release"), pinned=pinned))
            continue
        results.append(evaluate(tool, repo, pinned, releases, now))
    return results


def github_releases(repo):
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = RELEASES_URL.format(repo=repo)
    try:
        body = upstream.get(url, headers=headers)
    except ConnectionError as exc:
        # A workflow-scoped GitHub token can receive 403 for another public
        # repository. Retry as an unauthenticated public request instead of
        # silently missing updates (previously observed with Trivy).
        if not token or ("HTTP 403" not in str(exc) and "HTTP 401" not in str(exc)):
            raise
        headers.pop("Authorization", None)
        body = upstream.get(url, headers=headers)
    releases = json.loads(body)
    if not isinstance(releases, list):
        raise ValueError("the response is not a list of releases")
    return releases


def issue_title(result):
    return f"Toolchain pin update available: {result['tool']}"


def issue_body(result):
    eligible = result["eligible"]
    lines = [
        f"`toolchain.env` pins {result['tool']} at `{result['pinned']}`. Upstream has a newer stable release",
        f"that has passed the {policy.COOLDOWN_DAYS}-day cooldown.",
        "",
        f"- Pinned: `{result['pinned']}`",
        f"- Newest eligible: `{eligible['tag']}`, released {eligible['published_at']}",
        f"- Release notes: {eligible['url']}",
    ]
    pending = result["pending"]
    if pending:
        lines.append(f"- Newer, still in the cooldown: `{pending['tag']}`, eligible from {pending['cooldown_ends']}")
    lines += [
        "",
        "The workflows never change `toolchain.env`. To adopt the release, review its notes and open a",
        "pull request that changes the pin (for an image pin, the tag and the digest together). The file",
        "is part of the build definition, so the next update run rebuilds with the new pin.",
        "A BuildKit or buildx change can change the image digest, so change those pins on their own.",
        "",
        "This issue closes when the pin reaches the eligible release.",
    ]
    return "\n".join(lines) + "\n"


def summary(results):
    lines = ["### Toolchain pins"]
    for result in results:
        state = result["state"]
        if state == "fault":
            lines.append(f"- fault: {result['tool']}: {result['message']}")
        elif state == "update":
            held = f"; {result['pending']['tag']} is in the cooldown until {result['pending']['cooldown_ends']}" if result["pending"] else ""
            lines.append(f"- {result['tool']}: {result['pinned']} -> {result['eligible']['tag']} is eligible{held}")
        elif state == "pending":
            lines.append(f"- {result['tool']}: {result['pinned']}, {result['pending']['tag']} is in the cooldown until {result['pending']['cooldown_ends']}")
        else:
            lines.append(f"- {result['tool']}: {result['pinned']} is current")
    return "\n".join(lines) + "\n"


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    check_parser = sub.add_parser("check")
    check_parser.add_argument("--toolchain", default=os.path.join(lockfile.REPO_ROOT, "toolchain.env"))
    check_parser.add_argument("--out", required=True)
    check_parser.add_argument("--summary")
    check_parser.add_argument("--now", help="ISO time; default the current time")
    args = parser.parse_args(argv[1:])

    now = policy.parse_time(args.now) if args.now else datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    results = check(read_pins(args.toolchain), github_releases, now)
    for result in results:
        result["title"] = issue_title(result)
        if result["state"] == "update":
            result["body"] = issue_body(result)
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump({"checked_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "label": LABEL, "tools": results},
                  handle, indent=2, sort_keys=True)
        handle.write("\n")
    text = summary(results)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as handle:
            handle.write(text)
    # A fault is reported and never fails the run: it stays distinct from "no update".
    for result in results:
        if result["state"] == "fault":
            print(f"::error::{result['message']}")
    print(text, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
