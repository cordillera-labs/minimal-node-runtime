#!/usr/bin/env python3
"""Plan and apply narrowly scoped, CVE/GHSA-backed toolchain security upgrades.

Only *published repository advisories* naming the tool's own Go module and
giving an affected version range plus a first patched version authorize an
automatic cooldown bypass. Never infer that a release is safe from an arbitrary
CVE mention in release notes or from a dependency-only advisory.

The separate Actions workflow upgrades one pin at a time, verifies a registry
image digest, runs the full CI workflow on the exact branch commit and merges
only if all gates passed. No major-version changes are automatic.
"""

import argparse
import datetime
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import toolchain  # noqa: E402
import upstream  # noqa: E402

REPO_ROOT = toolchain.lockfile.REPO_ROOT
# These must be the *tool itself*, not a dependency pulled into the tool.
DIRECT_MODULES = {
    "buildkit": {"github.com/moby/buildkit"},
    "buildx": {"github.com/docker/buildx"},
    "cosign": {"github.com/sigstore/cosign", "github.com/sigstore/cosign/v2", "github.com/sigstore/cosign/v3"},
    "trivy": {"github.com/aquasecurity/trivy"},
}
ORDER = ("buildkit", "buildx", "cosign", "trivy")
GHSA = re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$")
VER = re.compile(r"^v?([0-9]+)\.([0-9]+)\.([0-9]+)$")
BOUND = re.compile(r"^(>=|<=|>|<|=)\s*v?([0-9]+)\.([0-9]+)\.([0-9]+)$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
ADVISORIES_URL = "https://api.github.com/repos/{repo}/security-advisories?state=published&per_page=100"


def version(text):
    match = VER.fullmatch(str(text))
    return tuple(map(int, match.groups())) if match else None


def affected(v, specification):
    """Return True/False for a fully understood semver range, or None if not.

    A malformed/novel range must *never* be treated as unaffected.
    """
    if not isinstance(specification, str) or not specification.strip():
        return None
    tokens = specification.split(",")
    if len(tokens) > 8:
        return None
    for token in tokens:
        match = BOUND.fullmatch(token.strip())
        if not match:
            return None
        op, *numbers = match.groups()
        bound = tuple(map(int, numbers))
        ok = {">": v > bound, ">=": v >= bound, "<": v < bound,
              "<=": v <= bound, "=": v == bound}[op]
        if not ok:
            return False
    return True


def direct_entries(tool, advisory):
    if not isinstance(advisory, dict) or advisory.get("state") != "published":
        return []
    if advisory.get("withdrawn_at") or not advisory.get("published_at"):
        return []
    if not GHSA.fullmatch(str(advisory.get("ghsa_id", ""))):
        return []
    entries = advisory.get("vulnerabilities")
    if not isinstance(entries, list):
        return []
    allowed = DIRECT_MODULES[tool]
    return [(entry, advisory) for entry in entries if isinstance(entry, dict)
            and isinstance(entry.get("package"), dict)
            and entry["package"].get("ecosystem", "").lower() == "go"
            and entry["package"].get("name") in allowed]


def pick(tool, repo, pinned, releases, advisories):
    """Return the *lowest* published fixed release in the same major line.

    Restrict to releases that solve all known, directly applicable GHSA
    advisories, not just the first. An unknown affected range or missing
    patch cannot certify the upgrade and blocks automation.
    """
    installed = version(pinned)
    if installed is None:
        raise ValueError("invalid pinned version")
    if not isinstance(advisories, list) or not isinstance(releases, list):
        raise ValueError("upstream security metadata is not a list")
    all_entries = []
    for advisory in advisories:
        all_entries.extend(direct_entries(tool, advisory))
    fixing = []
    for entry, advisory in all_entries:
        match = affected(installed, entry.get("vulnerable_version_range"))
        if match is None:
            raise ValueError(f"unparseable affected version range for {advisory['ghsa_id']}")
        if not match:
            continue
        patched = entry.get("first_patched_version")
        fixed = version(patched.get("identifier")) if isinstance(patched, dict) else None
        if fixed is None or fixed <= installed:
            raise ValueError(f"missing valid patched version for {advisory['ghsa_id']}")
        fixing.append((fixed, advisory["ghsa_id"], advisory.get("html_url", "")))
    if not fixing:
        return None
    lower_bound = max(fix[0] for fix in fixing)
    candidates = [(ver, tag, date, url) for ver, tag, date, url
                  in toolchain.stable_releases(releases)
                  if ver[0] == installed[0] and ver >= lower_bound]
    candidates.sort()
    for candidate, tag, date, url in candidates:
        # Do not replace a verified vulnerability with another known one.
        unknown = False
        safe = True
        for entry, advisory in all_entries:
            status = affected(candidate, entry.get("vulnerable_version_range"))
            if status is None:
                unknown = True
                break
            if status:
                safe = False
                break
        if unknown:
            raise ValueError("cannot validate all published direct-advisory ranges")
        if safe:
            return {
                "tool": tool,
                "key": next(k for k, (name, _, _) in toolchain.TOOLS.items() if name == tool),
                "repo": repo,
                "from": pinned,
                "to": tag,
                "release_date": date,
                "release_url": url,
                "advisories": sorted({item[1] for item in fixing}),
                "advisory_urls": sorted({item[2] for item in fixing if isinstance(item[2], str)
                                          and item[2].startswith(f"https://github.com/{repo}/security/advisories/")}),
                "reason": "published direct GHSA fixes verified against affected and patched versions",
                "major_change": False,
                "cooldown_bypassed": True,
            }
    return None  # Fixed only by another major version or not yet stably released.


def github_list(url):
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        raw = upstream.get(url, headers=headers)
    except ConnectionError as exc:
        # Public repository APIs sometimes deny a workflow's scoped token to
        # unrelated repositories (403). Retry as a *public* unauthenticated
        # fetch. A second failure is a fault, never a safe-to-upgrade result.
        if "HTTP 403" not in str(exc) and "HTTP 401" not in str(exc):
            raise
        headers.pop("Authorization", None)
        raw = upstream.get(url, headers=headers)
    result = json.loads(raw)
    if not isinstance(result, list):
        raise ValueError("GitHub did not return an array")
    return result


def plan(pins, fetch_releases, fetch_advisories):
    choices = []
    faults = []
    for key, (tool, repo, reader) in toolchain.TOOLS.items():
        raw = pins.get(key, "")
        pinned = reader(raw)
        if pinned is None:
            faults.append(f"{tool}: invalid or missing version pin")
            continue
        try:
            releases = fetch_releases(repo)
            advisories = fetch_advisories(repo)
            if not releases or not isinstance(releases, list):
                raise ValueError("no published releases")
            if not isinstance(advisories, list):
                raise ValueError("invalid advisories response")
            choice = pick(tool, repo, pinned, releases, advisories)
            if choice:
                choices.append(choice)
        except (ValueError, ConnectionError, KeyError, TypeError) as exc:
            faults.append(f"{tool}: {exc}")
    # One tool per run: builder upgrades can change the image digest.
    # BuildKit goes first so the builder and buildx do not change together.
    choices.sort(key=lambda item: ORDER.index(item["tool"]))
    return {"selected": choices[0] if choices else None,
            "queued": choices[1:], "faults": faults}


def apply(choice, path, digest=None):
    if not isinstance(choice, dict):
        raise ValueError("missing security upgrade plan")
    key = choice.get("key")
    if key not in toolchain.TOOLS:
        raise ValueError("tool pin is not allowlisted")
    name, _, reader = toolchain.TOOLS[key]
    if name != choice.get("tool"):
        raise ValueError("tool/key mismatch")
    old, new = choice.get("from", ""), choice.get("to", "")
    a, b = version(old), version(new)
    if not a or not b or b <= a or a[0] != b[0]:
        raise ValueError("automatic major/downgrade changes are forbidden")
    if not choice.get("advisories") or not choice.get("cooldown_bypassed"):
        raise ValueError("unverified security upgrade")
    pins = toolchain.read_pins(path)
    current = pins.get(key)
    if reader(current) != old:
        raise ValueError("pin changed since plan; refusing to overwrite")
    if key.endswith("_IMAGE"):
        if not DIGEST.fullmatch(digest or ""):
            raise ValueError("image pin requires a registry-verified sha256 digest")
        registry_name = current.split(":", 1)[0]
        if key == "BUILDKIT_IMAGE" and registry_name != "moby/buildkit":
            raise ValueError("unexpected BuildKit registry")
        if key == "COSIGN_IMAGE" and registry_name != "gcr.io/projectsigstore/cosign":
            raise ValueError("unexpected Cosign registry")
        replacement = f"{registry_name}:{new}@{digest}"
    else:
        if digest:
            raise ValueError("binary version pin must not specify image digest")
        replacement = new
    with open(path, encoding="utf-8") as handle:
        content = handle.read()
    line = f"{key}={current}"
    if content.splitlines().count(line) != 1:
        raise ValueError("pin line is not unique")
    updated = content.replace(line + "\n", f"{key}={replacement}\n", 1)
    if updated == content or updated.count(f"{key}={replacement}\n") != 1:
        raise ValueError("pin replacement failed")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(updated)
    return replacement


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    subs = parser.add_subparsers(dest="command", required=True)
    p = subs.add_parser("plan")
    p.add_argument("--out", required=True)
    a = subs.add_parser("apply")
    a.add_argument("--plan", required=True)
    a.add_argument("--toolchain", default=os.path.join(REPO_ROOT, "toolchain.env"))
    a.add_argument("--digest")
    args = parser.parse_args(argv[1:])
    if args.command == "plan":
        pins = toolchain.read_pins(os.path.join(REPO_ROOT, "toolchain.env"))
        result = plan(pins,
                      lambda repo: github_list(toolchain.RELEASES_URL.format(repo=repo)),
                      lambda repo: github_list(ADVISORIES_URL.format(repo=repo)))
        with open(args.out, "w", encoding="utf-8") as handle:
            json.dump(result, handle, sort_keys=True, indent=2)
            handle.write("\n")
        print(json.dumps(result, indent=2))
        return 0
    with open(args.plan, encoding="utf-8") as handle:
        info = json.load(handle)
    try:
        replacement = apply(info.get("selected"), args.toolchain, args.digest)
    except (ValueError, OSError) as exc:
        print(f"toolchain-security: {exc}", file=sys.stderr)
        return 1
    print(replacement)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
