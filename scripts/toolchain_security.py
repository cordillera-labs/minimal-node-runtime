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
CLOSED_RANGE = re.compile(r"^v?([0-9]+)\.([0-9]+)\.([0-9]+)\s+-\s+v?([0-9]+)\.([0-9]+)\.([0-9]+)$")
CVE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
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
    closed = CLOSED_RANGE.fullmatch(specification.strip())
    if closed:
        nums = tuple(map(int, closed.groups()))
        lower, upper = nums[:3], nums[3:]
        return lower <= v <= upper if lower <= upper else None
    tokens = specification.split(",")
    if len(tokens) > 8:
        return None
    parsed = []
    for token in tokens:
        match = BOUND.fullmatch(token.strip())
        if not match:
            return None
        op, *numbers = match.groups()
        parsed.append((op, tuple(map(int, numbers))))
    # Validate the *entire* range before declaring a version unaffected.
    # Otherwise a malformed final clause after a false first clause could
    # silently bypass our fail-closed advisory validation.
    return all({">": v > bound, ">=": v >= bound, "<": v < bound,
                "<=": v <= bound, "=": v == bound}[op] for op, bound in parsed)


def direct_entries(tool, advisory, installed_major):
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
    selected = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        package = entry.get("package")
        if isinstance(package, dict):
            ecosystem = package.get("ecosystem")
            name = package.get("name")
            if isinstance(ecosystem, str) and ecosystem.lower() == "go" and name in allowed:
                # The same Cosign GHSA may list distinct module ranges for
                # v2 and v3. A v3 entry such as <= 3.1.2 must not be
                # incorrectly applied to a pinned v2.6.1 binary.
                if tool == "cosign":
                    if name.endswith("/v2") and installed_major != 2:
                        continue
                    if name.endswith("/v3") and installed_major != 3:
                        continue
                selected.append((entry, advisory))
                continue
            # Some maintainers (including BuildKit and Buildx) publish their
            # *product* CVEs without naming a Go module or other package.
            # Only a published CVE in the tool's own repo with an explicitly
            # untyped package can use this narrow product-level path.
            if ecosystem == "other" and name in (None, "") and CVE.fullmatch(str(advisory.get("cve_id", ""))):
                selected.append((entry, advisory))
        elif package is None and CVE.fullmatch(str(advisory.get("cve_id", ""))):
            selected.append((entry, advisory))
    return selected


# Repository advisories sometimes combine *independent major lines* in one
# vulnerability entry (Cosign: "<= v3.0.5, <= v2.6.2" / "v3.0.6, v2.6.3").
# A comma is therefore not necessarily logical AND. Interpret this special
# form only when each major has exactly one comparator and one fixed version.
ADVISORY_PATCH_SENTENCE = re.compile(
    r"(?im)^\s*(?:The )?[Ii]ssue has been fixed in version "
    r"(v?[0-9]+\.[0-9]+\.[0-9]+\+?)\.\s*$"
)
PATCH_HEADING = re.compile(r"(?im)^#{2,4}\s*Patches\s*$")
NEXT_HEADING = re.compile(r"(?m)^#{2,4}\s+\S")


def patches(entry, advisory, tool):
    """An explicit fixed version for each major, or None if not provided.

    Reject arbitrary prose and malformed/ambiguous lists. A narrow exception
    handles older *published Buildx CVEs* whose structured patched_versions
    field is null despite an exact fixed-version sentence in the publisher's
    own Patches section. Never mine generic release notes.
    """
    raw = entry.get("patched_versions")
    if raw is None:
        legacy = entry.get("first_patched_version")
        raw = legacy.get("identifier") if isinstance(legacy, dict) else None
    if raw is None or raw == "None":
        if tool == "buildx" and CVE.fullmatch(str(advisory.get("cve_id", ""))):
            description = advisory.get("description")
            if isinstance(description, str):
                heading = PATCH_HEADING.search(description)
                if heading:
                    tail = description[heading.end():]
                    end = NEXT_HEADING.search(tail)
                    paragraph = tail[:end.start()] if end else tail
                    statements = ADVISORY_PATCH_SENTENCE.findall(paragraph)
                    if len(statements) == 1:
                        raw = statements[0]
    if raw is None:
        return None
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError(f"malformed patched versions for {advisory['ghsa_id']}")
    found = {}
    for part in raw.split(","):
        token = part.strip()
        # Repository advisories sometimes suffix a fixed version with '+',
        # meaning this release and later. Never accept a compound range here.
        fixed = version(token[:-1] if token.endswith("+") else token)
        if fixed is None or fixed[0] in found:
            raise ValueError(f"ambiguous patched versions for {advisory['ghsa_id']}")
        found[fixed[0]] = fixed
    return found


def advisory_affected(v, expression, patch_map):
    """Evaluate a complete, unambiguous range for the given version line.

    A multi-major patch list permits one comparator per matching major. Other
    comma-separated ranges retain the normal AND semantics in affected().
    """
    if not patch_map or len(patch_map) == 1:
        return affected(v, expression)
    if not isinstance(expression, str):
        return None
    clauses = [part.strip() for part in expression.split(",")]
    if len(clauses) != len(patch_map):
        return None
    by_major = {}
    for clause in clauses:
        match = BOUND.fullmatch(clause)
        if not match:
            return None
        major = int(match.group(2))
        if major in by_major:
            return None
        by_major[major] = clause
    if set(by_major) != set(patch_map):
        return None
    return affected(v, by_major[v[0]]) if v[0] in by_major else False


def pick(tool, repo, pinned, releases, advisories):
    """Choose the earliest published same-major release that fixes all GHSA risks.

    A patched version takes precedence over an older advisories' stale
    unbounded vulnerable range (Buildx GHSA-gwr2-q96m-6682 still says
    '>=0.21.0' despite its Patches section naming v0.37.2).
    Unknown/malformed metadata fails closed; an already-fixed pin needs no
    additional update for that advisory.
    """
    installed = version(pinned)
    if installed is None:
        raise ValueError("invalid pinned version")
    if not isinstance(advisories, list) or not isinstance(releases, list):
        raise ValueError("upstream security metadata is not a list")
    entries = []
    for advisory in advisories:
        for entry, source in direct_entries(tool, advisory, installed[0]):
            patch_map = patches(entry, source, tool)
            status = advisory_affected(installed, entry.get("vulnerable_version_range"), patch_map)
            if status is None:
                raise ValueError(f"unparseable affected version range for {source['ghsa_id']}")
            fixed = patch_map.get(installed[0]) if patch_map else None
            entries.append((entry, source, patch_map, fixed))
    fixing = []
    for entry, advisory, patch_map, fixed in entries:
        status = advisory_affected(installed, entry.get("vulnerable_version_range"), patch_map)
        if status and fixed is None:
            if patch_map and installed[0] not in patch_map:
                # The published fix exists, but only across a major boundary.
                # This is a human migration, never an automatic error or
                # downgrade to an unrelated same-major release.
                return None
            raise ValueError(f"missing valid patched version for {advisory['ghsa_id']}")
        # A publisher's explicit patched-version claim supersedes a stale
        # unbounded vulnerability-range field for the same installed major.
        if not status or (fixed is not None and installed >= fixed):
            continue
        fixing.append((fixed, advisory["ghsa_id"], advisory.get("html_url", "")))
    if not fixing:
        return None
    lower_bound = max(fix[0] for fix in fixing)
    candidates = [(ver, tag, date, url) for ver, tag, date, url
                  in toolchain.stable_releases(releases)
                  if ver[0] == installed[0] and ver >= lower_bound]
    candidates.sort()
    for candidate, tag, date, url in candidates:
        safe = True
        for entry, advisory, patch_map, fixed in entries:
            status = advisory_affected(candidate, entry.get("vulnerable_version_range"), patch_map)
            if status is None:
                raise ValueError(f"cannot validate range for {advisory['ghsa_id']}")
            # The version can be safe either by not matching the known
            # vulnerable range or by explicitly meeting its patched version.
            if status and (fixed is None or candidate < fixed):
                safe = False
                break
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
    return None  # No current-major stable release resolving all known risks.


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
        public_headers = {key: value for key, value in headers.items() if key != "Authorization"}
        raw = upstream.get(url, headers=public_headers)
    result = json.loads(raw)
    if not isinstance(result, list):
        raise ValueError("GitHub did not return an array")
    # Never certify a security upgrade from a possibly incomplete advisory
    # inventory. GitHub's documented per_page=100 response is truncated if
    # there are more; fail safely until explicit pagination is implemented.
    if "security-advisories?" in url and len(result) >= 100:
        raise ValueError("advisory inventory may be truncated at 100 entries")
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
