#!/usr/bin/env python3
"""Gate routine PR adoption on build-inert changes to main since validated CI.

The routine update already verifies a single toolchain.env pin change and full
CI on its exact commit. Independent root-trust observation snapshots can change
main between CI and adoption without altering any image/CI inputs. Permit only
those explicitly named paths; everything else requires a refreshed PR and CI.

Usage: toolchain_observation_drift.py <tested-parent> <current-main>
Exit status: 0 = safe to merge with existing exact-head CI,
             1 = refresh/retest required; 2 = invalid git state (fail closed).
"""
from pathlib import Path
import subprocess
import sys

# This is deliberately a fixed list, not state/trust/* or state/**: a future
# trust-state file may become security-relevant or affect a build.
OBSERVATION_ONLY = frozenset({
    "state/trust/chrome.json",
    "state/trust/mozilla.json",
    "state/heartbeat",
})


def git(repo: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, check=False,
    )


def is_observation_only(repo: Path, tested_parent: str, current_main: str) -> bool:
    # A rewritten/non-descendant main cannot inherit the earlier CI verdict.
    ancestor = git(repo, "merge-base", "--is-ancestor", tested_parent, current_main)
    if ancestor.returncode == 1:
        return False
    if ancestor.returncode:
        raise ValueError("cannot verify the previous main commit is an ancestor")

    # NUL-delimited paths preserve exactly what git reports. --no-renames
    # reports a rename as a deletion and an addition, preventing an unrelated
    # file from being smuggled into the allowlist through rename detection.
    changes = git(
        repo, "diff", "--no-renames", "--name-only", "-z",
        tested_parent, current_main, "--",
    )
    if changes.returncode:
        raise ValueError("cannot inspect changed paths between tested and current main")
    if not changes.stdout:
        return True
    paths = [part.decode("utf-8") for part in changes.stdout.split(b"\0") if part]
    return bool(paths) and all(path in OBSERVATION_ONLY for path in paths)


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        safe = is_observation_only(Path.cwd(), argv[1], argv[2])
    except (UnicodeError, ValueError) as error:
        print(f"observation drift: {error}", file=sys.stderr)
        return 2
    if safe:
        print("Only build-inert trust observations/heartbeat changed; exact-head CI remains valid.")
        return 0
    print("Build/security-relevant or unrelated main changes require refreshed exact-head CI.")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
