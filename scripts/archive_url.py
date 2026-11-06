#!/usr/bin/env python3
"""Print the live Debian archive URL of one exact binary package version.

    archive_url.py <package> <version> <suite>

This is a fallback for when snapshot.debian.org is unavailable. It reads the
suite's live Packages index and prints the pool URL of the entry whose Package
and Version match exactly. The index is not trusted: fetch-debs.sh accepts the
file only when its SHA-256 equals the lock. The live archive keeps only current
versions, so a superseded version is not found (exit 1).
"""
import lzma
import sys
import urllib.request

ARCHIVES = {
    "trixie": "https://deb.debian.org/debian",
    "trixie-updates": "https://deb.debian.org/debian",
    "trixie-security": "https://security.debian.org/debian-security",
}


def main() -> int:
    package, version, suite = sys.argv[1:4]
    base = ARCHIVES.get(suite)
    if base is None:
        print(f"archive_url: no live archive known for suite {suite}", file=sys.stderr)
        return 2
    index = f"{base}/dists/{suite}/main/binary-amd64/Packages.xz"
    with urllib.request.urlopen(index, timeout=60) as response:
        text = lzma.decompress(response.read()).decode("utf-8")
    for stanza in text.split("\n\n"):
        fields = {}
        for line in stanza.splitlines():
            if line and not line[0].isspace() and ":" in line:
                key, _, value = line.partition(":")
                fields[key] = value.strip()
        if fields.get("Package") == package and fields.get("Version") == version:
            print(f"{base}/{fields['Filename']}")
            return 0
    print(f"archive_url: {package} {version} is not in the live {suite} index", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
