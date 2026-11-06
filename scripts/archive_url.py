#!/usr/bin/env python3
"""Print the live Debian archive URL of one exact binary package version.

    archive_url.py <package> <version> <suite> <sha256>

This is a fallback for when snapshot.debian.org is unavailable. It reads the
suite's live Packages index, checked against the signed Release file of the
suite (scripts/debian_archive.py), and prints the pool URL of the entry whose
Package and Version match exactly. The entry must list <sha256>, the value the
lock pins, and fetch-debs.sh checks the downloaded file against it again. The
live archive keeps only current versions, so a superseded version is not found.

Exit status: 0 with the URL printed, 1 when the version is not listed or
lists another SHA-256, 2 on a usage or verification fault.
"""
import lzma
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import debian_archive  # noqa: E402
import upstream  # noqa: E402


def main() -> int:
    if len(sys.argv) != 5:
        print(__doc__, file=sys.stderr)
        return 2
    package, version, suite, sha256 = sys.argv[1:5]
    try:
        base = debian_archive.live_base(suite)
        text = upstream.verified_index(base, suite)
    except (debian_archive.ArchiveFault, upstream.UpstreamFault, ConnectionError, lzma.LZMAError) as fault:
        print(f"archive_url: {fault}", file=sys.stderr)
        return 2
    for fields in upstream.parse_packages(text, {package}).get(package, []):
        if fields.get("Version") != version:
            continue
        if fields.get("SHA256") != sha256:
            print(f"archive_url: the signed {suite} index lists {package} {version} with SHA-256 "
                  f"{fields.get('SHA256')}, the lock pins {sha256}", file=sys.stderr)
            return 1
        print(f"{base}/{fields['Filename']}")
        return 0
    print(f"archive_url: {package} {version} is not in the live {suite} index", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
