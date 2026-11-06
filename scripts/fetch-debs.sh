#!/bin/bash
# Collects the pinned .deb files of a lock into one directory, verified.
#
#   fetch-debs.sh <lock> <out-dir> [<assets-dir>]
#
# For each package, the first file whose SHA-256 equals the lock wins:
#   1. a file in <assets-dir>, such as the .deb assets of the release that
#      published the lock (gh release download <tag> --pattern '*.deb');
#   2. the content-addressed snapshot.debian.org URL in the lock;
#   3. if snapshot fails, the same version from the live Debian archive of the
#      package's suite (scripts/archive_url.py). The live archive keeps only
#      current versions, so this helps a current build, not an old one.
# A file in <assets-dir> with another SHA-256 is ignored. A download with
# another SHA-256 fails the run. <out-dir>/<package>.deb is the result, and
# <out-dir>/sources.txt says where each file came from.
set -euo pipefail
lock=$1
out=$2
assets=${3:-}
root="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$out"
: > "$out/sources.txt"

declare -A by_sha=()
if [ -n "$assets" ] && [ -d "$assets" ]; then
    while IFS= read -r -d '' file; do
        by_sha[$(sha256sum "$file" | cut -d' ' -f1)]=$file
    done < <(find "$assets" -maxdepth 1 -type f -name '*.deb' -print0)
fi

while IFS=$'\t' read -r package version sha256 url _asset suite; do
    target="$out/$package.deb"
    if [ -n "${by_sha[$sha256]:-}" ]; then
        cp "${by_sha[$sha256]}" "$target"
        origin="release asset $(basename "${by_sha[$sha256]}")"
    else
        if curl -fsSL --retry 3 --retry-all-errors --retry-delay 10 -o "$target.part" "$url"; then
            origin=$url
        elif live=$(python3 "$root/scripts/archive_url.py" "$package" "$version" "$suite") &&
            curl -fsSL --retry 3 --retry-all-errors --retry-delay 10 -o "$target.part" "$live"; then
            echo "fetch-debs: snapshot failed for $package, used the live archive" >&2
            origin=$live
        else
            rm -f "$target.part"
            echo "fetch-debs: $package $version is unavailable from snapshot and the live archive" >&2
            exit 1
        fi
        mv "$target.part" "$target"
    fi
    got=$(sha256sum "$target" | cut -d' ' -f1)
    if [ "$got" != "$sha256" ]; then
        rm -f "$target"
        echo "fetch-debs: $package $version from $origin has SHA-256 $got, the lock pins $sha256" >&2
        exit 1
    fi
    printf '%s\t%s\t%s\n' "$package" "$version" "$origin" >> "$out/sources.txt"
done < <(python3 "$root/scripts/lock.py" debs "$lock")
cut -f1,3 "$out/sources.txt" | sed 's/^/fetch-debs: /'
