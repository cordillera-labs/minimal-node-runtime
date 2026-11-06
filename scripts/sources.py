#!/usr/bin/env python3
"""Collects the Debian source packages of the shipped binary packages, for
the source offer of the GPL and LGPL components and the small packages.

  sources.py collect --lock <lock> --known <sources.json> --out <dir>

For each binary package in the lock it reads the Source field from the
Packages index of the snapshot that lists the pinned version, so the
binary-to-source mapping comes from Debian, not from this repository.

A source package already in <sources.json> is not downloaded again: a later
release links the release that carries it. A new one is downloaded from
snapshot.debian.org. Each file must match the SHA-256 in the Sources index of
the same snapshot, and each file the .dsc lists must also match the .dsc.

Writes:
  <dir>/files/       the new files, under GitHub-safe asset names
  <dir>/debian-sources.txt
                     sha256, asset name and Debian file name of each new file
  <dir>/sources.json the full set for this build: known entries keep their
                     release, new entries carry "release": null until the
                     publish step names the release that carries them
"""

import argparse
import datetime
import hashlib
import json
import lzma
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lock as lockfile  # noqa: E402
import upstream  # noqa: E402

SOURCES_INDEX = "main/source/Sources.xz"
# snapshot.debian.org answers 503 and 504 for minutes at a time, so a source
# download retries for longer than the shared request helper does.
FETCH_ROUNDS = 6
FETCH_BACKOFF_SECONDS = 30


class SourceFault(Exception):
    pass


def fetch(url):
    for round_number in range(FETCH_ROUNDS):
        try:
            return upstream.get(url)
        except ConnectionError:
            if round_number == FETCH_ROUNDS - 1:
                raise
            time.sleep(FETCH_BACKOFF_SECONDS * (round_number + 1))
    raise ConnectionError(url)


def reuse(path, sha256, size):
    """A file left by an earlier run, when it still verifies."""
    if not os.path.exists(path):
        return None
    with open(path, "rb") as handle:
        body = handle.read()
    return body if len(body) == size and hashlib.sha256(body).hexdigest() == sha256 else None


def stamp_of(value):
    if len(value) == 10:
        value += "T00:00:00Z"
    moment = datetime.datetime.strptime(value.rstrip("Z").split(".", 1)[0], "%Y-%m-%dT%H:%M:%S")
    return upstream.snapshot_stamp(moment.replace(tzinfo=datetime.timezone.utc))


def archive_of(suite):
    for archive, known_suite, _mirror in upstream.DEBIAN_SUITES:
        if known_suite == suite:
            return archive
    raise SourceFault(f"unknown suite {suite}")


def index(archive, stamp, suite, path, cache):
    key = (archive, stamp, suite, path)
    if key not in cache:
        url = f"{upstream.SNAPSHOT}/archive/{archive}/{stamp}/dists/{suite}/{path}"
        cache[key] = lzma.decompress(fetch(url)).decode()
    return cache[key]


def parse_stanzas(text, wanted):
    """Stanzas whose Package is in `wanted`, with continuation lines kept."""
    found = []
    for stanza in text.split("\n\n"):
        fields, current = {}, None
        for line in stanza.splitlines():
            if line[:1].isspace() and current:
                fields[current] += "\n" + line.strip()
            elif ":" in line:
                current, value = line.split(":", 1)
                fields[current] = value.strip()
        if fields.get("Package") in wanted:
            found.append(fields)
    return found


def checksums(field):
    """`Checksums-Sha256` lines -> {name: (sha256, size)}."""
    result = {}
    for line in field.splitlines():
        parts = line.split()
        if len(parts) == 3:
            result[parts[2]] = (parts[0], int(parts[1]))
    return result


def dsc_fields(text):
    """The fields of a .dsc, with a clearsign armor removed when present."""
    if text.startswith("-----BEGIN PGP SIGNED MESSAGE-----"):
        text = text.split("\n\n", 1)[1].split("\n-----BEGIN PGP SIGNATURE-----", 1)[0]
    fields, current = {}, None
    for line in text.splitlines():
        if line[:1].isspace() and current:
            fields[current] += "\n" + line.strip()
        elif ":" in line:
            current, value = line.split(":", 1)
            fields[current] = value.strip()
    return fields


def asset_name(name):
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)


def source_of(package, version, archive, suite, stamps, cache):
    for stamp in stamps:
        for fields in parse_stanzas(index(archive, stamp, suite, upstream.INDEX, cache), {package}):
            if fields.get("Version") != version:
                continue
            source = fields.get("Source", package)
            match = re.fullmatch(r"(\S+)(?: \((\S+)\))?", source)
            if not match:
                raise SourceFault(f"{package}: cannot read Source field {source!r}")
            return match.group(1), match.group(2) or version, stamp
    raise SourceFault(f"{package} {version} is not listed in {suite} at {', '.join(stamps)}")


def download(archive, stamp, suite, source, version, out_dir, cache):
    stanzas = [fields for fields in parse_stanzas(index(archive, stamp, suite, SOURCES_INDEX, cache), {source})
               if fields.get("Version") == version]
    if not stanzas:
        raise SourceFault(f"source {source} {version} is not in the {suite} Sources index at {stamp}")
    fields = stanzas[0]
    listed = checksums(fields.get("Checksums-Sha256", ""))
    dsc_names = [name for name in listed if name.endswith(".dsc")]
    if len(dsc_names) != 1:
        raise SourceFault(f"source {source} {version} lists {len(dsc_names)} .dsc files")
    base = f"{upstream.SNAPSHOT}/archive/{archive}/{stamp}/{fields['Directory']}"
    files = []
    contents = {}
    for name, (sha256, size) in sorted(listed.items()):
        body = reuse(os.path.join(out_dir, asset_name(name)), sha256, size) or fetch(f"{base}/{name}")
        if hashlib.sha256(body).hexdigest() != sha256 or len(body) != size:
            raise SourceFault(f"{name} does not match the Sources index of {suite} at {stamp}")
        contents[name] = body
    in_dsc = checksums(dsc_fields(contents[dsc_names[0]].decode()).get("Checksums-Sha256", ""))
    if not in_dsc:
        raise SourceFault(f"{dsc_names[0]} lists no Checksums-Sha256")
    if set(in_dsc) != set(listed) - {dsc_names[0]}:
        raise SourceFault(f"{dsc_names[0]} lists {sorted(in_dsc)}, the Sources index {sorted(listed)}")
    for name, (sha256, size) in in_dsc.items():
        if hashlib.sha256(contents[name]).hexdigest() != sha256 or len(contents[name]) != size:
            raise SourceFault(f"{name} does not match {dsc_names[0]}")
    os.makedirs(out_dir, exist_ok=True)
    for name, body in contents.items():
        with open(os.path.join(out_dir, asset_name(name)), "wb") as handle:
            handle.write(body)
        files.append({"name": name, "asset": asset_name(name),
                      "sha256": hashlib.sha256(body).hexdigest(), "size": len(body)})
    return files


def collect(lock, known, out):
    packages = lockfile.read_packages()
    cache = {}
    wanted = {}
    for package in packages:
        prefix = f"DEB_{lockfile.package_key(package)}_"
        suite = lock[prefix + "SUITE"]
        archive = archive_of(suite)
        stamps = [stamp_of(lock[prefix + "RELEASED"])]
        if lock.get("EVALUATED_AT"):
            stamps.append(stamp_of(lock["EVALUATED_AT"]))
        source, version, stamp = source_of(package, lock[prefix + "VERSION"], archive, suite, stamps, cache)
        entry = wanted.setdefault(f"{source} {version}", {
            "source": source, "version": version, "archive": archive, "suite": suite, "stamp": stamp,
            "binaries": []})
        entry["binaries"].append(package)

    result = {}
    lines = []
    for key, entry in sorted(wanted.items()):
        if key in known:
            result[key] = dict(known[key], binaries=entry["binaries"])
            continue
        files = download(entry["archive"], entry["stamp"], entry["suite"], entry["source"], entry["version"],
                         os.path.join(out, "files"), cache)
        result[key] = {"source": entry["source"], "version": entry["version"], "binaries": entry["binaries"],
                       "snapshot": f"{upstream.SNAPSHOT}/archive/{entry['archive']}/{entry['stamp']}/",
                       "files": files, "release": None, "release_url": None}
        lines += [f"{item['sha256']}  {item['asset']}  {item['name']}" for item in files]
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "sources.json"), "w") as handle:
        json.dump(result, handle, indent=2, sort_keys=True)
        handle.write("\n")
    if lines:
        with open(os.path.join(out, "debian-sources.txt"), "w") as handle:
            handle.write("# sha256  release-asset-name  debian-file-name\n" + "\n".join(lines) + "\n")
    for key, entry in sorted(result.items()):
        where = entry["release"] or "new in this build"
        print(f"sources: {key} ({', '.join(entry['binaries'])}): {where}")
    return result


def record(sources, tag, url):
    """Names this release as the carrier of every new entry."""
    for entry in sources.values():
        if entry["release"] is None:
            entry["release"], entry["release_url"] = tag, url
    return sources


def main(argv):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    collect_parser = sub.add_parser("collect")
    collect_parser.add_argument("--lock", required=True)
    collect_parser.add_argument("--known", required=True)
    collect_parser.add_argument("--out", required=True)
    record_parser = sub.add_parser("record")
    record_parser.add_argument("--sources", required=True)
    record_parser.add_argument("--tag", required=True)
    record_parser.add_argument("--url", required=True)
    args = parser.parse_args(argv[1:])
    try:
        if args.command == "collect":
            known = {}
            if os.path.exists(args.known) and os.path.getsize(args.known):
                with open(args.known) as handle:
                    known = json.load(handle)
            collect(lockfile.load(args.lock), known, args.out)
        else:
            with open(args.sources) as handle:
                sources = json.load(handle)
            json.dump(record(sources, args.tag, args.url), sys.stdout, indent=2, sort_keys=True)
            sys.stdout.write("\n")
    except (SourceFault, lockfile.LockError, ConnectionError, lzma.LZMAError) as fault:
        print(f"sources.py: {fault}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
