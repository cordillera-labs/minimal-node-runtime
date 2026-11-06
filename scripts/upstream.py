#!/usr/bin/env python3
"""Resolve the current upstream state of every input, and the evidence the
update policy needs.

  upstream.py resolve --base <lock> --out <upstream.json>
  upstream.py verify-node <version> <sha256>

`resolve` reads only public indexes. It writes upstream.json, which
scripts/plan.py turns into a decision. Nothing here decides eligibility.

Sources:
  Node.js     https://nodejs.org/dist/index.json, plus SHASUMS256.txt.asc for
              every 22.x release newer than the base lock. The signature must
              come from a key listed in node-release-keys.txt.
  helper      the debian:trixie-slim index digest, by a registry HEAD request.
              On a change, the image config "created" time is read as its
              release date.
  Debian      the Packages indexes of trixie, trixie-updates (deb.debian.org)
              and trixie-security (deb.debian.org/debian-security), each
              checked against its suite's signed Release file
              (scripts/debian_archive.py). On a
              version change, snapshot.debian.org supplies the
              content-addressed download URL and the cooldown evidence: whether
              the version was already listed in its suite in the snapshot taken
              the first 6-hour grid point at which a snapshot lists the
              version in its suite, which is its release date.
"""

import argparse
import datetime
import hashlib
import json
import lzma
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import debian_archive  # noqa: E402
import lock as lockfile  # noqa: E402

REPO_ROOT = lockfile.REPO_ROOT
USER_AGENT = "minimal-node-runtime-update-check"
TIMEOUT = 60

DEBIAN_SUITES = debian_archive.SUITES  # (archive, suite, live mirror)
SNAPSHOT = debian_archive.SNAPSHOT
INDEX = "main/binary-amd64/Packages.xz"


class UpstreamFault(Exception):
    """An upstream answer that fails verification. Never retried silently."""


# ---- HTTP ------------------------------------------------------------------------

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def request(url, method="GET", headers=None, follow=True, attempts=4):
    opener = urllib.request.build_opener() if follow else urllib.request.build_opener(NoRedirect)
    last_error = None
    for attempt in range(attempts):
        req = urllib.request.Request(url, method=method, headers={"User-Agent": USER_AGENT, **(headers or {})})
        try:
            with opener.open(req, timeout=TIMEOUT) as response:
                return response.status, dict(response.headers), response.read()
        except urllib.error.HTTPError as error:
            if not follow and 300 <= error.code < 400:
                return error.code, dict(error.headers), b""
            if error.code == 404:
                return 404, dict(error.headers), b""
            last_error = error
        except (urllib.error.URLError, TimeoutError, ConnectionError) as error:
            last_error = error
        time.sleep(2 * (attempt + 1))
    raise ConnectionError(f"{method} {url}: {last_error}")


def get(url, headers=None):
    status, _, body = request(url, headers=headers)
    if status != 200:
        raise ConnectionError(f"GET {url}: HTTP {status}")
    return body


def get_or_none(url):
    """The body, or None on HTTP 404: the `fetch` that debian_archive takes."""
    status, _, body = request(url)
    if status == 404:
        return None
    if status != 200:
        raise ConnectionError(f"GET {url}: HTTP {status}")
    return body


# ---- Node.js ------------------------------------------------------------------------

def read_release_keys():
    commit, fingerprints = None, []
    with open(os.path.join(REPO_ROOT, "node-release-keys.txt"), encoding="utf-8") as handle:
        for line in handle:
            line = line.split("#", 1)[0].strip()
            if line.startswith("RELEASE_KEYS_COMMIT="):
                commit = line.split("=", 1)[1]
            elif line:
                fingerprints.append(line.split()[0])
    if not commit or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise UpstreamFault("node-release-keys.txt has no valid RELEASE_KEYS_COMMIT")
    for fingerprint in fingerprints:
        if not re.fullmatch(r"[0-9A-F]{40}", fingerprint):
            raise UpstreamFault(f"invalid fingerprint {fingerprint!r} in node-release-keys.txt")
    return commit, fingerprints


def gpg(home, *args, data=None):
    return subprocess.run(["gpg", "--homedir", home, "--batch", "--no-tty", *args],
                          input=data, capture_output=True, check=False)


def verified_shasums(version):
    """The text of SHASUMS256.txt for a release, after its signature checks out
    against a pinned release key."""
    commit, fingerprints = read_release_keys()
    signed = get(f"https://nodejs.org/dist/v{version}/SHASUMS256.txt.asc")
    with tempfile.TemporaryDirectory() as home:
        os.chmod(home, 0o700)
        for fingerprint in fingerprints:
            key = get(f"https://raw.githubusercontent.com/nodejs/release-keys/{commit}/keys/{fingerprint}.asc")
            gpg(home, "--import", data=key)
        listed = gpg(home, "--with-colons", "--fingerprint", "--list-keys")
        # The listing holds primary and subkey fingerprints; at least one
        # pinned primary must be present.
        imported = {line.split(":")[9] for line in listed.stdout.decode().splitlines()
                    if line.startswith("fpr:")}
        if not imported & set(fingerprints):
            raise UpstreamFault("no pinned Node.js release key could be imported")
        # Status lines go to stderr; stdout carries the verified plaintext.
        result = gpg(home, "--status-fd", "2", "--output", "-", "--decrypt", data=signed)
        status = result.stderr.decode(errors="replace")
        valid = [line.split() for line in status.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")]
        if result.returncode != 0 or not valid:
            raise UpstreamFault(f"SHASUMS256.txt.asc for v{version} has no valid signature from a pinned key")
        primary = valid[0][-1]
        if primary not in fingerprints:
            raise UpstreamFault(f"SHASUMS256.txt.asc for v{version} is signed by {primary}, which is not pinned")
        # The plaintext gpg verified, never a hand-parsed copy of the message.
        return result.stdout.decode()


def node_tarball_sha256(version):
    name = f"node-v{version}-linux-x64.tar.gz"
    for line in verified_shasums(version).splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1] == name:
            if not re.fullmatch(r"[0-9a-f]{64}", parts[0]):
                break
            return parts[0]
    raise UpstreamFault(f"the signed SHASUMS256.txt of v{version} does not list {name}")


def node_releases(base_version):
    index = json.loads(get("https://nodejs.org/dist/index.json"))
    base = version_tuple(base_version)
    releases = []
    for entry in index:
        version = entry.get("version", "").lstrip("v")
        if not re.fullmatch(r"22\.[0-9]+\.[0-9]+", version):
            continue
        if version_tuple(version) < base:
            continue
        if "linux-x64" not in entry.get("files", []):
            continue
        releases.append({
            "version": version,
            "date": entry["date"],
            "security": bool(entry.get("security")),
            "sha256": node_tarball_sha256(version),
        })
    return sorted(releases, key=lambda release: version_tuple(release["version"]))


def version_tuple(version):
    return tuple(int(part) for part in version.split("."))


# ---- helper image ----------------------------------------------------------------------

def docker_hub_token():
    body = get("https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/debian:pull")
    return json.loads(body)["token"]


INDEX_TYPES = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json"
MANIFEST_TYPES = "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"


def helper_image(base_image):
    token = docker_hub_token()
    auth = {"Authorization": f"Bearer {token}"}
    url = "https://registry-1.docker.io/v2/library/debian/manifests/trixie-slim"
    # A HEAD request does not count against the Docker Hub pull limit.
    status, headers, _ = request(url, method="HEAD", headers={**auth, "Accept": INDEX_TYPES})
    digest = {k.lower(): v for k, v in headers.items()}.get("docker-content-digest", "")
    if status != 200 or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ConnectionError(f"HEAD {url}: HTTP {status}, digest {digest!r}")
    image = f"docker.io/library/debian:trixie-slim@{digest}"
    created = None
    if image != base_image:
        index = json.loads(get(f"https://registry-1.docker.io/v2/library/debian/manifests/{digest}",
                               headers={**auth, "Accept": INDEX_TYPES}))
        if not index.get("manifests"):
            raise ConnectionError("the trixie-slim index lists no manifests")
        amd64 = [m["digest"] for m in index["manifests"]
                 if m.get("platform", {}).get("architecture") == "amd64"
                 and m.get("platform", {}).get("os") == "linux"]
        manifest = json.loads(get(f"https://registry-1.docker.io/v2/library/debian/manifests/{amd64[0]}",
                                  headers={**auth, "Accept": MANIFEST_TYPES}))
        config = json.loads(get(f"https://registry-1.docker.io/v2/library/debian/blobs/{manifest['config']['digest']}",
                                headers=auth))
        created = config.get("created")
    return {"image": image, "created": created}


# ---- Debian ---------------------------------------------------------------------------------

def parse_packages(text, wanted):
    found = {}
    for stanza in text.split("\n\n"):
        fields = {}
        for line in stanza.splitlines():
            if line and not line[0].isspace() and ":" in line:
                key, value = line.split(":", 1)
                fields[key] = value.strip()
        name = fields.get("Package")
        if name in wanted:
            found.setdefault(name, []).append(fields)
    return found


def dpkg_compare(left, operator, right):
    return subprocess.run(["dpkg", "--compare-versions", left, operator, right], check=False).returncode == 0


def verified_index(base, suite, path=INDEX):
    """The decompressed text of an index file, checked against the signed
    Release of its suite. A suite with no Release file is a fault."""
    release = debian_archive.verified_release(get_or_none, base, suite)
    if release is None:
        raise UpstreamFault(f"{base}/dists/{suite} has no Release file")
    return lzma.decompress(debian_archive.index_file(get_or_none, release, path)).decode()


def debian_current(packages):
    """The newest version of each package across the three suites, from
    indexes that verify against the signed Release files."""
    best = {}
    for archive, suite, mirror in DEBIAN_SUITES:
        text = verified_index(mirror, suite)
        for name, stanzas in parse_packages(text, set(packages)).items():
            for fields in stanzas:
                candidate = {
                    "version": fields["Version"], "suite": suite, "archive": archive,
                    "filename": fields["Filename"], "sha256": fields["SHA256"],
                }
                if name not in best or dpkg_compare(candidate["version"], "gt", best[name]["version"]):
                    best[name] = candidate
    missing = sorted(set(packages) - set(best))
    if missing:
        raise UpstreamFault("packages missing from every trixie suite: " + ", ".join(missing))
    return best


def snapshot_stamp(moment):
    return moment.strftime("%Y%m%dT%H%M%SZ")


def snapshot_url(entry, now):
    """The content-addressed snapshot URL of a .deb, or None while snapshot has
    not imported it yet."""
    for hours_back in (0, 6, 24):
        stamp = snapshot_stamp(now - datetime.timedelta(hours=hours_back))
        url = f"{SNAPSHOT}/archive/{entry['archive']}/{stamp}/{entry['filename']}"
        try:
            status, headers, _ = request(url, method="HEAD", follow=False, attempts=2)
        except ConnectionError:
            continue
        location = {k.lower(): v for k, v in headers.items()}.get("location", "")
        match = re.fullmatch(r"(?:https?://snapshot\.debian\.org)?/file/([0-9a-f]{40})(?:/.*)?", location)
        if 300 <= status < 400 and match:
            content_url = f"{SNAPSHOT}/file/{match.group(1)}"
            body = get(content_url)
            if hashlib.sha256(body).hexdigest() != entry["sha256"]:
                raise UpstreamFault(f"{content_url} does not match the SHA-256 that {entry['suite']} lists")
            return content_url
    return None


# Snapshot probes sit on a fixed grid of whole 6-hour steps from the Unix epoch,
# so the date found does not depend on the time the search runs.
GRID = datetime.timedelta(hours=6)
SEARCH_WINDOW_STEPS = 480  # 120 days


def grid_point(index):
    return datetime.datetime.fromtimestamp(index * GRID.total_seconds(), datetime.timezone.utc)


def listed_at(entry, name, stamp, cache):
    """Whether the version was listed in its suite in the snapshot at `stamp`.
    True or False, or None when snapshot.debian.org cannot answer. Both
    Release files compared here, and the index read, are verified; a fault in
    that check raises."""
    archive, suite = entry["archive"], entry["suite"]
    key = (archive, suite, stamp)
    try:
        if key not in cache:
            mirror = {(a, s): m for a, s, m in DEBIAN_SUITES}[(archive, suite)]
            live_key = (archive, suite, "live")
            if live_key not in cache:
                live = debian_archive.verified_release(get_or_none, mirror, suite)
                cache[live_key] = live.files.get(INDEX, ("",))[0] if live else ""
            release = debian_archive.verified_release(get_or_none, debian_archive.snapshot_base(archive, stamp), suite)
            if release is None:
                cache[key] = ""  # the suite did not exist yet
            elif cache[live_key] and release.files.get(INDEX, ("",))[0] == cache[live_key]:
                cache[key] = None  # the same index as today, so it lists every live version
            else:
                cache[key] = lzma.decompress(debian_archive.index_file(get_or_none, release, INDEX)).decode()
        text = cache[key]
    except (ConnectionError, lzma.LZMAError):
        return None
    if text is None:
        return True
    stanzas = parse_packages(text, {name}).get(name, [])
    return any(fields.get("Version") == entry["version"] for fields in stanzas)


def first_listed(entry, name, now, cache):
    """The release date of a Debian package version: the first grid point at
    which snapshot.debian.org lists the version in its suite. The date is at
    most one grid step (6 hours) after the version appeared, so the cooldown
    can only start late, never early.

    Returns (iso_time, exact). When a probe fails part way, the search stops
    and returns the earliest grid point known to list the version: a later
    date than the true one, which delays the cooldown and never shortens it.
    `exact` is True only when the date is pinned to one grid step. Returns
    (None, False) when snapshot has not imported the version, or cannot say."""
    high = int(now.timestamp() // GRID.total_seconds())
    if listed_at(entry, name, snapshot_stamp(grid_point(high)), cache) is not True:
        return None, False
    low = high - SEARCH_WINDOW_STEPS
    def iso(index):
        return grid_point(index).strftime("%Y-%m-%dT%H:%M:%SZ")

    at_low = listed_at(entry, name, snapshot_stamp(grid_point(low)), cache)
    if at_low is None:
        return iso(high), False
    if at_low:
        return iso(low), False
    while high - low > 1:
        middle = (low + high) // 2
        answer = listed_at(entry, name, snapshot_stamp(grid_point(middle)), cache)
        if answer is None:
            return iso(high), False
        if answer:
            high = middle
        else:
            low = middle
    return iso(high), True


# ---- resolve ---------------------------------------------------------------------------------

def resolve(base, now):
    packages = lockfile.read_packages()
    result = {"resolved_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "faults": [], "warnings": []}
    try:
        result["node"] = {"releases": node_releases(base["NODE_VERSION"])}
    except UpstreamFault as fault:
        result["node"] = {"releases": []}
        result["faults"].append({"kind": "signature", "input": "node", "message": str(fault)})
    result["helper"] = helper_image(base.get("HELPER_IMAGE", ""))
    result["build_definition"] = lockfile.build_definition_hash()

    debian = {}
    cache = {}
    for name, entry in debian_current(packages).items():
        prefix = f"DEB_{lockfile.package_key(name)}_"
        entry = dict(entry)
        if entry["version"] != base.get(prefix + "VERSION"):
            entry["url"] = snapshot_url(entry, now)
            if entry["url"] is None:
                result["warnings"].append(f"{name} {entry['version']} is not on snapshot.debian.org yet")
            entry["released"], entry["released_exact"] = first_listed(entry, name, now, cache)
            if entry["released"] is None:
                result["warnings"].append(f"{name} {entry['version']}: no release date from snapshot.debian.org")
        debian[name] = entry
    result["debian"] = debian
    return result


def main(argv):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    resolve_parser = sub.add_parser("resolve")
    resolve_parser.add_argument("--base", required=True)
    resolve_parser.add_argument("--out", required=True)
    verify_parser = sub.add_parser("verify-node")
    verify_parser.add_argument("version")
    verify_parser.add_argument("sha256")
    args = parser.parse_args(argv[1:])

    if args.command == "verify-node":
        try:
            actual = node_tarball_sha256(args.version)
        except UpstreamFault as fault:
            print(f"upstream.py: {fault}", file=sys.stderr)
            return 3
        if actual != args.sha256:
            print(f"upstream.py: the signed checksum of v{args.version} is {actual}, the lock has {args.sha256}",
                  file=sys.stderr)
            return 3
        print(f"node v{args.version}: signed checksum matches the lock")
        return 0

    base = lockfile.load(args.base)
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    try:
        result = resolve(base, now)
    except (UpstreamFault, debian_archive.ArchiveFault) as fault:
        result = {"resolved_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                  "faults": [{"kind": "upstream", "input": "debian", "message": str(fault)}]}
    except ConnectionError as error:
        # An unreachable upstream builds nothing this hour; the next run retries.
        result = {"resolved_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                  "faults": [{"kind": "unreachable", "input": "upstream", "message": str(error)}]}
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, sort_keys=True)
        handle.write("\n")
    for fault in result.get("faults", []):
        print(f"::error::{fault['message']}")
    for warning in result.get("warnings", []):
        print(f"::warning::{warning}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
