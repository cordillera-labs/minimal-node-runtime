#!/usr/bin/env python3
"""What a publish run finds already published for the digest it built, so a
run that rebuilds the same inputs after a partial publish completes only what
is missing. publish.yml calls it after the push and before any other publish
side effect.

  publication.py release-state --releases <releases.json> --tag <tag> --image <repository>
                               --digest <sha256:...> --channel stable|candidate
                               --lock <lock> --sources <sources.json>
      Prints "absent" when no release carries the tag, or "present" when a
      published release carries it for this digest and holds every asset.

  publication.py release-match --assets <dir> --tag <tag> --url <release url> --digest <sha256:...>
                               --lock <lock> --sources <sources.json>
      Checks the downloaded assets of a present release against this build,
      and prints the release's source package record. Writes nothing else.

  publication.py release-record --release <release.json>
      Prints the commit and the run that published the release, one per line.

  publication.py tag-state --repository <repository> --tag <tag> --digest <sha256:...>
      Prints "absent" when the registry has no such tag, or "present" when the
      tag names this digest. Reads the token from REGISTRY_TOKEN and the user
      from REGISTRY_USER, when set.

<releases.json> is the list of every release, drafts included, that the
GitHub API returns, and <release.json> is one entry of it.

The safety rule: an existing release or tag is reused only when it records this
digest. A release or tag that records another digest, a draft release, a
release on the other channel and an incomplete release are faults. A fault
exits 1, names what differs, and changes nothing. Only a definite answer
counts as "absent": an HTTP 404 from the registry, or a release list without
the tag. Any other registry answer is a fault, so an unreadable tag is never
overwritten.
"""

import argparse
import base64
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lock as lockfile  # noqa: E402
import upstream  # noqa: E402

DIGEST = r"sha256:[0-9a-f]{64}"
# release-notes.sh writes these two lines into every release body.
DIGEST_LINE = re.compile(r"^Digest: `([^`@\s]+)@(sha256:[0-9a-f]{64})`$", re.MULTILINE)
RUN_LINE = re.compile(r"^Run: (\S+)$", re.MULTILINE)
# The assets that every release carries, apart from the .deb files and the
# source packages. The Trivy report is uploaded as scan.json.
FIXED_ASSETS = ("inputs.lock", "rootfs.manifest", "scan.json", "sbom.cdx.json", "upstream.json", "sources.json")
MANIFEST_TYPES = ", ".join((
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
))


class PublicationFault(Exception):
    pass


# ---- the release -------------------------------------------------------------------------

def new_source_assets(sources, tag):
    """The asset names of the source files that this release carries: the
    entries that are new in this build, or that already name this tag."""
    names = []
    for entry in sources.values():
        if entry.get("release") in (None, tag):
            names += [item["asset"] for item in entry["files"]]
    return names


def required_assets(lock, sources, tag):
    names = list(FIXED_ASSETS)
    names += [row[4] for row in lockfile.debs(lock, lockfile.read_packages())]
    source_assets = new_source_assets(sources, tag)
    if source_assets:
        names += source_assets + ["debian-sources.txt"]
    return names


def release_state(releases, tag, image, digest, channel, lock, sources):
    matching = [release for release in releases if release.get("tag_name") == tag]
    if not matching:
        return "absent"
    if len(matching) > 1:
        raise PublicationFault(f"{len(matching)} releases carry the tag {tag}; expected one")
    release = matching[0]
    if release.get("draft"):
        raise PublicationFault(
            f"a draft release carries the tag {tag}. An interrupted release upload leaves one. "
            "Check its assets, delete the draft, and run the update again")
    recorded = DIGEST_LINE.findall(release.get("body") or "")
    if len(recorded) != 1:
        raise PublicationFault(f"the release {tag} records {len(recorded)} digest lines; expected one")
    recorded_image, recorded_digest = recorded[0]
    if (recorded_image, recorded_digest) != (image, digest):
        raise PublicationFault(
            f"the release {tag} records {recorded_image}@{recorded_digest}, "
            f"but this run built and gated {image}@{digest}. The release is not reused")
    want_prerelease = channel == "candidate"
    if bool(release.get("prerelease")) != want_prerelease:
        published_as = "candidate" if release.get("prerelease") else "stable"
        raise PublicationFault(f"the release {tag} was published to {published_as}, and this run chose {channel}")
    present = {asset.get("name") for asset in release.get("assets") or []}
    missing = sorted(set(required_assets(lock, sources, tag)) - present)
    if missing:
        raise PublicationFault(f"the release {tag} lacks the assets {', '.join(missing)}")
    return "present"


def same_source(left, right):
    keys = ("source", "version", "binaries")
    if any(left.get(key) != right.get(key) for key in keys):
        return False
    def files(entry):
        return sorted((item["name"], item["asset"], item["sha256"], item["size"]) for item in entry.get("files") or [])
    return files(left) == files(right)


def release_match(assets, tag, url, digest, lock, sources):
    """The source record of the release, after its assets are checked
    against this build."""
    released_lock = lockfile.load(os.path.join(assets, "inputs.lock"))
    if lockfile.inputs_hash(released_lock) != lockfile.inputs_hash(lock):
        raise PublicationFault(f"the inputs.lock of the release {tag} differs from the inputs of this build")
    with open(os.path.join(assets, "sbom.cdx.json"), encoding="utf-8") as handle:
        sbom_digest = ((json.load(handle).get("metadata") or {}).get("component") or {}).get("version")
    if sbom_digest != digest:
        raise PublicationFault(f"the SBOM of the release {tag} describes {sbom_digest}, this run built {digest}")
    with open(os.path.join(assets, "sources.json"), encoding="utf-8") as handle:
        released = json.load(handle)
    if not isinstance(released, dict) or set(released) != set(sources):
        raise PublicationFault(f"the source packages of the release {tag} differ from this build's")
    for key, entry in sources.items():
        carried = released[key]
        if not same_source(entry, carried):
            raise PublicationFault(f"the release {tag} records other files for the source package {key}")
        expected = (tag, url) if entry.get("release") is None else (entry["release"], entry.get("release_url"))
        if (carried.get("release"), carried.get("release_url")) != expected:
            raise PublicationFault(f"the release {tag} names {carried.get('release')} as the carrier of {key}, "
                                   f"expected {expected[0]}")
    return released


def release_record(release):
    """(commit, run) of the run that created the release."""
    commit = release.get("target_commitish") or ""
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise PublicationFault(f"the release {release.get('tag_name')} targets {commit!r}, not a commit")
    runs = RUN_LINE.findall(release.get("body") or "")
    run = runs[-1] if runs else ""
    if not re.fullmatch(lockfile.PUBLICATION_PATTERNS["PUBLISHED_RUN"], run):
        raise PublicationFault(f"the release {release.get('tag_name')} names no run")
    return commit, run


# ---- the registry ------------------------------------------------------------------------

def split_repository(repository):
    host, _, name = repository.partition("/")
    if not re.fullmatch(r"[a-z0-9.-]+", host) or not re.fullmatch(r"[a-z0-9._/-]+", name):
        raise PublicationFault(f"cannot read the repository {repository!r}")
    return host, name


def registry_token(host, name, user, token):
    """A pull token. Credentials go only to the registry's own host."""
    headers = {}
    if token:
        basic = base64.b64encode(f"{user or 'token'}:{token}".encode()).decode()
        headers["Authorization"] = f"Basic {basic}"
    status, _, body = upstream.request(
        f"https://{host}/token?service={host}&scope=repository:{name}:pull", headers=headers)
    if status != 200:
        raise PublicationFault(f"the {host} token endpoint answered HTTP {status}")
    return json.loads(body)["token"]


def tag_digest(repository, tag, user=None, token=None):
    """The digest a tag names, or None when the registry answers 404."""
    host, name = split_repository(repository)
    bearer = registry_token(host, name, user, token)
    status, headers, _ = upstream.request(
        f"https://{host}/v2/{name}/manifests/{tag}", method="HEAD",
        headers={"Authorization": f"Bearer {bearer}", "Accept": MANIFEST_TYPES})
    if status == 404:
        return None
    if status != 200:
        raise PublicationFault(f"{repository}:{tag}: the registry answered HTTP {status}")
    digest = {key.lower(): value for key, value in headers.items()}.get("docker-content-digest", "")
    if not re.fullmatch(DIGEST, digest):
        raise PublicationFault(f"{repository}:{tag}: the registry sent no digest")
    return digest


def tag_state(have, want, label):
    if have is None:
        return "absent"
    if have != want:
        raise PublicationFault(f"{label} names {have}, but this run built and gated {want}. "
                               "A published tag is never moved to other content")
    return "present"


# ---- CLI ---------------------------------------------------------------------------------

def load_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def main(argv):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    state = sub.add_parser("release-state")
    match = sub.add_parser("release-match")
    record = sub.add_parser("release-record")
    tag = sub.add_parser("tag-state")
    state.add_argument("--releases", required=True)
    state.add_argument("--image", required=True)
    state.add_argument("--channel", choices=("stable", "candidate"), required=True)
    match.add_argument("--assets", required=True)
    match.add_argument("--url", required=True)
    record.add_argument("--release", required=True)
    tag.add_argument("--repository", required=True)
    for command in (state, match, tag):
        command.add_argument("--tag", required=True)
        command.add_argument("--digest", required=True)
    for command in (state, match):
        command.add_argument("--lock", required=True)
        command.add_argument("--sources", required=True)
    args = parser.parse_args(argv[1:])
    try:
        if getattr(args, "digest", None) and not re.fullmatch(DIGEST, args.digest):
            raise PublicationFault(f"invalid digest {args.digest!r}")
        if args.command == "release-state":
            print(release_state(load_json(args.releases), args.tag, args.image, args.digest, args.channel,
                                lockfile.load(args.lock), load_json(args.sources)))
        elif args.command == "release-match":
            released = release_match(args.assets, args.tag, args.url, args.digest,
                                     lockfile.load(args.lock), load_json(args.sources))
            json.dump(released, sys.stdout, indent=2, sort_keys=True)
            sys.stdout.write("\n")
        elif args.command == "release-record":
            print("\n".join(release_record(load_json(args.release))))
        else:
            have = tag_digest(args.repository, args.tag, os.environ.get("REGISTRY_USER"),
                              os.environ.get("REGISTRY_TOKEN"))
            print(tag_state(have, args.digest, f"{args.repository}:{args.tag}"))
    except (PublicationFault, lockfile.LockError, ConnectionError, OSError, ValueError, KeyError) as fault:
        print(f"publication.py: {fault}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
