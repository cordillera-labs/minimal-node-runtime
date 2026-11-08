#!/usr/bin/env python3
"""Read, validate, hash and write the channel lock files in state/<line>/.

A line is a Node.js major version. Each line has its own directory under
state/, named after the major (state/22/, state/24/), and its locks pin a
NODE_VERSION of that major. Adding a line means adding its directory with a
stable lock.

A lock file is KEY=VALUE lines. Three kinds of key exist:

* input keys, which decide the image content and are passed to the build;
* record keys, which say when and why an input was accepted (*_RELEASED,
  *_ACCEPTED);
* publication keys, which say what was published (PUBLISHED_*, CHANNEL,
  BREAKING_PACKAGES).

Only input keys enter the inputs hash. Every value is checked against a
pattern before use, because the values become build arguments and URLs.

Usage:
  lock.py check <lock> [<line>]        validate, check BUILD_DEFINITION_SHA256, and
                                       that NODE_VERSION belongs to <line>
  lock.py line <lock>                  print the line: the major of NODE_VERSION
  lock.py lines                        print the lines under state/, as a JSON array
  lock.py build-args <lock>            print the Dockerfile build arguments
  lock.py get <lock> <KEY>             print one value
  lock.py inputs-hash <lock>           print the hash of the input keys
  lock.py tag <lock>                   print the immutable image tag
  lock.py debs <lock>                  print package, version, sha256, url, asset name, suite
  lock.py set <lock> KEY=VALUE...      set keys and rewrite the file
  lock.py build-definition             print the hash of the build definition
"""

import datetime
import hashlib
import json
import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The files whose content defines the image, apart from the lock inputs.
# toolchain.env pins BuildKit, which fixes the layer bytes, so a tool bump is
# a build definition change and the next update run rebuilds.
BUILD_DEFINITION_FILES = (
    "Dockerfile", "packages.list", "certificates.exclude",
    "scripts/assemble-rootfs.sh", "scripts/select-ca-certificates.sh",
    "runtime/ca-distrust.cjs", "runtime/ca-image-filter.cjs",
    "runtime/ca-preload.cjs", "certificates.auto.exclude", "toolchain.env",
)

SHA256 = r"[0-9a-f]{64}"
LINE = r"[1-9][0-9]{0,2}"
DEBIAN_VERSION = r"[0-9][0-9A-Za-z.+~:-]{0,99}"

INPUT_PATTERNS = {
    "BUILD_DEFINITION_SHA256": SHA256,
    "SOURCE_DATE_EPOCH": r"[0-9]{9,11}",
    "HELPER_IMAGE": r"docker\.io/library/debian:trixie-slim@sha256:" + SHA256,
    "NODE_VERSION": LINE + r"\.[0-9]{1,3}\.[0-9]{1,3}",
    "NODE_SHA256": SHA256,
}
PACKAGE_INPUT_PATTERNS = {
    "VERSION": DEBIAN_VERSION,
    "URL": r"https://snapshot\.debian\.org/file/[0-9a-f]{40}",
    "SHA256": SHA256,
}
RECORD_PATTERNS = {
    "RELEASED": r"[0-9]{4}-[0-9]{2}-[0-9]{2}(T[0-9:.]+Z)?",
    "ACCEPTED": r"[A-Za-z0-9 .,:;()+~_/-]{1,300}",
    "SUITE": r"trixie(-updates|-security)?",
}
PUBLICATION_PATTERNS = {
    "CHANNEL": r"stable|candidate",
    "PUBLISHED_DIGEST": r"sha256:" + SHA256,
    "PUBLISHED_TAG": LINE + r"\.[0-9]+\.[0-9]+-trixie-[0-9a-f]{12}",
    "PUBLISHED_COMMIT": r"[0-9a-f]{40}",
    "PUBLISHED_RUN": r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/runs/[0-9]+(/attempts/[0-9]+)?",
    "PUBLISHED_RELEASE": r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/releases/tag/[A-Za-z0-9_.-]+",
    "BREAKING_PACKAGES": r"[a-z0-9.+, -]{0,500}",
    "EVALUATED_AT": r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
}

# The Dockerfile ARGs, in the order the Dockerfile declares them.
BUILD_ARG_KEYS = ("HELPER_IMAGE", "NODE_VERSION", "NODE_SHA256", "SOURCE_DATE_EPOCH")

HEADER = """\
# minimal-node-runtime: inputs of the {channel} channel.
# The hourly update workflow writes this file after a successful publish.
# Edit it by hand only to roll back, and expect the next run to re-evaluate it.
"""


class LockError(ValueError):
    pass


def package_key(package):
    """libstdc++6 -> LIBSTDCXX6, gcc-14-base -> GCC_14_BASE."""
    return re.sub(r"[-.]", "_", package.upper().replace("+", "X"))


def read_packages(path=None):
    path = path or os.path.join(REPO_ROOT, "packages.list")
    packages = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            name = line.split("#", 1)[0].strip()
            if name:
                if not re.fullmatch(r"[a-z0-9][a-z0-9.+-]*", name):
                    raise LockError(f"invalid package name in packages.list: {name!r}")
                packages.append(name)
    return sorted(packages)


def pattern_for(key):
    if key in INPUT_PATTERNS:
        return INPUT_PATTERNS[key], "input"
    if key in PUBLICATION_PATTERNS:
        return PUBLICATION_PATTERNS[key], "publication"
    match = re.fullmatch(r"DEB_([A-Z0-9_]+)_(VERSION|URL|SHA256|RELEASED|ACCEPTED|SUITE)", key)
    if match:
        field = match.group(2)
        if field in PACKAGE_INPUT_PATTERNS:
            return PACKAGE_INPUT_PATTERNS[field], "input"
        return RECORD_PATTERNS[field], "record"
    match = re.fullmatch(r"(NODE|HELPER_IMAGE|BUILD_DEFINITION)_(RELEASED|ACCEPTED)", key)
    if match:
        return RECORD_PATTERNS[match.group(2)], "record"
    raise LockError(f"unknown lock key {key!r}")


def validate(key, value):
    pattern, kind = pattern_for(key)
    if value == "" and kind != "input":
        return kind
    if not re.fullmatch(pattern, value):
        raise LockError(f"{key} has an invalid value {value!r}")
    return kind


def parse(text):
    lock = {}
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise LockError(f"line {number} is not KEY=VALUE")
        key, value = line.split("=", 1)
        if key in lock:
            raise LockError(f"{key} appears twice")
        validate(key, value)
        lock[key] = value
    return lock


def load(path):
    with open(path, encoding="utf-8") as handle:
        return parse(handle.read())


def is_input(key):
    return pattern_for(key)[1] == "input"


def inputs(lock):
    return {key: value for key, value in lock.items() if is_input(key)}


def inputs_hash(lock):
    digest = hashlib.sha256()
    for key in sorted(inputs(lock)):
        digest.update(f"{key}={lock[key]}\n".encode())
    return digest.hexdigest()


def require_complete(lock, packages):
    missing = [key for key in INPUT_PATTERNS if not lock.get(key)]
    for package in packages:
        for field in PACKAGE_INPUT_PATTERNS:
            key = f"DEB_{package_key(package)}_{field}"
            if not lock.get(key):
                missing.append(key)
    if missing:
        raise LockError("missing input keys: " + ", ".join(missing))
    extra = sorted(
        key for key in inputs(lock)
        if key.startswith("DEB_") and not any(
            key.startswith(f"DEB_{package_key(package)}_") for package in packages)
    )
    if extra:
        raise LockError("input keys for packages not in packages.list: " + ", ".join(extra))


def key_order(packages):
    order = ["CHANNEL", "EVALUATED_AT", "BUILD_DEFINITION_SHA256", "BUILD_DEFINITION_ACCEPTED", "SOURCE_DATE_EPOCH",
             "HELPER_IMAGE", "HELPER_IMAGE_RELEASED", "HELPER_IMAGE_ACCEPTED",
             "NODE_VERSION", "NODE_SHA256", "NODE_RELEASED", "NODE_ACCEPTED"]
    for package in packages:
        prefix = f"DEB_{package_key(package)}_"
        order += [prefix + field for field in ("VERSION", "SUITE", "URL", "SHA256", "RELEASED", "ACCEPTED")]
    order += ["BREAKING_PACKAGES", "PUBLISHED_DIGEST", "PUBLISHED_TAG", "PUBLISHED_COMMIT",
              "PUBLISHED_RELEASE", "PUBLISHED_RUN"]
    return order


def render(lock, channel, packages):
    order = key_order(packages)
    for key, value in lock.items():
        validate(key, value)
    unknown = sorted(set(lock) - set(order))
    if unknown:
        raise LockError("keys outside the lock layout: " + ", ".join(unknown))
    lines = [HEADER.format(channel=channel).rstrip("\n")]
    for key in order:
        if key in lock:
            lines.append(f"{key}={lock[key]}")
    return "\n".join(lines) + "\n"


# The helper image assembles the rootfs but ships no file, so its release time
# stays out of the epoch: a helper refresh then rebuilds to the same digest.
EPOCH_EXCLUDED = ("HELPER_IMAGE_RELEASED",)


def release_times(lock):
    """The *_RELEASED values of the inputs that ship, as aware datetimes."""
    times = []
    for key, value in lock.items():
        if key.endswith("_RELEASED") and value and key not in EPOCH_EXCLUDED:
            if len(value) == 10:
                value += "T00:00:00Z"
            trimmed = value.rstrip("Z").split(".", 1)[0]
            times.append(datetime.datetime.strptime(trimmed, "%Y-%m-%dT%H:%M:%S")
                         .replace(tzinfo=datetime.timezone.utc))
    return times


def derived_epoch(lock):
    """SOURCE_DATE_EPOCH: the release time of the newest input that ships. A
    pure function of the lock, so the same lock always builds the same digest."""
    times = release_times(lock)
    if not times:
        raise LockError("the lock records no release time, so SOURCE_DATE_EPOCH cannot be derived")
    return str(int(max(times).timestamp()))


def image_tag(lock):
    """The immutable tag: the Node version and the start of the inputs hash."""
    return f"{lock['NODE_VERSION']}-trixie-{inputs_hash(lock)[:12]}"


def build_definition_hash(root=REPO_ROOT):
    digest = hashlib.sha256()
    for name in BUILD_DEFINITION_FILES:
        with open(os.path.join(root, name), "rb") as handle:
            content = handle.read()
        digest.update(name.encode() + b"\0" + hashlib.sha256(content).hexdigest().encode() + b"\n")
    return digest.hexdigest()


def build_args(lock, packages):
    require_complete(lock, packages)
    args = [(key, lock[key]) for key in BUILD_ARG_KEYS]
    for package in packages:
        prefix = f"DEB_{package_key(package)}_"
        args.append((prefix + "SHA256", lock[prefix + "SHA256"]))
    return args


def asset_name(package, version):
    """The release asset name of a .deb. GitHub rewrites some characters in
    asset names, so only [A-Za-z0-9._-] stay; the fetcher matches by SHA-256."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", f"{package}_{version}_amd64.deb")


def debs(lock, packages):
    """One (package, version, sha256, url, asset name, suite) per pinned package."""
    require_complete(lock, packages)
    rows = []
    for package in packages:
        prefix = f"DEB_{package_key(package)}_"
        rows.append((package, lock[prefix + "VERSION"], lock[prefix + "SHA256"], lock[prefix + "URL"],
                     asset_name(package, lock[prefix + "VERSION"]), lock[prefix + "SUITE"]))
    return rows


def line_of(lock):
    """The line of a lock: the major version of its NODE_VERSION."""
    return lock["NODE_VERSION"].split(".", 1)[0]


def lines(root=REPO_ROOT):
    """The lines that have a directory with a stable lock under state/, in
    numeric order."""
    state = os.path.join(root, "state")
    found = [name for name in os.listdir(state)
             if re.fullmatch(LINE, name) and os.path.isfile(os.path.join(state, name, "stable.lock"))]
    return sorted(found, key=int)


def channel_of(path):
    name = os.path.basename(path)
    return "candidate" if name.startswith("candidate") else "stable"


def main(argv):
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    command = argv[1]
    try:
        if command == "build-definition":
            print(build_definition_hash())
            return 0
        if command == "lines":
            print(json.dumps(lines()))
            return 0
        path = argv[2]
        lock = load(path)
        packages = read_packages()
        if command == "check":
            require_complete(lock, packages)
            if lock["SOURCE_DATE_EPOCH"] != derived_epoch(lock):
                raise LockError(f"SOURCE_DATE_EPOCH is {lock['SOURCE_DATE_EPOCH']}, "
                                f"but the newest release time gives {derived_epoch(lock)}")
            if len(argv) > 3 and line_of(lock) != argv[3]:
                raise LockError(f"NODE_VERSION {lock['NODE_VERSION']} is not on the line {argv[3]}")
            current = build_definition_hash()
            if lock["BUILD_DEFINITION_SHA256"] != current:
                raise LockError(f"BUILD_DEFINITION_SHA256 is {lock['BUILD_DEFINITION_SHA256']}, "
                                f"but the repository hashes to {current}")
            print(f"{path}: valid, inputs hash {inputs_hash(lock)}")
        elif command == "build-args":
            for key, value in build_args(lock, packages):
                print(f"{key}={value}")
        elif command == "debs":
            for row in debs(lock, packages):
                print("\t".join(row))
        elif command == "get":
            print(lock.get(argv[3], ""))
        elif command == "inputs-hash":
            print(inputs_hash(lock))
        elif command == "line":
            print(line_of(lock))
        elif command == "tag":
            print(image_tag(lock))
        elif command == "set":
            for assignment in argv[3:]:
                key, value = assignment.split("=", 1)
                validate(key, value)
                lock[key] = value
            text = render(lock, channel_of(path), packages)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(text)
        else:
            print(__doc__, file=sys.stderr)
            return 2
    except (LockError, OSError, IndexError) as error:
        print(f"lock.py: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
