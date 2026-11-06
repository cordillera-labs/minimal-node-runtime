#!/usr/bin/env python3
"""Verify what the pipeline reads from a Debian archive.

The chain, for the live archive and for snapshot.debian.org alike:

  1. The suite's InRelease, or Release with Release.gpg, verifies with gpgv
     against debian-archive-keys.asc, and at least one valid signature comes
     from a primary key listed in debian-archive-keys.txt. Its Codename must
     equal the suite.
  2. An index file (Packages.xz, Sources.xz) must match the SHA-256 and size
     that the verified Release lists for it.
  3. A .deb or source file must match the SHA-256 that the verified index lists
     for it. The callers check this with check_file().

snapshot.debian.org serves the Release files that Debian signed, so the same
check applies there. A fault raises ArchiveFault and is never retried.

No function here opens a connection. Each takes `fetch(url)`, which returns the
body, returns None on HTTP 404, and raises ConnectionError on any other fault.
"""

import base64
import hashlib
import os
import re
import subprocess
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYS = os.path.join(REPO_ROOT, "debian-archive-keys.asc")
FINGERPRINTS = os.path.join(REPO_ROOT, "debian-archive-keys.txt")

SUITES = (
    # (archive, suite, live mirror)
    ("debian", "trixie", "https://deb.debian.org/debian"),
    ("debian", "trixie-updates", "https://deb.debian.org/debian"),
    ("debian-security", "trixie-security", "https://deb.debian.org/debian-security"),
)
SNAPSHOT = "https://snapshot.debian.org"

# OpenPGP hash algorithm IDs that a signature may use: SHA-256, SHA-384,
# SHA-512 and SHA-224. MD5, SHA-1 and RIPEMD-160 signatures do not count.
STRONG_HASHES = {"8", "9", "10", "11"}


class ArchiveFault(Exception):
    """A signature, a Release file or a hash that does not verify."""


def live_base(suite):
    for _archive, known, mirror in SUITES:
        if known == suite:
            return mirror
    raise ArchiveFault(f"no live archive is known for suite {suite}")


def snapshot_base(archive, stamp):
    return f"{SNAPSHOT}/archive/{archive}/{stamp}"


# ---- keys and signatures ----------------------------------------------------------

def read_fingerprints(path=None):
    path = path or FINGERPRINTS
    fingerprints = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.split("#", 1)[0].strip()
            if line:
                fingerprint = line.split()[0]
                if not re.fullmatch(r"[0-9A-F]{40}", fingerprint):
                    raise ArchiveFault(f"invalid fingerprint {fingerprint!r} in {os.path.basename(path)}")
                fingerprints.append(fingerprint)
    if not fingerprints:
        raise ArchiveFault(f"{os.path.basename(path)} lists no fingerprint")
    return fingerprints


def dearmor(text):
    """The binary packets of every ASCII-armored block in `text`. gpgv reads
    only a binary keyring, so the committed armored keys are converted here."""
    blocks = re.findall(r"-----BEGIN PGP PUBLIC KEY BLOCK-----\n(.*?)-----END PGP PUBLIC KEY BLOCK-----",
                        text, re.S)
    if not blocks:
        raise ArchiveFault("the key file holds no armored public key block")
    packets = b""
    for block in blocks:
        body = block.split("\n\n", 1)[1] if "\n\n" in block else block
        lines = [line.strip() for line in body.splitlines() if line.strip() and not line.startswith("=")]
        packets += base64.b64decode("".join(lines), validate=True)
    return packets


def signature_groups(status):
    """gpgv status lines, split into one list per signature (NEWSIG)."""
    groups = []
    for line in status.splitlines():
        if not line.startswith("[GNUPG:] "):
            continue
        parts = line.split()[1:]
        if parts[0] == "NEWSIG" or not groups:
            groups.append([])
        if parts[0] != "NEWSIG":
            groups[-1].append(parts)
    return groups


def accepted_signers(status, fingerprints):
    """The pinned primary fingerprints with a valid signature in gpgv's status
    output. Raises ArchiveFault on a bad or revoked signature from any key.

    gpgv checks the signature itself and ignores key expiry: a signature from
    a key that has since expired reports EXPKEYSIG and VALIDSIG. It does not
    check that the signature was made before the key expired, so that check is
    made here. A signature by a key gpgv does not hold (ERRSIG, NO_PUBKEY) is
    ignored: Debian signs each Release with more than one key."""
    signers = []
    for group in signature_groups(status):
        keywords = {parts[0] for parts in group}
        if keywords & {"BADSIG", "REVKEYSIG"}:
            raise ArchiveFault("a signature is bad or comes from a revoked key")
        valid = [parts for parts in group if parts[0] == "VALIDSIG"]
        if not valid or not keywords & {"GOODSIG", "EXPKEYSIG"}:
            continue
        fields = valid[0]
        signed_at, hash_algorithm, primary = int(fields[3]), fields[8], fields[-1]
        if primary not in fingerprints or hash_algorithm not in STRONG_HASHES:
            continue
        if "EXPKEYSIG" in keywords:
            expiries = [int(parts[1]) for parts in group if parts[0] == "KEYEXPIRED"]
            if not expiries or signed_at > min(expiries):
                continue
        signers.append(primary)
    return signers


def gpgv(keys, fingerprints, data_name, files):
    """Runs gpgv in an empty home directory. Returns (status text, the
    verified plaintext or None). `files` maps file names to bytes."""
    with tempfile.TemporaryDirectory() as home:
        os.chmod(home, 0o700)
        keyring = os.path.join(home, "keyring.gpg")
        with open(keys, encoding="ascii") as handle:
            packets = dearmor(handle.read())
        with open(keyring, "wb") as handle:
            handle.write(packets)
        for name, body in files.items():
            with open(os.path.join(home, name), "wb") as handle:
                handle.write(body)
        output = os.path.join(home, "plaintext")
        args = ["gpgv", "--homedir", home, "--keyring", keyring, "--status-fd", "1"]
        if data_name is None:
            args += ["--output", output, os.path.join(home, "InRelease")]
        else:
            args += [os.path.join(home, "Release.gpg"), os.path.join(home, data_name)]
        try:
            result = subprocess.run(args, capture_output=True, check=False)
        except FileNotFoundError as error:
            raise ArchiveFault("gpgv is not installed, so no Debian Release signature can be verified") from error
        plaintext = None
        if data_name is None and os.path.exists(output):
            with open(output, "rb") as handle:
                plaintext = handle.read()
        return result.stdout.decode(errors="replace"), plaintext


def verify_inrelease(signed, what, keys=None, fingerprints=None):
    """The plaintext of a clearsigned InRelease, as gpgv verified it. `keys`
    and `fingerprints` default to the committed Debian keys."""
    keys, fingerprints = keys or KEYS, fingerprints or read_fingerprints()
    if (not signed.startswith(b"-----BEGIN PGP SIGNED MESSAGE-----\n")
            or signed.count(b"-----BEGIN PGP SIGNED MESSAGE-----") != 1
            or signed.count(b"-----BEGIN PGP SIGNATURE-----") != 1):
        raise ArchiveFault(f"{what} is not one clearsigned message")
    status, plaintext = gpgv(keys, fingerprints, None, {"InRelease": signed})
    if not accepted_signers(status, fingerprints) or not plaintext:
        raise ArchiveFault(f"{what} has no valid signature from a key in debian-archive-keys.txt")
    return plaintext.decode()


def verify_detached(release, signature, what, keys=None, fingerprints=None):
    """The text of a Release file whose Release.gpg verifies."""
    keys, fingerprints = keys or KEYS, fingerprints or read_fingerprints()
    status, _ = gpgv(keys, fingerprints, "Release", {"Release": release, "Release.gpg": signature})
    if not accepted_signers(status, fingerprints):
        raise ArchiveFault(f"{what} has no valid signature from a key in debian-archive-keys.txt")
    return release.decode()


# ---- Release files and indexes ------------------------------------------------------

class Release:
    """A verified Release file: where it came from, and the SHA-256 and size of
    each file it lists."""

    def __init__(self, base, suite, text):
        self.base, self.suite = base, suite
        self.fields, self.files = {}, {}
        section = None
        for line in text.splitlines():
            if line[:1].isspace():
                parts = line.split()
                if section == "SHA256" and len(parts) == 3:
                    self.files[parts[2]] = (parts[0], int(parts[1]))
            elif ":" in line:
                section, value = line.split(":", 1)
                self.fields[section] = value.strip()
        self.by_hash = self.fields.get("Acquire-By-Hash") == "yes"
        if self.fields.get("Codename") != suite:
            raise ArchiveFault(f"the signed Release at {self.dists} names Codename "
                               f"{self.fields.get('Codename')!r}, expected {suite}")

    @property
    def dists(self):
        return f"{self.base}/dists/{self.suite}"


def verified_release(fetch, base, suite, keys=None, fingerprints=None):
    """The verified Release of `suite` under `base`, or None when the archive
    serves neither InRelease nor Release (the suite did not exist yet)."""
    dists = f"{base}/dists/{suite}"
    signed = fetch(f"{dists}/InRelease")
    if signed is not None:
        text = verify_inrelease(signed, f"{dists}/InRelease", keys, fingerprints)
    else:
        release = fetch(f"{dists}/Release")
        if release is None:
            return None
        signature = fetch(f"{dists}/Release.gpg")
        if signature is None:
            raise ArchiveFault(f"{dists}/Release has no Release.gpg")
        text = verify_detached(release, signature, f"{dists}/Release", keys, fingerprints)
    return Release(base, suite, text)


def matches(body, sha256, size):
    return len(body) == size and hashlib.sha256(body).hexdigest() == sha256


def index_file(fetch, release, path):
    """The bytes of an index file that the verified Release lists, by hash
    when the archive offers it, then by name. The first body that matches the
    listed SHA-256 and size is returned; none matching is a fault."""
    if path not in release.files:
        raise ArchiveFault(f"the signed Release at {release.dists} does not list {path}")
    sha256, size = release.files[path]
    urls = [f"{release.dists}/{path}"]
    if release.by_hash:
        urls.insert(0, f"{release.dists}/{os.path.dirname(path)}/by-hash/SHA256/{sha256}")
    served = False
    for number, url in enumerate(urls, 1):
        try:
            body = fetch(url)
        except ConnectionError:
            if number == len(urls):
                raise
            continue
        if body is None:
            continue
        served = True
        if matches(body, sha256, size):
            return body
    if not served:
        raise ArchiveFault(f"{release.dists}/{path} is listed in the signed Release but not served")
    raise ArchiveFault(f"{release.dists}/{path} does not match the SHA-256 {sha256} in the signed Release")


def check_file(body, sha256, size, what):
    """A pool file against the SHA-256 (and size, when known) in its verified
    index."""
    actual = hashlib.sha256(body).hexdigest()
    if actual != sha256 or (size is not None and len(body) != size):
        raise ArchiveFault(f"{what} has SHA-256 {actual}, the signed index lists {sha256}")
    return body
