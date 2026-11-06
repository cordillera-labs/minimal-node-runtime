#!/usr/bin/env python3
"""Regenerates the signed test archive in this directory.

    python3 -I tests/fixtures/debian/regenerate.py

The keys are throwaway test keys made here, in a temporary home that is
deleted afterwards. Their secret halves are never stored. Only the public keys
and the signatures are written:

  keys.asc, keys.txt     the "test" key, and the "expired" key, which expired
                         on 2021-01-01
  Packages.xz, Sources.xz
                         one binary and one source package, whose files are in
                         pool/
  Release                lists the SHA-256 of both indexes, Codename trixie
  InRelease              Release, clearsigned by the test key
  Release.gpg            a detached signature of Release by the test key
  InRelease.expired-before
                         signed by the expired key in 2020, while it was valid
  InRelease.expired-after
                         signed by the expired key in 2022, after it expired

trixie-security.InRelease.xz is a real InRelease of Debian, signed with the
committed archive keys, and is not regenerated.
"""

import hashlib
import lzma
import os
import subprocess
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))


def sha(body):
    return hashlib.sha256(body).hexdigest()


def write(name, body):
    with open(os.path.join(HERE, name), "wb") as handle:
        handle.write(body)


def read(name):
    with open(os.path.join(HERE, name), "rb") as handle:
        return handle.read()


def gpg(home, *args, time=None):
    extra = ["--faked-system-time", time] if time else []
    return subprocess.run(["gpg", "--homedir", home, "--batch", "--no-tty", "--pinentry-mode", "loopback",
                           "--passphrase", "", *extra, *args], check=True, capture_output=True).stdout


def fingerprint(home, uid):
    listing = gpg(home, "--with-colons", "--list-keys", uid).decode()
    return [line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")][0]


def main():
    deb = read("pool/hello_1.0-1_amd64.deb")
    tarball = read("pool/hello-src_1.0.orig.tar.xz")
    dsc = (f"Format: 3.0 (quilt)\nSource: hello-src\nVersion: 1.0-1\nChecksums-Sha256:\n"
           f" {sha(tarball)} {len(tarball)} hello-src_1.0.orig.tar.xz\n").encode()
    write("pool/hello-src_1.0-1.dsc", dsc)
    packages = (f"Package: hello\nSource: hello-src\nVersion: 1.0-1\nArchitecture: amd64\n"
                f"Filename: pool/main/h/hello-src/hello_1.0-1_amd64.deb\nSize: {len(deb)}\n"
                f"SHA256: {sha(deb)}\n\n").encode()
    sources = (f"Package: hello-src\nBinary: hello\nVersion: 1.0-1\nDirectory: pool/main/h/hello-src\n"
               f"Checksums-Sha256:\n {sha(dsc)} {len(dsc)} hello-src_1.0-1.dsc\n"
               f" {sha(tarball)} {len(tarball)} hello-src_1.0.orig.tar.xz\n\n").encode()
    indexes = {"main/binary-amd64/Packages.xz": lzma.compress(packages),
               "main/source/Sources.xz": lzma.compress(sources)}
    write("Packages.xz", indexes["main/binary-amd64/Packages.xz"])
    write("Sources.xz", indexes["main/source/Sources.xz"])
    release = ("Origin: Test\nLabel: Test\nSuite: stable\nCodename: trixie\n"
               "Date: Thu, 01 Jan 2026 00:00:00 UTC\nAcquire-By-Hash: yes\nArchitectures: amd64\n"
               "Components: main\nDescription: minimal-node-runtime test fixture, not a Debian archive\n"
               "SHA256:\n" + "".join(f" {sha(body)} {len(body)} {path}\n" for path, body in indexes.items()))
    write("Release", release.encode())

    with tempfile.TemporaryDirectory() as home:
        os.chmod(home, 0o700)
        gpg(home, "--quick-gen-key", "Test Archive Key <test@example.invalid>", "ed25519", "sign", "never")
        gpg(home, "--quick-gen-key", "Expired Archive Key <expired@example.invalid>", "ed25519", "sign", "never",
            time="20200101T000000")
        test, expired = fingerprint(home, "test@example.invalid"), fingerprint(home, "expired@example.invalid")
        source = os.path.join(home, "Release")
        with open(source, "wb") as handle:
            handle.write(release.encode())
        write("InRelease", gpg(home, "--local-user", test, "--clearsign", "--output", "-", source))
        write("Release.gpg", gpg(home, "--local-user", test, "--detach-sign", "--armor", "--output", "-", source))
        # A signature made in 2022, then an expiry of 2021 set by a newer
        # self-signature: gpgv reports the 2022 signature as good.
        write("InRelease.expired-after", gpg(home, "--local-user", expired, "--clearsign", "--output", "-",
                                             source, time="20220601T000000"))
        gpg(home, "--quick-set-expire", expired, "2021-01-01", time="20200301T000000")
        write("InRelease.expired-before", gpg(home, "--local-user", expired, "--clearsign", "--output", "-",
                                              source, time="20200601T000000"))
        write("keys.asc", gpg(home, "--export", "--armor", test, expired))
        write("keys.txt", (f"# Test keys made by regenerate.py. Not Debian keys.\n"
                           f"{test} test\n{expired} expired\n").encode())


if __name__ == "__main__":
    main()
