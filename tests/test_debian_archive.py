"""Unit tests for scripts/debian_archive.py: the Release signature, the index
hashes and the file hashes. The fixtures are in tests/fixtures/debian; see
regenerate.py there. The tests need gpgv, and gpg for the key file check."""

import lzma
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import debian_archive  # noqa: E402
import upstream  # noqa: E402

FIXTURES = os.path.join(ROOT, "tests", "fixtures", "debian")
TEST_KEYS = os.path.join(FIXTURES, "keys.asc")
TEST_FINGERPRINTS = debian_archive.read_fingerprints(os.path.join(FIXTURES, "keys.txt"))
TEST_KEY, EXPIRED_KEY = TEST_FINGERPRINTS
BASE = "https://archive.example.invalid/debian"
DISTS = f"{BASE}/dists/trixie"


def fixture(name):
    with open(os.path.join(FIXTURES, name), "rb") as handle:
        return handle.read()


def fake_fetch(files, failing=()):
    """A fetch over a dict of URL -> body: None for an unknown URL, and
    ConnectionError for a URL in `failing`."""
    def fetch(url):
        if url in failing:
            raise ConnectionError(url)
        return files.get(url)
    return fetch


def archive_files(**overrides):
    release = debian_archive.Release(BASE, "trixie", fixture("Release").decode())
    files = {f"{DISTS}/InRelease": fixture("InRelease")}
    for path, name in (("main/binary-amd64/Packages.xz", "Packages.xz"), ("main/source/Sources.xz", "Sources.xz")):
        sha256 = release.files[path][0]
        files[f"{DISTS}/{os.path.dirname(path)}/by-hash/SHA256/{sha256}"] = fixture(name)
        files[f"{DISTS}/{path}"] = fixture(name)
    files.update(overrides)
    return files


def verify(signed, fingerprints=TEST_FINGERPRINTS, keys=TEST_KEYS):
    return debian_archive.verify_inrelease(signed, "InRelease", keys, fingerprints)


class Signatures(unittest.TestCase):
    def test_a_real_debian_inrelease_verifies_with_the_committed_keys(self):
        text = debian_archive.verify_inrelease(lzma.decompress(fixture("trixie-security.InRelease.xz")),
                                               "trixie-security InRelease")
        release = debian_archive.Release(debian_archive.live_base("trixie-security"), "trixie-security", text)
        self.assertIn("main/source/Sources.xz", release.files)
        self.assertIn("main/binary-amd64/Packages.xz", release.files)

    def test_a_good_signature_returns_the_signed_text(self):
        self.assertEqual(verify(fixture("InRelease")), fixture("Release").decode())

    def test_a_good_detached_signature_verifies(self):
        text = debian_archive.verify_detached(fixture("Release"), fixture("Release.gpg"), "Release",
                                              TEST_KEYS, TEST_FINGERPRINTS)
        self.assertEqual(text, fixture("Release").decode())

    def test_a_changed_signed_text_is_a_bad_signature(self):
        signed = fixture("InRelease")
        self.assertIn(b"Label: Test", signed)
        with self.assertRaisesRegex(debian_archive.ArchiveFault, "bad"):
            verify(signed.replace(b"Label: Test", b"Label: Tost"))

    def test_a_changed_release_fails_its_detached_signature(self):
        with self.assertRaises(debian_archive.ArchiveFault):
            debian_archive.verify_detached(fixture("Release").replace(b"Test", b"Tost"), fixture("Release.gpg"),
                                           "Release", TEST_KEYS, TEST_FINGERPRINTS)

    def test_a_key_outside_the_keyring_is_unknown(self):
        with self.assertRaisesRegex(debian_archive.ArchiveFault, "no valid signature"):
            debian_archive.verify_inrelease(fixture("InRelease"), "InRelease")

    def test_a_key_in_the_keyring_but_not_pinned_does_not_count(self):
        with self.assertRaisesRegex(debian_archive.ArchiveFault, "no valid signature"):
            verify(fixture("InRelease"), fingerprints=[EXPIRED_KEY])

    def test_a_signature_made_before_the_key_expired_verifies(self):
        self.assertEqual(verify(fixture("InRelease.expired-before")), fixture("Release").decode())

    def test_a_signature_made_after_the_key_expired_is_rejected(self):
        # gpgv itself reports this signature as good; the check is ours.
        with self.assertRaisesRegex(debian_archive.ArchiveFault, "no valid signature"):
            verify(fixture("InRelease.expired-after"))

    def test_two_clearsigned_messages_in_one_file_are_rejected(self):
        with self.assertRaisesRegex(debian_archive.ArchiveFault, "not one clearsigned message"):
            verify(fixture("InRelease") + fixture("InRelease"))

    def test_an_unsigned_file_is_rejected(self):
        with self.assertRaisesRegex(debian_archive.ArchiveFault, "not one clearsigned message"):
            verify(fixture("Release"))


class Status(unittest.TestCase):
    GOOD = ("[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG 0 x\n"
            "[GNUPG:] VALIDSIG A 2026-01-01 1767225600 0 4 0 22 {hash} 01 {primary}\n")

    def test_a_bad_signature_fails_even_beside_a_good_one(self):
        status = self.GOOD.format(hash=10, primary=TEST_KEY) + "[GNUPG:] NEWSIG\n[GNUPG:] BADSIG 1 y\n"
        with self.assertRaisesRegex(debian_archive.ArchiveFault, "bad or comes from a revoked key"):
            debian_archive.accepted_signers(status, TEST_FINGERPRINTS)

    def test_a_revoked_key_fails(self):
        status = "[GNUPG:] NEWSIG\n[GNUPG:] REVKEYSIG 1 y\n"
        with self.assertRaises(debian_archive.ArchiveFault):
            debian_archive.accepted_signers(status, TEST_FINGERPRINTS)

    def test_an_unknown_cosigner_is_ignored(self):
        status = ("[GNUPG:] NEWSIG\n[GNUPG:] ERRSIG 1 1 8 01 0 9 B\n[GNUPG:] NO_PUBKEY 1\n"
                  + self.GOOD.format(hash=8, primary=TEST_KEY))
        self.assertEqual(debian_archive.accepted_signers(status, TEST_FINGERPRINTS), [TEST_KEY])

    def test_a_sha1_signature_does_not_count(self):
        status = self.GOOD.format(hash=2, primary=TEST_KEY)
        self.assertEqual(debian_archive.accepted_signers(status, TEST_FINGERPRINTS), [])


class Keys(unittest.TestCase):
    def test_the_committed_key_file_holds_exactly_the_listed_primary_keys(self):
        with tempfile.TemporaryDirectory() as home:
            listing = subprocess.run(["gpg", "--homedir", home, "--batch", "--with-colons", "--show-keys",
                                      debian_archive.KEYS], capture_output=True, check=True).stdout.decode()
        # The first fpr line after a pub line is the primary key's.
        primaries, in_primary = [], False
        for line in listing.splitlines():
            if line.startswith("pub:"):
                in_primary = True
            elif line.startswith("fpr:") and in_primary:
                primaries.append(line.split(":")[9])
                in_primary = False
        self.assertEqual(primaries, debian_archive.read_fingerprints())
        self.assertEqual(len(primaries), 3)


class Indexes(unittest.TestCase):
    def test_an_index_that_matches_the_signed_release_is_returned(self):
        fetch = fake_fetch(archive_files())
        release = debian_archive.verified_release(fetch, BASE, "trixie", TEST_KEYS, TEST_FINGERPRINTS)
        self.assertEqual(debian_archive.index_file(fetch, release, "main/binary-amd64/Packages.xz"),
                         fixture("Packages.xz"))

    def test_the_detached_signature_is_used_when_there_is_no_inrelease(self):
        files = archive_files(**{f"{DISTS}/Release": fixture("Release"), f"{DISTS}/Release.gpg": fixture("Release.gpg")})
        del files[f"{DISTS}/InRelease"]
        release = debian_archive.verified_release(fake_fetch(files), BASE, "trixie", TEST_KEYS, TEST_FINGERPRINTS)
        self.assertIn("main/source/Sources.xz", release.files)

    def test_a_release_without_its_signature_is_a_fault(self):
        files = archive_files(**{f"{DISTS}/Release": fixture("Release")})
        del files[f"{DISTS}/InRelease"]
        with self.assertRaisesRegex(debian_archive.ArchiveFault, "no Release.gpg"):
            debian_archive.verified_release(fake_fetch(files), BASE, "trixie", TEST_KEYS, TEST_FINGERPRINTS)

    def test_a_suite_with_no_release_file_is_none(self):
        self.assertIsNone(debian_archive.verified_release(fake_fetch({}), BASE, "trixie",
                                                          TEST_KEYS, TEST_FINGERPRINTS))

    def test_an_index_with_another_hash_is_a_fault(self):
        release = debian_archive.Release(BASE, "trixie", fixture("Release").decode())
        files = {url: (fixture("Sources.xz") if "binary-amd64" in url else body)
                 for url, body in archive_files().items()}
        with self.assertRaisesRegex(debian_archive.ArchiveFault, "does not match the SHA-256"):
            debian_archive.index_file(fake_fetch(files), release, "main/binary-amd64/Packages.xz")

    def test_a_missing_by_hash_file_falls_back_to_the_name(self):
        release = debian_archive.Release(BASE, "trixie", fixture("Release").decode())
        files = {url: body for url, body in archive_files().items() if "by-hash" not in url}
        self.assertEqual(debian_archive.index_file(fake_fetch(files), release, "main/source/Sources.xz"),
                         fixture("Sources.xz"))

    def test_an_index_the_release_does_not_list_is_a_fault(self):
        release = debian_archive.Release(BASE, "trixie", fixture("Release").decode())
        with self.assertRaisesRegex(debian_archive.ArchiveFault, "does not list"):
            debian_archive.index_file(fake_fetch(archive_files()), release, "main/binary-arm64/Packages.xz")

    def test_a_release_of_another_suite_is_a_fault(self):
        with self.assertRaisesRegex(debian_archive.ArchiveFault, "Codename 'trixie', expected trixie-updates"):
            debian_archive.Release(BASE, "trixie-updates", fixture("Release").decode())


class Files(unittest.TestCase):
    def packages(self):
        text = lzma.decompress(fixture("Packages.xz")).decode()
        return upstream.parse_packages(text, {"hello"})["hello"][0]

    def test_a_deb_that_matches_the_verified_index_passes(self):
        entry = self.packages()
        body = fixture("pool/hello_1.0-1_amd64.deb")
        self.assertEqual(debian_archive.check_file(body, entry["SHA256"], int(entry["Size"]), "hello"), body)

    def test_a_deb_with_another_hash_is_a_fault(self):
        entry = self.packages()
        with self.assertRaisesRegex(debian_archive.ArchiveFault, "the signed index lists"):
            debian_archive.check_file(b"evil deb\n", entry["SHA256"], None, "hello")


if __name__ == "__main__":
    unittest.main()
