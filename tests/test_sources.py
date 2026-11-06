"""Unit tests for scripts/sources.py. The downloads run against the signed
test archive in tests/fixtures/debian; the publish workflow exercises them
against snapshot.debian.org."""

import os
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
sys.path.insert(0, os.path.join(ROOT, "tests"))
import debian_archive  # noqa: E402
import sources  # noqa: E402
from test_debian_archive import FIXTURES, archive_files, fake_fetch, fixture  # noqa: E402

STAMP = "20260101T000000Z"
SNAPSHOT_BASE = debian_archive.snapshot_base("debian", STAMP)
POOL = "pool/main/h/hello-src"

SIGNED_DSC = """-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Format: 3.0 (quilt)
Source: glibc
Version: 2.41-12+deb13u4
Checksums-Sha256:
 f24aa441021121a79266f0d75242706cab8843a47901fefe74527491807f1998 20323540 glibc_2.41.orig.tar.xz
 dda4153511bfd543502d18e5bc9323110996fe9c531f14ae3fad6eb17f027c7d 499524 glibc_2.41-12+deb13u4.debian.tar.xz

-----BEGIN PGP SIGNATURE-----

iQIzBAEBCgAdFiEE
-----END PGP SIGNATURE-----
"""


class Parsing(unittest.TestCase):
    def test_a_clearsigned_dsc_yields_its_checksums(self):
        listed = sources.checksums(sources.dsc_fields(SIGNED_DSC)["Checksums-Sha256"])
        self.assertEqual(set(listed), {"glibc_2.41.orig.tar.xz", "glibc_2.41-12+deb13u4.debian.tar.xz"})
        self.assertEqual(listed["glibc_2.41.orig.tar.xz"][1], 20323540)

    def test_an_unsigned_dsc_parses_the_same(self):
        unsigned = SIGNED_DSC.split("\n\n", 1)[1].split("\n-----BEGIN PGP SIGNATURE-----", 1)[0]
        self.assertEqual(sources.dsc_fields(unsigned), sources.dsc_fields(SIGNED_DSC))

    def test_asset_names_keep_only_safe_characters(self):
        self.assertEqual(sources.asset_name("glibc_2.41-12+deb13u4.dsc"), "glibc_2.41-12_deb13u4.dsc")

    def test_record_names_the_release_of_new_entries_only(self):
        result = sources.record({
            "glibc 1": {"release": None, "release_url": None},
            "gcc-14 1": {"release": "old", "release_url": "https://example.invalid/old"},
        }, "new", "https://example.invalid/new")
        self.assertEqual(result["glibc 1"]["release"], "new")
        self.assertEqual(result["gcc-14 1"]["release"], "old")

    def test_stamps_follow_the_lock_time_formats(self):
        self.assertEqual(sources.stamp_of("2026-10-20"), "20261020T000000Z")
        self.assertEqual(sources.stamp_of("2026-09-12T12:00:00Z"), "20260912T120000Z")



def served_at(base, pool_overrides=None):
    """The test archive served under `base`: its signed Release, its indexes
    and its pool files."""
    files = {url.replace("https://archive.example.invalid/debian", base): body
             for url, body in archive_files().items()}
    for name in ("hello-src_1.0-1.dsc", "hello-src_1.0.orig.tar.xz", "hello_1.0-1_amd64.deb"):
        files[f"{base}/{POOL}/{name}"] = fixture(f"pool/{name}")
    files.update(pool_overrides or {})
    return files


class SignedArchive(unittest.TestCase):
    """Trusts the test keys in place of the Debian keys."""

    def setUp(self):
        patches = [mock.patch.object(debian_archive, "KEYS", os.path.join(FIXTURES, "keys.asc")),
                   mock.patch.object(debian_archive, "FINGERPRINTS", os.path.join(FIXTURES, "keys.txt"))]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        out = tempfile.TemporaryDirectory()
        self.addCleanup(out.cleanup)
        self.out = out.name


class Download(SignedArchive):
    """sources.py against the signed test archive, as if it were snapshot."""

    def run_with(self, files, *calls):
        with mock.patch.object(sources, "fetch", fake_fetch(files)):
            cache = {}
            return [call(cache) for call in calls]

    def test_the_source_of_a_binary_comes_from_the_verified_packages_index(self):
        (found,) = self.run_with(served_at(SNAPSHOT_BASE), lambda cache: sources.source_of(
            "hello", "1.0-1", "debian", "trixie", [STAMP], cache))
        self.assertEqual(found, ("hello-src", "1.0-1", STAMP))

    def test_the_source_files_match_the_verified_sources_index(self):
        ((files, base),) = self.run_with(served_at(SNAPSHOT_BASE), lambda cache: sources.download(
            "debian", STAMP, "trixie", "hello-src", "1.0-1", self.out, cache))
        self.assertEqual(sorted(item["name"] for item in files),
                         ["hello-src_1.0-1.dsc", "hello-src_1.0.orig.tar.xz"])
        self.assertEqual(base, SNAPSHOT_BASE)

    def test_a_source_file_with_another_hash_is_a_fault(self):
        files = served_at(SNAPSHOT_BASE, {f"{SNAPSHOT_BASE}/{POOL}/hello-src_1.0.orig.tar.xz": b"evil\n"})
        with self.assertRaisesRegex(debian_archive.ArchiveFault, "the signed index lists"):
            self.run_with(files, lambda cache: sources.download(
                "debian", STAMP, "trixie", "hello-src", "1.0-1", self.out, cache))

    def test_an_index_with_a_bad_release_signature_is_a_fault(self):
        files = served_at(SNAPSHOT_BASE)
        url = f"{SNAPSHOT_BASE}/dists/trixie/InRelease"
        files[url] = files[url].replace(b"Label: Test", b"Label: Tost")
        with self.assertRaises(debian_archive.ArchiveFault):
            self.run_with(files, lambda cache: sources.source_of(
                "hello", "1.0-1", "debian", "trixie", [STAMP], cache))



class LiveFallback(SignedArchive):
    """sources.py when snapshot.debian.org fails: the same checks, against the
    live archive of the suite."""

    LIVE = debian_archive.live_base("trixie")

    def run_failing(self, files, failing, *calls):
        requested = []

        def fetch(url):
            requested.append(url)
            if any(url.startswith(prefix) for prefix in failing):
                raise ConnectionError(f"GET {url}: HTTP 503")
            return files.get(url)

        with mock.patch.object(sources, "fetch", fetch), mock.patch("sys.stderr"):
            cache = {}
            return [call(cache) for call in calls], requested

    def both(self, **overrides):
        return {**served_at(SNAPSHOT_BASE), **served_at(self.LIVE), **overrides}

    def test_a_failing_snapshot_reads_the_verified_live_archive(self):
        (found, (files, base)), requested = self.run_failing(
            self.both(), [SNAPSHOT_BASE],
            lambda cache: sources.source_of("hello", "1.0-1", "debian", "trixie", [STAMP], cache),
            lambda cache: sources.download("debian", STAMP, "trixie", "hello-src", "1.0-1", self.out, cache))
        self.assertEqual(found, ("hello-src", "1.0-1", STAMP))
        self.assertEqual(base, self.LIVE)
        self.assertEqual(len(files), 2)
        self.assertIn(f"{self.LIVE}/dists/trixie/InRelease", requested)

    def test_snapshot_is_not_asked_again_after_it_failed(self):
        _, requested = self.run_failing(
            self.both(), [SNAPSHOT_BASE],
            lambda cache: sources.source_of("hello", "1.0-1", "debian", "trixie", [STAMP], cache),
            lambda cache: sources.download("debian", STAMP, "trixie", "hello-src", "1.0-1", self.out, cache))
        self.assertEqual([url for url in requested if url.startswith(SNAPSHOT_BASE)],
                         [f"{SNAPSHOT_BASE}/dists/trixie/InRelease"])

    def test_a_pool_file_that_snapshot_fails_comes_from_the_live_pool(self):
        tarball = f"{SNAPSHOT_BASE}/{POOL}/hello-src_1.0.orig.tar.xz"
        ((files, base),), requested = self.run_failing(
            self.both(), [tarball],
            lambda cache: sources.download("debian", STAMP, "trixie", "hello-src", "1.0-1", self.out, cache))
        self.assertEqual(base, SNAPSHOT_BASE)
        self.assertIn(f"{self.LIVE}/{POOL}/hello-src_1.0.orig.tar.xz", requested)
        self.assertEqual(len(files), 2)

    def test_a_bad_snapshot_signature_fails_and_does_not_fall_back(self):
        url = f"{SNAPSHOT_BASE}/dists/trixie/InRelease"
        files = self.both(**{url: served_at(SNAPSHOT_BASE)[url].replace(b"Label: Test", b"Label: Tost")})
        with self.assertRaises(debian_archive.ArchiveFault):
            self.run_failing(files, [], lambda cache: sources.source_of(
                "hello", "1.0-1", "debian", "trixie", [STAMP], cache))

    def test_a_snapshot_file_with_another_hash_fails_and_does_not_fall_back(self):
        files = self.both(**{f"{SNAPSHOT_BASE}/{POOL}/hello-src_1.0.orig.tar.xz": b"evil\n"})
        with self.assertRaisesRegex(debian_archive.ArchiveFault, "the signed index lists"):
            self.run_failing(files, [], lambda cache: sources.download(
                "debian", STAMP, "trixie", "hello-src", "1.0-1", self.out, cache))

    def test_a_live_file_with_another_hash_fails(self):
        files = self.both(**{f"{self.LIVE}/{POOL}/hello-src_1.0.orig.tar.xz": b"evil\n"})
        with self.assertRaisesRegex(debian_archive.ArchiveFault, "the signed index lists"):
            self.run_failing(files, [SNAPSHOT_BASE], lambda cache: sources.download(
                "debian", STAMP, "trixie", "hello-src", "1.0-1", self.out, cache))

    def test_a_version_the_live_archive_no_longer_lists_is_a_fault(self):
        with self.assertRaisesRegex(sources.SourceFault, "not listed in trixie at the live archive"):
            self.run_failing(self.both(), [SNAPSHOT_BASE], lambda cache: sources.source_of(
                "hello", "0.9-1", "debian", "trixie", [STAMP], cache))

    def test_a_live_archive_that_also_fails_raises(self):
        with self.assertRaises(ConnectionError):
            self.run_failing(self.both(), [SNAPSHOT_BASE, self.LIVE], lambda cache: sources.source_of(
                "hello", "1.0-1", "debian", "trixie", [STAMP], cache))


if __name__ == "__main__":
    unittest.main()
