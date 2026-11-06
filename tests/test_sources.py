"""Unit tests for the parsing in scripts/sources.py. The downloads are
exercised against snapshot.debian.org by the publish workflow."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))
import sources  # noqa: E402

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


if __name__ == "__main__":
    unittest.main()
