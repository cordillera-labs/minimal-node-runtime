"""The library rule of scripts/assemble-rootfs.sh: which .deb paths ship as libraries."""

import os
import re
import unittest

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts", "assemble-rootfs.sh")


def library_pattern():
    with open(SCRIPT, encoding="utf-8") as handle:
        match = re.search(r"^library_pattern='(.*)'$", handle.read(), re.MULTILINE)
    assert match, "assemble-rootfs.sh defines no library_pattern"
    return re.compile(match.group(1))


class LibraryRule(unittest.TestCase):
    def setUp(self):
        self.pattern = library_pattern()

    def test_libraries_of_libc6_ship(self):
        for name in ("libc.so.6", "libm.so.6", "libresolv.so.2", "librt.so.1", "libnss_files.so.2",
                     "libnss_dns.so.2", "libmemusage.so", "libpcprofile.so", "ld-linux-x86-64.so.2",
                     "libc_malloc_debug.so.0", "libBrokenLocale.so.1"):
            self.assertTrue(self.pattern.match("usr/lib/x86_64-linux-gnu/" + name), name)

    def test_the_gcc_libraries_and_their_links_ship(self):
        for name in ("libgcc_s.so.1", "libstdc++.so.6", "libstdc++.so.6.0.33"):
            self.assertTrue(self.pattern.match("usr/lib/x86_64-linux-gnu/" + name), name)

    def test_the_loader_link_ships(self):
        self.assertTrue(self.pattern.match("usr/lib64/ld-linux-x86-64.so.2"))

    def test_gconv_plug_ins_do_not_ship(self):
        self.assertFalse(self.pattern.match("usr/lib/x86_64-linux-gnu/gconv/BIG5.so"))

    def test_files_that_are_not_libraries_do_not_ship(self):
        for path in ("usr/lib/x86_64-linux-gnu/gconv/gconv-modules.d/gconv-modules-extra.conf",
                     "usr/share/gdb/auto-load/usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.33-gdb.py",
                     "usr/share/doc/libc6/copyright", "etc/ld.so.conf.d/x86_64-linux-gnu.conf",
                     "usr/lib/x86_64-linux-gnu/libfoo.so.1-gdb.py", "usr/lib/x86_64-linux-gnu/",
                     "usr/lib/python3/dist-packages/a.so"):
            self.assertFalse(self.pattern.match(path), path)


if __name__ == "__main__":
    unittest.main()
