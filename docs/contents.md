# Image contents

What the image holds, why each part is there, and how a scanner sees it.

`state/<line>/stable.rootfs` lists every path in a line's current stable
image, with the package that owns it and its type. The build writes the same file list as the
`rootfs.manifest` asset of each release.

## Paths

| Path | Content | Source |
|---|---|---|
| `/nodejs/bin/node`, `/nodejs/LICENSE` | the Node.js binary of the line (22 or 24) and its licence | the official `node-v<version>-linux-x64.tar.gz` from nodejs.org |
| `/usr/lib/x86_64-linux-gnu/` | 22 shared libraries: the 20 of `libc6` (see below), `libstdc++.so.6` and `libgcc_s.so.1` | Debian packages `libc6`, `libstdc++6`, `libgcc-s1` |
| `/usr/lib64/ld-linux-x86-64.so.2` | a link to the loader, the interpreter path that `node` names | `libc6` |
| `/bin`, `/lib`, `/lib64` | links to `usr/bin`, `usr/lib`, `usr/lib64` (merged-usr layout) | generated |
| `/etc/ssl/certs/ca-certificates.crt` | the Mozilla CA bundle | built from the certificates in `ca-certificates` |
| `/etc/debian_version`, `/etc/os-release` | the OS identity that scanners read | `base-files` |
| `/usr/share/doc/<package>/copyright` | the copyright file of each shipped package | each package |
| `/usr/share/common-licenses/` | the licence texts that the copyright files refer to | `base-files` |
| `/var/lib/dpkg/status.d/` | one dpkg status entry per shipped package, and the MD5 sums of its shipped files | generated from each package's control data |
| `/etc/passwd`, `/etc/group` | `root` (0:0) and `nonroot` (65532:65532), both with `/sbin/nologin` as the shell | generated |
| `/etc/nsswitch.conf` | users and groups from files; hosts from files, then DNS | generated |
| `/tmp` | writable by every user (mode 1777) | generated |
| `/home/nonroot` | the home and working directory of `nonroot`, owned by 65532:65532 | generated |

Every other path is owned by root and is not writable by `nonroot`. The smoke
test checks that a write to `/etc` fails.

## Packages

`packages.list` names the six Debian packages whose files ship, with the reason
for each:

| Package | Why it ships |
|---|---|
| `base-files` | `/etc/debian_version` and `/etc/os-release`, which scanners use to detect the OS; the common licence texts |
| `ca-certificates` | the certificates the CA bundle is built from |
| `gcc-14-base` | the copyright file that `libgcc-s1` and `libstdc++6` point to: their `/usr/share/doc/<package>` entries are links to `gcc-14-base` |
| `libc6` | all 20 of its shared libraries |
| `libgcc-s1` | `libgcc_s.so.1` |
| `libstdc++6` | `libstdc++.so.6` |

A package ships its shared libraries, its copyright file and the files named
above, not the rest of the package.

## How the library set is chosen

The rule: the image ships every shared library of each package in
`packages.list`. The build does not take a list of libraries from this
repository. It reads the file list of each pinned `.deb` and ships every path
that matches `usr/lib/*.so*`, `usr/lib/x86_64-linux-gnu/*.so*` or
`usr/lib64/*.so*`, with each symlink as the package ships it. The set follows
every glibc or GCC update with no change here.

For `libc6` in Debian 13 that is 20 libraries: the loader, `libc`, `libm`,
`libdl`, `libpthread`, `librt`, `libutil`, `libanl`, `libresolv`, `libmvec`,
`libnsl`, `libBrokenLocale`, `libthread_db`, `libc_malloc_debug`, `libmemusage`,
`libpcprofile`, and the NSS modules `libnss_files`, `libnss_dns`, `libnss_compat`
and `libnss_hesiod`. `libstdc++6` and `libgcc-s1` each ship one library, which
was already the whole set.

The reason: a native addon links libraries that `node` does not. The libvips
that `sharp` bundles needs `libresolv.so.2`, and the addon fails to load without
it. These libraries add files but no package, so the scanner sees the same six
packages.

**The `gconv` modules do not ship.** `libc6` also ships 253 files under
`usr/lib/x86_64-linux-gnu/gconv/` (8.2 MB). They are plug-ins that glibc loads
only through the `gconv-modules` configuration, for `iconv` and for character
sets that glibc does not build in. The rule matches libraries in the library
directory itself, so these deeper paths stay out. An application that needs them
needs the configuration as well, and adds both in its own layer. Node.js does
its text conversion with its built-in ICU.

`scripts/assemble-rootfs.sh` also asks the dynamic loader from the pinned
`libc6` which libraries `node` needs, and fails the build when:

- the downloaded packages differ from `packages.list`;
- the loader reports a library as not found;
- the loader resolves a library outside the pinned packages;
- a listed package ships no file;
- a zlib file appears anywhere in the root filesystem;
- the root filesystem and its file list disagree.

## Not in the image

- No shell. The smoke test checks that `/bin/sh` does not run.
- No package manager. The smoke test checks that `apt-get` and `dpkg` do not run.
- No `npm` and no `corepack`. Only `bin/node` and `LICENSE` are taken from the
  Node.js tarball.
- No `tzdata`. Time zones work anyway: see below.
- No system zlib. `node` does not link it. Node.js compiles its own zlib into the
  binary, which a scanner cannot see. See [sbom.md](sbom.md).
- No dpkg log, apt cache, `/var/log` or `ld.so.cache`. The image is `FROM scratch`
  and receives one copy of the assembled root filesystem.

A native addon that links a library from another Debian package needs its own
image layer with that library.

## Runtime configuration

| Setting | Value |
|---|---|
| `ENTRYPOINT` | `["/nodejs/bin/node"]` |
| `USER` | `65532:65532` |
| `WORKDIR` | `/home/nonroot` |
| `PATH` | `/nodejs/bin` |
| `SSL_CERT_FILE` | `/etc/ssl/certs/ca-certificates.crt` |

**Time zones.** The official Node.js binary carries full ICU with its own time
zone data. `Intl` resolves any IANA zone, and `TZ` sets the local zone. The smoke
test checks both with `TZ=America/Vancouver`, and checks that ICU is the full
build.

**Certificates.** Node.js trusts its own built-in Mozilla root store by default.
The CA bundle is the system store that Node.js reads: the smoke test checks that
`tls.getCACertificates('system')` returns exactly the certificates in the
bundle. To trust the system store, start `node` with `--use-system-ca`.

## What a scanner sees

A `FROM scratch` image has no package database by default. A scanner that cannot
identify the OS reports zero findings, and zero findings reads as a pass. This
image avoids that false pass on purpose:

- `base-files` supplies `/etc/debian_version` and `/etc/os-release`, so a scanner
  detects Debian 13.
- `/var/lib/dpkg/status.d/` holds one status entry for each shipped package, in
  the layout that distroless images use. A scanner reads the exact package
  versions from it.
- No status entry exists for a package whose files do not ship.

The publish workflow enforces this with Trivy. Trivy must detect Debian 13 and
list exactly the six packages at the versions in the lock. Three negative
controls prove that the check can fail: without `/etc/debian_version` Trivy must
lose the OS, with an old `libc6` entry Trivy must report fixable findings, and
with an extra `zlib1g` entry the check must fail. See [gates.md](gates.md).

Trivy sees only the Debian packages. The libraries compiled into `node` (OpenSSL,
zlib, ICU, libuv and others) are invisible to it. A CVE in one of them is not in
the scan and does not block a publish. Their fixes arrive through Node.js
releases. See [update-policy.md](update-policy.md#security-updates).
