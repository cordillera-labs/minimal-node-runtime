# Image contents

What the image holds, why each part is there, and how a scanner sees it.

`state/stable.rootfs` lists every path in the current stable image, with the
package that owns it and its type. The build writes the same file list as the
`rootfs.manifest` asset of each release.

## Paths

| Path | Content | Source |
|---|---|---|
| `/nodejs/bin/node`, `/nodejs/LICENSE` | the Node.js 22 binary and its licence | the official `node-v22.x.y-linux-x64.tar.gz` from nodejs.org |
| `/usr/lib/x86_64-linux-gnu/` | the dynamic loader `ld-linux-x86-64.so.2`, `libc.so.6`, `libm.so.6`, `libdl.so.2`, `libpthread.so.0`, `libstdc++.so.6`, `libgcc_s.so.1` | Debian packages `libc6`, `libstdc++6`, `libgcc-s1` |
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
| `libc6` | the dynamic loader, `libc`, `libm`, `libdl` and `libpthread` |
| `libgcc-s1` | `libgcc_s.so.1` |
| `libstdc++6` | `libstdc++.so.6` |

Only the needed files of each package ship, not the whole package. For example,
`libc6` contributes the loader and four libraries.

## How the library set is chosen

The build does not take a list of libraries from this repository. It asks the
dynamic loader from the pinned `libc6` which libraries `node` needs, and ships
exactly those. `scripts/assemble-rootfs.sh` fails the build when:

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

A native addon that links a library outside this set needs its own image layer
with that library.

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
