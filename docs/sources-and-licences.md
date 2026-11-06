# Sources and licences

The licences of this repository and of the software in the image, and where to
get the source code of every shipped component.

## This repository

The files in this repository are licensed under either of
[MIT](../LICENSE-MIT) or [Apache-2.0](../LICENSE-APACHE), at your option.

## The image contents

The image contains third-party software under its own licences. The copyright
file of each Debian package is at `/usr/share/doc/<package>/copyright` in the
image, and the licence texts those files refer to are in
`/usr/share/common-licenses/`. The copyright files are authoritative. This table
summarises them:

| Component | Main licence | Licence file in the image |
|---|---|---|
| Node.js and the components bundled into it | MIT for Node.js; each bundled component under its own licence | `/nodejs/LICENSE` |
| GNU C Library (`libc6`) | LGPL-2.1-or-later, with some parts under other free licences | `/usr/share/doc/libc6/copyright` |
| GCC runtime libraries (`libgcc-s1`, `libstdc++6`, `gcc-14-base`) | GPL-3.0-or-later with the GCC Runtime Library Exception 3.1 | `/usr/share/doc/gcc-14-base/copyright` |
| CA certificates (`ca-certificates`) | MPL-2.0 for the Mozilla certificate data; GPL-2.0-or-later for the Debian packaging | `/usr/share/doc/ca-certificates/copyright` |
| Debian base files (`base-files`) | GPL-2.0-or-later; the licence texts are distributed verbatim | `/usr/share/doc/base-files/copyright` |

## Source code

The GNU C Library and the GCC runtime libraries ship in binary form, so their
source is published with the image. The same applies to the CA certificates and
`base-files`. Each binary package maps to one Debian source package:

| Binary packages | Debian source package |
|---|---|
| `libc6` | `glibc` |
| `gcc-14-base`, `libgcc-s1`, `libstdc++6` | `gcc-14` |
| `ca-certificates` | `ca-certificates` |
| `base-files` | `base-files` |

### Where the source packages are

A release that is the first to ship a source package version attaches that
source package as release assets: the `.dsc`, the `.orig` tarball and the
`.debian` tarball, or the single tarball of a native package. A later release
with the same source version does not attach it again. Its release notes link
the release that carries it. `state/sources.json` on `main` records which
release carries each source package.

### How they are collected

The publish workflow reads the binary-to-source mapping from the Debian Packages
index of the snapshot that lists the pinned version. The mapping comes from
Debian, not from this repository. It downloads each source file from
snapshot.debian.org and checks it twice:

- against the SHA-256 and size in the Sources index of the same snapshot;
- against the checksums in the `.dsc`.

A mismatch fails the publish.

### Download and unpack a source package

GitHub rewrites some characters in asset names, such as `+`. The
`debian-sources.txt` asset of the carrying release maps each asset to its Debian
file name and SHA-256. This restores the names, checks the files and unpacks a
source package. `dpkg-source` comes with the `dpkg-dev` package.

```sh
tag=<the release that carries the source package>
mkdir src && cd src
gh release download "$tag" --repo cordillera-labs/minimal-node-runtime \
  --pattern '*.dsc' --pattern '*.tar.*' --pattern debian-sources.txt
grep -v '^#' debian-sources.txt | while read -r sha asset name; do
  [ "$asset" = "$name" ] || mv "$asset" "$name"
done
grep -v '^#' debian-sources.txt | awk '{print $1"  "$3}' | sha256sum -c
dpkg-source -x glibc_<version>.dsc
```

For example, `libc6` version `2.41-12+deb13u4` comes from
`glibc_2.41-12+deb13u4.dsc`.

### Node.js

The Node.js source of each release is at
`https://nodejs.org/dist/v<version>/node-v<version>.tar.gz`. The release notes of
each digest link the exact version.
