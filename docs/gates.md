# Publish gates

Every check a build passes before it is published, where each check runs, and
what the checks do not cover.

## The gate chain

`.github/workflows/publish.yml` runs these checks in order. A failure at any
step publishes nothing. Nothing is pushed before step 13.

1. **The lock.** Every value matches a fixed pattern before it becomes a build
   argument or a URL. `SOURCE_DATE_EPOCH` must equal the value derived from the
   release dates. The build definition hash must match the repository.
2. **The Node.js signature.** `SHASUMS256.txt.asc` verifies against a primary key
   in `node-release-keys.txt`, and lists the tarball SHA-256 in the lock.
   BuildKit then downloads the tarball with `ADD --checksum` and fails on a
   mismatch.
3. **The `.deb` files.** Each file must match the SHA-256 in the lock, when
   `scripts/fetch-debs.sh` collects it and again inside the build.
4. **Assembly.** `scripts/assemble-rootfs.sh` ships exactly the libraries that the
   dynamic loader resolves for `node`, and fails on any library outside the
   pinned packages, on any zlib file, and on any file missing from the file list.
   See [contents.md](contents.md#how-the-library-set-is-chosen).
5. **Reproducibility.** Two builds in two fresh BuildKit builders, with no shared
   cache, must give the same digest and the same file list.
6. **Scanner visibility.** Trivy scans the built image. `scripts/gate.sh` requires
   that Trivy:
   - detects the OS as Debian 13;
   - reports one OS package result and no language packages;
   - lists exactly the packages in `packages.list`, at the versions in the lock;
   - lists no zlib package.

   It also requires that the image filesystem holds no zlib file and no zlib
   status entry.
7. **The vulnerability policy.** No HIGH or CRITICAL finding has a fixed version.
   See [update-policy.md](update-policy.md#the-vulnerability-policy).
8. **The smoke test.** `tests/smoke.mjs` runs inside the image as its default
   user. It checks:
   - the Node.js version equals the lock;
   - the process runs as `nonroot` (65532:65532) with home `/home/nonroot`;
   - `/tmp` is writable and `/etc` is not;
   - time zones resolve without `tzdata`, and `TZ` sets the local zone;
   - ICU is the full build;
   - `localhost` and a DNS name resolve through glibc;
   - the CA bundle holds more than 100 distinct certificates and equals the
     system store that Node.js reads;
   - HTTPS works with only the CA bundle as trust store, and with the default
     trust store.

   `scripts/smoke-test.sh` then checks that `/bin/sh`, `apt-get` and `dpkg` do not
   run in the image.
9. **Negative controls.** Three variants of the built image must each be
   rejected, which proves that the gates can fail:
   - without `/etc/debian_version`: Trivy must not detect Debian, and the
     scanner-visibility gate must fail;
   - with an old `libc6` status entry: Trivy must report fixable HIGH or CRITICAL
     findings for `libc6`, and the vulnerability policy must block them;
   - with an extra `zlib1g` status entry: the scanner-visibility gate must fail.

   If the Trivy database stops reporting findings for the old `libc6`, this step
   fails, and nothing is published until the control is updated.
10. **The channel.** `scripts/policy.py channel` compares the file list with
    stable. A stable-only build that is still breaking fails here. See
    [update-policy.md](update-policy.md#channels).
11. **The SBOM.** The OpenSSL, zlib and ICU versions in the SBOM must equal what
    the image's own `node` reports. See [sbom.md](sbom.md).
12. **The source packages.** Each Debian source file must match the Sources index
    and its `.dsc`. See [sources-and-licences.md](sources-and-licences.md).
13. **The push.** The image is pushed by digest, with no tag. The pushed digest
    must equal the tested digest, or nothing is signed or tagged.
14. **Signature and attestations.** The workflow signs the digest, attaches the
    scan, provenance and SBOM attestations, and then verifies all four as a
    consumer would.
15. **The tags.** The tags move. Each tag must then resolve to the tested
    digest.

## Where the checks run

| Check | publish | ci (every pull request) | promote |
|---|---|---|---|
| Node.js signature | yes | yes | no |
| double build | yes | yes | no |
| scanner visibility | yes | yes | yes, on a fresh scan |
| vulnerability policy | yes | yes | yes, on a fresh scan |
| smoke test | yes | yes | yes |
| negative controls | yes | yes | no |
| SBOM check | yes | yes | no |
| signature and attestations | creates and verifies | no | verifies |

CI builds the stable lock with the pull request's build definition, and
publishes nothing.

## What the gates do not cover

The gates check that the image matches its pinned inputs, and that a scanner can
see what it holds. They do not establish that the inputs are benign.

- **Node.js.** A release that a listed releaser signed is accepted. A compromised
  release key, or malicious code in a signed release, passes every gate.
- **Debian packages.** The pipeline reads the Packages index from deb.debian.org
  over HTTPS and checks each `.deb` against its SHA-256. It does not verify the
  OpenPGP signature on Debian's Release file. An attacker who could serve a false
  index over HTTPS, and a matching file through snapshot.debian.org or the live
  archive, could change a package.
- **The helper image.** `debian:trixie-slim` runs the assembly. It is pinned by
  digest, and a new digest is accepted after the cooldown. Its signature is not
  verified. Both reproducibility builds use the same helper, so the double build
  does not detect a compromised helper.
- **The scanner.** Trivy cannot see the libraries compiled into `node`, and it
  reports only CVEs its database knows. A clean scan is not proof of no
  vulnerability.
- **The pipeline.** The gates run in workflows on `main`. A person or token with
  write access to `main` can change them. Rebuilding a digest yourself, as
  [reproduce.md](reproduce.md) describes, checks the build without trusting the
  pipeline.
