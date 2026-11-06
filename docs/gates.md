# Publish gates

Every check a build passes before it is published, where each check runs, and
what the checks do not cover.

## The gate chain

`.github/workflows/publish.yml` runs these checks in order. A failure before
step 13 publishes nothing, because nothing is pushed before step 13. A failure
after it leaves a partial publication, which the next run completes.

1. **The lock.** Every value matches a fixed pattern before it becomes a build
   argument or a URL. `SOURCE_DATE_EPOCH` must equal the value derived from the
   release dates. The build definition hash must match the repository.
2. **The Node.js signature.** `SHASUMS256.txt.asc` verifies against a primary key
   in `node-release-keys.txt`, and lists the tarball SHA-256 in the lock.
   BuildKit then downloads the tarball with `ADD --checksum` and fails on a
   mismatch.
3. **The `.deb` files.** Each file must match the SHA-256 in the lock, when
   `scripts/fetch-debs.sh` collects it and again inside the build. The lock
   took that SHA-256 from a Packages index that verified against Debian's
   signed Release file. When the live-archive fallback runs, its Packages index
   is verified the same way and must list the SHA-256 in the lock. See
   [Debian archive signatures](#debian-archive-signatures).
4. **Assembly.** `scripts/assemble-rootfs.sh` ships every shared library of each
   listed package (read from the file list of its `.deb`), and fails when `node`
   links a library outside the pinned packages, on any zlib file, and on any file missing from the file list.
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
   status entry. It requires `libresolv.so.2` in that filesystem, as the marker of
   the whole `libc6` library set.
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
12. **The source packages.** Each Debian source file must match the Sources index,
    which must match the signed Release file, and its `.dsc`. See
    [sources-and-licences.md](sources-and-licences.md).
13. **The push.** The image is pushed by digest, with no tag. The pushed digest
    must equal the tested digest, or nothing is signed or tagged.
14. **What is already published.** `scripts/publication.py` reads the release
    and the immutable tag of this build, and `scripts/verify-published.sh`
    checks the signature and the three attestations of the digest. A release
    or an immutable tag that records another digest fails the run. See
    [Resuming a partial publish](#resuming-a-partial-publish).
15. **Signature and attestations.** The workflow signs the digest and attaches
    the scan, provenance and SBOM attestations, except each one that already
    verifies. It then verifies all four as a consumer would.
16. **The tags.** The tags move. Each tag must then resolve to the tested
    digest.
17. **The release.** The workflow creates the GitHub release with its assets,
    unless step 14 found the release of this digest.

## Resuming a partial publish

A run can publish and then fail before the `record` job commits
`state/<line>/`. The line's state then names no publication, so the next run builds the same inputs to
the same digest. Steps 14 to 17 make that run complete the publication:

- The push of an existing digest sends the same bytes and changes nothing.
- A signature or attestation that verifies as a consumer would is kept. The
  run creates only the ones that do not verify, so a consumer never sees a
  duplicate scan, provenance or SBOM attestation from the recovery.
- The immutable tag is kept when it names the tested digest. The moving tags
  are set to the digest again, which changes nothing when they already name
  it.
- The release is kept when its notes and its SBOM record the tested digest,
  its `inputs.lock` has the same inputs, its source package record matches
  this build, and it holds every asset. The run creates no release and
  uploads no asset. The lock records the commit and the run that created the
  release.

Reuse depends on the digest only. A release that records another digest, a
draft release, a release on the other channel, an incomplete release, or an
immutable tag that names another digest fails the run before anything is
signed, tagged or released. An unreadable tag fails the run too: only an
HTTP 404 counts as absent, so a tag is never overwritten. A maintainer
resolves such a fault by hand.

The check runs after the push, so a fault can leave an untagged, unsigned
digest in the registry. The digest passed every gate.

## Debian archive signatures

`scripts/debian_archive.py` verifies everything the pipeline reads from a
Debian archive, on deb.debian.org and on snapshot.debian.org alike. It checks
a chain of three links:

1. **The Release file.** The suite's `InRelease`, or `Release` with
   `Release.gpg`, verifies with `gpgv` against `debian-archive-keys.asc`. At
   least one valid signature must come from a primary key listed in
   `debian-archive-keys.txt`, with a SHA-2 hash. The `Codename` must equal the
   suite that was asked for.
2. **The index files.** `Packages.xz` and `Sources.xz` must match the SHA-256
   and size that the verified Release lists.
3. **The pool files.** A `.deb` or a source file must match the SHA-256 that
   the verified index lists.

A missing signature, a bad signature, a signature from a revoked key, or a
hash mismatch is a fault. The fault fails the step that read the file, and
names the file. Signatures from keys that are not pinned are ignored, because
Debian signs each Release file with the keys of more than one release.

`gpgv` accepts a signature from a key that has expired since. This is
necessary, because snapshot.debian.org serves old Release files unchanged. The
script accepts such a signature only when it was made before the key expired.

The update run applies the chain when it reads new Debian versions, so each
SHA-256 in a lock comes from a verified index. The verification runs only in
the steps that download from Debian. It changes neither the Dockerfile nor a
build input, so it changes no image digest.

## Where the checks run

| Check | publish | ci (every pull request) | promote |
|---|---|---|---|
| Node.js signature | yes | yes | no |
| Debian Release signature | yes, on the source packages and the live-archive fallback | yes, on the live-archive fallback | no |
| double build | yes | yes | no |
| scanner visibility | yes | yes | yes, on a fresh scan |
| vulnerability policy | yes | yes | yes, on a fresh scan |
| smoke test | yes | yes | yes |
| negative controls | yes | yes | no |
| SBOM check | yes | yes | no |
| signature and attestations | creates what does not verify, then verifies | no | verifies |

CI builds the stable lock with the pull request's build definition, and
publishes nothing.

## What the gates do not cover

The gates check that the image matches its pinned inputs, and that a scanner can
see what it holds. They do not establish that the inputs are benign.

- **Node.js.** A release that a listed releaser signed is accepted. A compromised
  release key, or malicious code in a signed release, passes every gate.
- **Debian packages.** A package is accepted when an index that Debian signed
  lists it. A compromised Debian archive key, or a malicious package that Debian
  signed, passes every gate. The pipeline does not check the `Valid-Until`
  field of a Release file, because snapshot.debian.org serves expired ones.
  An attacker who could replay an older signed Release file could therefore
  hold back a newer version, but could not change a file.
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
