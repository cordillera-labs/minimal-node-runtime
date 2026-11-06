# Reproducing a published digest

How to rebuild a published digest from this repository and confirm that your
build gives the same bytes.

Every published digest rebuilds bit for bit from its lock, at the commit that
built it. The publish workflow requires this before it pushes anything: it builds
each lock twice, in two fresh BuildKit builders with no shared cache, and the
two digests must match. A weekly workflow repeats the rebuild for the current
stable and candidate digests.

## What you need

- An amd64 (x86-64) host. Builds under emulation are not tested.
- Docker with buildx. `scripts/reproduce.sh` creates its own `docker-container`
  builders that run the BuildKit image pinned in `toolchain.env`.
- `python3`, `jq`, `git` and `curl`, and `gpgv` for the live-archive fallback.
- The [GitHub CLI](https://cli.github.com/), logged in, to download release
  assets.
- Network access to:
  - nodejs.org, for the Node.js tarball;
  - Docker Hub, for the BuildKit image and the `debian:trixie-slim` helper image;
  - the GitHub release, snapshot.debian.org, or the live Debian archive, for the
    `.deb` files.

## Rebuild the current stable digest

The lock on `main` names the commit that built the published digest. Check out
that commit and build its lock. Set `line` to the Node.js major, `22` or `24`:

```sh
git clone https://github.com/cordillera-labs/minimal-node-runtime
cd minimal-node-runtime
work=$(mktemp -d)
line=24
cp "state/$line/stable.lock" "$work/stable.lock"
git checkout "$(python3 scripts/lock.py get "$work/stable.lock" PUBLISHED_COMMIT)"
scripts/reproduce.sh "$work/stable.lock" "$work/out"
```

`scripts/reproduce.sh` builds the lock twice in two fresh builders. It compares
the two digests with each other, and with `PUBLISHED_DIGEST` in the lock. It also
compares the two file lists. It exits non-zero on any difference, and prints
`reproduce: pass` on success. The digest it built is in `$work/out/digest`.

For the candidate channel, use `state/$line/candidate.lock` in the same way. That file
exists only after a candidate has been published.

## Build from the release assets

By default the `.deb` files download from snapshot.debian.org. To use the `.deb`
assets of the release instead, download them and point `DEBS_FROM` at the
directory:

```sh
tag=$(python3 scripts/lock.py get "$work/stable.lock" PUBLISHED_TAG)
gh release download "$tag" --repo cordillera-labs/minimal-node-runtime --pattern '*.deb' --dir "$work/debs"
DEBS_FROM="$work/debs" scripts/reproduce.sh "$work/stable.lock" "$work/out"
```

The weekly reproduce workflow builds this way.

## Rebuild an older digest

Each release attaches its lock as `inputs.lock`, and its tag points at the
commit that built it. In the same clone and shell as above:

```sh
tag=<major>.<minor>.<patch>-trixie-<hash>
git checkout "$tag"
gh release download "$tag" --repo cordillera-labs/minimal-node-runtime --pattern inputs.lock --dir "$work/old"
gh release download "$tag" --repo cordillera-labs/minimal-node-runtime --pattern '*.deb' --dir "$work/old-debs"
DEBS_FROM="$work/old-debs" scripts/reproduce.sh "$work/old/inputs.lock" "$work/old-out"
cat "$work/old-out/digest"
```

`inputs.lock` holds the inputs only, not the publication record. The script
therefore checks that its two builds agree, but cannot compare them with the
published digest. Compare the printed digest with the digest in the release
notes yourself.

## Where the `.deb` files come from

`scripts/fetch-debs.sh` takes each package from the first source that works:

1. A file in `DEBS_FROM` whose SHA-256 equals the lock. A file with another
   SHA-256 is ignored.
2. The content-addressed snapshot.debian.org URL in the lock.
3. If snapshot.debian.org fails, the same version from the live Debian archive
   of its suite: deb.debian.org/debian for `trixie` and `trixie-updates`,
   deb.debian.org/debian-security for `trixie-security`. The suite's Release
   file must verify against `debian-archive-keys.asc`, its Packages index must
   match the signed Release, and the index must list the SHA-256 in the lock.
   See [gates.md](gates.md#debian-archive-signatures).

Every file must match the SHA-256 in the lock, so the source never changes what
is built. The Dockerfile checks the SHA-256 values a second time, inside the
build. `$work/out/a/debs/sources.txt` records where each file came from.

The live archive keeps only current versions. It helps a build of current
inputs, not of an old digest. An old digest needs the release assets or
snapshot.debian.org.

## What makes the build deterministic

- Every input is pinned by digest or SHA-256 in the lock: the Node.js tarball,
  each `.deb`, and the helper image. No `apt` runs.
- `SOURCE_DATE_EPOCH` is the release time of the newest input that ships, read
  from the lock. The helper image ships no file, so it does not count, and a
  helper refresh alone rebuilds to the same digest.
- Every file's mtime is set to `SOURCE_DATE_EPOCH`. BuildKit rewrites the layer
  timestamps (`rewrite-timestamp=true`).
- The CA bundle is concatenated in a fixed, sorted order.
- The image is `FROM scratch` and receives one copy of the assembled root
  filesystem. It holds no dpkg log, apt cache, `/var/log` or `ld.so.cache`.
- The build exports no provenance or SBOM attestation into the image index.
  Those are attached after the push, so they do not change the digest.
- CI pins the BuildKit image and the buildx version in `toolchain.env`, which is
  part of the build definition hash in the lock. A lock therefore names the
  BuildKit that built it. `scripts/reproduce.sh` uses the pinned BuildKit image,
  and the buildx version on your machine.

## What the weekly check covers

`.github/workflows/reproduce.yml` runs every Monday at 05:43 UTC. For each of the
current stable and candidate locks, it:

1. checks out the commit that built the digest;
2. downloads the `.deb` assets of its release;
3. runs `scripts/reproduce.sh`, which must match the published digest;
4. checks that the registry still serves the published digest.

A failure opens an issue labelled `reproducibility`. A later success closes it.

The weekly check covers the current stable and candidate digests only. It does
not rebuild older digests.
