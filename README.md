# minimal-node-runtime

A container base image that holds the Node.js 22 binary, the Debian 13 (trixie)
libraries that the binary links, a CA bundle and a nonroot user. It has no
shell, no package manager and no application code. It is built `FROM scratch`.

```
ghcr.io/cordillera-labs/minimal-node-runtime
```

The image is checked hourly, rebuilt when an eligible input changes, and
published only after it passes every gate below. Every published digest is
signed, carries an SBOM, a scan result and a build provenance attestation, and
can be rebuilt bit for bit from this repository.

Platform: `linux/amd64` only. There is no arm64 image.

## Tags and channels

| Tag | Channel | Moves to |
|---|---|---|
| `22`, `22-trixie` | stable | non-breaking updates, automatically; breaking changes only after promotion, or for a security fix |
| `22-candidate` | candidate | breaking changes, automatically; never promoted automatically |
| `22.<minor>.<patch>-trixie-<hash>` | one build | never moves |

`<hash>` is the first 12 characters of the hash of the build inputs. Tags move.
Digests never change and are never deleted. Pin a digest in your builds:

```dockerfile
FROM ghcr.io/cordillera-labs/minimal-node-runtime@sha256:<digest>
COPY --chown=65532:65532 build/ /app/
WORKDIR /app
CMD ["server.js"]
```

The entrypoint is `/nodejs/bin/node`, so `CMD` lists the script and its
arguments. Without a shell, `CMD` and `HEALTHCHECK` need the exec form.

## What is in the image

| Path | Content | Source |
|---|---|---|
| `/nodejs/bin/node`, `/nodejs/LICENSE` | the Node.js 22 binary and its licence | the official `node-v22.x.y-linux-x64.tar.gz` from nodejs.org |
| `/usr/lib/x86_64-linux-gnu/` | the dynamic loader, `libc.so.6`, `libm.so.6`, `libdl.so.2`, `libpthread.so.0`, `libstdc++.so.6`, `libgcc_s.so.1` | Debian packages `libc6`, `libstdc++6`, `libgcc-s1` |
| `/etc/ssl/certs/ca-certificates.crt` | the Mozilla CA bundle | Debian package `ca-certificates` |
| `/etc/debian_version`, `/etc/os-release` | the OS identity that scanners read | Debian package `base-files` |
| `/usr/share/doc/<package>/copyright`, `/usr/share/common-licenses/` | the copyright and licence texts of the shipped packages | each package, `gcc-14-base` and `base-files` |
| `/var/lib/dpkg/status.d/` | one dpkg status entry per shipped package, with the checksums of its shipped files | generated from each package's control data |
| `/etc/passwd`, `/etc/group`, `/etc/nsswitch.conf` | `root` and `nonroot` (65532:65532), name service from files then DNS | generated |
| `/tmp` (mode 1777), `/home/nonroot` | writable directories | generated |

The libraries are exactly what the dynamic loader resolves for `node`; the
build fails if the set differs from the packages in `packages.list`. The
`state/stable.rootfs` file lists every path in the current stable image.

The image runs as `65532:65532`. Not in the image: a shell, `apt`, `dpkg`,
`npm`, `corepack`, `tzdata` and zlib. Time zones work without `tzdata`,
because the Node.js binary carries full ICU with its own time zone data, and
`TZ` is honoured. A native addon that links a library outside this set needs
its own image layer.

`SSL_CERT_FILE` points at the CA bundle. Node.js uses its own built-in root
store by default; start it with `--use-system-ca` to use the bundle instead.

## Update policy

### Inputs

The inputs are pinned in `state/stable.lock` and `state/candidate.lock`:

- the Node.js version and the SHA-256 of its tarball;
- the version, download URL and SHA-256 of each Debian package;
- the digest of the `debian:trixie-slim` image that assembles the root
  filesystem (its own files do not ship);
- the hash of the build definition (`Dockerfile`, `packages.list` and
  `scripts/assemble-rootfs.sh`).

The hourly run reads the current upstream state of each input. A changed input
is eligible when its cooldown has elapsed, or at once when it is a security
update. A run that finds an eligible change builds, gates and publishes in the
same run, and then commits the updated lock to `main`. The lock records when
each decision was made (`EVALUATED_AT`), each input's release date, and why it
was accepted, so anyone can recompute the decision with
`scripts/policy.py plan --now <EVALUATED_AT>` and the `upstream.json` asset of
the release.

### Cooldown

A change that fixes no known CVE becomes eligible 7 days after its upstream
release (`COOLDOWN_DAYS` in `scripts/policy.py`). The release date of each
input:

| Input | Release date |
|---|---|
| Node.js | the `date` of the release in `https://nodejs.org/dist/index.json` |
| Debian package | the first snapshot on snapshot.debian.org that lists the version in its suite (trixie, trixie-updates or trixie-security). Snapshots are probed on a fixed 6-hour grid, so the recorded date is at most 6 hours after the true one, and the cooldown can start late but never early. |
| helper image | the `created` time in the image configuration |

### Security updates

A security update skips the cooldown. An update is a security update when:

- Trivy reports a CVE against the published stable image whose fixed version is
  at or below the new version of that package; or
- for Node.js, `https://nodejs.org/dist/index.json` marks a release in the
  update range with `"security": true`.

### Breaking changes and the two channels

A change is breaking when it changes any of these:

- the Node.js major version (22 is pinned and never moves automatically);
- the Debian release (trixie is pinned and never moves automatically);
- the shared-library SONAMEs in the image;
- the set of shipped packages, libraries or files.

The build compares its file list with `state/stable.rootfs`. A build with the
same file list is non-breaking and goes to the stable channel. A breaking build
goes to `22-candidate` only, and the run opens an issue. When the breaking
change comes from specific packages, the same run also builds the other
eligible updates without them, for the stable channel. A breaking change to the
build definition itself reaches stable only through promotion.

When a security fix is available only as a breaking change, it goes to the
stable channel directly, through every gate, and the run opens an issue
labelled `breaking`.

### Promotion

The `promote` workflow moves `22` and `22-trixie` to a published candidate
digest. A maintainer runs it after validating the candidate in a consuming
stack. It verifies that the digest is the current candidate, that its
signature and attestations verify, and that it passes the gate, the
vulnerability policy and the smoke test again. Promotion is the only manual
step in the update model.

### Cadence

The hourly check runs at minute 17. GitHub can delay or drop a scheduled run
under load, so "hourly" is the schedule, not a guarantee. Most hours find no
eligible change and publish nothing.

## Gates

A run publishes nothing unless all of these pass:

1. **The Node.js signature.** `SHASUMS256.txt.asc` verifies against a key in
   `node-release-keys.txt`, and lists the tarball checksum in the lock.
2. **Reproducibility.** Two builds in two fresh BuildKit builders, with no shared
   cache, give the same digest.
3. **Scanner visibility.** Trivy detects the OS as Debian 13 and lists exactly
   the packages in `packages.list`, at the versions in the lock, and zlib1g is
   absent. A root filesystem that a scanner cannot identify scans with zero
   findings, which reads as a pass; this gate prevents that.
4. **The vulnerability policy.** No HIGH or CRITICAL finding has a fixed version.
5. **The smoke test.** `tests/smoke.mjs`: the Node.js version, the nonroot user,
   a writable `/tmp`, time zones, DNS, and HTTPS with the CA bundle.
6. **Negative controls.** Variants without `/etc/debian_version`, with an old
   libc6, and with an extra zlib1g entry must each be rejected. This proves the
   gates can fail.

The pushed digest must equal the tested digest before anything is signed or
tagged.

## Vulnerabilities with no fix

A HIGH or CRITICAL finding with no fixed version does not block publishing,
because no fixed package exists to build from. The run opens or updates one
issue per finding, and closes it when the hourly scan of the published stable
image no longer reports it. No VEX statement is generated automatically.

Trivy scans the Debian packages. It does not see the libraries compiled into the
`node` binary (OpenSSL, zlib, ICU, libuv and others). Those follow Node.js
releases, and the Node.js security flag governs their updates.

## Verifying a digest

Signatures are keyless (Sigstore Fulcio and Rekor). The signing identity is the
`publish.yml` workflow of this repository on `main`.

```sh
image=ghcr.io/cordillera-labs/minimal-node-runtime@sha256:<digest>
identity='^https://github\.com/cordillera-labs/minimal-node-runtime/\.github/workflows/publish\.yml@refs/heads/main$'
issuer=https://token.actions.githubusercontent.com

# The signature
cosign verify "$image" --certificate-identity-regexp "$identity" --certificate-oidc-issuer "$issuer"

# The Trivy scan result recorded at publication
cosign verify-attestation --type vuln "$image" \
  --certificate-identity-regexp "$identity" --certificate-oidc-issuer "$issuer" \
  | jq -r .payload | base64 -d | jq .predicate.scanner.result

# The SLSA build provenance
signer=cordillera-labs/minimal-node-runtime/.github/workflows/publish.yml
gh attestation verify "oci://$image" --repo cordillera-labs/minimal-node-runtime --signer-workflow "$signer"

# The CycloneDX SBOM
gh attestation verify "oci://$image" --repo cordillera-labs/minimal-node-runtime --signer-workflow "$signer" \
  --predicate-type https://cyclonedx.org/bom --format json \
  --jq '.[0].verificationResult.statement.predicate' > sbom.cdx.json
```

Each digest also has a GitHub release, named by its immutable tag, with the
lock (`inputs.lock`), the SBOM, the full Trivy report, the file list and the
upstream state as assets.

## Reproducing a digest

Every published digest rebuilds bit for bit from its lock at the commit that
built it. A weekly workflow checks this for the current stable and candidate
digests and opens an issue on a mismatch.

You need Docker with buildx, `python3`, `jq`, `git`, and network access to
nodejs.org, snapshot.debian.org and Docker Hub. The build runs in the BuildKit
version pinned in `toolchain.env`, which `scripts/reproduce.sh` starts in a
container.

```sh
git clone https://github.com/cordillera-labs/minimal-node-runtime
cd minimal-node-runtime
cp state/stable.lock /tmp/stable.lock
git checkout "$(python3 scripts/lock.py get /tmp/stable.lock PUBLISHED_COMMIT)"
scripts/reproduce.sh /tmp/stable.lock /tmp/reproduce
```

`scripts/reproduce.sh` builds the lock twice in two fresh builders, then
compares both digests with each other and with `PUBLISHED_DIGEST` in the lock.
It exits non-zero on any difference. The digest it built is in
`/tmp/reproduce/digest`.

For an older digest, take `inputs.lock` from its release and check out the
release tag, which points at the commit that built it:

```sh
git checkout 22.23.4-trixie-<hash>
gh release download 22.23.4-trixie-<hash> --pattern inputs.lock --dir /tmp/old
scripts/reproduce.sh /tmp/old/inputs.lock /tmp/reproduce-old
cat /tmp/reproduce-old/digest    # compare with the digest in the release notes
```

What makes the build deterministic:

- every input is pinned by digest or SHA-256, and the Debian packages download
  from content-addressed snapshot.debian.org URLs, never from a live mirror;
  no `apt` runs at all;
- `SOURCE_DATE_EPOCH` is the release time of the newest input, read from the
  lock;
- every file's mtime is set to `SOURCE_DATE_EPOCH`, BuildKit rewrites the layer
  timestamps (`rewrite-timestamp=true`), and the image `created` time and
  history use the same epoch;
- the image is `FROM scratch` with a single file layer, so it holds no dpkg log,
  apt cache, `/var/log` or `ld.so.cache`;
- the build exports no provenance or SBOM attestation into the image index;
  those are attached separately after the push;
- the BuildKit and buildx versions are pinned.

## Licence

The files in this repository are licensed under either of [MIT](LICENSE-MIT)
or [Apache-2.0](LICENSE-APACHE), at your option.

The image contains third-party software under its own licences: Node.js and the
components bundled into its binary (`/nodejs/LICENSE`), the GNU C Library,
the GCC runtime libraries, the Debian CA certificate bundle and Debian's
base-files. Each package's copyright file is at
`/usr/share/doc/<package>/copyright`, and the licence texts those files refer
to are in `/usr/share/common-licenses/`. The source of each Debian package, at
the exact version in the lock, is on snapshot.debian.org; the Node.js source
for each release is at `https://nodejs.org/dist/v<version>/node-v<version>.tar.gz`.
