# minimal-node-runtime

A container base image for Node.js 22 and Node.js 24 applications. Each image
holds one official Node.js binary, the 22 Debian 13 (trixie) shared libraries
of glibc and the GCC runtime, the Mozilla CA bundle and a nonroot user. It is built `FROM scratch` from
pinned inputs. Each published digest is signed, carries an SBOM and a build
provenance attestation, and can be rebuilt bit for bit from this repository. We build
our own stack on it, and we publish it so that anyone can check how it is made.

```
ghcr.io/cordillera-labs/minimal-node-runtime
```

Each published digest has a GitHub release that names the digest, its inputs and
its scan result. See [Releases](https://github.com/cordillera-labs/minimal-node-runtime/releases)
for the first and the latest.

## What is in it

| Content | Detail |
|---|---|
| Node.js 22 or 24 | `/nodejs/bin/node` from the official `linux-x64` tarball, and its `LICENSE` |
| 6 Debian packages | `base-files`, `ca-certificates`, `gcc-14-base`, `libc6`, `libgcc-s1`, `libstdc++6` |
| 22 shared libraries | every shared library of `libc6` (the dynamic loader, `libc`, `libm`, `libresolv` and 16 more), `libstdc++.so.6` and `libgcc_s.so.1` |
| CA bundle | `/etc/ssl/certs/ca-certificates.crt`, built from `ca-certificates` |
| Users | `root` and `nonroot` (65532:65532); the image runs as `nonroot` |

Each package ships all of its shared libraries, so a native addon finds the libc
libraries that `node` itself does not link, such as `libresolv.so.2`. glibc's
`gconv` plug-ins (character set converters for `iconv`) do not ship.
Each package has a dpkg status entry, so a scanner sees all six.

Not in the image: a shell, `apt`, `dpkg`, `npm`, `corepack`, `tzdata` and the
system zlib (`zlib1g`). Node.js carries its own copies of zlib, OpenSSL, ICU and
other libraries inside the binary.

The CA bundle is generated deterministically from the pinned Debian roots.
Reviewed `certificates.exclude` paths and the automated, removal-only
`certificates.auto.exclude` fingerprints both remove CAs from new images.
The default `NODE_OPTIONS` preload also removes those roots from Node's
embedded trust store, even when `--use-openssl-ca` is not specified.
If you override `NODE_OPTIONS` downstream, preserve
`--require=/nodejs/lib/ca-preload.cjs` to keep this policy enforced.
See [external root monitoring](docs/external-root-trust.md).
See [certificate selection](docs/contents.md#runtime-configuration).

A separate, optional [live CA distrust feature](docs/hot-ca-distrust.md)
can remove trusted roots for new TLS connections in running Node processes
from an operator-managed, read-only mounted policy file. It doesn't require
an image rebuild and cannot add new roots.

Full inventory: [docs/contents.md](docs/contents.md).

## Use it

Pin a digest, not a tag:

```dockerfile
FROM ghcr.io/cordillera-labs/minimal-node-runtime@sha256:<digest>
COPY build/ /app/
WORKDIR /app
CMD ["server.js"]
```

The entrypoint is `/nodejs/bin/node`, so `CMD` lists the script and its
arguments. There is no shell, so `CMD` and `HEALTHCHECK` need the exec form.
The copied files stay owned by root, so the application cannot modify its own
code.

Each Node.js major is a line, with its own tags, channels, locks and releases.
The lines are 22 and 24. They share the build definition and the Debian
package set, and update independently. A line never moves to another major:
moving an application from 22 to 24 means changing the digest it pins.

| Tag | Channel | Points at |
|---|---|---|
| `24`, `24-trixie` | stable | the latest stable Node.js 24 build |
| `24-candidate` | candidate | the latest Node.js 24 build with a breaking change; `24` moves to it only by promotion |
| `22`, `22-trixie` | stable | the latest stable Node.js 22 build |
| `22-candidate` | candidate | the latest Node.js 22 build with a breaking change; `22` moves to it only by promotion |
| `<major>.<minor>.<patch>-trixie-<hash>` | one build | one digest; set once at publication |

Platform: `linux/amd64` only.

## Verify an image

You need [cosign](https://github.com/sigstore/cosign) v2 and the
[GitHub CLI](https://cli.github.com/), logged in.

```sh
image=ghcr.io/cordillera-labs/minimal-node-runtime@sha256:<digest>

cosign verify "$image" \
  --certificate-identity-regexp '^https://github\.com/cordillera-labs/minimal-node-runtime/\.github/workflows/publish\.yml@refs/heads/main$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

gh attestation verify "oci://$image" --repo cordillera-labs/minimal-node-runtime \
  --signer-workflow cordillera-labs/minimal-node-runtime/.github/workflows/publish.yml
```

The first command checks the signature. The second checks the SLSA build
provenance. [docs/verify.md](docs/verify.md) covers the scan result, the SBOM and
what a valid signature does not prove.

## Guarantees

- **Checked hourly.** The update workflow runs at minute 17 of each hour, for
  every line. It rebuilds a line only when one of its inputs has changed and
  the change is eligible, so most runs publish nothing. GitHub can delay or drop a scheduled run.
- **Gated.** A build is published only after it passes every gate: the Node.js
  release signature, the Debian archive signature, a double build, scanner
  visibility, the vulnerability policy, a smoke test and negative controls. See [docs/gates.md](docs/gates.md).
- **Reproducible.** Two builds in two fresh builders must give the same digest
  before anything is pushed. A weekly workflow rebuilds each line's current
  stable and candidate digests at the commit that built them, and opens an issue on a
  mismatch. See [docs/reproduce.md](docs/reproduce.md).
- **Signed.** Each published digest carries a keyless cosign signature, a
  Trivy scan attestation, SLSA build provenance and a CycloneDX SBOM. The publish
  workflow verifies all four as a consumer would before any tag moves.
- **7-day cooldown.** A change that fixes no known CVE waits 7 days after its
  upstream release. A security update skips the wait: a Debian package version
  that fixes a CVE Trivy reports against the published stable image, or a
  Node.js release that nodejs.org marks as a security release.
- **Breaking changes go through the candidate channel.** A build that changes
  the image's file list publishes to its line's candidate tag (`22-candidate`,
  `24-candidate`) only. Stable moves to it only through the manual `promote`
  workflow. One exception: a security fix
  that exists only as a breaking change goes to stable directly, through every
  gate, and the run opens an issue labelled `breaking`.

The full rules: [docs/update-policy.md](docs/update-policy.md).

## Known limits

- **Trivy cannot see the libraries inside `node`.** A CVE in the bundled
  OpenSSL, zlib or ICU does not appear in the scan and does not block a publish.
  Fixes arrive only through Node.js releases. The SBOM lists the bundled
  components for inventory, and scanners may not match CVEs against them. See
  [docs/sbom.md](docs/sbom.md).
- **amd64 only.** There is no arm64 image.
- **The live-archive fallback serves current builds only.** When
  snapshot.debian.org fails, a build fetches the `.deb` files and the source
  packages from the live Debian archive, which keeps only current versions. An
  old digest reproduces from the release assets or snapshot.debian.org.
- **Debian packages are trusted as far as Debian's archive keys.** The pipeline
  verifies each Release file it reads against the pinned Debian 13 archive keys
  in `debian-archive-keys.asc`, each index against the signed Release, and each
  `.deb` and source file against its index. A package that Debian signed, or a
  compromised archive key, passes. See
  [docs/gates.md](docs/gates.md#debian-archive-signatures).

## Licence

The files in this repository are licensed under either of [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE), at your option. The image contains third-party
software under its own licences. The Debian source packages are attached to the
releases. See [docs/sources-and-licences.md](docs/sources-and-licences.md).

## Documentation

| Document | Covers |
|---|---|
| [docs/contents.md](docs/contents.md) | every path in the image, why each package ships, what a scanner sees |
| [docs/verify.md](docs/verify.md) | signature, provenance, scan result and SBOM checks |
| [docs/reproduce.md](docs/reproduce.md) | rebuilding a published digest from this repository |
| [docs/update-policy.md](docs/update-policy.md) | the hourly check, cooldown, security updates, channels, promotion, issues |
| [docs/gates.md](docs/gates.md) | every check a build passes before publication, and what the checks do not cover |
| [docs/sbom.md](docs/sbom.md) | the SBOM structure, the components bundled into `node`, determinism |
| [docs/sources-and-licences.md](docs/sources-and-licences.md) | the licences of the contents and the source packages |
