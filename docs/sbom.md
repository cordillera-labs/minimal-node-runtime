# The SBOM

What the CycloneDX SBOM of each published digest contains, how it is made, and
what it can and cannot tell a scanner.

## Where to get it

- As a signed GitHub attestation of the digest, with predicate type
  `https://cyclonedx.org/bom`. [verify.md](verify.md#the-sbom) shows how to
  verify and extract it.
- As the `sbom.cdx.json` asset of the digest's release. This copy carries no
  signature of its own.

The SBOM is an attestation, not part of the image, so it does not affect the
image digest.

## How it is made

1. Trivy generates a CycloneDX SBOM from the built image. It lists the six Debian
   packages it reads from the dpkg status entries.
2. `scripts/sbom-bundled.sh` runs the image's own `node`, with no network, and
   reads `process.versions`.
3. `scripts/sbom-merge.py` adds the components bundled into `node`, and makes the
   document deterministic.
4. The script checks that `openssl`, `zlib` and `icu` appear in the SBOM with the
   versions that `node` reports. A mismatch fails the publish.

## Structure

| Part | Content |
|---|---|
| `metadata.component` | the image: its repository as the name, the digest as the version, and a `pkg:oci` package URL |
| Debian packages | the six packages, as Trivy reports them |
| `node` | one `application` component, `pkg:generic/node@<version>` |
| bundled components | nested inside the `node` component, one per `process.versions` entry |
| `dependencies` | the image depends on `node`, and `node` depends on each bundled component |

`process.versions` entries that are not components are left out: `node` itself,
and the ABI numbers `modules` and `napi`.

## The bundled components

Each bundled component carries:

- its name and version exactly as `process.versions` reports them;
- a package URL;
- the property `minimal-node-runtime:source` with the value `process.versions`;
- the property `minimal-node-runtime:bundled-in` with the value
  `node@<version>`.

The `cldr`, `tz` and `unicode` entries have type `data`. All others have type
`library`.

| Package URL type | Components |
|---|---|
| `pkg:npm/<name>@<version>` | `acorn`, `amaro`, `cjs-module-lexer`, `undici` |
| `pkg:github/<owner>/<repo>@v<version>` | `ada`, `ares` (c-ares), `brotli`, `nghttp2`, `simdjson`, `simdutf`, `uv` (libuv), `zstd` |
| `pkg:generic/<name>@<version>` | every other entry, for example `openssl`, `zlib`, `icu`, `v8`, `llhttp`, `sqlite` |

The set of entries is whatever the shipped `node` reports. A Node.js release that
adds or removes a bundled library changes the SBOM accordingly.

## What scanners can do with it

The bundled components are listed for inventory and for advisory matching by
hand. Do not expect a scanner to match CVEs against them:

- Most carry a `pkg:generic` package URL, which vulnerability databases rarely
  index.
- Node.js patches several of them, so an upstream version number does not
  describe the code. The bundled zlib, for example, is a Chromium fork, and its
  version reads like `1.3.1-<commit>`.

Security fixes to the bundled libraries arrive through Node.js security
releases, which skip the cooldown. See
[update-policy.md](update-policy.md#security-updates).

## Determinism

The same Trivy SBOM content and the same `process.versions` give a
byte-identical SBOM. Trivy's random values are replaced:

- the serial number and the UUID references derive from the image digest and
  the component identity;
- the timestamp is `SOURCE_DATE_EPOCH`;
- the root component names the image instead of the local path Trivy read;
- components, dependencies and properties are sorted.

Merging an already merged document again gives the same bytes.
