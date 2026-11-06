# Verifying an image

How to check that a digest was built and published by this repository, and how
to read its scan result and SBOM.

## What you need

- [cosign](https://github.com/sigstore/cosign) v2. The pipeline uses v2.6.1.
- The [GitHub CLI](https://cli.github.com/), logged in with `gh auth login`.
- `jq` and `base64`.

## Find the digest

A tag moves. Verify and pin a digest. To read the digest a tag points at now:

```sh
docker buildx imagetools inspect ghcr.io/cordillera-labs/minimal-node-runtime:24 \
  --format '{{json .Manifest}}' | jq -r .digest
```

The lock on `main` records each line's current stable digest. For the `24` tag
it must match:

```sh
curl -fsSL https://raw.githubusercontent.com/cordillera-labs/minimal-node-runtime/main/state/24/stable.lock \
  | grep '^PUBLISHED_DIGEST='
```

Each release on the [Releases](https://github.com/cordillera-labs/minimal-node-runtime/releases)
page also names its digest.

## Set up

```sh
repo=cordillera-labs/minimal-node-runtime
image=ghcr.io/$repo@sha256:<digest>
identity='^https://github\.com/cordillera-labs/minimal-node-runtime/\.github/workflows/publish\.yml@refs/heads/main$'
issuer=https://token.actions.githubusercontent.com
signer=$repo/.github/workflows/publish.yml
```

## The signature

Signatures are keyless, through Sigstore Fulcio and Rekor. The certificate
identity is the `publish.yml` workflow of this repository, at `refs/heads/main`.
The identity regex above matches that one workflow file on that one branch, and
nothing else.

```sh
cosign verify "$image" --certificate-identity-regexp "$identity" --certificate-oidc-issuer "$issuer"
```

## The build provenance

`actions/attest-build-provenance` attaches an SLSA provenance statement. It
names the workflow run, the commit and the repository.

```sh
gh attestation verify "oci://$image" --repo "$repo" --signer-workflow "$signer" \
  --source-ref refs/heads/main --deny-self-hosted-runners
```

`--source-ref` requires the run to have started from `main`. Every publishing
run does. `--deny-self-hosted-runners` requires a GitHub-hosted runner. Every
job in this repository runs on `ubuntu-24.04`.

## The scan result

The Trivy report from the moment of publication is attached as a cosign `vuln`
attestation. This prints the report:

```sh
cosign verify-attestation --type vuln "$image" \
  --certificate-identity-regexp "$identity" --certificate-oidc-issuer "$issuer" \
  | jq -r .payload | base64 -d | jq .predicate.scanner.result
```

The predicate also records the Trivy version (`.predicate.scanner.version`), the
date of the vulnerability database (`.predicate.scanner.db.version`) and the scan
time (`.predicate.metadata.scanFinishedOn`).

The report is a snapshot. A CVE published later is not in it. For a current
answer, scan the digest yourself, for example with
`trivy image --scanners vuln "$image"`. The hourly update run rescans the
published stable digest with a current database; see
[update-policy.md](update-policy.md).

## The SBOM

The CycloneDX SBOM is attached as a GitHub attestation. This verifies it and
writes it to `sbom.cdx.json`:

```sh
gh attestation verify "oci://$image" --repo "$repo" --signer-workflow "$signer" \
  --predicate-type https://cyclonedx.org/bom --format json \
  --jq '.[0].verificationResult.statement.predicate' > sbom.cdx.json
```

[sbom.md](sbom.md) describes its structure.

## The release assets

Each published digest has a GitHub release, named by its immutable tag. Its
assets:

| Asset | Content |
|---|---|
| `inputs.lock` | the lock the image was built from |
| `rootfs.manifest` | every path in the image, with its owner and type |
| `trivy-report.json` | the full Trivy report from publication |
| `sbom.cdx.json` | the CycloneDX SBOM |
| `upstream.json` | the upstream state the update decision used |
| `sources.json` | which release carries each Debian source package |
| `*.deb` | the six Debian packages the image was built from |
| source package files, `debian-sources.txt` | the Debian source packages that this release is the first to carry; see [sources-and-licences.md](sources-and-licences.md) |

The release assets are copies for convenience. They carry no signature of their
own. The signed forms are the attestations above, and the `.deb` files are
checked against the SHA-256 values in the lock.

## What a valid signature does not prove

A valid signature and provenance prove that the `publish.yml` workflow on `main`
of this repository built and pushed the digest. They do not prove that the
workflow was correct. A person or token with write access to `main` can change
the workflow, and its output would still verify.

The independent check is to rebuild the digest yourself from the commit that the
provenance names. See [reproduce.md](reproduce.md). A rebuild needs no trust in
the signing pipeline. It still trusts the pinned inputs; [gates.md](gates.md)
lists what the pipeline checks about them and what it does not.
