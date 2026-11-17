# Public security-scan action

This composite GitHub Action provides a reusable, SBOM-driven assessment using
Trivy, Socket, and OpenSSF Package Analysis evidence. It **does not** rewrite a
canonical SBOM, execute third-party packages, or alter an image. It is intended
for transparent, reproducible *security evidence*, not a guarantee against malware.

## Example

A caller checks out the project and generates a CycloneDX SBOM and Trivy JSON
for the exact application image it has built. Then:

~~~yaml
- name: Reusable security assessment
  id: security
  uses: cordillera-labs/minimal-node-runtime/actions/security-scan@FULL_REVIEWED_COMMIT_SHA
  with:
    sbom: sbom.cdx.json
    trivy-report: scan.json
    providers: trivy,socket,openssf
    mode: report
    socket-org: my-socket-org
    socket-token: SECRET_FROM_TRUSTED_CONTEXT
    openssf-project: my-billing-project
~~~

The SHA and token shown above are placeholders. For real use, pin a full reviewed
commit SHA and inject the Socket token using a GitHub secret only in a trusted
job. Never grant API credentials to pull-request code on self-hosted runners.

Inputs:

- sbom (required): canonical CycloneDX JSON; nested components are supported
- image: image reference for invoking an already installed Trivy CLI if no
  trivy-report path is provided
- trivy-report: preexisting Trivy JSON, avoiding an additional scan
- providers: comma-separated trivy,socket,openssf (default: all three)
- mode: report or enforce (default: report)
- trivy-fixable-only: true (default), only mark fixable HIGH/CRITICAL as blocking
- socket-org: Socket organization name; socket-token: API token with packages:list
- openssf-json: optional BigQuery JSON export to consume without querying
- openssf-project: GCP billing project for live OpenSSF BigQuery via pre-authenticated
  bq executable; this **may incur BigQuery costs**
- timeout: per-provider time limit in seconds, default 20
- output: optional normalized JSON report path, otherwise runner temp

Outputs: report (absolute JSON path) and verdict (pass, block, incomplete).

## Provider behavior and data coverage

Trivy reads the caller's vulnerability report, or scans an image with a Trivy
CLI that the caller pins and installs. It does NOT replace this repository's
separate scanner-visibility, negative-control and signed-publish gates.

Socket uses its documented org-scoped batch PURL API with Bearer auth:
https://docs.socket.dev/reference/batchpackagefetchbyorg .
Requests contain exact npm package URLs found in the SBOM, not application
source code. Request batches consume Socket API quota. Critical/high alerts and
org-policy action=error are blocking signals. pendingScan and notFound
represent *missing* coverage, not a pass. An unrecognized response also fails
coverage.

OpenSSF consumes a prior JSON export of its public Package Analysis dataset,
or queries the live public BigQuery table
ossf-malware-analysis.packages.analysis using a caller-authorized billing
project and bq CLI. The parameterized query matches exact npm package names
and versions, limits billed bytes to 100 GB and times out. It reads observed
install commands and DNS names from the published analysis. These behavioral
observations are **informational**, not proof of malicious behavior. No local
gVisor sandbox or privilege is required by this action.

Coverage statuses: complete, partial, unavailable, not_applicable. Without
credentials, provider data or matching results, coverage is explicitly
incomplete; the scanner never calls that clean. Missing providers cause the
enforce mode to fail. Report mode emits the result but does not block on provider
findings or missing coverage; malformed input remains an error in either mode.

The normalized JSON report records the exact input SBOM hash, component URLs,
provider status, evidence and the calculated verdict. Findings are **not**
automatically a cryptographic attestation; a publication workflow can sign the
assessment against its image digest after verification.

## Threat-model limitations

The Node runtime contains no installed npm modules. Its SBOM does include
upstream npm package URLs for bundled Node components such as undici and acorn.
A Socket/OpenSSF lookup of one of those upstream versions is *not* proof about
the bytes compiled into Node. No scanner alone proves a vendored component
byte-identical to a registry tarball.

An image-only SBOM excludes build-only dependencies; applications should also
assess their build lockfiles. This first action matches exact package versions,
and it does not yet investigate an entire package-release sequence to discover
a malicious intermediate version in a sandwich attack.

Unobserved behavior, network/provider faults and delayed execution can all
escape behavioral scanners. Customers should evaluate these limitations rather
than relying on a green checkmark alone.

## Tests

Run the same unit tests exercised by the repository's existing CI:

~~~sh
python3 -m unittest discover -s tests -p 'test_security_scan.py' -v
~~~

Tests cover nested SBOM components, exact version matching, missing provider
results, Socket alerts, OpenSSF command/DNS observations, a
benign-malicious-benign fixture, and report/enforce modes.

Provider references:
- https://docs.socket.dev/reference/authentication
- https://docs.socket.dev/reference/batchpackagefetchbyorg
- https://github.com/ossf/package-analysis
