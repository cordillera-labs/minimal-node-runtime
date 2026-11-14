# Shared CI actions for app images

Composite actions under `actions/` give any application repository the same
build, scan and publish gate for a container image that runs on this runtime.
They exist so a scanner pin, a fix to the dependency audit, or a policy change
is made once. This repository is public: the actions hold no project names,
paths, hostnames or secrets, and take everything as inputs.

| Action | What it does |
| --- | --- |
| `audit-deps` | `pnpm audit` over every tracked `pnpm-lock.yaml`; fails at or above a threshold. Exit 1 is a finding, 69 a fault; a fault never passes. |
| `build-image` | Builds the Dockerfile for `linux/amd64` and fails if the image holds `.env`, `.env.*` or `.npmrc`. |
| `scan-image` | Hash-pinned Trivy scan for High and Critical findings, plus an optional minimum-Node-version check (Trivy cannot see Node-core CVEs in a standalone binary). |
| `publish-image` | Pushes `sha-<commit>` and a moving tag to GHCR and outputs the digest. |
| `deploy-coolify` | POSTs the Coolify deploy webhook; fails on a missing credential. |
| `report-issue` | One GitHub issue per scheduled scan: a failure opens or comments, a pass closes. |

## Using them

Pin every use by full commit SHA, with the release in a comment, and let
Dependabot's `github-actions` ecosystem propose bumps:

```yaml
- uses: cordillera-labs/minimal-node-runtime/actions/scan-image@<full-sha> # <date or tag>
  with:
    image-ref: my-app:ci
    min-node-version: 22.22.2
```

The calling repository keeps the job structure, `permissions`, `runs-on`,
environments and concurrency. That is deliberate: the actions never hold a
token, so a caller decides which job may write packages or issues, and the
deploy job runs no checkout.

## What stays private

- Calling repositories are not recorded here. GitHub's "Used by" graph lists
  public dependents only.
- The actions take no secrets. `publish-image`, `deploy-coolify` and
  `report-issue` receive a token as an input from the caller's own job.
- The only outbound data is package names and versions to the npm registry
  (what `pnpm install` already sends) and the public Trivy vulnerability DB.
  Source never leaves the runner.
- Everything committed here, including commit messages, PRs and Actions logs,
  is public. Keep project names, internal runner labels and fixtures drawn from
  real lockfiles out of this repository.

## Trivy pin

`actions/scan-image/trivy-image-scan.sh` downloads Trivy from the immutable
GitHub release and checks the tarball against a sha256 recorded in the script,
rather than using `aquasecurity/trivy-action` (whose installer fetches through
`get.trivy.dev`). To upgrade, take a release at least 7 days old, verify its
sigstore bundle as the script header describes, and update both pinned lines.
