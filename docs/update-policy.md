# Update policy

When the image is rebuilt, which channel a build goes to, and what the workflows
report. `scripts/policy.py` implements these rules and makes no network calls.

## Lines

A line is a Node.js major version with its own directory in `state/`:
`state/22/` and `state/24/`. Each line has its own locks, file lists, source
record, tags, releases and issues, and updates independently of the others.
Every rule below applies to each line on its own. All lines build from the same
`Dockerfile`, `packages.list` and tool pins.

To add a line, add `state/<major>/stable.lock` with a release of that major
that has passed its cooldown and verifies against `node-release-keys.txt`. The
next update run publishes it as the line's first stable build. To retire a
line, remove its directory: its published digests and tags stay.

## Inputs

Each channel of a line has a lock file: `state/<line>/stable.lock` and, once a
candidate exists, `state/<line>/candidate.lock`. A lock pins every input of the
build:

- the Node.js version and the SHA-256 of its `linux-x64` tarball;
- the version, suite, snapshot.debian.org URL and SHA-256 of each Debian package,
  read from a Packages index that verified against Debian's signed Release file;
- the digest of the `debian:trixie-slim` helper image that assembles the root
  filesystem (its own files do not ship);
- the hash of the build definition: `Dockerfile`, `packages.list`,
  `scripts/assemble-rootfs.sh` and `toolchain.env`.

For each input, the lock also records its release date and why it was accepted
(`*_RELEASED`, `*_ACCEPTED`), and the time of the decision (`EVALUATED_AT`). After
a publication it records the digest, tag, commit, release and run
(`PUBLISHED_*`).

The tool pins in `toolchain.env` (BuildKit, buildx, Trivy, cosign) are part of
the build definition. A change to them is a build definition change, so the
next update run rebuilds with the new pins. A BuildKit or buildx change can
change the layer bytes, and so the digest, of the same inputs. A change to the
other pins rebuilds to the published digest and publishes nothing new.

## The hourly run

`.github/workflows/update.yml` runs at minute 17 of every hour, on `main` only.
GitHub can delay or drop a scheduled run under load, so "hourly" is the
schedule, not a guarantee. It lists the lines and runs
`.github/workflows/line.yml` once per line, in parallel. A failure in one line
does not stop another. For each line, these jobs run:

1. **plan**: rescans the line's published stable digest with a current Trivy database,
   reads the current upstream state of every input, and applies the rules below.
2. **publish**: when a change is eligible, builds the new lock, runs every gate
   and publishes. See [gates.md](gates.md).
3. **split**: when that build was breaking and went to the candidate channel,
   builds the non-breaking subset for stable.
4. **record**: commits the published lock and file list to `state/<line>/` on
   `main`.
5. **report**: opens, updates or closes the line's issues.

Beside the lines, a **toolchain** job checks the pins in `toolchain.env`.
An independent hourly `root-trust.yml` observes Mozilla and Chrome program
changes. Only explicit Mozilla website-trust withdrawals can append removal-only
DER fingerprints to `certificates.auto.exclude`; that change to the build
definition is eligible immediately and dispatches this normal update workflow.
Chrome restrictions and ambiguous removals create review issues. See
[external root trust](external-root-trust.md). See
[Toolchain pins](#toolchain-pins).

After every line, **keepalive** commits a heartbeat when `main` has been quiet.
See [Keepalive](#keepalive).

The update and promote workflows share one concurrency group, so they never run
at the same time.

A run that publishes and then fails before **record** leaves `state/` without
the publication. The next run builds the same inputs to the same digest, finds
the signature, the attestations, the tags and the release of that digest, and
creates only what is missing. **record** then commits the lock with the commit
and run that created the release. An existing release or tag that records
another digest fails the run. See
[gates.md](gates.md#resuming-a-partial-publish).

Most runs find no eligible change and publish nothing. When upstream cannot be
reached, the run builds nothing and the next run tries again. That case opens no
issue; the run summary records the fault.

## Eligibility and the cooldown

A changed input is eligible when 7 days have passed since its upstream release
(`COOLDOWN_DAYS` in `scripts/policy.py`), or at once when it is a security
update. The release date of each input:

| Input | Release date |
|---|---|
| Node.js | the `date` of the release in `https://nodejs.org/dist/index.json`. This is a calendar day, counted from 00:00 UTC. |
| Debian package | the first point on a fixed 6-hour grid at which snapshot.debian.org lists the version in its suite (`trixie`, `trixie-updates` or `trixie-security`). The date is never earlier than the first snapshot that lists the version. It is at most 6 hours later when every probe succeeds, and later still when a probe fails. The cooldown can start late, never early. |
| helper image | the `created` time in the image configuration |

The rules per input:

- **Node.js.** The run considers each release of the line's major newer than the stable lock
  that has a `linux-x64` build. It takes the newest eligible release. Newer
  releases that are still inside the cooldown stay pending.
- **Debian packages.** The run takes the newest version of each package across
  the three suites. It never moves a package to an older version. A new version
  waits until snapshot.debian.org has imported it and a release date is known,
  because the lock pins snapshot URLs. This applies to security updates too.
- **Helper image.** The run reads the current `debian:trixie-slim` index digest.
  A new digest is eligible after the cooldown. It has no security path.
- **Build definition.** A change to the build definition on `main` is eligible
  at once. CI runs the full gate chain on every pull request.

## Security updates

A security update skips the cooldown. An update is a security update when:

- for a Debian package, Trivy reports a CVE of any severity against the published
  stable image whose fixed version is at or below the new version of that
  package; or
- for Node.js, `https://nodejs.org/dist/index.json` marks a release in the update
  range with `"security": true`.

The libraries compiled into `node` (OpenSSL, zlib, ICU and others) are invisible
to Trivy. Their fixes arrive only through Node.js releases, and only the
nodejs.org security flag puts those releases on the fast path. A CVE in a
bundled library that Node.js has not yet fixed ships, and the pipeline opens no
issue for it.

## Node.js release signatures

The plan accepts a Node.js release only when its `SHASUMS256.txt.asc` verifies
against a primary key listed in `node-release-keys.txt`, and the signed file lists
the tarball checksum. The public keys are fetched from a pinned commit of
`github.com/nodejs/release-keys` and checked against the listed fingerprints. A
new releaser needs a change to that file.

When a signature or checksum does not verify, no Node.js update is accepted that
hour. The other inputs keep updating. The run opens an issue labelled
`upstream-signature`.

## Debian archive signatures

The run reads Debian versions only from indexes that verify against Debian's
signed Release files. This applies to the live Packages indexes, and to the
snapshot.debian.org indexes that give the release dates.
[gates.md](gates.md#debian-archive-signatures) describes the chain of checks.
When a check fails, the run builds nothing, and the run summary names the
file. No issue is opened; the next run checks again.

### Rotating the Debian archive keys

`debian-archive-keys.asc` holds the public keys and `debian-archive-keys.txt`
lists their primary fingerprints. A unit test fails unless the two files list
the same keys. Debian publishes the keys of the next release ahead of time, on
https://ftp-master.debian.org/keys.html and in the `debian-archive-keyring`
package, and the Release files of a supported release keep a signature from its
own keys. A key change is therefore a manual, reviewed change:

1. Download the new key file from https://ftp-master.debian.org/keys.html.
2. Check its primary fingerprint against `keys.html`, and against the copy in
   the `debian-archive-keyring` package of a current Debian image, such as
   `/etc/apt/trusted.gpg.d/` in `debian:trixie-slim`.
3. Append the key to `debian-archive-keys.asc` and its fingerprint to
   `debian-archive-keys.txt`, in one pull request.
4. Remove a key only when no Release file that the pipeline reads depends on it
   alone. This includes the snapshot.debian.org Release files of every lock that
   is still rebuilt.

When Debian revokes a key, download the key file again: `gpgv` knows of the
revocation only from the committed key file. A signature from a revoked key
fails the run.

## What never moves automatically

- A line's Node.js major version: the 22 line stays on 22.x, the 24 line on
  24.x.
- The Debian release stays trixie.
- The platform stays `linux/amd64`.

The update run offers a line only releases of its own major, and the lock
accepts no Debian release but trixie. A new major is a new line, which needs a
change to this repository.

## Breaking and non-breaking changes

Each build writes a file list (`rootfs.manifest`): every path in the image, with
the package that owns it and its type, and the target of each link. A build is
**breaking** when its file list differs from its line's `state/<line>/stable.rootfs`. A build whose
file list is equal is **non-breaking**, even when file contents change.

Examples:

- A new Node.js release on the line or a patched `libc6` at the same paths: non-breaking.
- A `libstdc++6` version whose library file has a new name: breaking.
- A `base-files` version that adds a licence text: breaking.
- A Node.js release that links a new library, or a change to `packages.list`:
  breaking.

## Channels

Each line has the same channels, under tags named after its major (`<line>`
is `22` or `24`):

| Tags | Channel | Receives |
|---|---|---|
| `<line>`, `<line>-trixie` | stable | non-breaking builds, at once; breaking builds by promotion, or for security |
| `<line>-candidate` | candidate | breaking builds, at once; never promoted automatically |
| `<line>.<minor>.<patch>-trixie-<hash>` | one build | one digest |

`<hash>` is the first 12 hex characters of the SHA-256 over the input keys of the
lock. The publish workflow sets an immutable tag once, when it publishes the
digest. A GitHub release of a candidate build is marked as a pre-release.

A breaking build goes to `<line>-candidate` only, and the run opens an issue
labelled `candidate`. When the breaking part comes from specific packages, the
same run also builds the other eligible updates without them, for the stable
channel. That split does not happen when the breaking part comes from the build
definition or from a generated file. Those reach stable only through promotion.

While a candidate waits, each run that finds the same inputs builds nothing new
for the candidate channel.

When a build gives a digest that is already published on its channel, for
example after a helper image refresh alone, the run publishes no new tag or
release. The lock records the new inputs with the earlier publication record.

### A security fix that is only available as a breaking change

When every breaking part of a build was accepted as a security update, and the
build definition is unchanged, the build goes to the stable channel directly.
It passes every gate first. The run opens an issue labelled `breaking`, which
names the release and the breaking packages.

## Promotion

`.github/workflows/promote.yml` moves `<line>` and `<line>-trixie` to a
published candidate digest of that line. The line is the one whose
`state/<line>/candidate.lock` names the digest. A maintainer runs it by hand after validating the candidate in
a consuming stack. It is the only manual step in the update model.

The workflow checks that:

- the digest is the current candidate;
- the build definition has not changed since the candidate was built;
- the signature, the scan attestation, the SBOM attestation and the provenance
  verify;
- a fresh scan passes the scanner-visibility gate and the vulnerability policy;
- the smoke test passes.

It then moves the tags, copies the candidate lock to the stable lock on `main`,
and closes the `candidate` issue. The digest itself does not change.

## The vulnerability policy

A build with a HIGH or CRITICAL finding that has a fixed version is not
published. A finding of MEDIUM or LOW severity never blocks.

A HIGH or CRITICAL finding with no fixed version does not block publishing,
because no fixed package exists to build from. The run opens one issue per
finding, labelled `unfixed-cve` and keyed by the line, the CVE and the package.
It closes the issue when the hourly scan of the line's published stable image
no longer reports the finding. No VEX statement is generated.

## Issues the workflows open

The workflows report through issues. One open issue exists per title, and the
title names the line or, for a toolchain pin, the tool. An update
edits the issue body, which sends no notification.

| Label | Opened when | Closed when |
|---|---|---|
| `update-failure` | a job of a line's update fails | a later run of that line completes without a failure |
| `upstream-signature` | a Node.js signature or checksum does not verify | by a maintainer |
| `unfixed-cve` | a HIGH or CRITICAL finding has no fixed version | the hourly scan of the published stable image no longer reports it |
| `toolchain-update` | a tool pin has a stable upstream release past the cooldown | the pin reaches that release |
| `toolchain-security-fault` | a tool's published advisory or release feed could not be read safely | a later observation successfully reads all tool feeds |
| `toolchain-security-failure` | an automated GHSA-backed security PR, CI, merge or image dispatch fails | maintainer review / successful retry |
| `candidate` | a breaking build is published to `<line>-candidate` | the candidate is promoted |
| `breaking` | a breaking security fix is published to stable | by a maintainer |
| `reproducibility` | the weekly rebuild gives another digest, or the registry does not serve it | a later weekly run succeeds |

## Toolchain pins

`toolchain.env` pins BuildKit, buildx, Trivy and cosign. Dependabot does not
read that file, so the **toolchain** job of the hourly run (`scripts/toolchain.py`)
compares each pin with the latest stable release of its tool on GitHub
(`aquasecurity/trivy`, `moby/buildkit`, `docker/buildx`, `sigstore/cosign`).
A draft, a prerelease and a tag that is not `vMAJOR.MINOR.PATCH` never count.

A newer **nonsecurity** release is eligible when its GitHub release is
`COOLDOWN_DAYS` old. The toolchain job opens one `toolchain-update` issue per
eligible pin and never changes it. A person may review and adopt those updates.

### Automatic, advisory-backed security fixes

The independent `.github/workflows/toolchain-security.yml` runs hourly at
minute 31 on `main` (and on manual dispatch). It uses
`scripts/toolchain_security.py` to read **published upstream GitHub
Security Advisories** for BuildKit, Buildx and Cosign, and the official
**reviewed Go vulnerability database** for Trivy's own Go module.
Neither path infers security from arbitrary release-note text.
The bypass applies only when:

- The advisory identifies the currently pinned version as vulnerable
  with a parseable affected-version range and provides a patched version.
  It must name **the tool's own Go module**, not an unrelated dependency, OR
  be a **published CVE** from the tool's own repository with an explicitly
  untyped/no-package product-level advisory (as BuildKit and Buildx use).
  Unnamed advisories without a CVE are never automatic.
- The target is a published, stable `vMAJOR.MINOR.PATCH` release in the **same
  major**; the planner chooses the earliest such release that fixes **all**
  applicable published direct advisories. It ignores drafts, prereleases and
  unrecognized ranges. An unavailable API, missing patch, or malformed
  advisory is **not** authorization for an upgrade.
- For BuildKit and Cosign, the exact immutable digest of the official new
  registry image is resolved and pinned alongside the tag. The registry digest
  must be a valid SHA-256; a tag alone is never accepted.
- Only one tool changes per iteration, in order: BuildKit, Buildx, Cosign,
  Trivy. This isolates builder-related changes that might change image digests.

For a qualifying security fix, the bot creates a **single-pin** pull request,
explicitly dispatches the existing complete read-only `ci.yml` workflow on
that PR's exact head commit (PRs created with `GITHUB_TOKEN` do not trigger
the usual `pull_request` workflow), and **merges only if the full CI passes**
on both Node lines, including reproducible double builds, lint, vulnerability
gates, negative controls and the CA distrust integration test. It never uses
`--admin` or bypasses branch protection. A failed CI or merge leaves the
security PR open with an actionable `toolchain-security-failure` issue.
After successful merge it explicitly dispatches the usual `update.yml`
publication pipeline, because bot-authored commits do not trigger push-based
workflows.

The first adoption requires enabling the repository setting allowing GitHub
Actions to **create pull requests**; ordinary write permissions and CI branch
protection must also permit the intended merge. Without that, the bot will
fail visibly and leave the current pinned versions unchanged.

### Trivy 403 recovery and Go advisory coverage

GitHub Actions has repeatedly received HTTP 403 from both authenticated and
anonymous requests for `aquasecurity/trivy` releases and repository security
advisories, including smaller advisory pages. The normal version monitor now
requests ten releases instead of fifty; on an API authorization/rate-limit
failure it reads GitHub's **public Trivy releases Atom feed** instead.
The feed's repository identity, self-link, release-tag URLs and timestamps
are strictly validated. The timestamp is the later of Atom `updated` and
`published` (when present), which can delay the seven-day cooldown but
does not make an older release newly eligible early. Corrupt, empty,
misidentified or unreachable feeds are still faults.

For security advisories, Trivy's repository API is unavailable from Actions.
The security watcher instead queries the **canonical Go vulnerability database**
at `https://vuln.go.dev/index/modules.json` and the referenced OSV reports
for exactly `github.com/aquasecurity/trivy`. Only records reviewed by the
Go security team, explicitly naming the direct Trivy module, with a GHSA
alias and unambiguous introduced/fixed semantic versions can authorize a
cooldown bypass. Unreviewed, withdrawn, dependency-only and ambiguous records
do not authorize automatic upgrades. Live CI probes both the GitHub Atom feed
and official Go vulnerability database; offline tests cover malformed data.

**Coverage limitation:** Go's vulnerability database is not a complete list
of Trivy CLI, distribution, build-pipeline or dependency vulnerabilities.
Security fixes absent from reviewed direct-module OSV reports are handled
through the existing ordinary cooldown/manual upgrade issues, not falsely
classified as safe fast-path updates. The current pinned v0.74.0 is newer than
the fixed versions for all five direct-module entries observed on 2026-11-09;
there is no outstanding direct Go-module security update indicated by that
source.

### Limits of the evidence

A GHSA with a patched version is evidence that **a particular disclosed
vulnerability is addressed**. It does not certify the release as generally
safe or prove a compromise did not occur. In particular, Trivy's own release
pipeline was compromised earlier in 2026. We therefore limit automatic
updates to versioned, published upstream advisories, authenticated registry
digest lookups, pinned image digests, an auditable PR and the complete repository
CI suite. The new Cosign binary must additionally verify the keyless signature
of an existing stable image before the bot proposes its PR. Security
fixes found **only** in dependencies or inferred solely from release notes
remain manual. **Major upgrades** (such as Cosign 2 → 3) also stay manual.
These restrictions trade some speed for supply-chain protection.

For each nonsecurity tool with an eligible release, the existing hourly
`toolchain-update` issue remains the manual-review queue. Image pins must
always update tag and digest together; BuildKit and Buildx should never change
in the same PR.

When the normal GitHub release lookup and any validated fallback fail, or
a pin cannot be read, the job reports a fault in
the run summary and as an annotation, opens no issue and leaves the tool's issue
as it was. A fault is not "no update". The job is independent of the lines, so a
fault never delays or fails a publication. A key added to `toolchain.env` with no
entry in `scripts/toolchain.py` is a fault, and a unit test fails on it.
The independent security watcher additionally opens or updates an issue for
advisory lookup faults, instead of treating those faults as no available fix.

## Keepalive

GitHub disables scheduled workflows in a public repository after 60 days without
repository activity. Each record commit counts as activity. When the last commit
on `main` is at least 45 days old after every line has run, the run commits a
heartbeat to `state/heartbeat`.

## Recomputing a decision

The policy is a pure function of its inputs, so a decision can be checked
afterwards. You need the line's stable and candidate locks as they stood before
the run (from the history of `state/<line>/` on `main`), the `upstream.json` asset of the
release, and the lock's `EVALUATED_AT`:

```sh
python3 scripts/policy.py plan --stable stable.lock --candidate candidate.lock \
  --upstream upstream.json --now <EVALUATED_AT> --out-dir plan
```

The script needs `dpkg` for version comparison. A Debian update accepted for
security names its CVEs in its `*_ACCEPTED` field. The scan of the previous image
that found those CVEs is not attached to the release. Without `--scan`, the
script applies the cooldown to those updates, so its result can differ.

## The pipeline's own dependencies

Every GitHub Action is pinned by commit SHA. Dependabot proposes Action updates
monthly, with a 7-day cooldown, and never merges them. CI checks each pull
request. Dependabot does not read `toolchain.env`; the toolchain job opens an
issue when a pin is behind (see [Toolchain pins](#toolchain-pins)). Security
fixes with verified direct GHSA fixed versions use the separate fully-gated
automatic PR workflow; other updates still require manual review. A merged
toolchain change dispatches the normal build and publication pipeline.

CI also lints the workflows on every pull request (`scripts/workflow-lint.sh`):
zizmor for security mistakes such as unpinned actions, template injection,
broad token permissions and persisted credentials, and actionlint for workflow
errors and shellcheck in `run:` scripts. Both run from images pinned by digest
in that script, not in `toolchain.env`, because they are not part of the build.
The toolchain job does not check them; a person updates them, after the same
cooldown. A deliberate exception is an inline `# zizmor: ignore[<rule>]` comment
that says why.
