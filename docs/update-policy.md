# Update policy

When the image is rebuilt, which channel a build goes to, and what the workflows
report. `scripts/policy.py` implements these rules and makes no network calls.

## Inputs

Each channel has a lock file: `state/stable.lock` and, once a candidate exists,
`state/candidate.lock`. A lock pins every input of the build:

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
schedule, not a guarantee. Each run has these jobs:

1. **plan**: rescans the published stable digest with a current Trivy database,
   reads the current upstream state of every input, and applies the rules below.
2. **publish**: when a change is eligible, builds the new lock, runs every gate
   and publishes. See [gates.md](gates.md).
3. **split**: when that build was breaking and went to the candidate channel,
   builds the non-breaking subset for stable.
4. **record**: commits the published lock and file list to `state/` on `main`.
5. **report**: opens, updates or closes issues.
6. **keepalive**: commits a heartbeat when `main` has been quiet. See
   [Keepalive](#keepalive).

The update and promote workflows share one concurrency group, so they never run
at the same time.

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

- **Node.js.** The run considers each 22.x release newer than the stable lock
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

- The Node.js major version stays 22.
- The Debian release stays trixie.
- The platform stays `linux/amd64`.

The lock accepts no other value for the first two. A move needs a change to this
repository.

## Breaking and non-breaking changes

Each build writes a file list (`rootfs.manifest`): every path in the image, with
the package that owns it and its type, and the target of each link. A build is
**breaking** when its file list differs from `state/stable.rootfs`. A build whose
file list is equal is **non-breaking**, even when file contents change.

Examples:

- A new Node.js 22 release or a patched `libc6` at the same paths: non-breaking.
- A `libstdc++6` version whose library file has a new name: breaking.
- A `base-files` version that adds a licence text: breaking.
- A Node.js release that links a new library, or a change to `packages.list`:
  breaking.

## Channels

| Tags | Channel | Receives |
|---|---|---|
| `22`, `22-trixie` | stable | non-breaking builds, at once; breaking builds by promotion, or for security |
| `22-candidate` | candidate | breaking builds, at once; never promoted automatically |
| `22.<minor>.<patch>-trixie-<hash>` | one build | one digest |

`<hash>` is the first 12 hex characters of the SHA-256 over the input keys of the
lock. The publish workflow sets an immutable tag once, when it publishes the
digest. A GitHub release of a candidate build is marked as a pre-release.

A breaking build goes to `22-candidate` only, and the run opens an issue
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

`.github/workflows/promote.yml` moves `22` and `22-trixie` to a published
candidate digest. A maintainer runs it by hand after validating the candidate in
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
finding, labelled `unfixed-cve` and keyed by the CVE and the package. It closes
the issue when the hourly scan of the published stable image no longer reports
the finding. No VEX statement is generated.

## Issues the workflows open

The workflows report through issues. One open issue exists per title. An update
edits the issue body, which sends no notification.

| Label | Opened when | Closed when |
|---|---|---|
| `update-failure` | a job of the update run fails | a later run completes without a failure |
| `upstream-signature` | a Node.js signature or checksum does not verify | by a maintainer |
| `unfixed-cve` | a HIGH or CRITICAL finding has no fixed version | the hourly scan of the published stable image no longer reports it |
| `candidate` | a breaking build is published to `22-candidate` | the candidate is promoted |
| `breaking` | a breaking security fix is published to stable | by a maintainer |
| `reproducibility` | the weekly rebuild gives another digest, or the registry does not serve it | a later weekly run succeeds |

## Keepalive

GitHub disables scheduled workflows in a public repository after 60 days without
repository activity. Each record commit counts as activity. When a run finds no
eligible change and the last commit on `main` is at least 45 days old, the run
commits a heartbeat to `state/heartbeat`.

## Recomputing a decision

The policy is a pure function of its inputs, so a decision can be checked
afterwards. You need the stable and candidate locks as they stood before the run
(from the history of `state/` on `main`), the `upstream.json` asset of the
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
request. The tool versions in `toolchain.env` are changed by hand, and the
next update run rebuilds with them.
