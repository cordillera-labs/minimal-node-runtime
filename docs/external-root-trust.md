# External CA root-store monitoring, V1

This is an **image-update** feature. It is separate from:
- Debian \`ca-certificates\` package updates (existing signed Debian snapshots);
- reviewed manual package-file exclusions in \`certificates.exclude\`;
- optional live distrust from an operator-managed read-only mount.

## Sources and decision policy

\`.github/workflows/root-trust.yml\` observes two independently versioned public
upstream source files every hour (minute 43), or when dispatched by a maintainer:

| Source | Verified input | V1 outcome |
|---|---|---|
| Mozilla Firefox release NSS root store | \`mozilla-firefox/firefox\` \`security/nss/lib/ckfw/builtins/certdata.txt\` | Previously server-trusted root explicitly loses TLS trust: **automatic removal** |
| Mozilla certificate disappears entirely | Same | Review issue, **not** automatic; removal can be retirement or other policy |
| Mozilla distrust-after / conditional restriction | Same | Review issue; certificates issued before the cutoff can remain valid |
| Chrome Root Store | \`chromium/chromium\` \`net/data/ssl/chrome_root_store/root_store.textproto\` | Removed roots or changed constraints: **review issue**, no automatic full-root distrust |
| New roots from either source | Same | Observe only; **never** automatically import into the image |

For Mozilla, an automatic exclusion requires a root's prior
\`CKA_TRUST_SERVER_AUTH\` to be \`CKT_NSS_TRUSTED_DELEGATOR\` and its new value to
be explicitly \`CKT_NSS_MUST_VERIFY_TRUST\` or \`CKT_NSS_NOT_TRUSTED\`, with no
change to its conditional server distrust-after rule. Ambiguous and mass
changes fail or produce review issues. This conservative V1 **does not
automatically blacklist a root merely because it disappears**. That is
intentional: NSS's ordinary removal procedure removes both certificate and
trust blocks, and the reason cannot be deduced from the absence alone.

Source observations are made over HTTPS, resolved to a GitHub repository commit
SHA, and then fetched at that immutable commit. The snapshot stored under
\`state/trust/\` records source commit, content SHA-256 and the trust inventory,
keyed by the DER SHA-256 fingerprint of each certificate. The snapshot and
overlay are committed by GitHub Actions. A source outage, malformed file,
unexpectedly small inventory or failed validation does **not** replace the
accepted snapshot. This records provenance, but does not amount to a signature
verification of each upstream commit.

## Bootstrap, subsequent changes and rebuilds

On the **first** successful scheduled observation, both source snapshots are
written as baselines. This deliberately introduces **no** exclusions from
inventory differences: a missing Debian root is not proof of security distrust.
The snapshots are the reference point for later source changes.

When Mozilla explicitly withdraws website trust for an existing tracked root,
the monitor appends its exact DER SHA-256 to \`certificates.auto.exclude\`.
Existing automatic exclusions are never deleted or overwritten. No new roots
are ever added. It commits the policy and observations to \`main\` and
dispatches the normal \`update.yml\` workflow immediately.

The existing locked-image pipeline sees a changed build-definition hash,
builds Node 22 and 24 against the **currently pinned Debian package set**,
and applies all the normal reproducibility, scan, signing and provenance
gates. This avoids the seven-day package cooldown without upgrading Debian
or introducing new roots. Existing containers still require redeployment.

The initial merge of this feature adds new runtime preload files. The existing
file-list compatibility policy may therefore publish a **candidate** for each
Node line until validated and promoted. After that one-time promotion, changes
to the exclusion *contents* leave the file layout unchanged, allowing normal
stable-channel publication.

## Actual Node TLS enforcement

The deterministic selector removes matching certificates from the generated
\`/etc/ssl/certs/ca-certificates.crt\` bundle **and** writes the combined manual
and automatic denied DER fingerprints to the image at
\`/nodejs/lib/ca-image-exclusions.txt\`.

The image defaults to \`NODE_OPTIONS=--require=/nodejs/lib/ca-preload.cjs\`.
The preload removes those fingerprints from Node's effective TLS roots for
new connections, including when Node would otherwise use its embedded Mozilla
roots. This is removal-only; it does not add trust. Users overriding
\`NODE_OPTIONS\` must preserve the preload. The optional live watcher runs
after the static filter and can only remove additional roots.

Existing sockets, cached TLS sessions, worker threads that do not execute the
preload, and code supplying custom CA contexts aren't retroactively revoked.
Emergency full-session revocation may require restarting applications.

## Audit, failure and review

- Every accepted source commit and content hash appears in \`state/trust/\`.
- Every automatic exclusion is in the immutable image's build definition and
  has a corresponding source transition in Git history.
- Chrome restrictions and Mozilla ambiguous removals create individual
  \`root-trust-review\` issues without silently modifying trust.
- A source, record, or dispatch failure opens/updates a
  \`root-trust-failure\` issue; the next successful run closes it.
- The production image contains neither the observer nor network update tools.
- The operator retains the explicit manual \`certificates.exclude\` file.

The V1 policy intentionally favors evidence for automated exclusions over
deducing distrust solely from disagreement between root programs.
