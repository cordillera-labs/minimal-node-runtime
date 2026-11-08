# Live CA distrust (opt in)

This is independent of the **pinned Debian `ca-certificates` update** and
the **build-time `certificates.exclude`** policy. Those change the contents of
new immutable image digests. The live feature only *removes* roots from the
current Node.js process's effective default trust list, without rebuilding the
image, changing the Debian CA package, or contacting a network service.

## Setup

The operator owns a small JSON policy file, mounted into the container as a
read-only **directory**, for example `/run/mnr-ca/policy.json`:

```json
{
  "generation": 1,
  "exclude_cert_sha256": [],
  "exclude_spki_sha256": []
}
```

Each entry is a lowercase, 64-character SHA-256 digest in hex:
- `exclude_cert_sha256`: hash the **DER encoding** of the certificate. This
  removes that exact certificate, including one particular cross-sign.
- `exclude_spki_sha256`: hash the DER SubjectPublicKeyInfo of the certificate.
  This distrusts all root certificates using the same public key, even if
  cross-signed. Prefer this when revoking an entire CA key.

Both lists are removal-only. If a hash does not match any existing root, it
adds no trust. An empty policy is valid.

For example, with Docker and an operator-managed host directory:

```sh
docker run --rm \
  --mount type=bind,src=/srv/mnr-ca,dst=/run/mnr-ca,readonly \
  -e MNR_CA_DISTRUST_FILE=/run/mnr-ca/policy.json \
  ghcr.io/cordillera-labs/minimal-node-runtime:24 /app/server.js
```

`/srv/mnr-ca` must contain a valid policy **before the process starts**.
Mount a directory, **not a single file bind mount**: the operator can update
a file in the directory with an atomic rename and the container will see the
replacement. In Kubernetes, use a projected ConfigMap/Secret directory
volume; avoid `subPath` mounts, which don't receive projected updates.

The image preloads `/nodejs/lib/ca-preload.cjs` automatically. It first applies
baked-in exclusions and then activates the live watcher when
`MNR_CA_DISTRUST_FILE` is set. Without the latter, no live polling runs.
When overriding `NODE_OPTIONS`, retain the image preload to preserve static
and live exclusions. This
preload works with both supported Node 22 and Node 24 lines.

## Update semantics

1. The operator validates and atomically replaces the **read-only mounted**
   policy file, with a larger `generation` value.
2. The preload reads the file every 60 seconds by default. Set
   `MNR_CA_DISTRUST_POLL_MS` to an integer between 100 and 60000 if needed.
   No shell, package manager, background updater, or container privilege
   is required.
3. The preload removes matching certificates from the process's **original**
   effective default CA list via `tls.setDefaultCACertificates()`.
   It cannot add a certificate that wasn't already trusted.
4. Updates only **accumulate exclusions** for the life of the process: an
   omitted old exclusion, a generation rollback, a malformed file, or a
   transient missing file cannot restore a previously removed root.
5. If the initial policy cannot be loaded, the process **exits** instead of
   silently falling back to unrestricted trust. Later read/parse failures
   retain the previously restricted list and log an error (once per distinct
   error).

The file belongs to the host or orchestrator, not the application. Protect
updates with operator authorization, audit logs, and rollback protection.
The `generation` check is in-memory only; an attacker who can replace the
file before a **fresh** process starts can still roll back trust policy.
Use a protected distribution layer for cross-restart anti-rollback guarantees.

## What the feature does *not* do

- **Existing sessions remain alive.** Node's API updates the CA defaults for
  *new* TLS contexts/connections; existing HTTPS-agent TLS session caches and
  established sockets aren't revoked. For emergency distrust, close/recreate
  connection pools or restart workloads if immediate revocation of all traffic
  is required.
- **Worker threads have separate CA defaults.** Ensure the preload runs in
  every worker thread that makes TLS connections; Node's setter applies to the
  calling thread only.
- Explicit `ca` options provided by application code, native addons using
  their own OpenSSL contexts, and other languages are not controlled by this
  Node API.
- This is **not a root-addition channel**, not an automatic Debian CA updater,
  and not a remotely fetched trust-policy service. Root additions and Debian
  package changes still go through the ordinary image build.
- Runtime exclusions only affect the running process. Bake urgent distrust
  into `certificates.exclude` or an updated Debian package as well, so new
  application deployments remain safe without live-policy opt-in.

Node's `--use-system-ca` normally **adds** system roots to bundled roots,
and doesn't remove bundled roots. The preload filters the *effective* default
list, so it works whether Node started with bundled, system, or OpenSSL
CA defaults. `--use-openssl-ca` is not required for this preload.
