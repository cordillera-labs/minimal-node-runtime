'use strict';

// Opt-in, removal-only live CA distrust for Node 22.19+ and 24.5+.
// Loaded before the application with NODE_OPTIONS=--require=/nodejs/lib/ca-distrust.cjs.
// The policy is a read-only, externally managed file; this module never updates it.
const fs = require('node:fs');
const tls = require('node:tls');
const { X509Certificate, createHash } = require('node:crypto');

const MAX_POLICY_BYTES = 65536;
const DEFAULT_POLL_MS = 60000;
const SHA256 = /^[0-9a-f]{64}$/;

function fingerprint(pem) {
  const cert = new X509Certificate(pem);
  return {
    cert: createHash('sha256').update(cert.raw).digest('hex'),
    spki: createHash('sha256').update(cert.publicKey.export({ type: 'spki', format: 'der' })).digest('hex'),
  };
}

function parsePolicy(input) {
  if (Buffer.byteLength(input) > MAX_POLICY_BYTES) throw new Error('policy exceeds 64 KiB');
  let policy;
  try { policy = JSON.parse(input.toString()); }
  catch { throw new Error('policy is not valid JSON'); }
  if (policy === null || Array.isArray(policy) || typeof policy !== 'object') {
    throw new Error('policy must be an object');
  }
  const fields = ['generation', 'exclude_cert_sha256', 'exclude_spki_sha256'];
  for (const field of Object.keys(policy)) {
    if (!fields.includes(field)) throw new Error(`unknown policy field: ${field}`);
  }
  if (!Number.isSafeInteger(policy.generation) || policy.generation < 0) {
    throw new Error('generation must be a nonnegative integer');
  }
  for (const field of fields.slice(1)) {
    if (!Array.isArray(policy[field]) || policy[field].length > 1024) {
      throw new Error(`${field} must be an array of at most 1024 hashes`);
    }
    const unique = new Set();
    for (const hash of policy[field]) {
      if (typeof hash !== 'string' || !SHA256.test(hash)) {
        throw new Error(`${field} must contain lowercase SHA-256 hashes`);
      }
      if (unique.has(hash)) throw new Error(`duplicate ${field} entry: ${hash}`);
      unique.add(hash);
    }
  }
  return policy;
}

function createController({ getDefaults, setDefaults, readPolicy }) {
  if (typeof getDefaults !== 'function' || typeof setDefaults !== 'function') {
    throw new Error('this Node.js version does not support live default CA replacement');
  }
  const baseline = getDefaults().map(pem => ({ pem, ...fingerprint(pem) }));
  let generation = -1;
  let lastContents = null;
  let deniedCertificates = new Set();
  let deniedKeys = new Set();

  function reload() {
    const input = readPolicy();
    if (!Buffer.isBuffer(input)) throw new Error('policy reader must return a Buffer');
    if (input.length > MAX_POLICY_BYTES) throw new Error('policy exceeds 64 KiB');
    const contents = input.toString('utf8');
    if (contents === lastContents) return false;
    const policy = parsePolicy(input);
    if (policy.generation < generation) throw new Error('policy generation rollback');
    if (policy.generation === generation) throw new Error('policy changed without generation increment');

    // Monotonic distrust: a live update can only remove more trust anchors.
    // Deliberate restoration requires a process restart with a new trusted policy.
    const certs = new Set([...deniedCertificates, ...policy.exclude_cert_sha256]);
    const keys = new Set([...deniedKeys, ...policy.exclude_spki_sha256]);
    const allowed = baseline.filter(c => !certs.has(c.cert) && !keys.has(c.spki)).map(c => c.pem);
    setDefaults(allowed);
    deniedCertificates = certs;
    deniedKeys = keys;
    generation = policy.generation;
    lastContents = contents;
    return true;
  }

  return { reload, getGeneration: () => generation };
}

function start(file, { fsApi = fs, tlsApi = tls, pollMs = DEFAULT_POLL_MS, log = console.error } = {}) {
  if (!Number.isSafeInteger(pollMs) || pollMs < 100 || pollMs > 60000) {
    throw new Error('poll interval must be between 100 and 60000 ms');
  }
  const controller = createController({
    getDefaults: () => tlsApi.getCACertificates('default'),
    setDefaults: tlsApi.setDefaultCACertificates?.bind(tlsApi),
    readPolicy: () => fsApi.readFileSync(file),
  });
  // The first policy must be readable and valid before any user code executes.
  controller.reload();
  let lastError = null;
  const timer = setInterval(() => {
    try {
      controller.reload();
      lastError = null;
    } catch (error) {
      // Keep the last known good, already-restricted trust list on failure.
      if (error.message !== lastError) {
        log(`minimal-node-runtime CA policy: ${error.message}; keeping previous exclusions`);
        lastError = error.message;
      }
    }
  }, pollMs);
  timer.unref();
  return { controller, close: () => clearInterval(timer) };
}

if (process.env.MNR_CA_DISTRUST_FILE) {
  try {
    const pollMs = process.env.MNR_CA_DISTRUST_POLL_MS
      ? Number(process.env.MNR_CA_DISTRUST_POLL_MS) : DEFAULT_POLL_MS;
    start(process.env.MNR_CA_DISTRUST_FILE, { pollMs });
  } catch (error) {
    console.error(`minimal-node-runtime CA policy: ${error.message}`);
    // Do not launch the application with an unrestricted fallback trust list.
    process.exit(1);
  }
}

module.exports = { DEFAULT_POLL_MS, fingerprint, parsePolicy, createController, start };
