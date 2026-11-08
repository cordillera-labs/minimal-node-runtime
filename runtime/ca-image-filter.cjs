'use strict';
// Pure filter shared by the image's preload and isolated offline tests.
const { createHash, X509Certificate } = require('node:crypto');
const tls = require('node:tls');

function parse(text) {
  const denied = new Set();
  for (const raw of text.split(/\r?\n/)) {
    const hash = raw.trim();
    if (!hash || hash.startsWith('#')) continue;
    if (!/^[0-9a-f]{64}$/.test(hash) || denied.has(hash)) {
      throw new Error('invalid or duplicate baked CA exclusion fingerprint');
    }
    denied.add(hash);
  }
  return denied;
}

function apply(text, api = tls) {
  const denied = parse(text);
  if (!denied.size) return 0;
  if (typeof api.getCACertificates !== 'function' ||
      typeof api.setDefaultCACertificates !== 'function') {
    throw new Error('Node cannot apply baked CA distrust');
  }
  const roots = api.getCACertificates('default');
  const allowed = roots.filter(pem => {
    const der = new X509Certificate(pem).raw;
    return !denied.has(createHash('sha256').update(der).digest('hex'));
  });
  api.setDefaultCACertificates(allowed);
  return roots.length - allowed.length;
}

module.exports = { parse, apply };
