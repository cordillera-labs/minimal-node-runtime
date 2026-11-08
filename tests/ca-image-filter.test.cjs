'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createHash, X509Certificate } = require('node:crypto');
const tls = require('node:tls');
const { parse, apply } = require('../runtime/ca-image-filter.cjs');
const roots = tls.rootCertificates.slice(0, 3);
const digest = pem => createHash('sha256').update(new X509Certificate(pem).raw).digest('hex');
const hash = digest(roots[0]);

test('empty baked policy preserves defaults without calling setter', () => {
  const fake = { getCACertificates: () => roots,
    setDefaultCACertificates: () => { throw Error('unexpected'); } };
  assert.equal(apply('# empty\n', fake), 0);
});
test('baked fingerprint filters Node bundled defaults', () => {
  let installed;
  const fake = { getCACertificates: () => roots,
    setDefaultCACertificates: value => { installed = value; } };
  assert.equal(apply(hash + '\n', fake), 1);
  assert.deepEqual(installed, roots.slice(1));
});
test('other roots are never added', () => {
  let installed;
  const fake = { getCACertificates: () => roots,
    setDefaultCACertificates: value => { installed = value; } };
  assert.equal(apply('a'.repeat(64) + '\n', fake), 0);
  assert.deepEqual(installed, roots);
});
test('invalid or duplicate hashes fail startup rather than bypass filter', () => {
  for (const raw of ['BAD', hash + '\n' + hash, hash.toUpperCase()]) {
    assert.throws(() => parse(raw));
  }
});
