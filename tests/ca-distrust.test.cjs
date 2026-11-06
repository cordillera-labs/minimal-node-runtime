'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const tls = require('node:tls');
const { DEFAULT_POLL_MS, fingerprint, parsePolicy, createController, start } = require('../runtime/ca-distrust.cjs');

const roots = tls.rootCertificates.slice(0, 3);
const fp = roots.map(fingerprint);
const empty = (generation = 1) => ({ generation, exclude_cert_sha256: [], exclude_spki_sha256: [] });

function fixture(policy = empty()) {
  let input = Buffer.from(JSON.stringify(policy));
  let current = roots;
  const controller = createController({
    getDefaults: () => roots,
    setDefaults: certs => { current = certs; },
    readPolicy: () => input,
  });
  return { controller, get: () => current, set: p => { input = Buffer.from(JSON.stringify(p)); },
    raw: str => { input = Buffer.from(str); } };
}


test('the default live policy polling interval is one minute', () => {
  assert.equal(DEFAULT_POLL_MS, 60000);
});

test('empty policy preserves the initial trust set', () => {
  const f = fixture();
  assert.equal(f.controller.reload(), true);
  assert.deepEqual(f.get(), roots);
  assert.equal(f.controller.reload(), false);
});

test('DER fingerprint removes only the specified root', () => {
  const policy = { ...empty(), exclude_cert_sha256: [fp[0].cert] };
  const f = fixture(policy);
  f.controller.reload();
  assert.deepEqual(f.get(), roots.slice(1));
});

test('SPKI fingerprint removes all certificates sharing a key', () => {
  const f = fixture({ ...empty(), exclude_spki_sha256: [fp[1].spki] });
  f.controller.reload();
  assert.deepEqual(f.get(), [roots[0], roots[2]]);
});

test('a live update can add exclusions but cannot restore roots', () => {
  const f = fixture({ ...empty(), exclude_cert_sha256: [fp[0].cert] });
  f.controller.reload();
  f.set({ ...empty(2), exclude_cert_sha256: [fp[1].cert] });
  assert.equal(f.controller.reload(), true);
  assert.deepEqual(f.get(), [roots[2]]);
  f.set(empty(3));
  f.controller.reload();
  assert.deepEqual(f.get(), [roots[2]]);
});

test('stale generations or in-place mutations are rejected without altering trust', () => {
  const f = fixture({ ...empty(5), exclude_cert_sha256: [fp[0].cert] });
  f.controller.reload();
  f.set({ ...empty(4), exclude_cert_sha256: [fp[1].cert] });
  assert.throws(() => f.controller.reload(), /rollback/);
  f.set({ ...empty(5), exclude_cert_sha256: [fp[1].cert] });
  assert.throws(() => f.controller.reload(), /generation increment/);
  assert.deepEqual(f.get(), roots.slice(1));
});

test('invalid policy cannot modify previously installed trust', () => {
  const f = fixture({ ...empty(), exclude_cert_sha256: [fp[0].cert] });
  f.controller.reload();
  for (const input of ['not-json', '{"generation":2}',
    JSON.stringify({ ...empty(2), exclude_cert_sha256: ['garbage'] }),
    JSON.stringify({ ...empty(2), extra: ['root'] })]) {
    f.raw(input);
    assert.throws(() => f.controller.reload());
    assert.deepEqual(f.get(), roots.slice(1));
  }
});

test('oversized policy, invalid hash cases and duplicates fail closed', () => {
  assert.throws(() => parsePolicy(' '.repeat(65537)), /64 KiB/);
  assert.throws(() => parsePolicy(JSON.stringify({ ...empty(), exclude_spki_sha256: [fp[0].spki.toUpperCase()] })), /lowercase/);
  assert.throws(() => parsePolicy(JSON.stringify({ ...empty(), exclude_cert_sha256: [fp[0].cert, fp[0].cert] })), /duplicate/);
});

test('unsupported Node versions refuse to silently fall back', () => {
  assert.throws(() => createController({ getDefaults: () => roots, setDefaults: null,
    readPolicy: () => Buffer.from(JSON.stringify(empty())) }), /does not support/);
});

test('poll-based update picks up atomically replaced policy without growing trust', async () => {
  let content = Buffer.from(JSON.stringify(empty()));
  let result = null;
  const io = { readFileSync: () => content };
  const mockTls = { getCACertificates: () => roots, setDefaultCACertificates: certs => { result = certs; } };
  const watcher = start('/test/policy.json', { fsApi: io, tlsApi: mockTls, pollMs: 100, log: () => {} });
  try {
    assert.deepEqual(result, roots);
    content = Buffer.from(JSON.stringify({ ...empty(2), exclude_cert_sha256: [fp[0].cert] }));
    await new Promise(resolve => setTimeout(resolve, 180));
    assert.deepEqual(result, roots.slice(1));
  } finally { watcher.close(); }
});
