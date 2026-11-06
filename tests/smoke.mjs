// Runs inside the image as its default user: /nodejs/bin/node /smoke/smoke.mjs
// Each check prints one line. Any failure exits non-zero.
import assert from 'node:assert/strict';
import dns from 'node:dns/promises';
import fs from 'node:fs';
import https from 'node:https';
import os from 'node:os';
import tls from 'node:tls';

const BUNDLE = '/etc/ssl/certs/ca-certificates.crt';
const checks = [];
const check = (name, run) => checks.push({ name, run });

check('node version matches the lock', () => {
    assert.equal(process.versions.node, process.env.EXPECTED_NODE_VERSION);
});
check('runs as nonroot 65532:65532', () => {
    assert.equal(process.getuid(), 65532);
    assert.equal(process.getgid(), 65532);
    const user = os.userInfo();
    assert.equal(user.username, 'nonroot');
    assert.equal(user.homedir, '/home/nonroot');
});
check('/tmp is writable', () => {
    const path = fs.mkdtempSync('/tmp/smoke-');
    fs.writeFileSync(`${path}/file`, 'ok');
    assert.equal(fs.readFileSync(`${path}/file`, 'utf8'), 'ok');
    fs.rmSync(path, { recursive: true });
});
check('the root filesystem outside /tmp and the home directory is not writable', () => {
    assert.throws(() => fs.writeFileSync('/etc/smoke', 'x'), { code: 'EACCES' });
});
check('time zones resolve from the ICU data in node (no tzdata files)', () => {
    assert.equal(fs.existsSync('/usr/share/zoneinfo'), false);
    const summer = new Date('2026-07-01T12:00:00Z');
    const formatted = new Intl.DateTimeFormat('en-CA', {
        timeZone: 'America/Vancouver', hour: 'numeric', hour12: false, timeZoneName: 'short',
    }).format(summer);
    assert.match(formatted, /^0?5\b.*PDT$/);
});
check('the TZ environment variable sets the local zone', () => {
    assert.equal(process.env.TZ, 'America/Vancouver');
    assert.equal(new Date('2026-07-01T12:00:00Z').getTimezoneOffset(), 420);
    assert.equal(new Date('2026-01-01T12:00:00Z').getTimezoneOffset(), 480);
});
check('ICU is the full build (locale data beyond English)', () => {
    // A small-icu build answers in English: "Germany".
    assert.equal(new Intl.DisplayNames(['de'], { type: 'region' }).of('DE'), 'Deutschland');
});
check('/etc/hosts lookup through glibc', async () => {
    const { address } = await dns.lookup('localhost', { family: 4 });
    assert.equal(address, '127.0.0.1');
});
check('DNS lookup through glibc', async () => {
    const { address } = await dns.lookup('nodejs.org');
    assert.ok(address.length > 0);
});
check('the CA bundle parses and is the system store', () => {
    const pem = fs.readFileSync(BUNDLE, 'utf8');
    const count = pem.match(/BEGIN CERTIFICATE/g).length;
    assert.ok(count > 100, `only ${count} certificates`);
    // OpenSSL can read the same file through two default paths, so compare
    // the distinct certificates rather than the count.
    const normalise = (cert) => cert.replace(/\s+/g, '');
    const fromBundle = new Set(pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g).map(normalise));
    const system = new Set(tls.getCACertificates('system').map(normalise));
    assert.equal(fromBundle.size, count, 'the bundle holds duplicate certificates');
    assert.deepEqual([...system].sort(), [...fromBundle].sort(), 'the system store differs from the bundle');
});
check('HTTPS with only the CA bundle as trust store', async () => {
    const ca = fs.readFileSync(BUNDLE);
    const status = await new Promise((resolve, reject) => {
        https.get('https://nodejs.org/dist/index.json', { ca, method: 'HEAD' }, (res) => {
            res.resume();
            resolve(res.statusCode);
        }).on('error', reject);
    });
    assert.equal(status, 200);
});
check('fetch with the default trust store', async () => {
    const response = await fetch('https://nodejs.org/dist/index.json', { method: 'HEAD' });
    assert.equal(response.status, 200);
});

let failed = 0;
for (const { name, run } of checks) {
    try {
        await run();
        console.log(`ok   ${name}`);
    } catch (error) {
        failed += 1;
        console.log(`FAIL ${name}: ${error.message}`);
    }
}
process.exit(failed === 0 ? 0 : 1);
