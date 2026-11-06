// Runs inside the image as its default user: /nodejs/bin/node /smoke/smoke.mjs
// Each check prints one line. Any failure exits non-zero.
import { spawnSync } from 'node:child_process';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import fs from 'node:fs';
import https from 'node:https';
import os from 'node:os';
import tls from 'node:tls';

const BUNDLE = '/etc/ssl/certs/ca-certificates.crt';
const LIBRARY_DIRECTORY = '/usr/lib/x86_64-linux-gnu';
// The libc6 libraries that node does not link. Native addons need them: the
// libvips inside sharp needs libresolv.so.2.
const LIBC_LIBRARIES_NODE_DOES_NOT_LINK = [
    'libanl.so.1', 'libBrokenLocale.so.1', 'libc_malloc_debug.so.0', 'libmemusage.so', 'libmvec.so.1',
    'libnsl.so.1', 'libnss_compat.so.2', 'libnss_dns.so.2', 'libnss_files.so.2', 'libnss_hesiod.so.2',
    'libpcprofile.so', 'libresolv.so.2', 'librt.so.1', 'libthread_db.so.1', 'libutil.so.1',
];
// Three libraries are checked for presence and content only. libmemusage.so and
// libpcprofile.so are LD_PRELOAD profilers that print a report when loaded, and
// libthread_db.so.1 takes its ps_* symbols from a debugger, so it cannot load
// into a process that is not one.
const NOT_LOADED_IN_PROCESS = new Set(['libmemusage.so', 'libpcprofile.so', 'libthread_db.so.1']);
// dlopen succeeds for any shared library. node then reports that the library
// registers no addon. A library that cannot load fails with another message.
const loads_as_library = (path) => {
    try {
        process.dlopen({ exports: {} }, path);
    } catch (error) {
        return /did not self-register|napi_register_module|node_register_module/.test(error.message)
            ? null
            : error.message;
    }
    return null;
};
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
check('the libc6 libraries that node does not link are present and load', () => {
    for (const name of LIBC_LIBRARIES_NODE_DOES_NOT_LINK) {
        const path = `${LIBRARY_DIRECTORY}/${name}`;
        assert.ok(fs.existsSync(path), `${path} is missing`);
        if (NOT_LOADED_IN_PROCESS.has(name)) continue;
        assert.equal(loads_as_library(path), null, `${path} does not load`);
    }
});
check('every shared library in the dpkg file lists is present, intact and loads', () => {
    const status_directory = '/var/lib/dpkg/status.d';
    const library_pattern = /^usr\/lib(64)?(\/x86_64-linux-gnu)?\/[^/]+\.so(\.[0-9]+)*$/;
    let library_count = 0;
    for (const file_name of fs.readdirSync(status_directory).filter((name) => name.endsWith('.md5sums'))) {
        for (const line of fs.readFileSync(`${status_directory}/${file_name}`, 'utf8').split('\n').filter(Boolean)) {
            const [md5, relative_path] = [line.slice(0, 32), line.slice(34)];
            if (!library_pattern.test(relative_path)) continue;
            const path = `/${relative_path}`;
            const content = fs.readFileSync(path);
            assert.equal(crypto.createHash('md5').update(content).digest('hex'), md5, `${path} differs from the package`);
            if (!NOT_LOADED_IN_PROCESS.has(relative_path.split('/').pop())) {
                assert.equal(loads_as_library(path), null, `${path} does not load`);
            }
            library_count += 1;
        }
    }
    // libc6 ships 20 libraries, libstdc++6 and libgcc-s1 one file each (and a link).
    assert.ok(library_count >= 22, `only ${library_count} libraries are listed`);
});
check('the gconv plug-ins are not shipped', () => {
    assert.equal(fs.existsSync(`${LIBRARY_DIRECTORY}/gconv`), false);
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


check('opt-in CA distrust preload and live reload', () => {
    // The published Node 22/24 binaries support tls.setDefaultCACertificates().
    // Verify against the actual runtime, not just a mocked unit-test interface.
    const baseline = tls.getCACertificates('default');
    assert.ok(baseline.length > 2, 'expected bundled CA roots');
    const digest = (pem) => crypto.createHash('sha256').update(new crypto.X509Certificate(pem).raw).digest('hex');
    const first = digest(baseline[0]);
    const second = digest(baseline[1]);
    const folder = fs.mkdtempSync('/tmp/mnr-ca-');
    const policyFile = `${folder}/policy.json`;
    const policy = (generation, certs) => JSON.stringify({
        generation, exclude_cert_sha256: certs, exclude_spki_sha256: [],
    });
    try {
        fs.writeFileSync(policyFile, policy(1, [first]));
        const childCode = `
            const assert = require('node:assert/strict');
            const tls = require('node:tls');
            const fs = require('node:fs');
            const crypto = require('node:crypto');
            const digest = (pem) => crypto.createHash('sha256')
                .update(new crypto.X509Certificate(pem).raw).digest('hex');
            const accepted = () => new Set(tls.getCACertificates('default').map(digest));
            assert.ok(!accepted().has(process.env.MNR_FIRST), 'initial root was not excluded');
            assert.ok(accepted().has(process.env.MNR_SECOND), 'unlisted root was excluded');
            fs.writeFileSync(process.env.MNR_CA_DISTRUST_FILE, JSON.stringify({
                generation: 2, exclude_cert_sha256: [process.env.MNR_SECOND],
                exclude_spki_sha256: [],
            }));
            setTimeout(() => {
                assert.ok(!accepted().has(process.env.MNR_FIRST), 'reload restored old trust');
                assert.ok(!accepted().has(process.env.MNR_SECOND), 'reload did not remove new root');
            }, 350);
        `;
        const env = {
            ...process.env,
            NODE_OPTIONS: '--require=/nodejs/lib/ca-distrust.cjs',
            MNR_CA_DISTRUST_FILE: policyFile,
            MNR_CA_DISTRUST_POLL_MS: '100',
            MNR_FIRST: first,
            MNR_SECOND: second,
        };
        const child = spawnSync(process.execPath, ['-e', childCode], { env, encoding: 'utf8' });
        assert.equal(child.status, 0, child.stderr || child.stdout);

        // Missing/broken initial policy is not allowed to start an unrestricted app.
        fs.writeFileSync(policyFile, 'malformed JSON');
        const invalid = spawnSync(process.execPath, ['-e', 'process.exit(0)'], { env, encoding: 'utf8' });
        assert.notEqual(invalid.status, 0, 'invalid initial policy started an app');
        assert.match(invalid.stderr, /CA policy.*not valid JSON/);
    } finally {
        fs.rmSync(folder, { recursive: true, force: true });
    }
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
