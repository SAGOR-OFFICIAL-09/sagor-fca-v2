'use strict';

const assert = require('node:assert/strict');
const { enableE2EE, parseEnvelope, buildEnvelope } = require('../e2ee-bridge');
const { createE2EE } = require('../e2ee');

let passed = 0;
async function check(name, fn) {
  await fn();
  passed++;
  console.log('  ok -', name);
}

function mockApi() {
  const sent = [];
  let cb = null;
  const api = {
    sent,
    listen(fn) { cb = fn; return () => { cb = null; }; },
    sendMessage(message, threadID, callback) {
      sent.push({ message, threadID });
      if (typeof callback === 'function') callback(null, { messageID: 'mid.mock' });
      return 'mock-sent';
    },
    _emit(event) { cb(null, event); },
  };
  return api;
}

function tick(ms = 60) {
  return new Promise((r) => setTimeout(r, ms));
}

(async () => {
  console.log('[sagor-fca] e2ee-bridge test (offline)');

  const api = mockApi();
  await enableE2EE(api, { keyPath: null });

  await check('api gains e2ee namespace and helpers', () => {
    assert.ok(api.e2ee);
    assert.equal(typeof api.isE2EEThread, 'function');
    assert.equal(typeof api.markE2EEThread, 'function');
    assert.equal(typeof api.sendE2EMessage, 'function');
    assert.equal(typeof api.getE2EIdentityKey, 'function');
    assert.match(api.getE2EIdentityKey(), /^[A-Za-z0-9+/=]+$/);
  });

  await check('envelope build/parse round-trip', () => {
    const env = buildEnvelope(3, 'aGVsbG8=');
    assert.ok(env.startsWith('e2ee:'));
    const p = parseEnvelope(env);
    assert.equal(p.type, 3);
    assert.equal(p.body, 'aGVsbG8=');
    assert.equal(parseEnvelope('plain text'), null);
    assert.equal(parseEnvelope('e2ee:bad'), null);
  });

  await check('plain events pass through untouched', async () => {
    const seen = [];
    api.listen((err, ev) => seen.push(ev));
    api._emit({ body: 'hello world', senderID: 'u1', threadID: 't1' });
    await tick();
    assert.equal(seen.length, 1);
    assert.equal(seen[0].body, 'hello world');
    assert.equal(seen[0].isE2EE, undefined);
  });

  const peer = await createE2EE({ keyPath: null });

  await check('E2EE envelope event decrypts to plaintext', async () => {
    const bridgeBundle = await api.e2ee.generatePreKeyBundle();
    await peer.establishSession({ name: 'bridge', deviceId: 1 }, bridgeBundle);
    const ct = await peer.encryptFor({ name: 'bridge', deviceId: 1 }, Buffer.from('secret hello'));
    const seen = [];
    api.listen((err, ev) => seen.push(ev));
    api._emit({
      body: buildEnvelope(ct.type, Buffer.from(ct.body).toString('base64')),
      senderID: 'peer1',
      threadID: 't1',
    });
    await tick();
    assert.equal(seen.length, 1);
    assert.equal(seen[0].body, 'secret hello');
    assert.equal(seen[0].isE2EE, true);
  });

  await check('undecryptable E2EE event yields decryptionError, no crash', async () => {
    const seen = [];
    api.listen((err, ev) => seen.push(ev));
    api._emit({
      body: buildEnvelope(1, Buffer.from('garbage-bytes-xxxxxxxx').toString('base64')),
      senderID: 'stranger',
      threadID: 't9',
    });
    await tick();
    assert.equal(seen.length, 1);
    assert.equal(seen[0].isE2EE, true);
    assert.ok(seen[0].decryptionError);
  });

  await check('marked E2EE thread encrypts outgoing messages', async () => {
    const peerBundle = await peer.generatePreKeyBundle();
    await api.e2ee.establishSession({ name: 't2', deviceId: 1 }, peerBundle);
    api.markE2EEThread('t2');
    assert.equal(api.isE2EEThread('t2'), true);
    api.sendMessage('hello peer', 't2');
    await tick();
    assert.equal(api.sent.length, 1);
    const env = parseEnvelope(api.sent[0].message);
    assert.ok(env, 'outgoing must be an e2ee envelope');
    const pt = await peer.decryptFrom({ name: 'bridge', deviceId: 1 }, { type: env.type, body: env.body });
    assert.equal(Buffer.from(pt).toString('utf8'), 'hello peer');
  });

  await check('non-E2EE thread sends pass through unchanged', () => {
    const before = api.sent.length;
    const ret = api.sendMessage('plain hi', 't3');
    assert.equal(ret, 'mock-sent');
    assert.equal(api.sent.length, before + 1);
    assert.equal(api.sent[before].message, 'plain hi');
    assert.equal(parseEnvelope(api.sent[before].message), null);
  });

  await check('unmarking a thread disables encryption', () => {
    api.markE2EEThread('t2', false);
    assert.equal(api.isE2EEThread('t2'), false);
  });

  console.log(`\n[sagor-fca] e2ee-bridge: ${passed} checks passed ✔`);
})().catch((e) => {
  console.error('[sagor-fca] e2ee-bridge FAILED:', e);
  process.exit(1);
});
