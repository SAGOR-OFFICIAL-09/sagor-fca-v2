'use strict';

// Offline test for the bridge wrapper logic using a fake e2ee engine (no libsignal needed at runtime).
const assert = require('node:assert/strict');
const { enableE2EE, parseEnvelope, buildEnvelope } = require('../e2ee-bridge');

function fakeE2EE() {
  return {
    getIdentityKeyPublic: () => Buffer.from('id-key'),
    async encryptFor(addr, text) { return { type: 1, body: Buffer.from('enc:' + addr.name + ':' + text) }; },
    async decryptFrom(addr, msg) {
      if (addr.name !== 'peer') throw new Error('no session for ' + addr.name);
      return Buffer.from('dec:' + Buffer.from(msg.body, 'base64').toString());
    },
  };
}

function mockApi() {
  const calls = [];
  let cb = null;
  return {
    calls,
    listen(fn) { cb = fn; return () => {}; },
    listenMqtt(fn) { cb = fn; return () => {}; },
    sendMessage(...args) { calls.push(args); return 'sent'; },
    _emit(ev) { cb(null, ev); },
  };
}

const tick = (ms = 20) => new Promise((r) => setTimeout(r, ms));
let n = 0;
async function check(name, fn) { await fn(); n++; console.log('  ok -', name); }

(async () => {
  console.log('[sagor-fca] e2ee-bridge mock test (offline)');
  const api = mockApi();
  await enableE2EE(api, { e2ee: fakeE2EE() });

  await check('enableE2EE is idempotent (no double wrapping)', async () => {
    const wrapped = api.sendMessage;
    await enableE2EE(api, { e2ee: fakeE2EE() });
    assert.equal(api.sendMessage, wrapped);
  });

  await check('parseEnvelope rejects non-numeric / empty type', () => {
    assert.equal(parseEnvelope('e2ee::abc'), null);
    assert.equal(parseEnvelope('e2ee:x:abc'), null);
    assert.deepEqual(parseEnvelope(buildEnvelope(3, 'QQ==')), { type: 3, body: 'QQ==' });
  });

  await check('non-E2EE sendMessage forwards every extra argument', () => {
    const cb = () => {};
    api.sendMessage('hi', 't1', cb, 'mid.reply', true);
    assert.deepEqual(api.calls[0], ['hi', 't1', cb, 'mid.reply', true]);
  });

  await check('E2EE thread: text is encrypted and extra args kept', async () => {
    api.markE2EEThread('t2');
    api.calls.length = 0;
    const cb = () => {};
    api.sendMessage('secret', 't2', cb, 'mid.reply');
    await tick();
    assert.equal(api.calls.length, 1);
    assert.ok(parseEnvelope(api.calls[0][0]));
    assert.equal(api.calls[0][2], cb);
    assert.equal(api.calls[0][3], 'mid.reply');
  });

  await check('E2EE thread: attachments are refused, never sent in plaintext', async () => {
    api.calls.length = 0;
    await assert.rejects(api.sendMessage({ body: 'x', attachment: {} }, 't2'), /cannot be sent on an E2EE thread/);
    let cbErr = null;
    api.sendMessage({ body: 'x', sticker: '1' }, 't2', (e) => { cbErr = e; });
    assert.ok(cbErr instanceof Error);
    assert.equal(api.calls.length, 0);
  });

  await check('decrypt falls back from senderID to threadID', async () => {
    const seen = [];
    api.listen((e, ev) => seen.push(ev));
    api._emit({ body: buildEnvelope(1, Buffer.from('hello').toString('base64')), senderID: 'self', threadID: 'peer' });
    await tick();
    assert.equal(seen[0].body, 'dec:hello');
    assert.equal(seen[0].isE2EE, true);
  });

  await check('encrypted event without ciphertext reports decryptionError', async () => {
    const seen = [];
    api.listen((e, ev) => seen.push(ev));
    api._emit({ messageMetadata: { encrypted: true }, senderID: 'peer', threadID: 'peer' });
    await tick();
    assert.equal(seen[0].isE2EE, true);
    assert.match(seen[0].decryptionError, /no ciphertext/);
  });

  await check('listenMqtt is wrapped too and decrypts', async () => {
    const seen = [];
    api.listenMqtt((e, ev) => seen.push(ev));
    api._emit({ body: buildEnvelope(1, Buffer.from('via mqtt').toString('base64')), senderID: 'peer', threadID: 'peer' });
    await tick();
    assert.equal(seen[0].body, 'dec:via mqtt');
    assert.equal(seen[0].decrypted, true);
  });

  await check('E2EE thread: emoji / mentions / body-less messages are refused, never plaintext', async () => {
    api.calls.length = 0;
    await assert.rejects(api.sendMessage({ emoji: 'x' }, 't2'), /cannot be sent on an E2EE thread/);
    await assert.rejects(api.sendMessage({ body: 'hi', mentions: [{}] }, 't2'), /cannot be sent on an E2EE thread/);
    await assert.rejects(api.sendMessage({}, 't2'), /cannot be sent on an E2EE thread/);
    assert.equal(api.calls.length, 0);
  });

  await check('failed decrypt sets decrypted=false', async () => {
    const seen = [];
    api.listen((e, ev) => seen.push(ev));
    api._emit({ body: buildEnvelope(1, 'QQ=='), senderID: 'nobody', threadID: 'nobody' });
    await tick();
    assert.equal(seen[0].decrypted, false);
    assert.ok(seen[0].decryptionError);
  });

  console.log(`\n[sagor-fca] e2ee-bridge mock: ${n} checks passed ✔`);
})().catch((e) => { console.error('FAILED:', e); process.exit(1); });
