'use strict';
// Offline test of e2ee.js against a FAKE, class-based libsignal (no network / node_modules needed).
// It exercises the real wiring in e2ee.js: `new (...)` calls, key store persistence, session
// establishment, encrypt/decrypt, legacy key files and the init race. It does NOT test real crypto.
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const Module = require('module');

const sha = (...b) => crypto.createHash('sha256').update(Buffer.concat(b.map((x) => Buffer.from(x)))).digest();
const calls = { identity: 0 };
let BODY_AS_STRING = false;
let WITH_CURVE = true;

function makeKP(priv) {
  priv = priv || crypto.randomBytes(32);
  return { privKey: priv, pubKey: Buffer.concat([Buffer.from([5]), sha(priv)]) };
}
class ProtocolAddress {
  constructor(id, deviceId) {
    if (typeof id !== 'string' || id.includes('.')) throw new TypeError('bad id');
    this.id = id; this.deviceId = deviceId;
  }
  toString() { return this.id + '.' + this.deviceId; }
}
class SessionRecord {
  constructor(d) { this.d = d || { open: false }; }
  static deserialize(o) { return new SessionRecord(JSON.parse(JSON.stringify(o))); }
  serialize() { return JSON.parse(JSON.stringify(this.d)); }
  haveOpenSession() { return !!this.d.open; }
}
class SessionBuilder {
  constructor(storage, addr) { this.s = storage; this.a = addr; }
  async initOutgoing(dev) {
    if (!(await this.s.isTrustedIdentity(this.a.id, dev.identityKey))) throw new Error('UntrustedIdentityKeyError');
    const expect = sha(dev.identityKey.subarray(1), dev.signedPreKey.publicKey);
    if (!expect.equals(Buffer.from(dev.signedPreKey.signature))) throw new Error('bad signature');
    await this.s.storeSession(this.a.toString(), new SessionRecord({ open: true, pending: true, preKeyId: dev.preKey ? dev.preKey.keyId : 0, peerIdentity: dev.identityKey.toString('base64') }));
  }
}
const MAGIC = Buffer.from([0xff, 0xfe, 0x80]);
class SessionCipher {
  constructor(storage, addr) { this.s = storage; this.a = addr; }
  async encrypt(buf) {
    assert(Buffer.isBuffer(buf), 'encrypt needs Buffer');
    const rec = await this.s.loadSession(this.a.toString());
    if (!rec) throw new Error('no session');
    const type = rec.d.pending ? 3 : 1;
    const body = Buffer.concat([MAGIC, Buffer.from([type, rec.d.preKeyId || 0]), buf]);
    return { type, body: BODY_AS_STRING ? body.toString('binary') : body, registrationId: 1 };
  }
  _open(data, enc) {
    data = Buffer.from(data, enc);
    assert(data.subarray(0, 3).equals(MAGIC), 'ciphertext corrupted (bad magic)');
    return { type: data[3], preKeyId: data[4], pt: data.subarray(5) };
  }
  async decryptPreKeyWhisperMessage(data, enc) {
    const m = this._open(data, enc);
    assert.equal(m.type, 3);
    await this.s.loadPreKey(m.preKeyId);
    await this.s.removePreKey(m.preKeyId);
    await this.s.storeSession(this.a.toString(), new SessionRecord({ open: true }));
    return m.pt;
  }
  async decryptWhisperMessage(data, enc) {
    const m = this._open(data, enc);
    const rec = await this.s.loadSession(this.a.toString());
    if (!rec) throw new Error('no session');
    return m.pt;
  }
}
function fakeLib() {
  const lib = {
    ProtocolAddress, SessionRecord, SessionBuilder, SessionCipher,
    keyhelper: {
      generateIdentityKeyPair() { calls.identity++; return makeKP(); },
      generateRegistrationId() { return 1234; },
      generateSignedPreKey(idKP, keyId) { const kp = makeKP(); return { keyId, keyPair: kp, signature: sha(idKP.pubKey.subarray(1), kp.pubKey) }; },
      generatePreKey(keyId) { return { keyId, keyPair: makeKP() }; },
    },
  };
  Object.defineProperty(lib, 'curve', {
    enumerable: true,
    get() {
      return WITH_CURVE ? { calculateSignature: (priv, msg) => sha(sha(priv), msg) } : undefined;
    },
  });
  return lib;
}
const origLoad = Module._load;
Module._load = function (req) { return req === 'libsignal' ? fakeLib() : origLoad.apply(this, arguments); };
const { createE2EE, E2EEStore, toProtocolAddress } = require('../e2ee');

let n = 0, failed = 0;
async function check(name, fn) {
  try { await fn(); n++; console.log('  ok - ' + name); }
  catch (e) { failed++; console.log('  FAIL - ' + name + '\n    ' + (e && e.stack ? e.stack.split('\n').slice(0, 3).join('\n    ') : e)); }
}
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sagor-e2ee-'));
const kp = (n) => path.join(tmp, n + '.json');
const A = { name: 'alice', deviceId: 1 };
const B = { name: 'bob', deviceId: 1 };

(async () => {
  console.log('[sagor-fca] e2ee.js core test (fake class-based libsignal)');

  await check('toProtocolAddress builds a real instance with `new` and validates input', async () => {
    const pa = toProtocolAddress(A);
    assert(pa instanceof ProtocolAddress); assert.equal(pa.toString(), 'alice.1');
    assert.throws(() => toProtocolAddress({ deviceId: 1 }), /name is required/);
    assert.throws(() => toProtocolAddress({ name: 'x' }), /deviceId/);
    assert.throws(() => toProtocolAddress({ name: 'x', deviceId: 0 }), /deviceId/);
  });

  await check('init creates identity and persists a 0600 key file', async () => {
    const e = await createE2EE({ keyPath: kp('a') });
    assert(e.getIdentityKeyPublic().length === 33); assert.equal(e.getRegistrationId(), 1234);
    const st = fs.statSync(kp('a'));
    if (process.platform !== 'win32') assert.equal(st.mode & 0o777, 0o600);
    assert.equal(JSON.parse(fs.readFileSync(kp('a'), 'utf8')).format, 'sagor-e2ee-keys/v1');
  });

  await check('concurrent init() runs once (no race)', async () => {
    const before = calls.identity;
    const s = new E2EEStore(null);
    await Promise.all([s.init(), s.init(), s.init()]);
    assert.equal(calls.identity - before, 1);
  });

  for (const asString of [false, true]) {
    await check('full roundtrip A<->B (ciphertext body as ' + (asString ? 'binary string' : 'Buffer') + ')', async () => {
      BODY_AS_STRING = asString;
      const a = await createE2EE({ keyPath: kp('ra' + asString) });
      const b = await createE2EE({ keyPath: kp('rb' + asString) });
      const bundle = await a.generatePreKeyBundle();
      await b.establishSession(A, bundle);
      assert.equal(await b.hasSession(A), true);
      const m1 = await b.encryptFor(A, 'hello \u09b9\u09cd\u09af\u09be\u09b2\u09cb \ud83d\ude00');
      assert.equal(m1.type, 3); assert(Buffer.isBuffer(m1.body));
      const pt1 = await a.decryptFrom(B, { type: m1.type, body: m1.body.toString('base64') });
      assert.equal(pt1.toString('utf8'), 'hello \u09b9\u09cd\u09af\u09be\u09b2\u09cb \ud83d\ude00');
      assert.equal(a.store.preKeys.has(bundle.preKey.keyId), false, 'one-time prekey must be consumed');
      const m2 = await a.encryptFor(B, 'reply');
      assert.equal(m2.type, 1);
      assert.equal((await b.decryptFrom(A, { type: m2.type, body: m2.body })).toString(), 'reply');
      BODY_AS_STRING = false;
    });
  }

  await check('bundles reuse the same signed pre-key; one-time pre-keys differ', async () => {
    const a = await createE2EE({ keyPath: kp('bun') });
    const b1 = await a.generatePreKeyBundle(); const b2 = await a.generatePreKeyBundle();
    assert.equal(b1.signedPreKey.keyId, b2.signedPreKey.keyId);
    assert(b1.signedPreKey.publicKey.equals(b2.signedPreKey.publicKey));
    assert.notEqual(b1.preKey.keyId, b2.preKey.keyId);
  });

  await check('sessions + identities survive a restart (JSON roundtrip)', async () => {
    const a = await createE2EE({ keyPath: kp('pa') });
    const b = await createE2EE({ keyPath: kp('pb') });
    await b.establishSession(A, await a.generatePreKeyBundle());
    const b2 = await createE2EE({ keyPath: kp('pb') });
    assert.equal(await b2.hasSession(A), true);
    assert(b2.getIdentityKeyPublic().equals(b.getIdentityKeyPublic()));
    const m = await b2.encryptFor(A, 'after restart');
    assert.equal((await a.decryptFrom(B, { type: m.type, body: m.body })).toString(), 'after restart');
  });

  await check('changed identity key for a known peer is rejected (TOFU)', async () => {
    const a1 = await createE2EE({ keyPath: kp('t1') });
    const a2 = await createE2EE({ keyPath: kp('t2') });
    const b = await createE2EE({ keyPath: kp('tb') });
    await b.establishSession(A, await a1.generatePreKeyBundle());
    await assert.rejects(b.establishSession(A, await a2.generatePreKeyBundle()), /Untrusted/);
  });

  await check('encryptFor without a session fails clearly (never plaintext)', async () => {
    const b = await createE2EE({ keyPath: kp('ns') });
    await assert.rejects(b.encryptFor(A, 'x'), /no session/);
  });

  await check('establishSession rejects an incomplete bundle', async () => {
    const b = await createE2EE({ keyPath: kp('ib') });
    await assert.rejects(b.establishSession(A, {}), /needs identityKey/);
  });

  for (const withCurve of [true, false]) {
    await check('legacy key file (unsigned signed-pre-key) is upgraded' + (withCurve ? ' by signing the SAME key' : ' via fallback'), async () => {
      WITH_CURVE = withCurve;
      const seed = await createE2EE({ keyPath: kp('lg' + withCurve) });
      const raw = JSON.parse(fs.readFileSync(kp('lg' + withCurve), 'utf8'));
      const id = Object.keys(raw.signedPreKeys)[0];
      const oldPub = raw.signedPreKeys[id].pubKey;
      delete raw.signedPreKeys[id].signature;
      fs.writeFileSync(kp('lg' + withCurve), JSON.stringify(raw));
      const e = await createE2EE({ keyPath: kp('lg' + withCurve) });
      const bundle = await e.generatePreKeyBundle();
      assert(bundle.signedPreKey.signature.length > 0);
      if (withCurve) assert.equal(bundle.signedPreKey.publicKey.toString('base64'), oldPub, 'must keep the existing key');
      const b = await createE2EE({ keyPath: kp('lgb' + withCurve) });
      await b.establishSession(A, bundle);  // signature must verify
      WITH_CURVE = true;
      void seed;
    });
  }

  await check('corrupt key file is backed up, not silently overwritten', async () => {
    fs.writeFileSync(kp('bad'), '{not json');
    const w = console.warn; console.warn = () => {};
    try { await createE2EE({ keyPath: kp('bad') }); } finally { console.warn = w; }
    assert(fs.readdirSync(tmp).some((f) => f.startsWith('bad.json.corrupt-')));
  });

  await check('keyPath:null works in memory only', async () => {
    const e = await createE2EE({ keyPath: null });
    assert(e.getIdentityKeyPublic().length === 33);
  });

  fs.rmSync(tmp, { recursive: true, force: true });
  console.log(failed ? `\n[sagor-fca] e2ee core: ${failed} FAILED, ${n} passed` : `\n[sagor-fca] e2ee core: ${n} checks passed \u2714`);
  process.exit(failed ? 1 : 0);
})();
