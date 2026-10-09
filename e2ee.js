'use strict';

const fs = require('node:fs');
const path = require('node:path');
const libsignal = require('libsignal');

const DEFAULT_KEY_PATH = './sagor-e2ee-keys.json';

const MSG_TYPE_PREKEY = 3;
const MSG_TYPE_NORMAL = 1;

function b64encode(data) {
  return Buffer.from(data).toString('base64');
}

function b64decode(str) {
  return Buffer.from(String(str || ''), 'base64');
}

function toProtocolAddress(address) {
  const name = String(address && address.name != null ? address.name : '');
  if (!name) throw new Error('[sagor-e2ee] address.name is required');
  const deviceId = Number(address.deviceId);
  if (!Number.isInteger(deviceId) || deviceId < 1) {
    throw new Error('[sagor-e2ee] address.deviceId must be a positive integer');
  }
  return new libsignal.ProtocolAddress(name, deviceId);
}

function sessionKey(address) {
  return toProtocolAddress(address).toString();
}

class E2EEStore {
    constructor(keyPath) {
    this.keyPath = keyPath == null ? null : String(keyPath);
    this.identityKeyPair = null;
    this.registrationId = null;
    this.preKeys = new Map();
    this.signedPreKeys = new Map();
    this.sessions = new Map();
    this.trustedIdentities = new Map();
    this.nextPreKeyId = 1;
    this.nextSignedPreKeyId = 1;
    this._loaded = false;
  }

    async init() {
    if (this._loaded) return this;
    this._loadFromDisk();
    if (!this.identityKeyPair) {
      const kp = await libsignal.keyhelper.generateIdentityKeyPair();
      this.identityKeyPair = { pubKey: Buffer.from(kp.pubKey), privKey: Buffer.from(kp.privKey) };
    }
    if (!this.registrationId) {
      this.registrationId = await libsignal.keyhelper.generateRegistrationId();
    }
    if (this.signedPreKeys.size === 0) {
      await this._mintSignedPreKey();
    }
    this._saveToDisk();
    this._loaded = true;
    return this;
  }

  _loadFromDisk() {
    if (!this.keyPath) return;
    let raw;
    try {
      raw = fs.readFileSync(this.keyPath, 'utf8');
    } catch {
      return;
    }
    let data;
    try {
      data = JSON.parse(raw);
    } catch {
      return;
    }
    try {
      if (data.identityKeyPair) {
        this.identityKeyPair = {
          pubKey: b64decode(data.identityKeyPair.pubKey),
          privKey: b64decode(data.identityKeyPair.privKey),
        };
      }
      if (typeof data.registrationId === 'number') this.registrationId = data.registrationId;
      for (const [id, kp] of Object.entries(data.preKeys || {})) {
        this.preKeys.set(Number(id), { pubKey: b64decode(kp.pubKey), privKey: b64decode(kp.privKey) });
      }
      for (const [id, kp] of Object.entries(data.signedPreKeys || {})) {
        this.signedPreKeys.set(Number(id), {
          pubKey: b64decode(kp.pubKey),
          privKey: b64decode(kp.privKey),
        });
      }
      for (const [id, rec] of Object.entries(data.sessions || {})) {
        this.sessions.set(id, rec);
      }
      for (const [id, key] of Object.entries(data.trustedIdentities || {})) {
        this.trustedIdentities.set(id, String(key));
      }
      if (Number.isInteger(data.nextPreKeyId)) this.nextPreKeyId = data.nextPreKeyId;
      if (Number.isInteger(data.nextSignedPreKeyId)) {
        this.nextSignedPreKeyId = data.nextSignedPreKeyId;
      }
    } catch {

    }
  }

  _saveToDisk() {
    if (!this.keyPath) return;
    const data = {
      format: 'sagor-e2ee-keys/v1',
      identityKeyPair: this.identityKeyPair
        ? {
            pubKey: b64encode(this.identityKeyPair.pubKey),
            privKey: b64encode(this.identityKeyPair.privKey),
          }
        : null,
      registrationId: this.registrationId,
      preKeys: {},
      signedPreKeys: {},
      sessions: {},
      trustedIdentities: {},
      nextPreKeyId: this.nextPreKeyId,
      nextSignedPreKeyId: this.nextSignedPreKeyId,
    };
    for (const [id, kp] of this.preKeys) {
      data.preKeys[id] = { pubKey: b64encode(kp.pubKey), privKey: b64encode(kp.privKey) };
    }
    for (const [id, kp] of this.signedPreKeys) {
      data.signedPreKeys[id] = { pubKey: b64encode(kp.pubKey), privKey: b64encode(kp.privKey) };
    }
    for (const [id, rec] of this.sessions) data.sessions[id] = rec;
    for (const [id, key] of this.trustedIdentities) data.trustedIdentities[id] = key;
    try {
      const dir = path.dirname(path.resolve(this.keyPath));
      fs.mkdirSync(dir, { recursive: true });
      const tmp = this.keyPath + '.tmp';
      fs.writeFileSync(tmp, JSON.stringify(data), { mode: 0o600 });
      fs.renameSync(tmp, this.keyPath);
    } catch {

    }
  }

  async _mintSignedPreKey() {
    const spk = await libsignal.keyhelper.generateSignedPreKey(
      { pubKey: this.identityKeyPair.pubKey, privKey: this.identityKeyPair.privKey },
      this.nextSignedPreKeyId++
    );
    this.signedPreKeys.set(spk.keyId, {
      pubKey: Buffer.from(spk.keyPair.pubKey),
      privKey: Buffer.from(spk.keyPair.privKey),
    });
    return spk.keyId;
  }

  async _mintPreKey() {
    const pk = await libsignal.keyhelper.generatePreKey(this.nextPreKeyId++);
    this.preKeys.set(pk.keyId, {
      pubKey: Buffer.from(pk.keyPair.pubKey),
      privKey: Buffer.from(pk.keyPair.privKey),
    });
    return pk.keyId;
  }

  async getOurIdentity() {
    return { pubKey: this.identityKeyPair.pubKey, privKey: this.identityKeyPair.privKey };
  }

  async getOurRegistrationId() {
    return this.registrationId;
  }

    async isTrustedIdentity(identifier, identityKey) {
    const seen = this.trustedIdentities.get(identifier);
    const current = b64encode(identityKey);
    if (!seen) {
      this.trustedIdentities.set(identifier, current);
      this._saveToDisk();
      return true;
    }
    return seen === current;
  }

  async loadSession(identifier) {
    const rec = this.sessions.get(identifier);
    if (!rec) return undefined;
    return libsignal.SessionRecord.deserialize(rec);
  }

  async storeSession(identifier, record) {
    this.sessions.set(identifier, record.serialize());
    this._saveToDisk();
  }

  async loadPreKey(keyId) {
    const kp = this.preKeys.get(Number(keyId));
    if (!kp) throw new Error('[sagor-e2ee] unknown one-time pre-key');
    return { pubKey: kp.pubKey, privKey: kp.privKey };
  }

  async removePreKey(keyId) {
    this.preKeys.delete(Number(keyId));
    this._saveToDisk();
  }

  async loadSignedPreKey(keyId) {
    const kp = this.signedPreKeys.get(Number(keyId));
    if (!kp) throw new Error('[sagor-e2ee] unknown signed pre-key');
    return { pubKey: kp.pubKey, privKey: kp.privKey };
  }
}

async function createE2EE(opts = {}) {
  const keyPath = opts.keyPath === undefined ? DEFAULT_KEY_PATH : opts.keyPath;
  const store = new E2EEStore(keyPath);
  await store.init();

  return {
        store,

        getIdentityKeyPublic() {
      return Buffer.from(store.identityKeyPair.pubKey);
    },

    getRegistrationId() {
      return store.registrationId;
    },

        async generatePreKeyBundle() {
      const preKeyId = await store._mintPreKey();
      const spkId = [...store.signedPreKeys.keys()][0];
      const pk = store.preKeys.get(preKeyId);
      const spk = store.signedPreKeys.get(spkId);

      const fresh = await libsignal.keyhelper.generateSignedPreKey(
        { pubKey: store.identityKeyPair.pubKey, privKey: store.identityKeyPair.privKey },
        spkId
      );
      store.signedPreKeys.set(spkId, {
        pubKey: Buffer.from(fresh.keyPair.pubKey),
        privKey: Buffer.from(fresh.keyPair.privKey),
      });
      store._saveToDisk();
      return {
        identityKey: Buffer.from(store.identityKeyPair.pubKey),
        registrationId: store.registrationId,
        preKey: { keyId: preKeyId, publicKey: Buffer.from(pk.pubKey) },
        signedPreKey: {
          keyId: spkId,
          publicKey: Buffer.from(fresh.keyPair.pubKey),
          signature: Buffer.from(fresh.signature),
        },
      };
    },

        async establishSession(address, bundle) {
      const pa = toProtocolAddress(address);
      const builder = new libsignal.SessionBuilder(store, pa);
      await builder.initOutgoing({
        identityKey: b64decode(b64encode(bundle.identityKey)),
        registrationId: bundle.registrationId,
        preKey: bundle.preKey
          ? { keyId: bundle.preKey.keyId, publicKey: b64decode(b64encode(bundle.preKey.publicKey)) }
          : undefined,
        signedPreKey: {
          keyId: bundle.signedPreKey.keyId,
          publicKey: b64decode(b64encode(bundle.signedPreKey.publicKey)),
          signature: b64decode(b64encode(bundle.signedPreKey.signature)),
        },
      });
      return true;
    },

        async hasSession(address) {
      const rec = await store.loadSession(sessionKey(address));
      return !!rec && rec.haveOpenSession();
    },

        async encryptFor(address, plaintext) {
      const pa = toProtocolAddress(address);
      if (!(await this.hasSession(address))) {
        throw new Error(
          `[sagor-e2ee] no session for ${pa.toString()} — call establishSession() with their pre-key bundle first`
        );
      }
      const cipher = new libsignal.SessionCipher(store, pa);
      const out = await cipher.encrypt(Buffer.from(plaintext));
      return { type: out.type, body: Buffer.from(out.body) };
    },

        async decryptFrom(address, msg) {
      const pa = toProtocolAddress(address);
      const body = Buffer.isBuffer(msg.body) ? msg.body : b64decode(msg.body);
      const cipher = new libsignal.SessionCipher(store, pa);
      const pt =
        Number(msg.type) === MSG_TYPE_PREKEY
          ? await cipher.decryptPreKeyWhisperMessage(body, 'binary')
          : await cipher.decryptWhisperMessage(body, 'binary');
      return Buffer.from(pt);
    },
  };
}

function detectE2EEThread(threadInfo) {
  const t = threadInfo || {};
  if (t.encrypted === true || t.isEncrypted === true) return true;
  const tt = String(t.threadType || t.type || '').toLowerCase();
  if (tt === 'e2ee' || tt === 'secret' || tt === 'encrypted' || tt === 'secret_conversation') {
    return true;
  }
  const key = t.threadKey || {};
  if (key.encrypted === true || key.isEncrypted === true) return true;
  return false;
}

function isE2EEDelta(delta) {
  if (!delta || typeof delta !== 'object') return false;
  if (delta.e2ee && (delta.e2ee.body || delta.e2ee.ciphertext)) return true;
  const md = delta.messageMetadata || {};
  if (md.encrypted === true || md.isEncrypted === true) return true;
  if (delta.encryptedPayload || delta.armadilloPayload) return true;
  return false;
}

module.exports = {
  createE2EE,
  E2EEStore,
  detectE2EEThread,
  isE2EEDelta,
  toProtocolAddress,
  DEFAULT_KEY_PATH,
  MSG_TYPE_PREKEY,
  MSG_TYPE_NORMAL,
};
