'use strict';

const { createE2EE, detectE2EEThread, isE2EEDelta } = require('./e2ee');

const ENVELOPE_PREFIX = 'e2ee:';

function parseEnvelope(text) {
  if (typeof text !== 'string' || !text.startsWith(ENVELOPE_PREFIX)) return null;
  const rest = text.slice(ENVELOPE_PREFIX.length);
  const idx = rest.indexOf(':');
  if (idx < 0) return null;
  const type = Number(rest.slice(0, idx));
  if (!Number.isFinite(type)) return null;
  return { type, body: rest.slice(idx + 1) };
}

function buildEnvelope(type, bodyB64) {
  return ENVELOPE_PREFIX + type + ':' + bodyB64;
}

function eventThreadID(event) {
  return String(event.threadID || event.threadId || '');
}

function eventSenderID(event) {
  return String(event.senderID || event.senderId || event.author || '');
}

async function enableE2EE(api, opts = {}) {
  if (!api || typeof api.listen !== 'function' || typeof api.sendMessage !== 'function') {
    throw new Error('[sagor-fca] enableE2EE needs an api object with listen() and sendMessage()');
  }
  const e2ee = await createE2EE({ keyPath: opts.keyPath });
  const e2eeThreads = new Set();
  const deviceIdOf = opts.deviceId || 1;

  const origListen = api.listen.bind(api);
  const origSend = api.sendMessage.bind(api);

  api.listen = function (cb) {
    return origListen(function (err, event) {
      if (err || !event || typeof event !== 'object') return cb(err, event);
      const tid = eventThreadID(event);
      if (tid && detectE2EEThread(event)) e2eeThreads.add(tid);
      const env = parseEnvelope(event.body);
      const payload = env || (event.e2ee && (event.e2ee.body || event.e2ee.ciphertext)
        ? { type: Number(event.e2ee.type) || 1, body: event.e2ee.body || event.e2ee.ciphertext }
        : null);
      if (!payload && !isE2EEDelta(event)) return cb(null, event);
      const sender = eventSenderID(event);
      const msg = payload || { type: 1, body: '' };
      e2ee.decryptFrom({ name: sender || tid || 'unknown', deviceId: deviceIdOf }, msg).then(function (pt) {
        event.body = Buffer.from(pt).toString('utf8');
        event.isE2EE = true;
        cb(null, event);
      }).catch(function (e) {
        event.isE2EE = true;
        event.decryptionError = e && e.message ? e.message : String(e);
        cb(null, event);
      });
    });
  };

  function sendEncrypted(text, threadID, callback, messageID) {
    return e2ee.encryptFor({ name: String(threadID), deviceId: deviceIdOf }, text).then(function (out) {
      const envelope = buildEnvelope(out.type, Buffer.from(out.body).toString('base64'));
      return origSend(envelope, threadID, callback, messageID);
    });
  }

  api.sendMessage = function (message, threadID, callback, messageID) {
    const text = typeof message === 'string' ? message : (message && message.body);
    if (typeof text === 'string' && e2eeThreads.has(String(threadID))) {
      const p = sendEncrypted(text, threadID, callback, messageID);
      if (typeof callback !== 'function') return p;
      p.catch(function (e) { callback(e); });
      return undefined;
    }
    return origSend(message, threadID, callback, messageID);
  };

  api.e2ee = e2ee;
  api.isE2EEThread = function (threadID) { return e2eeThreads.has(String(threadID)); };
  api.markE2EEThread = function (threadID, on) {
    const id = String(threadID);
    if (on === false) e2eeThreads.delete(id);
    else e2eeThreads.add(id);
  };
  api.getE2EIdentityKey = function () {
    return e2ee.getIdentityKeyPublic().toString('base64');
  };
  api.sendE2EMessage = function (text, threadID, deviceId, callback) {
    const did = deviceId || deviceIdOf;
    return e2ee.encryptFor({ name: String(threadID), deviceId: did }, String(text)).then(function (out) {
      const envelope = buildEnvelope(out.type, Buffer.from(out.body).toString('base64'));
      return origSend(envelope, threadID, callback);
    });
  };

  return api;
}

module.exports = { enableE2EE, parseEnvelope, buildEnvelope, ENVELOPE_PREFIX };
