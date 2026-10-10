'use strict';

const { createE2EE, detectE2EEThread, isE2EEDelta } = require('./e2ee');

const ENVELOPE_PREFIX = 'e2ee:';

// Message fields that cannot be carried inside an encrypted text envelope.
const UNSUPPORTED_E2EE_FIELDS = ['attachment', 'sticker', 'url', 'location', 'emoji', 'mentions'];

function parseEnvelope(text) {
  if (typeof text !== 'string' || !text.startsWith(ENVELOPE_PREFIX)) return null;
  const rest = text.slice(ENVELOPE_PREFIX.length);
  const idx = rest.indexOf(':');
  if (idx < 0) return null;
  const typeStr = rest.slice(0, idx);
  if (!/^\d+$/.test(typeStr)) return null;
  return { type: Number(typeStr), body: rest.slice(idx + 1) };
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

function hasUnsupportedFields(message) {
  if (!message || typeof message !== 'object') return null;
  for (const key of UNSUPPORTED_E2EE_FIELDS) {
    if (message[key] != null) return key;
  }
  return null;
}

async function enableE2EE(api, opts = {}) {
  if (
    !api ||
    (typeof api.listen !== 'function' && typeof api.listenMqtt !== 'function') ||
    typeof api.sendMessage !== 'function'
  ) {
    throw new Error('[sagor-fca] enableE2EE needs an api object with listen()/listenMqtt() and sendMessage()');
  }
  // Calling enableE2EE twice used to wrap listen/sendMessage twice (double decrypt/encrypt).
  if (api.e2ee) return api;

  const e2ee = opts.e2ee || (await createE2EE({ keyPath: opts.keyPath }));
  const e2eeThreads = new Set();
  const deviceIdOf = opts.deviceId || 1;

  const origSend = api.sendMessage.bind(api);

  async function decryptWithFallback(candidates, msg) {
    let lastErr;
    for (const name of candidates) {
      try {
        return await e2ee.decryptFrom({ name, deviceId: deviceIdOf }, msg);
      } catch (e) {
        lastErr = e;
      }
    }
    throw lastErr || new Error('no address to decrypt from');
  }

  function wrapListen(origListen) {
   return function (cb) {
    if (typeof cb !== 'function') {
      throw new TypeError('[sagor-fca] listen(callback) needs a callback function');
    }
    return origListen(function (err, event) {
      if (err || !event || typeof event !== 'object') return cb(err, event);
      const tid = eventThreadID(event);
      if (tid && detectE2EEThread(event)) e2eeThreads.add(tid);
      const env = parseEnvelope(event.body);
      const payload = env || (event.e2ee && (event.e2ee.body || event.e2ee.ciphertext)
        ? { type: Number(event.e2ee.type) || 1, body: event.e2ee.body || event.e2ee.ciphertext }
        : null);
      if (!payload && !isE2EEDelta(event)) return cb(null, event);
      if (!payload) {
        // flagged as encrypted but carries no ciphertext we understand
        event.isE2EE = true;
        event.decrypted = false;
        event.decryptionError = 'no ciphertext payload found on encrypted event';
        return cb(null, event);
      }
      const sender = eventSenderID(event);
      // sessions are keyed by the peer id; in a 1:1 chat that is both senderID and threadID
      const candidates = [...new Set([sender, tid].filter(Boolean))];
      if (candidates.length === 0) candidates.push('unknown');
      decryptWithFallback(candidates, payload).then(function (pt) {
        event.body = Buffer.from(pt).toString('utf8');
        event.isE2EE = true;
        event.decrypted = true;
        cb(null, event);
      }).catch(function (e) {
        event.isE2EE = true;
        event.decrypted = false;
        event.decryptionError = e && e.message ? e.message : String(e);
        cb(null, event);
      });
    });
   };
  }

  // api.listen is only an alias of api.listenMqtt in sagor-fca - wrap BOTH (once per distinct function),
  // otherwise bots that call listenMqtt() would never get decrypted messages.
  const wrapped = new Map();
  for (const name of ['listen', 'listenMqtt']) {
    if (typeof api[name] !== 'function') continue;
    const orig = api[name];
    if (!wrapped.has(orig)) wrapped.set(orig, wrapListen(orig.bind(api)));
    api[name] = wrapped.get(orig);
  }

  function rejectUnsupported(field, callback) {
    const err = new Error(
      '[sagor-e2ee] "' + field + '" cannot be sent on an E2EE thread (only text is supported); refusing to send it unencrypted'
    );
    if (typeof callback === 'function') {
      callback(err);
      return undefined;
    }
    return Promise.reject(err);
  }

  function sendEncrypted(text, threadID, rest) {
    const callback = typeof rest[0] === 'function' ? rest[0] : undefined;
    const envelopeP = e2ee
      .encryptFor({ name: String(threadID), deviceId: deviceIdOf }, text)
      .then(function (out) {
        return buildEnvelope(out.type, Buffer.from(out.body).toString('base64'));
      });
    if (callback) {
      envelopeP.then(
        function (envelope) { origSend(envelope, threadID, ...rest); },
        function (e) { callback(e); }
      );
      return undefined;
    }
    return envelopeP.then(function (envelope) { return origSend(envelope, threadID, ...rest); });
  }

  // Extra arguments (callback, replyToMessage, isGroup, ...) are forwarded untouched.
  api.sendMessage = function (message, threadID, ...rest) {
    if (e2eeThreads.has(String(threadID))) {
      const text = typeof message === 'string' ? message : (message && message.body);
      const bad = hasUnsupportedFields(message);
      if (bad) return rejectUnsupported(bad, rest[0]);
      if (typeof text === 'string') return sendEncrypted(text, threadID, rest);
      // never fall back to plaintext on an E2EE thread
      return rejectUnsupported('body (a text string is required)', rest[0]);
    }
    return origSend(message, threadID, ...rest);
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
