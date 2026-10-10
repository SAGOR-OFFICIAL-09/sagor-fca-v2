# SAGOR FCA

**SAGOR's own Facebook Chat API for Node.js** — interact with Facebook Messenger programmatically.

This is SAGOR's maintained fork of the FCA family (v1.0.0 marks the start of the SAGOR-owned line).

## Install

```bash
npm install github:SAGOR-OFFICIAL-09/sagor-fca-v2
```

## Usage

```js
const login = require('sagor-fca');

// appState = your Facebook cookie array [{key, value, domain, ...}]
login({ appState }, (err, api) => {
  if (err) return console.error(err);

  console.log('Logged in as', api.getCurrentUserID());

  // listen for incoming messages
  api.listen((err, event) => {
    if (err) return console.error(err);
    if (event.type === 'message') {
      console.log(event.senderID, 'says:', event.body);
      api.sendMessage('Hello from SAGOR FCA!', event.threadID);
    }
  });
});
```

Or with async/await (Promise API):

```js
const api = await login({ appState });
const info = await api.getUserInfo(api.getCurrentUserID());
```

## Config

See `fca-config.example.json` for the available options (copy to `fca-config.json`).

- `checkUpdate.install` defaults to `false` (only logs when a newer version exists). Set it to `true` only if you want the library to run `npm i` in your project automatically.
- `apiServer` is empty by default. API login (email/password/2FA) is only attempted when you set it explicitly; your credentials are sent to that server, so only use one you trust.

## E2EE support (Signal protocol) 🔐

SAGOR FCA v2.0.0 merges the full chat API with the from-scratch E2EE module (`e2ee.js` + `e2ee-bridge.js`).

```js
const login = require('sagor-fca');
const { enableE2EE } = require('sagor-fca/e2ee-bridge');

login({ appState }, async (err, api) => {
  if (err) throw err;
  await enableE2EE(api, { keyPath: './sagor-e2ee-keys.json' });

  api.markE2EEThread('THREAD_ID'); // outgoing messages to this thread get encrypted

  api.listen((err, event) => {
    if (event && event.isE2EE) console.log(event.decrypted ? 'decrypted:' : 'could not decrypt:', event.decrypted ? event.body : event.decryptionError);
  });

  console.log('my identity key:', api.getE2EIdentityKey());
});
```

Sessions are established from the peer's pre-key bundle: `await api.e2ee.establishSession({ name: 'THREAD_ID', deviceId: 1 }, peerBundle)`.

Notes:
- `listen` and `listenMqtt` are both wrapped. On E2EE threads only plain text is supported; `attachment`, `sticker`, `url`, `location`, `emoji`, `mentions` are refused (never sent unencrypted).
- E2EE keys are stored with file mode `0600` and never logged. Never commit `sagor-e2ee-keys.json`.
- Facebook's server-side E2EE key distribution is not implemented — sessions must be bootstrapped manually. The on-the-wire envelope (`e2ee:<type>:<base64>`) is SAGOR's interim contract.

## Notes (unofficial API)

- This is an unofficial API. Facebook may restrict accounts that show bot-like behavior — use responsibly.
- Keep your `appState`/cookies private. Never share them or commit them to git.

## License

Apache-2.0
