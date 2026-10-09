# SAGOR FCA

**SAGOR's own Facebook Chat API for Node.js** — interact with Facebook Messenger programmatically.

This is SAGOR's maintained fork of the FCA family (v1.0.0 marks the start of the SAGOR-owned line).

## Install

```bash
npm install github:SAGOR-OFFICIAL-09/sagor-fca
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

## Notes

- This is an unofficial API. Facebook may restrict accounts that show bot-like behavior — use responsibly.
- Keep your `appState`/cookies private. Never share them or commit them to git.

## License

Apache-2.0
