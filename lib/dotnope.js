'use strict';

const crypto = require('crypto');
const { createEnvProxy, enable, disable, restore, setFilterKeysFn } = require('./proxy');
const { getCallingPackage, wasTamperingDetected } = require('./stack-parser');
const { loadConfig, getConfig, getOptions, clearCache: clearConfigCache, getSerializableConfig } = require('./config-loader');
const { isPackageAllowed, clearCache: clearDepCache } = require('./dependency-resolver');
const nativeBridge = require('./native-bridge');

// Worker thread support
let isMainThread = true;
let parentPort = null;
try {
    const workerThreads = require('worker_threads');
    isMainThread = workerThreads.isMainThread;
    parentPort = workerThreads.parentPort;
} catch (e) {
    // worker_threads not available (older Node.js or browser)
}

let isInitialized = false;
let disableToken = null;

// Access tracking: "packageName:envVar" -> count
const accessCounts = new Map();

// Track if security warnings have been emitted
let securityWarningsEmitted = false;

// Track if this is a worker that was explicitly allowed
let workerAllowed = false;

/**
 * Check if a package is allowed to access an environment variable
 * Throws an error if access is denied
 * @param {string} envVar - The environment variable being accessed
 * @param {string} operation - The operation type: 'read', 'write', or 'delete'
 */
function checkAccess(envVar, operation = 'read') {
    // Get the caller info - isInternalFile check handles skipping strictenv frames
    const callerInfo = getCallingPackage(0);
    const options = getOptions();

    if (!callerInfo) {
        // Cannot determine caller - this can happen in some edge cases
        // Fail-closed by default (configurable)
        if (options.failClosed) {
            const error = new Error(
                `dotnope: Unable to identify calling package!\n` +
                `\n` +
                `  Attempted to ${operation}: "${envVar}"\n` +
                `  Caller could not be determined from stack trace.\n` +
                `\n` +
                `This may happen with eval(), async contexts, or native addons.\n` +
                `To allow unknown callers (less secure), add to your package.json:\n` +
                `\n` +
                `  "environmentWhitelist": {\n` +
                `    "__options__": {\n` +
                `      "failClosed": false\n` +
                `    }\n` +
                `  }\n`
            );
            error.code = 'ERR_DOTNOPE_UNKNOWN_CALLER';
            error.envVar = envVar;
            error.operation = operation;
            throw error;
        }
        return;
    }

    const { packageName, fileName, lineNumber, functionName, isEval } = callerInfo;

    // Block eval/Function contexts when failClosed is enabled
    // eval() and new Function() can be used to hide the true calling package
    if (isEval && options.failClosed) {
        const error = new Error(
            `dotnope: Environment variable access from eval context blocked!\n` +
            `\n` +
            `  Attempted to ${operation}: "${envVar}"\n` +
            `  Access originated from eval() or new Function()\n` +
            `  Detected package: "${packageName}"\n` +
            `  Location: ${fileName}:${lineNumber}\n` +
            `\n` +
            `eval() and Function constructor can obscure the true caller.\n` +
            `This is blocked by default for security. To allow (less secure):\n` +
            `\n` +
            `  "environmentWhitelist": {\n` +
            `    "__options__": {\n` +
            `      "failClosed": false\n` +
            `    }\n` +
            `  }\n`
        );
        error.code = 'ERR_DOTNOPE_EVAL_CONTEXT';
        error.envVar = envVar;
        error.operation = operation;
        error.packageName = packageName;
        error.fileName = fileName;
        error.lineNumber = lineNumber;
        throw error;
    }

    // Main application always has access
    if (packageName === '__main__') {
        return;
    }

    const config = getConfig();

    // Track access
    const trackingKey = `${packageName}:${envVar}:${operation}`;
    accessCounts.set(trackingKey, (accessCounts.get(trackingKey) || 0) + 1);

    // Check if access is allowed based on operation type
    let isAllowed = false;
    let configKey = 'allowed';

    if (operation === 'read') {
        isAllowed = isPackageAllowed(packageName, envVar, config);
        configKey = 'allowed';
    } else if (operation === 'write') {
        isAllowed = isPackageAllowedForOperation(packageName, envVar, config, 'canWrite');
        configKey = 'canWrite';
    } else if (operation === 'delete') {
        isAllowed = isPackageAllowedForOperation(packageName, envVar, config, 'canDelete');
        configKey = 'canDelete';
    }

    if (!isAllowed) {
        const operationVerb = operation === 'read' ? 'read' : operation === 'write' ? 'write to' : 'delete';
        const error = new Error(
            `dotnope: Unauthorized environment variable ${operation}!\n` +
            `\n` +
            `  Package: "${packageName}"\n` +
            `  Attempted to ${operationVerb}: "${envVar}"\n` +
            `  Location: ${fileName}:${lineNumber}\n` +
            `  Function: ${functionName}\n` +
            `\n` +
            `To allow this access, add to your package.json:\n` +
            `\n` +
            `  "environmentWhitelist": {\n` +
            `    "${packageName}": {\n` +
            `      "${configKey}": ["${envVar}"]\n` +
            `    }\n` +
            `  }\n`
        );

        error.code = 'ERR_DOTNOPE_UNAUTHORIZED';
        error.packageName = packageName;
        error.envVar = envVar;
        error.operation = operation;
        error.fileName = fileName;
        error.lineNumber = lineNumber;
        error.functionName = functionName;

        throw error;
    }
}

/**
 * Check if a package is allowed for write/delete operations
 * @param {string} packageName
 * @param {string} envVar
 * @param {Object} config
 * @param {string} operationKey - 'canWrite' or 'canDelete'
 * @returns {boolean}
 */
function isPackageAllowedForOperation(packageName, envVar, config, operationKey) {
    // Main application always has access
    if (packageName === '__main__') {
        return true;
    }

    const packageConfig = config[packageName];
    if (!packageConfig) {
        return false;
    }

    const allowedVars = packageConfig[operationKey] || [];
    return allowedVars.includes(envVar) || allowedVars.includes('*');
}

/**
 * Filter ownKeys results based on caller's allowed env vars
 * @param {Array} allKeys - All environment variable keys
 * @returns {Array|null} Filtered keys or null to skip filtering
 */
function filterKeys(allKeys) {
    const callerInfo = getCallingPackage(0);

    // Can't determine caller - return null to skip filtering
    if (!callerInfo) {
        const options = getOptions();
        // If fail-closed, return empty array (no keys visible)
        // If fail-open, return all keys
        return options.failClosed ? [] : null;
    }

    const { packageName } = callerInfo;

    // Main application sees everything
    if (packageName === '__main__') {
        return null; // Skip filtering
    }

    const config = getConfig();
    const packageConfig = config[packageName];

    // Package not in whitelist - sees nothing
    if (!packageConfig) {
        return [];
    }

    // Package has wildcard access - sees everything
    if (packageConfig.allowed.includes('*')) {
        return null; // Skip filtering
    }

    // Filter to only allowed keys (keep symbols and non-string keys)
    return allKeys.filter(key => {
        if (typeof key !== 'string') {
            return true; // Keep symbols
        }
        return packageConfig.allowed.includes(key);
    });
}

/**
 * Check if LD_PRELOAD is active with our library
 * @returns {boolean}
 */
function isPreloadActive() {
    const preload = process.env.LD_PRELOAD || '';
    return preload.includes('libdotnope_preload.so') || preload.includes('dotnope_preload');
}

/**
 * Emit security warnings based on current state
 * @param {Object} options - Options passed to enableStrictEnv
 */
function emitSecurityWarnings(options = {}) {
    if (securityWarningsEmitted && !options.forceWarnings) {
        return;
    }
    securityWarningsEmitted = true;

    // Suppress warnings if explicitly requested
    if (options.suppressWarnings) {
        return;
    }

    const warnings = [];

    // Check native addon availability
    if (!nativeBridge.isNativeAvailable()) {
        warnings.push({
            level: 'warn',
            message: '[dotnope] Native addon not available - using JavaScript fallback.',
            detail: '[dotnope] For maximum security, run: npm run build:native'
        });
    } else if (!nativeBridge.isIntegrityVerified()) {
        warnings.push({
            level: 'warn',
            message: '[dotnope] Native addon integrity could not be verified.',
            detail: '[dotnope] Run: node scripts/generate-addon-manifest.js after building.'
        });
    }

    // Check for stack trace tampering
    if (wasTamperingDetected()) {
        warnings.push({
            level: 'error',
            message: '[dotnope] SECURITY WARNING: Stack trace tampering detected!',
            detail: '[dotnope] Error.prepareStackTrace was modified before dotnope loaded.'
        });
    }

    // Check for LD_PRELOAD on Linux
    if (process.platform === 'linux' && !isPreloadActive()) {
        warnings.push({
            level: 'info',
            message: '[dotnope] LD_PRELOAD not active - native addons can bypass protection.',
            detail: '[dotnope] For native addon protection, use: npx dotnope-run your-app.js'
        });
    }

    // Check for early module loading
    const loadedModules = Object.keys(require.cache).length;
    if (loadedModules > 20) {
        warnings.push({
            level: 'warn',
            message: `[dotnope] ${loadedModules} modules loaded before enableStrictEnv().`,
            detail: '[dotnope] Some modules may have captured process.env reference. Load dotnope first.'
        });
    }

    // Emit warnings
    for (const warning of warnings) {
        if (warning.level === 'error') {
            console.error(warning.message);
            if (warning.detail) console.error(warning.detail);
        } else if (warning.level === 'warn') {
            console.warn(warning.message);
            if (warning.detail) console.warn(warning.detail);
        } else {
            // info level - only show if verbose
            if (options.verbose) {
                console.log(warning.message);
                if (warning.detail) console.log(warning.detail);
            }
        }
    }

    return warnings;
}

/**
 * Enable strict environment variable access control
 * @param {Object} options - Configuration options
 * @param {string} [options.configPath] - Custom path to package.json
 * @param {boolean} [options.suppressWarnings] - Suppress security warnings
 * @param {boolean} [options.verbose] - Show all warnings including info level
 * @param {boolean} [options.allowInWorker] - Allow enabling in worker threads
 * @param {Object} [options.workerConfig] - Config passed from main thread
 * @returns {Object} Handle with token-protected disable() and getAccessStats() methods
 */
function enableStrictEnv(options = {}) {
    if (isInitialized) {
        console.warn('dotnope: Already enabled');
        // Return a handle with the existing token
        return createHandle();
    }

    // Check if we're in a worker thread
    if (!isMainThread) {
        if (!options.allowInWorker) {
            const error = new Error(
                'dotnope: Cannot enable in worker thread without explicit opt-in!\n' +
                '\n' +
                'Worker threads have separate V8 isolates and require explicit setup.\n' +
                'To enable dotnope in a worker, call:\n' +
                '\n' +
                '  enableStrictEnv({ allowInWorker: true, workerConfig: config })\n' +
                '\n' +
                'Where config is passed from the main thread via workerData or postMessage.'
            );
            error.code = 'ERR_DOTNOPE_WORKER_NOT_ALLOWED';
            throw error;
        }
        workerAllowed = true;
    }

    // Generate a cryptographically secure token for disable protection
    disableToken = crypto.randomBytes(32).toString('hex');

    // Load configuration from package.json or use worker config
    if (!isMainThread && options.workerConfig) {
        // Worker thread with passed config - load directly
        loadConfig(options.configPath, options.workerConfig);
    } else {
        // Main thread - load from package.json
        loadConfig(options.configPath);
    }

    // Create and activate the proxy with options
    const configOptions = getOptions();
    createEnvProxy(checkAccess, configOptions);

    // Set up enumeration filtering if enabled
    if (configOptions.protectEnumeration) {
        setFilterKeysFn(filterKeys);
    }

    // Enable promise hooks for async context tracking (if native available)
    if (nativeBridge.isNativeAvailable()) {
        nativeBridge.enablePromiseHooks();
    }

    enable();

    isInitialized = true;

    // Emit security warnings
    emitSecurityWarnings(options);

    return createHandle();
}

/**
 * Check if we're running in the main thread
 * @returns {boolean}
 */
function isRunningInMainThread() {
    return isMainThread;
}

/**
 * Check if worker was explicitly allowed
 * @returns {boolean}
 */
function isWorkerAllowed() {
    return workerAllowed;
}

/**
 * Create a secure handle with token-protected disable
 * @returns {Object} Handle with disable() and getAccessStats() methods
 */
function createHandle() {
    const token = disableToken;

    return {
        /**
         * Disable strict environment variable access control
         * @param {string} providedToken - The token returned from enableStrictEnv
         */
        disable: (providedToken) => {
            if (providedToken !== token) {
                throw new Error(
                    'dotnope: Invalid disable token!\n' +
                    '\n' +
                    'You must use the token returned from enableStrictEnv() to disable.\n' +
                    'This prevents malicious packages from disabling protection.\n' +
                    '\n' +
                    'Example:\n' +
                    '  const handle = enableStrictEnv();\n' +
                    '  // Later:\n' +
                    '  handle.disable(token);  // Must pass the correct token\n'
                );
            }
            disableStrictEnvInternal();
        },
        /**
         * Get access statistics
         * @returns {Object} Access counts by "packageName:envVar:operation"
         */
        getAccessStats: getAccessStats,
        /**
         * Get the disable token (store securely!)
         * @returns {string} The token required to disable protection
         */
        getToken: () => token
    };
}

/**
 * Internal: Disable strict environment variable access control
 * Called only with valid token via handle.disable()
 */
function disableStrictEnvInternal() {
    // Disable promise hooks if native is available
    if (nativeBridge.isNativeAvailable()) {
        nativeBridge.disablePromiseHooks();
    }

    disable();
    restore();
    isInitialized = false;
    disableToken = null;

    // Clear caches
    clearConfigCache();
    clearDepCache();
    accessCounts.clear();
}

/**
 * Disable strict environment variable access control
 * @deprecated REMOVED - Use handle.disable(token) instead
 * @throws {Error} Always throws - use token-protected disable
 */
function disableStrictEnv() {
    const error = new Error(
        'dotnope: disableStrictEnv() has been removed for security!\n' +
        '\n' +
        'Allowing direct disable would let malicious packages bypass protection.\n' +
        'Use token-protected disable instead:\n' +
        '\n' +
        '  const handle = enableStrictEnv();\n' +
        '  const token = handle.getToken();\n' +
        '  // Store token securely, then later:\n' +
        '  handle.disable(token);\n'
    );
    error.code = 'ERR_DOTNOPE_DEPRECATED';
    throw error;
}

/**
 * Get access statistics
 * @returns {Object} Access counts by "packageName:envVar"
 */
function getAccessStats() {
    const result = {};
    for (const [key, count] of accessCounts) {
        result[key] = count;
    }
    return result;
}

/**
 * Check if strict mode is currently enabled
 * @returns {boolean}
 */
function isEnabled() {
    return isInitialized;
}

module.exports = {
    enableStrictEnv,
    disableStrictEnv,
    getAccessStats,
    isEnabled,
    isPreloadActive,
    emitSecurityWarnings,
    isRunningInMainThread,
    isWorkerAllowed,
    getSerializableConfig
};
