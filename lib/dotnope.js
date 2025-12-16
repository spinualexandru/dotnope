'use strict';

const { createEnvProxy, enable, disable, restore } = require('./proxy');
const { getCallingPackage } = require('./stack-parser');
const { loadConfig, getConfig, clearCache: clearConfigCache } = require('./config-loader');
const { isPackageAllowed, clearCache: clearDepCache } = require('./dependency-resolver');

let nativeCache = null;
let isInitialized = false;

// Try to load native module for performance
try {
    const native = require('../build/Release/dotnope_native.node');
    nativeCache = new native.DotnopeCache();
} catch (err) {
    // Native module not available, using pure JS fallback
    // This is expected during development or on unsupported platforms
}

/**
 * Check if a package is allowed to access an environment variable
 * Throws an error if access is denied
 * @param {string} envVar - The environment variable being accessed
 */
function checkAccess(envVar) {
    // Get the caller info - isInternalFile check handles skipping strictenv frames
    const callerInfo = getCallingPackage(0);

    if (!callerInfo) {
        // Cannot determine caller - this can happen in some edge cases
        // Fail open for safety to avoid breaking applications
        return;
    }

    const { packageName, fileName, lineNumber, functionName } = callerInfo;

    // Main application always has access
    if (packageName === '__main__') {
        return;
    }

    const config = getConfig();

    // Check using native cache if available for O(1) lookup
    let isAllowed;
    if (nativeCache) {
        isAllowed = nativeCache.isAllowed(packageName, envVar);
        nativeCache.trackAccess(packageName, envVar);
    } else {
        isAllowed = isPackageAllowed(packageName, envVar, config);
    }

    if (!isAllowed) {
        const error = new Error(
            `dotnope: Unauthorized environment variable access!\n` +
            `\n` +
            `  Package: "${packageName}"\n` +
            `  Attempted to read: "${envVar}"\n` +
            `  Location: ${fileName}:${lineNumber}\n` +
            `  Function: ${functionName}\n` +
            `\n` +
            `To allow this access, add to your package.json:\n` +
            `\n` +
            `  "environmentWhitelist": {\n` +
            `    "${packageName}": {\n` +
            `      "allowed": ["${envVar}"]\n` +
            `    }\n` +
            `  }\n`
        );

        error.code = 'ERR_DOTNOPE_UNAUTHORIZED';
        error.packageName = packageName;
        error.envVar = envVar;
        error.fileName = fileName;
        error.lineNumber = lineNumber;
        error.functionName = functionName;

        throw error;
    }
}

/**
 * Enable strict environment variable access control
 * @param {Object} options - Configuration options
 * @param {string} [options.configPath] - Custom path to package.json
 * @returns {Object} Handle with disable() and getAccessStats() methods
 */
function enableStrictEnv(options = {}) {
    if (isInitialized) {
        console.warn('dotnope: Already enabled');
        return {
            disable: disableStrictEnv,
            getAccessStats: getAccessStats
        };
    }

    // Load configuration from package.json
    const config = loadConfig(options.configPath);

    // Initialize native cache if available
    if (nativeCache) {
        initializeNativeCache(config);
    }

    // Create and activate the proxy
    createEnvProxy(checkAccess);
    enable();

    isInitialized = true;

    return {
        disable: disableStrictEnv,
        getAccessStats: getAccessStats
    };
}

/**
 * Initialize the native cache with whitelist configuration
 * @param {Object} config - Whitelist configuration
 */
function initializeNativeCache(config) {
    if (!nativeCache) return;

    const { getPackageDependencies } = require('./dependency-resolver');

    for (const [packageName, packageConfig] of Object.entries(config)) {
        // Set whitelist for this package
        nativeCache.setWhitelist(packageName, packageConfig.allowed);

        // If allowPeerDependencies is true, propagate permissions
        if (packageConfig.allowPeerDependencies) {
            const deps = getPackageDependencies(packageName);
            if (deps.size > 0) {
                nativeCache.addPeerDeps(packageName, Array.from(deps));
            }
        }
    }
}

/**
 * Disable strict environment variable access control
 */
function disableStrictEnv() {
    disable();
    restore();
    isInitialized = false;

    // Clear caches
    clearConfigCache();
    clearDepCache();

    if (nativeCache) {
        nativeCache.clear();
    }
}

/**
 * Get access statistics (requires native module)
 * @returns {Object|null} Access counts by package:envVar or null if native not available
 */
function getAccessStats() {
    if (nativeCache) {
        return nativeCache.getAccessCount();
    }
    return null;
}

/**
 * Check if strict mode is currently enabled
 * @returns {boolean}
 */
function isEnabled() {
    return isInitialized;
}

/**
 * Check if native module is available
 * @returns {boolean}
 */
function hasNativeModule() {
    return nativeCache !== null;
}

module.exports = {
    enableStrictEnv,
    disableStrictEnv,
    getAccessStats,
    isEnabled,
    hasNativeModule
};
