/**
 * native-bridge.js - JavaScript bridge to native C++ addon
 *
 * Provides optional native functionality for enhanced security:
 * - V8-level stack trace capture (bypasses Error.prepareStackTrace tampering)
 * - Promise hooks for async context tracking
 * - Worker thread protection
 */

'use strict';

const crypto = require('crypto');

let native = null;
let nativeAvailable = false;
let initializationError = null;
let integrityVerified = false;
let integrityError = null;

/**
 * Verify the integrity of the native addon against the manifest
 * @param {string} addonPath - Path to the addon file
 * @returns {Object} Result with verified boolean and any error
 */
function verifyAddonIntegrity(addonPath) {
    const fs = require('fs');
    const path = require('path');
    const manifestPath = path.join(__dirname, '../addon-manifest.json');

    // Check if manifest exists
    if (!fs.existsSync(manifestPath)) {
        // No manifest - cannot verify, but allow loading with warning
        return {
            verified: false,
            warning: 'No addon-manifest.json found. Addon integrity cannot be verified.',
            error: null
        };
    }

    try {
        // Load manifest
        const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

        // Read addon file
        const addonBuffer = fs.readFileSync(addonPath);

        // Compute hash
        const actualHash = crypto.createHash(manifest.addon.algorithm || 'sha256')
            .update(addonBuffer)
            .digest('hex');

        // Compare hashes
        if (actualHash !== manifest.addon.hash) {
            return {
                verified: false,
                warning: null,
                error: new Error(
                    `Native addon integrity check failed!\n` +
                    `Expected: ${manifest.addon.hash}\n` +
                    `Got: ${actualHash}\n` +
                    `The addon may have been tampered with or rebuilt.`
                )
            };
        }

        // Check size as secondary verification
        const stats = fs.statSync(addonPath);
        if (stats.size !== manifest.addon.size) {
            return {
                verified: false,
                warning: null,
                error: new Error(
                    `Native addon size mismatch!\n` +
                    `Expected: ${manifest.addon.size} bytes\n` +
                    `Got: ${stats.size} bytes`
                )
            };
        }

        return {
            verified: true,
            warning: null,
            error: null
        };
    } catch (err) {
        return {
            verified: false,
            warning: `Could not verify addon integrity: ${err.message}`,
            error: null
        };
    }
}

/**
 * Attempt to load the native addon
 */
function loadNativeAddon() {
    if (native !== null || initializationError !== null) {
        return nativeAvailable;
    }

    try {
        const fs = require('fs');
        const path = require('path');
        const addonPath = path.join(__dirname, '../build/Release/dotnope_native.node');

        // First check if the file exists
        if (!fs.existsSync(addonPath)) {
            initializationError = new Error('Native addon not built');
            nativeAvailable = false;
            return false;
        }

        // Verify addon integrity before loading
        const integrityResult = verifyAddonIntegrity(addonPath);
        integrityVerified = integrityResult.verified;

        if (integrityResult.error) {
            // Integrity check failed - refuse to load
            console.error('[dotnope] SECURITY WARNING:', integrityResult.error.message);
            console.error('[dotnope] Native addon will NOT be loaded. Falling back to JavaScript.');
            integrityError = integrityResult.error;
            initializationError = integrityResult.error;
            nativeAvailable = false;
            return false;
        }

        if (integrityResult.warning) {
            // Warning but continue loading
            console.warn('[dotnope]', integrityResult.warning);
        }

        // Check Node.js version compatibility
        // Symbol lookup errors often happen due to ABI mismatch
        const nodeVersion = process.versions.node.split('.')[0];
        const nodeAbi = process.versions.modules;

        // Try to load the compiled native addon
        native = require('../build/Release/dotnope_native.node');
        nativeAvailable = true;

        // Initialize the native module with the module's base path
        // This allows the native addon to recognize dotnope's own files
        // even when running from a development directory
        const modulePath = path.resolve(__dirname, '..');
        native.initialize(modulePath);

        return true;
    } catch (err) {
        // Native addon not available - fall back to pure JS
        // This handles both missing files and ABI mismatches
        initializationError = err;
        native = null;
        nativeAvailable = false;
        return false;
    }
}

/**
 * Check if native functionality is available
 */
function isNativeAvailable() {
    if (native === null) {
        loadNativeAddon();
    }
    return nativeAvailable;
}

/**
 * Get the initialization error if native failed to load
 */
function getInitializationError() {
    return initializationError;
}

/**
 * Get native module version
 */
function getVersion() {
    if (!isNativeAvailable()) {
        return null;
    }
    return native.getVersion();
}

/**
 * Capture stack trace using native V8 API
 * Falls back to JavaScript implementation if native not available
 *
 * @param {number} skipFrames - Number of frames to skip
 * @returns {Array|null} Array of stack frames or null
 */
function captureStackTrace(skipFrames = 0) {
    if (!isNativeAvailable()) {
        return null;
    }
    return native.captureStackTrace(skipFrames);
}

/**
 * Get caller information using native V8 API
 * Falls back to JavaScript implementation if native not available
 *
 * @param {number} skipFrames - Number of frames to skip
 * @returns {Object|null} Caller info object or null
 */
function getCallerInfo(skipFrames = 0) {
    if (!isNativeAvailable()) {
        return null;
    }
    return native.getCallerInfo(skipFrames);
}

/**
 * Enable promise hooks for async context tracking
 *
 * @returns {boolean} Success
 */
function enablePromiseHooks() {
    if (!isNativeAvailable()) {
        return false;
    }
    return native.enablePromiseHooks();
}

/**
 * Disable promise hooks
 *
 * @returns {boolean} Success
 */
function disablePromiseHooks() {
    if (!isNativeAvailable()) {
        return false;
    }
    return native.disablePromiseHooks();
}

/**
 * Get the async context (package name that initiated current async chain)
 *
 * @returns {string|null} Package name or null
 */
function getAsyncContext() {
    if (!isNativeAvailable()) {
        return null;
    }
    return native.getAsyncContext();
}

/**
 * Get promise tracking statistics
 *
 * @returns {Object|null} Stats object or null if native not available
 */
function getPromiseStats() {
    if (!isNativeAvailable()) {
        return null;
    }
    return native.getPromiseStats();
}

/**
 * Check if we're running in a worker thread
 *
 * @returns {boolean}
 */
function isWorkerThread() {
    if (!isNativeAvailable()) {
        // Fall back to checking worker_threads
        try {
            const { isMainThread } = require('worker_threads');
            return !isMainThread;
        } catch (e) {
            return false;
        }
    }
    return native.isWorkerThread();
}

/**
 * Get the number of registered isolates
 *
 * @returns {number}
 */
function getIsolateCount() {
    if (!isNativeAvailable()) {
        return 1;
    }
    return native.getIsolateCount();
}

/**
 * Cleanup native resources
 */
function cleanup() {
    if (isNativeAvailable()) {
        native.cleanup();
    }
}

/**
 * Check if the native addon passed integrity verification
 * @returns {boolean}
 */
function isIntegrityVerified() {
    return integrityVerified;
}

/**
 * Get the integrity verification error if any
 * @returns {Error|null}
 */
function getIntegrityError() {
    return integrityError;
}

/**
 * Get complete security status of the native bridge
 * @returns {Object} Status object with availability, integrity, etc.
 */
function getSecurityStatus() {
    return {
        nativeAvailable,
        integrityVerified,
        hasIntegrityError: integrityError !== null,
        initializationError: initializationError ? initializationError.message : null
    };
}

module.exports = {
    loadNativeAddon,
    isNativeAvailable,
    getInitializationError,
    getVersion,
    captureStackTrace,
    getCallerInfo,
    enablePromiseHooks,
    disablePromiseHooks,
    getAsyncContext,
    getPromiseStats,
    isWorkerThread,
    getIsolateCount,
    cleanup,
    isIntegrityVerified,
    getIntegrityError,
    getSecurityStatus
};
