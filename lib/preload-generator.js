/**
 * preload-generator.js - Generate LD_PRELOAD policy from whitelist config
 *
 * Generates the DOTNOPE_POLICY environment variable value from the
 * environmentWhitelist configuration for use with libdotnope_preload.so
 */

'use strict';

const fs = require('fs');
const path = require('path');

/**
 * Generate DOTNOPE_POLICY from whitelist configuration
 * @param {Object} config - Whitelist configuration object
 * @returns {string} Comma-separated list of allowed env vars
 */
function generatePolicy(config) {
    const allowedVars = new Set();

    // Collect all allowed variables from all packages
    for (const [packageName, packageConfig] of Object.entries(config)) {
        // Skip options
        if (packageName === '__options__') {
            continue;
        }

        // Add allowed vars
        if (packageConfig.allowed) {
            for (const envVar of packageConfig.allowed) {
                // Skip wildcard - preload library handles wildcards separately
                if (envVar === '*') {
                    // Return wildcard to allow all
                    return '*';
                }
                allowedVars.add(envVar);
            }
        }

        // Add writable vars (they're also readable)
        if (packageConfig.canWrite) {
            for (const envVar of packageConfig.canWrite) {
                if (envVar === '*') {
                    return '*';
                }
                allowedVars.add(envVar);
            }
        }
    }

    // Sort for deterministic output
    return [...allowedVars].sort().join(',');
}

/**
 * Generate policy from a package.json file
 * @param {string} pkgPath - Path to package.json
 * @returns {string} Policy string
 */
function generatePolicyFromPackageJson(pkgPath) {
    const pkgContent = fs.readFileSync(pkgPath, 'utf8');
    const pkg = JSON.parse(pkgContent);
    const whitelist = pkg.environmentWhitelist || {};

    // Normalize config (simplified version of config-loader)
    const config = {};
    for (const [packageName, rawConfig] of Object.entries(whitelist)) {
        if (packageName === '__options__') continue;

        if (typeof rawConfig === 'object' && rawConfig !== null && !Array.isArray(rawConfig)) {
            config[packageName] = {
                allowed: rawConfig.allowed || [],
                canWrite: rawConfig.canWrite || []
            };
        } else if (Array.isArray(rawConfig)) {
            config[packageName] = { allowed: rawConfig, canWrite: [] };
        }
    }

    return generatePolicy(config);
}

/**
 * Find the preload library path
 * @returns {string|null} Path to libdotnope_preload.so or null
 */
function findPreloadLibrary() {
    const possiblePaths = [
        path.join(__dirname, '../build/Release/libdotnope_preload.so'),
        path.join(__dirname, '../native/preload/libdotnope_preload.so'),
        '/usr/local/lib/libdotnope_preload.so',
        '/usr/lib/libdotnope_preload.so'
    ];

    for (const libPath of possiblePaths) {
        if (fs.existsSync(libPath)) {
            return libPath;
        }
    }

    return null;
}

/**
 * Check if LD_PRELOAD is currently active with our library
 * @returns {boolean}
 */
function isPreloadActive() {
    const preload = process.env.LD_PRELOAD || '';
    return preload.includes('libdotnope_preload.so') || preload.includes('dotnope_preload');
}

/**
 * Generate environment variables for launching with preload
 * @param {string} pkgPath - Path to package.json
 * @returns {Object} Environment variables to set
 */
function generatePreloadEnv(pkgPath) {
    const preloadPath = findPreloadLibrary();
    if (!preloadPath) {
        throw new Error(
            'dotnope: libdotnope_preload.so not found!\n' +
            'Build with: make -C native/preload'
        );
    }

    const policy = generatePolicyFromPackageJson(pkgPath);

    return {
        LD_PRELOAD: preloadPath,
        DOTNOPE_POLICY: policy
    };
}

module.exports = {
    generatePolicy,
    generatePolicyFromPackageJson,
    findPreloadLibrary,
    isPreloadActive,
    generatePreloadEnv
};
