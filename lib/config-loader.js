'use strict';

const fs = require('fs');
const path = require('path');

let cachedConfig = null;
let configPath = null;

/**
 * Find package.json by walking up from a starting directory
 * @param {string} startDir - Directory to start searching from
 * @returns {string|null} Path to package.json or null
 */
function findPackageJson(startDir = process.cwd()) {
    let dir = path.resolve(startDir);

    while (dir !== path.dirname(dir)) {
        const pkgPath = path.join(dir, 'package.json');
        if (fs.existsSync(pkgPath)) {
            return pkgPath;
        }
        dir = path.dirname(dir);
    }

    // Check root as well
    const rootPkgPath = path.join(dir, 'package.json');
    if (fs.existsSync(rootPkgPath)) {
        return rootPkgPath;
    }

    return null;
}

/**
 * Load and parse the environmentWhitelist configuration
 * @param {string|null} customPath - Custom path to package.json
 * @returns {Object} Normalized whitelist configuration
 */
function loadConfig(customPath = null) {
    const pkgPath = customPath || findPackageJson();

    if (!pkgPath) {
        throw new Error('dotnope: Could not find package.json. Please ensure you are running from a Node.js project directory.');
    }

    configPath = pkgPath;

    try {
        const pkgContent = fs.readFileSync(pkgPath, 'utf8');
        const pkg = JSON.parse(pkgContent);

        const whitelist = pkg.environmentWhitelist || {};

        // Normalize and validate configuration
        cachedConfig = normalizeConfig(whitelist);

        return cachedConfig;
    } catch (err) {
        if (err.code === 'ENOENT') {
            throw new Error(`dotnope: package.json not found at ${pkgPath}`);
        }
        if (err instanceof SyntaxError) {
            throw new Error(`dotnope: Invalid JSON in ${pkgPath}: ${err.message}`);
        }
        throw new Error(`dotnope: Failed to load config from ${pkgPath}: ${err.message}`);
    }
}

/**
 * Normalize whitelist configuration to a consistent format
 * @param {Object} whitelist - Raw whitelist from package.json
 * @returns {Object} Normalized configuration
 */
function normalizeConfig(whitelist) {
    const normalized = {};

    for (const [packageName, config] of Object.entries(whitelist)) {
        if (typeof config === 'object' && config !== null && !Array.isArray(config)) {
            // Full object format
            normalized[packageName] = {
                allowed: Array.isArray(config.allowed) ? config.allowed : [],
                allowPeerDependencies: Boolean(config.allowPeerDependencies)
            };
        } else if (Array.isArray(config)) {
            // Shorthand: just an array of allowed vars
            normalized[packageName] = {
                allowed: config,
                allowPeerDependencies: false
            };
        } else if (typeof config === 'string') {
            // Single env var as string
            normalized[packageName] = {
                allowed: [config],
                allowPeerDependencies: false
            };
        }
        // Skip invalid entries
    }

    return normalized;
}

/**
 * Get the current configuration (loads if not cached)
 * @returns {Object} Whitelist configuration
 */
function getConfig() {
    if (!cachedConfig) {
        loadConfig();
    }
    return cachedConfig;
}

/**
 * Get the path to the loaded package.json
 * @returns {string|null}
 */
function getConfigPath() {
    return configPath;
}

/**
 * Clear the configuration cache (useful for testing)
 */
function clearCache() {
    cachedConfig = null;
    configPath = null;
}

/**
 * Reload configuration from disk
 * @returns {Object} Fresh configuration
 */
function reloadConfig() {
    clearCache();
    return loadConfig(configPath);
}

/**
 * Check if a package has any whitelist entries
 * @param {string} packageName
 * @returns {boolean}
 */
function hasWhitelistEntry(packageName) {
    const config = getConfig();
    return packageName in config;
}

/**
 * Get allowed env vars for a specific package
 * @param {string} packageName
 * @returns {string[]} Array of allowed env var names
 */
function getAllowedForPackage(packageName) {
    const config = getConfig();
    const entry = config[packageName];
    return entry ? entry.allowed : [];
}

module.exports = {
    findPackageJson,
    loadConfig,
    getConfig,
    getConfigPath,
    clearCache,
    reloadConfig,
    hasWhitelistEntry,
    getAllowedForPackage,
    normalizeConfig
};
