'use strict';

const fs = require('fs');
const path = require('path');

let cachedConfig = null;
let cachedOptions = null;
let configPath = null;

/**
 * Default options for dotnope behavior
 */
const DEFAULT_OPTIONS = {
    failClosed: true,           // Deny access when caller cannot be determined
    protectWrites: true,        // Control write operations to process.env
    protectDeletes: true,       // Control delete operations on process.env
    protectEnumeration: true    // Filter ownKeys to only show allowed vars
};

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
 * @param {Object|null} directConfig - Direct config object (for worker threads)
 * @returns {Object} Normalized whitelist configuration
 */
function loadConfig(customPath = null, directConfig = null) {
    // If direct config is provided (e.g., for worker threads), use it
    if (directConfig && typeof directConfig === 'object') {
        const whitelist = directConfig.environmentWhitelist || directConfig;
        const { config, options } = normalizeConfig(whitelist);
        cachedConfig = config;
        cachedOptions = options;
        configPath = '<worker:direct>';
        return cachedConfig;
    }

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
        const { config, options } = normalizeConfig(whitelist);
        cachedConfig = config;
        cachedOptions = options;

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
 * Get a serializable copy of the current config for passing to workers
 * @returns {Object} Config object that can be serialized
 */
function getSerializableConfig() {
    return {
        config: cachedConfig,
        options: cachedOptions
    };
}

/**
 * Normalize whitelist configuration to a consistent format
 * Extracts __options__ into separate options object
 * @param {Object} whitelist - Raw whitelist from package.json
 * @returns {Object} Object with { config, options }
 */
function normalizeConfig(whitelist) {
    const normalized = {};
    let options = { ...DEFAULT_OPTIONS };

    for (const [packageName, config] of Object.entries(whitelist)) {
        // Handle __options__ special key
        if (packageName === '__options__') {
            if (typeof config === 'object' && config !== null && !Array.isArray(config)) {
                options = {
                    failClosed: config.failClosed !== false,  // Default true
                    protectWrites: config.protectWrites !== false,  // Default true
                    protectDeletes: config.protectDeletes !== false,  // Default true
                    protectEnumeration: config.protectEnumeration !== false  // Default true
                };
            }
            continue;
        }

        if (typeof config === 'object' && config !== null && !Array.isArray(config)) {
            // Full object format
            normalized[packageName] = {
                allowed: Array.isArray(config.allowed) ? config.allowed : [],
                canWrite: Array.isArray(config.canWrite) ? config.canWrite : [],
                canDelete: Array.isArray(config.canDelete) ? config.canDelete : [],
                allowPeerDependencies: Boolean(config.allowPeerDependencies)
            };
        } else if (Array.isArray(config)) {
            // Shorthand: just an array of allowed vars
            normalized[packageName] = {
                allowed: config,
                canWrite: [],
                canDelete: [],
                allowPeerDependencies: false
            };
        } else if (typeof config === 'string') {
            // Single env var as string
            normalized[packageName] = {
                allowed: [config],
                canWrite: [],
                canDelete: [],
                allowPeerDependencies: false
            };
        }
        // Skip invalid entries
    }

    return { config: normalized, options };
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
 * Get the current options (loads config if not cached)
 * @returns {Object} Options configuration
 */
function getOptions() {
    if (!cachedOptions) {
        loadConfig();
    }
    return cachedOptions || DEFAULT_OPTIONS;
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
    cachedOptions = null;
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
    getOptions,
    getConfigPath,
    clearCache,
    reloadConfig,
    hasWhitelistEntry,
    getAllowedForPackage,
    normalizeConfig,
    getSerializableConfig,
    DEFAULT_OPTIONS
};
