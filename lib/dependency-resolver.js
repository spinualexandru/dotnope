'use strict';

const fs = require('fs');
const path = require('path');

// Cache: packageName -> Set of dependency names
const dependencyCache = new Map();

// Cache: envVar -> Set of packages allowed to access it
const envVarAllowedCache = new Map();

// Track warnings already emitted to avoid spam
const peerDepWarningsEmitted = new Set();

/**
 * Resolve the path to a package's directory
 * @param {string} packageName - Name of the package
 * @param {string} fromDir - Directory to start searching from
 * @returns {string|null} Path to package directory or null
 */
function resolvePackagePath(packageName, fromDir = process.cwd()) {
    // Handle scoped packages
    const packageParts = packageName.split('/');

    let searchDir = path.resolve(fromDir);

    while (searchDir !== path.dirname(searchDir)) {
        const nodeModulesPath = path.join(searchDir, 'node_modules');

        let pkgDir;
        if (packageParts.length >= 2 && packageParts[0].startsWith('@')) {
            // Scoped package
            pkgDir = path.join(nodeModulesPath, packageParts[0], packageParts[1]);
        } else {
            pkgDir = path.join(nodeModulesPath, packageName);
        }

        const pkgJsonPath = path.join(pkgDir, 'package.json');

        if (fs.existsSync(pkgJsonPath)) {
            return pkgDir;
        }

        searchDir = path.dirname(searchDir);
    }

    return null;
}

/**
 * Get all dependencies of a package
 * @param {string} packageName
 * @returns {Set<string>} Set of dependency names
 */
function getPackageDependencies(packageName) {
    // Check cache
    if (dependencyCache.has(packageName)) {
        return dependencyCache.get(packageName);
    }

    const pkgDir = resolvePackagePath(packageName);

    if (!pkgDir) {
        dependencyCache.set(packageName, new Set());
        return new Set();
    }

    const pkgJsonPath = path.join(pkgDir, 'package.json');

    try {
        const pkgContent = fs.readFileSync(pkgJsonPath, 'utf8');
        const pkg = JSON.parse(pkgContent);

        const deps = new Set();

        // Include all dependency types that could access env vars
        const allDeps = {
            ...pkg.dependencies,
            ...pkg.peerDependencies,
            ...pkg.optionalDependencies
        };

        for (const depName of Object.keys(allDeps)) {
            deps.add(depName);
        }

        dependencyCache.set(packageName, deps);
        return deps;
    } catch (err) {
        dependencyCache.set(packageName, new Set());
        return new Set();
    }
}

/**
 * Check if childPackage is a dependency of parentPackage
 * @param {string} childPackage
 * @param {string} parentPackage
 * @returns {boolean}
 */
function isDependencyOf(childPackage, parentPackage) {
    const deps = getPackageDependencies(parentPackage);
    return deps.has(childPackage);
}

/**
 * Get dependencies with depth limit
 * @param {string} packageName - Package to get dependencies for
 * @param {number} depthLimit - Maximum depth (1 = direct deps only)
 * @param {Set<string>} excludePackages - Packages to exclude
 * @param {number} currentDepth - Current recursion depth
 * @param {Set<string>} visited - Already visited packages
 * @returns {Set<string>} Set of dependency names
 */
function getDependenciesWithLimit(packageName, depthLimit, excludePackages = new Set(), currentDepth = 0, visited = new Set()) {
    if (currentDepth >= depthLimit) {
        return visited;
    }

    const deps = getPackageDependencies(packageName);

    for (const dep of deps) {
        // Skip excluded packages
        if (excludePackages.has(dep)) {
            continue;
        }

        // Skip already visited to prevent infinite loops
        if (visited.has(dep)) {
            continue;
        }

        visited.add(dep);

        // Recurse if we have depth remaining
        if (currentDepth + 1 < depthLimit) {
            getDependenciesWithLimit(dep, depthLimit, excludePackages, currentDepth + 1, visited);
        }
    }

    return visited;
}

/**
 * Get all packages that are allowed to access a specific env var
 * @param {string} envVar - Environment variable name
 * @param {Object} config - Whitelist configuration
 * @returns {Set<string>} Set of allowed package names
 */
function getAllowedPackagesForEnvVar(envVar, config) {
    // Check cache first - config is loaded once at init and cleared on disable
    if (envVarAllowedCache.has(envVar)) {
        return envVarAllowedCache.get(envVar);
    }

    const allowedPackages = new Set();

    for (const [packageName, packageConfig] of Object.entries(config)) {
        // Skip options object
        if (packageName === '__options__') {
            continue;
        }

        // Check if this package is allowed to access this env var
        const isAllowed = packageConfig.allowed &&
                         (packageConfig.allowed.includes(envVar) ||
                          packageConfig.allowed.includes('*'));

        if (isAllowed) {
            allowedPackages.add(packageName);

            // If allowPeerDependencies is true, add dependencies with limits
            if (packageConfig.allowPeerDependencies) {
                // Get depth limit (default: unlimited for backwards compatibility)
                // A depth of 1 means only direct dependencies
                const depthLimit = typeof packageConfig.peerDepthLimit === 'number'
                    ? packageConfig.peerDepthLimit
                    : 99; // Effectively unlimited

                // Get excluded packages
                const excludePackages = new Set(packageConfig.excludePeerDependencies || []);

                // Get dependencies with limits
                const deps = getDependenciesWithLimit(packageName, depthLimit, excludePackages);

                for (const dep of deps) {
                    allowedPackages.add(dep);
                }

                // Log warning for sensitive env vars with deep or unlimited propagation
                if (depthLimit > 2 && !envVar.startsWith('NODE_') && !envVar.startsWith('npm_')) {
                    // Only warn once per package/envVar combination
                    const warnKey = `${packageName}:${envVar}`;
                    if (!peerDepWarningsEmitted.has(warnKey)) {
                        console.warn(`[dotnope] WARNING: "${packageName}" grants "${envVar}" access to ${deps.size} peer dependencies.`);
                        console.warn(`[dotnope] Consider setting peerDepthLimit to limit propagation.`);
                        peerDepWarningsEmitted.add(warnKey);
                    }
                }
            }
        }
    }

    envVarAllowedCache.set(envVar, allowedPackages);
    return allowedPackages;
}

/**
 * Check if a package is allowed to access an env var
 * @param {string} packageName
 * @param {string} envVar
 * @param {Object} config - Whitelist configuration
 * @returns {boolean}
 */
function isPackageAllowed(packageName, envVar, config) {
    // Main application always has access
    if (packageName === '__main__') {
        return true;
    }

    const allowedPackages = getAllowedPackagesForEnvVar(envVar, config);
    return allowedPackages.has(packageName);
}

/**
 * Clear all caches
 */
function clearCache() {
    dependencyCache.clear();
    envVarAllowedCache.clear();
    peerDepWarningsEmitted.clear();
}

/**
 * Get dependency tree for a package (recursive, with depth limit)
 * @param {string} packageName
 * @param {number} maxDepth
 * @param {number} currentDepth
 * @param {Set<string>} visited
 * @returns {Set<string>}
 */
function getDependencyTree(packageName, maxDepth = 3, currentDepth = 0, visited = new Set()) {
    if (currentDepth >= maxDepth || visited.has(packageName)) {
        return visited;
    }

    visited.add(packageName);
    const deps = getPackageDependencies(packageName);

    for (const dep of deps) {
        getDependencyTree(dep, maxDepth, currentDepth + 1, visited);
    }

    return visited;
}

module.exports = {
    resolvePackagePath,
    getPackageDependencies,
    isDependencyOf,
    getAllowedPackagesForEnvVar,
    isPackageAllowed,
    clearCache,
    getDependencyTree,
    getDependenciesWithLimit
};
