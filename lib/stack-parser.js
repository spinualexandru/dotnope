'use strict';

const path = require('path');

// Cache for file path -> package name mapping
const packageCache = new Map();

// Paths to skip when walking the stack (relative to project root)
const INTERNAL_PATHS = [
    'lib/proxy.js',
    'lib/stack-parser.js',
    'lib/dotnope.js',
    'lib/config-loader.js',
    'lib/dependency-resolver.js'
];

/**
 * Get information about the package that is calling into process.env
 * @param {number} skipFrames - Number of internal frames to skip
 * @returns {Object|null} Caller info or null if cannot determine
 */
function getCallingPackage(skipFrames = 0) {
    const originalPrepareStackTrace = Error.prepareStackTrace;
    const originalStackTraceLimit = Error.stackTraceLimit;

    try {
        Error.stackTraceLimit = 30; // Capture enough frames
        Error.prepareStackTrace = (err, stack) => stack;

        const err = new Error();
        Error.captureStackTrace(err, getCallingPackage);

        const stack = err.stack;

        if (!stack || stack.length === 0) {
            return null;
        }

        // Walk through stack frames
        for (let i = skipFrames; i < stack.length; i++) {
            const frame = stack[i];
            const fileName = frame.getFileName();

            if (!fileName) continue;

            // Skip internal Node.js modules
            if (fileName.startsWith('node:') || fileName.startsWith('internal/')) {
                continue;
            }

            // Skip dotnope's own files
            if (isInternalFile(fileName)) {
                continue;
            }

            // Extract package name from file path
            const packageName = extractPackageName(fileName);

            return {
                packageName,
                fileName,
                lineNumber: frame.getLineNumber(),
                columnNumber: frame.getColumnNumber(),
                functionName: frame.getFunctionName() || '<anonymous>'
            };
        }

        return null;
    } finally {
        Error.prepareStackTrace = originalPrepareStackTrace;
        Error.stackTraceLimit = originalStackTraceLimit;
    }
}

/**
 * Check if a file path belongs to dotnope internals
 * @param {string} filePath
 * @returns {boolean}
 */
function isInternalFile(filePath) {
    const normalized = path.normalize(filePath);

    // Check if it's in the dotnope module's lib folder
    // Match paths like: /node_modules/dotnope/lib/proxy.js
    // Or development paths like: /path/to/dotnope/lib/proxy.js (but NOT in node_modules)

    for (const internalPath of INTERNAL_PATHS) {
        // Check for node_modules/dotnope/lib/... pattern
        if (normalized.includes(`node_modules${path.sep}dotnope${path.sep}`) &&
            normalized.endsWith(internalPath)) {
            return true;
        }
    }

    // Check for dotnope entry points in node_modules
    if (normalized.includes(`node_modules${path.sep}dotnope${path.sep}`)) {
        if (normalized.endsWith(`dotnope${path.sep}index.js`) ||
            normalized.endsWith(`dotnope${path.sep}index.mjs`)) {
            return true;
        }
    }

    // For development: check if this IS the dotnope module (not in node_modules)
    // by seeing if lib/proxy.js etc exists relative to the path
    const dirName = path.dirname(normalized);
    const baseName = path.basename(normalized);

    // Check if it's directly in dotnope's own lib folder during development
    if (dirName.endsWith(`${path.sep}lib`) &&
        !normalized.includes('node_modules') &&
        INTERNAL_PATHS.some(p => normalized.endsWith(p))) {
        // Verify it's actually dotnope's lib by checking parent dir has binding.gyp
        const possibleRoot = path.dirname(dirName);
        try {
            const pkgPath = path.join(possibleRoot, 'package.json');
            const pkg = JSON.parse(require('fs').readFileSync(pkgPath, 'utf8'));
            if (pkg.name === 'dotnope') {
                return true;
            }
        } catch (e) {
            // Not dotnope's lib
        }
    }

    return false;
}

/**
 * Extract package name from a file path
 * @param {string} filePath - Full path to a file
 * @returns {string} Package name or '__main__' for app code
 */
function extractPackageName(filePath) {
    // Check cache first
    if (packageCache.has(filePath)) {
        return packageCache.get(filePath);
    }

    const normalized = path.normalize(filePath);

    // Find the last occurrence of node_modules in the path
    // (handles nested node_modules)
    const nodeModulesIndex = normalized.lastIndexOf(`${path.sep}node_modules${path.sep}`);

    let packageName;

    if (nodeModulesIndex === -1) {
        // Not in node_modules - this is the main application
        packageName = '__main__';
    } else {
        // Extract package name from node_modules path
        const afterNodeModules = normalized.slice(
            nodeModulesIndex + `${path.sep}node_modules${path.sep}`.length
        );
        const parts = afterNodeModules.split(path.sep);

        if (parts[0] && parts[0].startsWith('@')) {
            // Scoped package: @scope/package-name
            packageName = `${parts[0]}/${parts[1]}`;
        } else {
            // Regular package
            packageName = parts[0];
        }
    }

    // Cache the result
    packageCache.set(filePath, packageName);

    return packageName;
}

/**
 * Clear the package name cache
 */
function clearCache() {
    packageCache.clear();
}

/**
 * Get a formatted stack trace string for error messages
 * @param {number} skipFrames - Number of frames to skip
 * @returns {string}
 */
function getFormattedStack(skipFrames = 0) {
    const originalPrepareStackTrace = Error.prepareStackTrace;
    const originalStackTraceLimit = Error.stackTraceLimit;

    try {
        Error.stackTraceLimit = 15;
        Error.prepareStackTrace = (err, stack) => stack;

        const err = new Error();
        Error.captureStackTrace(err, getFormattedStack);

        const stack = err.stack;
        const lines = [];

        for (let i = skipFrames; i < Math.min(stack.length, skipFrames + 10); i++) {
            const frame = stack[i];
            const fileName = frame.getFileName() || '<unknown>';
            const lineNumber = frame.getLineNumber() || '?';
            const functionName = frame.getFunctionName() || '<anonymous>';
            lines.push(`    at ${functionName} (${fileName}:${lineNumber})`);
        }

        return lines.join('\n');
    } finally {
        Error.prepareStackTrace = originalPrepareStackTrace;
        Error.stackTraceLimit = originalStackTraceLimit;
    }
}

module.exports = {
    getCallingPackage,
    extractPackageName,
    clearCache,
    getFormattedStack,
    isInternalFile
};
