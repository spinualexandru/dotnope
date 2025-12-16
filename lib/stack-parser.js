'use strict';

const path = require('path');

// Lazy-load native bridge to avoid circular dependencies
let nativeBridge = null;
function getNativeBridge() {
    if (nativeBridge === null) {
        nativeBridge = require('./native-bridge');
    }
    return nativeBridge;
}

// Capture and freeze Error stack trace methods at module load
// This prevents malicious code from tampering with stack capture
const originalCaptureStackTrace = Error.captureStackTrace;
const originalStackTraceLimit = Error.stackTraceLimit;

// Track if stack trace tampering was detected at load time
let tamperingDetected = false;

// Detect pre-load hijacking at module load time
// If Error.prepareStackTrace was already modified, warn about potential tampering
let tamperingWarningEmitted = false;
const prepareStackTraceAtLoad = Error.prepareStackTrace;
if (prepareStackTraceAtLoad !== undefined) {
    // V8's default is undefined - if it's set, someone modified it before us
    tamperingDetected = true;
    if (!tamperingWarningEmitted) {
        console.warn('[dotnope] WARNING: Error.prepareStackTrace was modified before dotnope loaded!');
        console.warn('[dotnope] Stack trace analysis may be compromised.');
        console.warn('[dotnope] For maximum security, ensure dotnope loads first or build the native addon.');
        tamperingWarningEmitted = true;
    }
}

// Attempt to freeze captureStackTrace to prevent tampering
// Note: This only provides partial protection; native code can still bypass
try {
    Object.defineProperty(Error, 'captureStackTrace', {
        value: originalCaptureStackTrace,
        writable: false,
        configurable: false,
        enumerable: false
    });
} catch (e) {
    // Already frozen or not configurable - that's fine
}

// Also try to freeze prepareStackTrace if it's not already set
// This prevents future tampering (but not past tampering)
try {
    if (!tamperingDetected) {
        Object.defineProperty(Error, 'prepareStackTrace', {
            value: undefined,
            writable: false,
            configurable: false
        });
    }
} catch (e) {
    // Cannot freeze - might already be non-configurable
}

// Cache for file path -> package name mapping
const packageCache = new Map();

// Eval detection patterns
const EVAL_FUNCTION_NAMES = ['eval', 'Function', 'anonymous'];
const EVAL_FILENAME_PATTERNS = [/^eval at/, /^\[eval\]/, /^<anonymous>/, /^evalmachine\./];

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
    const bridge = getNativeBridge();

    // Try native first - more secure, immune to Error.prepareStackTrace tampering
    if (bridge.isNativeAvailable()) {
        const nativeResult = bridge.getCallerInfo(skipFrames + 1);
        if (nativeResult) {
            return {
                packageName: nativeResult.packageName,
                fileName: nativeResult.fileName,
                lineNumber: nativeResult.lineNumber,
                columnNumber: nativeResult.columnNumber,
                functionName: nativeResult.functionName || '<anonymous>',
                isEval: nativeResult.isEval || false,
                isConstructor: nativeResult.isConstructor || false
            };
        }

        // Native returned null - check async context as fallback
        const asyncContext = bridge.getAsyncContext();
        if (asyncContext && asyncContext !== '__main__') {
            return {
                packageName: asyncContext,
                fileName: '<async>',
                lineNumber: 0,
                columnNumber: 0,
                functionName: '<promise>',
                isEval: false,
                isAsync: true
            };
        }
    }

    // Fall back to JavaScript implementation
    return getCallingPackageJS(skipFrames);
}

/**
 * Enhanced eval detection using multiple heuristics
 * More reliable than V8's frame.isEval() alone
 * @param {Object} frame - V8 stack frame
 * @returns {boolean} True if frame appears to be from eval/Function context
 */
function detectEvalContext(frame) {
    // Check V8's built-in isEval
    if (typeof frame.isEval === 'function' && frame.isEval()) {
        return true;
    }

    // Check getEvalOrigin for eval'd code
    if (typeof frame.getEvalOrigin === 'function') {
        const evalOrigin = frame.getEvalOrigin();
        if (evalOrigin) {
            return true;
        }
    }

    // Check function name patterns
    const funcName = frame.getFunctionName?.() || '';
    for (const evalName of EVAL_FUNCTION_NAMES) {
        if (funcName === evalName || funcName.includes(evalName)) {
            return true;
        }
    }

    // Check filename patterns for eval
    const fileName = frame.getFileName?.() || '';
    for (const pattern of EVAL_FILENAME_PATTERNS) {
        if (pattern.test(fileName)) {
            return true;
        }
    }

    // Check for null/undefined filename with non-anonymous function
    // This often indicates dynamically generated code
    if (!fileName && funcName && funcName !== '<anonymous>') {
        return true;
    }

    return false;
}

/**
 * Scan entire stack for eval context indicators
 * @param {Array} stack - Array of V8 stack frames
 * @returns {boolean} True if any frame indicates eval context
 */
function hasEvalInStack(stack) {
    for (const frame of stack) {
        if (detectEvalContext(frame)) {
            return true;
        }
    }
    return false;
}

/**
 * JavaScript-only implementation of getCallingPackage
 * Used when native addon is not available
 * @param {number} skipFrames - Number of internal frames to skip
 * @returns {Object|null} Caller info or null if cannot determine
 */
function getCallingPackageJS(skipFrames = 0) {
    const savedPrepareStackTrace = Error.prepareStackTrace;
    const savedStackTraceLimit = Error.stackTraceLimit;

    try {
        Error.stackTraceLimit = 30; // Capture enough frames
        Error.prepareStackTrace = (err, stack) => stack;

        const err = new Error();
        // Use our captured original to prevent tampering
        originalCaptureStackTrace.call(Error, err, getCallingPackageJS);

        const stack = err.stack;

        if (!stack || stack.length === 0) {
            return null;
        }

        // Check for eval anywhere in the stack (more thorough detection)
        const evalDetectedInStack = hasEvalInStack(stack);

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

            // Enhanced eval detection - check this frame AND overall stack
            const isEval = detectEvalContext(frame) || evalDetectedInStack;
            const isConstructor = typeof frame.isConstructor === 'function' ? frame.isConstructor() : false;

            return {
                packageName,
                fileName,
                lineNumber: frame.getLineNumber(),
                columnNumber: frame.getColumnNumber(),
                functionName: frame.getFunctionName() || '<anonymous>',
                isEval,
                isConstructor
            };
        }

        return null;
    } finally {
        Error.prepareStackTrace = savedPrepareStackTrace;
        Error.stackTraceLimit = savedStackTraceLimit;
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
        // Verify it's actually dotnope's lib by checking package.json name
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
    const savedPrepareStackTrace = Error.prepareStackTrace;
    const savedStackTraceLimit = Error.stackTraceLimit;

    try {
        Error.stackTraceLimit = 15;
        Error.prepareStackTrace = (err, stack) => stack;

        const err = new Error();
        // Use our captured original to prevent tampering
        originalCaptureStackTrace.call(Error, err, getFormattedStack);

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
        Error.prepareStackTrace = savedPrepareStackTrace;
        Error.stackTraceLimit = savedStackTraceLimit;
    }
}

/**
 * Check if stack trace tampering was detected at module load
 * @returns {boolean} True if tampering was detected
 */
function wasTamperingDetected() {
    return tamperingDetected;
}

module.exports = {
    getCallingPackage,
    extractPackageName,
    clearCache,
    getFormattedStack,
    isInternalFile,
    wasTamperingDetected
};
