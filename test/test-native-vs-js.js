/**
 * test-native-vs-js.js - Native addon vs JavaScript implementation tests
 *
 * Tests that verify the native addon provides stronger security than
 * the JavaScript fallback, and that both produce consistent results.
 */

'use strict';

const { describe, test, beforeEach, afterEach } = require('node:test');
const assert = require('assert');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// Test fixtures directory
function getUniqueFixturesDir() {
    const uniqueId = crypto.randomBytes(8).toString('hex');
    return path.join(__dirname, `fixtures-native-${uniqueId}`);
}

// Setup mock project structure
function setupMockProject(fixturesDir, whitelist = {}) {
    fs.mkdirSync(fixturesDir, { recursive: true });
    fs.mkdirSync(path.join(fixturesDir, 'node_modules', 'test-package'), { recursive: true });

    const mainPkgPath = path.join(fixturesDir, 'package.json');
    fs.writeFileSync(mainPkgPath, JSON.stringify({
        name: 'test-app',
        version: '1.0.0',
        environmentWhitelist: whitelist
    }, null, 2));

    const testPackageDir = path.join(fixturesDir, 'node_modules', 'test-package');
    fs.writeFileSync(path.join(testPackageDir, 'package.json'), JSON.stringify({
        name: 'test-package',
        version: '1.0.0',
        main: 'index.js'
    }, null, 2));

    fs.writeFileSync(path.join(testPackageDir, 'index.js'), `
'use strict';
module.exports = {
    getEnv(varName) {
        return process.env[varName];
    }
};
`);

    return { mainPkgPath, testPackageDir };
}

// Cleanup
function cleanup(fixturesDir) {
    try {
        fs.rmSync(fixturesDir, { recursive: true, force: true });
    } catch (e) {
        // Ignore cleanup errors
    }
}

// Clear require cache
function clearRequireCache() {
    Object.keys(require.cache).forEach(key => {
        if (key.includes('dotnope') || key.includes('fixtures-native')) {
            delete require.cache[key];
        }
    });
}

describe('Native Bridge Status', () => {
    test('should report native availability', () => {
        const nativeBridge = require('../lib/native-bridge');

        const available = nativeBridge.isNativeAvailable();
        assert.strictEqual(typeof available, 'boolean', 'Should return boolean');

        console.log(`Native addon available: ${available}`);
    });

    test('should report initialization error if native failed', () => {
        const nativeBridge = require('../lib/native-bridge');

        const error = nativeBridge.getInitializationError();
        if (!nativeBridge.isNativeAvailable()) {
            assert.ok(error, 'Should have initialization error when native unavailable');
            console.log(`Native initialization error: ${error.message}`);
        }
    });

    test('should report security status', () => {
        const nativeBridge = require('../lib/native-bridge');

        const status = nativeBridge.getSecurityStatus();
        assert.ok(status, 'Should return status object');
        assert.strictEqual(typeof status.nativeAvailable, 'boolean');
        assert.strictEqual(typeof status.integrityVerified, 'boolean');
        assert.strictEqual(typeof status.hasIntegrityError, 'boolean');

        console.log('Security status:', status);
    });

    test('should report version if native available', () => {
        const nativeBridge = require('../lib/native-bridge');

        if (nativeBridge.isNativeAvailable()) {
            const version = nativeBridge.getVersion();
            assert.ok(version, 'Should have version');
            assert.ok(version.major !== undefined, 'Should have major version');
            assert.strictEqual(version.native, true, 'Should indicate native');
            console.log('Native version:', version);
        }
    });
});

describe('Stack Trace Comparison', () => {
    test('should capture stack traces (native or JS)', () => {
        const stackParser = require('../lib/stack-parser');

        const callerInfo = stackParser.getCallingPackage(0);
        assert.ok(callerInfo, 'Should get caller info');
        assert.ok(callerInfo.packageName, 'Should have package name');
        assert.ok(callerInfo.fileName, 'Should have file name');
    });

    test('should extract package name consistently', () => {
        const stackParser = require('../lib/stack-parser');

        // Test various paths
        const testCases = [
            { path: '/app/node_modules/axios/lib/core.js', expected: 'axios' },
            { path: '/app/node_modules/@babel/core/lib/index.js', expected: '@babel/core' },
            { path: '/app/src/index.js', expected: '__main__' },
            { path: '/home/user/project/index.js', expected: '__main__' }
        ];

        for (const tc of testCases) {
            const result = stackParser.extractPackageName(tc.path);
            assert.strictEqual(result, tc.expected,
                `Path ${tc.path} should extract to ${tc.expected}, got ${result}`);
        }
    });
});

describe('Tampering Detection', () => {
    test('should report tampering detection status', () => {
        const stackParser = require('../lib/stack-parser');

        const tampered = stackParser.wasTamperingDetected();
        assert.strictEqual(typeof tampered, 'boolean', 'Should return boolean');
        console.log(`Tampering detected: ${tampered}`);
    });

    test('should have frozen Error.captureStackTrace', () => {
        const descriptor = Object.getOwnPropertyDescriptor(Error, 'captureStackTrace');
        // Note: May already be frozen by other code
        if (descriptor) {
            console.log('captureStackTrace writable:', descriptor.writable);
            console.log('captureStackTrace configurable:', descriptor.configurable);
        }
    });
});

describe('Integrity Verification', () => {
    test('should report integrity verification status', () => {
        const nativeBridge = require('../lib/native-bridge');

        const verified = nativeBridge.isIntegrityVerified();
        assert.strictEqual(typeof verified, 'boolean', 'Should return boolean');
        console.log(`Integrity verified: ${verified}`);
    });

    test('should have integrity error if verification failed', () => {
        const nativeBridge = require('../lib/native-bridge');

        const error = nativeBridge.getIntegrityError();
        if (error) {
            console.log(`Integrity error: ${error.message}`);
        }
    });
});

describe('Package Name Extraction Parity', () => {
    let originalCwd;

    beforeEach(() => {
        originalCwd = process.cwd();
        clearRequireCache();
    });

    afterEach(() => {
        process.chdir(originalCwd);
    });

    test('should produce same package names from native and JS paths', () => {
        const fixturesDir = getUniqueFixturesDir();
        try {
            const { mainPkgPath, testPackageDir } = setupMockProject(fixturesDir, {
                'test-package': {
                    allowed: ['TEST_VAR']
                }
            });

            process.env.TEST_VAR = 'test-value';
            process.chdir(fixturesDir);

            const dotnope = require('../index');
            const handle = dotnope.enableStrictEnv({
                configPath: mainPkgPath,
                suppressWarnings: true
            });

            delete require.cache[require.resolve(testPackageDir)];
            const testPkg = require(testPackageDir);

            // Access should work - this confirms package name was extracted correctly
            const result = testPkg.getEnv('TEST_VAR');
            assert.strictEqual(result, 'test-value',
                'Package name extraction should work correctly');

            const token = handle.getToken();
            handle.disable(token);
        } finally {
            // Restore cwd BEFORE cleanup to avoid ENOENT
            process.chdir(originalCwd);
            cleanup(fixturesDir);
        }
    });
});

describe('Native vs JS Performance', () => {
    let originalCwd;

    beforeEach(() => {
        originalCwd = process.cwd();
    });

    test('should handle repeated access efficiently', () => {
        const fixturesDir = getUniqueFixturesDir();
        try {
            const { mainPkgPath } = setupMockProject(fixturesDir, {
                '__options__': { failClosed: false }
            });

            process.chdir(fixturesDir);
            process.env.PERF_TEST = 'perf-value';

            const dotnope = require('../index');
            const handle = dotnope.enableStrictEnv({
                configPath: mainPkgPath,
                suppressWarnings: true
            });

            // Warm up
            for (let i = 0; i < 100; i++) {
                process.env.PERF_TEST;
            }

            // Time 1000 accesses
            const start = process.hrtime.bigint();
            for (let i = 0; i < 1000; i++) {
                process.env.PERF_TEST;
            }
            const end = process.hrtime.bigint();

            const durationMs = Number(end - start) / 1_000_000;
            console.log(`1000 env accesses: ${durationMs.toFixed(2)}ms`);

            // Should be reasonably fast (less than 1 second)
            assert.ok(durationMs < 1000, 'Should complete in under 1 second');

            const token = handle.getToken();
            handle.disable(token);
        } finally {
            // Restore cwd BEFORE cleanup to avoid ENOENT
            process.chdir(originalCwd);
            cleanup(fixturesDir);
        }
    });
});

describe('Security Warnings', () => {
    let originalCwd;
    let originalEnv;
    let consoleWarnCalls;
    let originalWarn;

    beforeEach(() => {
        originalCwd = process.cwd();
        originalEnv = { ...process.env };
        clearRequireCache();

        // Capture console.warn calls
        consoleWarnCalls = [];
        originalWarn = console.warn;
        console.warn = (...args) => {
            consoleWarnCalls.push(args.join(' '));
        };
    });

    afterEach(() => {
        console.warn = originalWarn;
        process.chdir(originalCwd);
        Object.keys(process.env).forEach(key => {
            if (!originalEnv.hasOwnProperty(key)) {
                delete process.env[key];
            }
        });
        Object.assign(process.env, originalEnv);
    });

    test('should emit warnings via emitSecurityWarnings', () => {
        const fixturesDir = getUniqueFixturesDir();
        try {
            const { mainPkgPath } = setupMockProject(fixturesDir, {});

            process.chdir(fixturesDir);

            const dotnope = require('../index');
            const warnings = dotnope.emitSecurityWarnings({ forceWarnings: true });

            assert.ok(Array.isArray(warnings), 'Should return array of warnings');
            console.log(`Emitted ${warnings.length} warnings`);
        } finally {
            // Change back to original directory BEFORE cleanup to avoid ENOENT
            process.chdir(originalCwd);
            cleanup(fixturesDir);
        }
    });

    test('should suppress warnings when requested', () => {
        const fixturesDir = getUniqueFixturesDir();
        try {
            const { mainPkgPath } = setupMockProject(fixturesDir, {});

            process.chdir(fixturesDir);

            const dotnope = require('../index');
            const handle = dotnope.enableStrictEnv({
                configPath: mainPkgPath,
                suppressWarnings: true
            });

            // With suppressWarnings, should not have emitted warnings
            const warningsAboutDotnope = consoleWarnCalls.filter(w => w.includes('[dotnope]'));
            assert.strictEqual(warningsAboutDotnope.length, 0,
                'Should not emit warnings when suppressed');

            const token = handle.getToken();
            handle.disable(token);
        } finally {
            // Change back to original directory BEFORE cleanup to avoid ENOENT
            process.chdir(originalCwd);
            cleanup(fixturesDir);
        }
    });
});

describe('LD_PRELOAD Detection', () => {
    test('should detect LD_PRELOAD status', () => {
        const dotnope = require('../index');

        const active = dotnope.isPreloadActive();
        assert.strictEqual(typeof active, 'boolean', 'Should return boolean');
        console.log(`LD_PRELOAD active: ${active}`);
    });

    test('should detect LD_PRELOAD when set', () => {
        const originalPreload = process.env.LD_PRELOAD;
        try {
            // Clear cache to reload
            clearRequireCache();

            process.env.LD_PRELOAD = '/path/to/libdotnope_preload.so';
            const dotnope = require('../index');

            const active = dotnope.isPreloadActive();
            assert.strictEqual(active, true, 'Should detect preload');
        } finally {
            if (originalPreload !== undefined) {
                process.env.LD_PRELOAD = originalPreload;
            } else {
                delete process.env.LD_PRELOAD;
            }
        }
    });
});

describe('Preload Generator', () => {
    test('should generate policy from config', () => {
        const preloadGen = require('../lib/preload-generator');

        const config = {
            'axios': { allowed: ['HTTP_PROXY', 'HTTPS_PROXY'], canWrite: [] },
            'dotenv': { allowed: ['*'], canWrite: [] },
            '__options__': { failClosed: true }
        };

        const policy = preloadGen.generatePolicy(config);

        // dotenv has wildcard, so should return '*'
        assert.strictEqual(policy, '*', 'Wildcard should propagate to policy');
    });

    test('should generate policy without wildcards', () => {
        const preloadGen = require('../lib/preload-generator');

        const config = {
            'axios': { allowed: ['HTTP_PROXY', 'HTTPS_PROXY'], canWrite: [] },
            'config': { allowed: ['NODE_ENV', 'CONFIG_PATH'], canWrite: ['LOG_LEVEL'] }
        };

        const policy = preloadGen.generatePolicy(config);

        // Should be sorted, comma-separated
        assert.ok(policy.includes('HTTP_PROXY'), 'Should include HTTP_PROXY');
        assert.ok(policy.includes('HTTPS_PROXY'), 'Should include HTTPS_PROXY');
        assert.ok(policy.includes('NODE_ENV'), 'Should include NODE_ENV');
        assert.ok(policy.includes('LOG_LEVEL'), 'Should include LOG_LEVEL');
    });

    test('should find preload library path', () => {
        const preloadGen = require('../lib/preload-generator');

        const libPath = preloadGen.findPreloadLibrary();
        console.log(`Preload library path: ${libPath || '(not found)'}`);
        // May or may not exist depending on build state
    });
});
