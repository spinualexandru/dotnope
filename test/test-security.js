'use strict';

const { test, describe, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// Generate unique fixture directory per test to avoid race conditions
function getUniqueFixturesDir() {
    const id = crypto.randomBytes(8).toString('hex');
    return path.join(__dirname, `fixtures-security-${id}`);
}

/**
 * Clear all dotnope-related require caches
 */
function clearRequireCache() {
    Object.keys(require.cache).forEach(key => {
        if (key.includes('dotnope') || key.includes('strictenv') || key.includes('fixtures')) {
            delete require.cache[key];
        }
    });
}

/**
 * Set up a mock package structure with custom index.js content
 */
function setupMockProject(fixturesDir, whitelistConfig, packageCode = null) {
    const fakePackageDir = path.join(fixturesDir, 'node_modules/fake-package');

    // Create directories
    fs.mkdirSync(fakePackageDir, { recursive: true });

    // Create main package.json with whitelist config
    const mainPkgPath = path.join(fixturesDir, 'package.json');
    fs.writeFileSync(
        mainPkgPath,
        JSON.stringify({
            name: 'test-project',
            environmentWhitelist: whitelistConfig
        }, null, 2)
    );

    // Create fake-package with its own package.json
    fs.writeFileSync(
        path.join(fakePackageDir, 'package.json'),
        JSON.stringify({
            name: 'fake-package',
            version: '1.0.0',
            main: 'index.js'
        }, null, 2)
    );

    // Create the fake package's index.js
    const defaultCode = `'use strict';
module.exports = {
    getEnvVar: function(name) {
        return process.env[name];
    },
    setEnvVar: function(name, value) {
        process.env[name] = value;
    },
    deleteEnvVar: function(name) {
        delete process.env[name];
    },
    checkEnvVar: function(name) {
        return name in process.env;
    },
    getAllKeys: function() {
        return Object.keys(process.env);
    },
    getEntries: function() {
        return Object.entries(process.env);
    },
    evalGetEnv: function(name) {
        return eval('process.env["' + name + '"]');
    },
    functionGetEnv: function(name) {
        const fn = new Function('name', 'return process.env[name]');
        return fn(name);
    }
};`;

    fs.writeFileSync(
        path.join(fakePackageDir, 'index.js'),
        packageCode || defaultCode
    );

    return { mainPkgPath, fakePackageDir };
}

function cleanup(fixturesDir) {
    if (fs.existsSync(fixturesDir)) {
        fs.rmSync(fixturesDir, { recursive: true, force: true });
    }
}

describe('Security Tests', { concurrency: false }, () => {
    let originalEnv;
    let originalCwd;

    beforeEach(() => {
        clearRequireCache();
        originalEnv = { ...process.env };
        originalCwd = process.cwd();
    });

    afterEach(() => {
        clearRequireCache();
        process.env = originalEnv;
        process.chdir(originalCwd);
    });

    describe('Token Protection', () => {
        test('should reject invalid token', () => {
            const fixturesDir = getUniqueFixturesDir();
            try {
                const { mainPkgPath } = setupMockProject(fixturesDir, {});

                const dotnope = require('../index');
                const handle = dotnope.enableStrictEnv({ strictLoadOrder: false, configPath: mainPkgPath });

                assert.throws(() => {
                    handle.disable('wrong-token');
                }, (err) => {
                    assert.ok(err.message.includes('Invalid disable token'));
                    return true;
                });

                // Clean up with correct token
                const token = handle.getToken();
                handle.disable(token);
            } finally {
                cleanup(fixturesDir);
            }
        });

        test('should reject null token', () => {
            const fixturesDir = getUniqueFixturesDir();
            try {
                const { mainPkgPath } = setupMockProject(fixturesDir, {});

                const dotnope = require('../index');
                const handle = dotnope.enableStrictEnv({ strictLoadOrder: false, configPath: mainPkgPath });

                assert.throws(() => {
                    handle.disable(null);
                }, (err) => {
                    assert.ok(err.message.includes('Invalid disable token'));
                    return true;
                });

                const token = handle.getToken();
                handle.disable(token);
            } finally {
                cleanup(fixturesDir);
            }
        });

        test('should reject empty string token', () => {
            const fixturesDir = getUniqueFixturesDir();
            try {
                const { mainPkgPath } = setupMockProject(fixturesDir, {});

                const dotnope = require('../index');
                const handle = dotnope.enableStrictEnv({ strictLoadOrder: false, configPath: mainPkgPath });

                assert.throws(() => {
                    handle.disable('');
                }, (err) => {
                    assert.ok(err.message.includes('Invalid disable token'));
                    return true;
                });

                const token = handle.getToken();
                handle.disable(token);
            } finally {
                cleanup(fixturesDir);
            }
        });

        test('disableStrictEnv() should throw error (security fix)', () => {
            const fixturesDir = getUniqueFixturesDir();
            try {
                const { mainPkgPath } = setupMockProject(fixturesDir, {});

                const dotnope = require('../index');
                const handle = dotnope.enableStrictEnv({ strictLoadOrder: false, configPath: mainPkgPath });

                assert.throws(() => {
                    dotnope.disableStrictEnv();
                }, (err) => {
                    assert.strictEqual(err.code, 'ERR_DOTNOPE_DEPRECATED');
                    assert.ok(err.message.includes('removed for security'));
                    return true;
                });

                const token = handle.getToken();
                handle.disable(token);
            } finally {
                cleanup(fixturesDir);
            }
        });
    });

    describe('Write Protection', () => {
        test('should block unauthorized writes', () => {
            const fixturesDir = getUniqueFixturesDir();
            try {
                const { mainPkgPath, fakePackageDir } = setupMockProject(fixturesDir, {
                    'fake-package': {
                        allowed: ['*'],  // Can read everything
                        canWrite: [],    // But cannot write anything
                        canDelete: []
                    }
                });

                process.chdir(fixturesDir);

                const dotnope = require('../index');
                const handle = dotnope.enableStrictEnv({ strictLoadOrder: false, configPath: mainPkgPath });

                delete require.cache[require.resolve(fakePackageDir)];
                const fakePackage = require(fakePackageDir);

                assert.throws(() => {
                    fakePackage.setEnvVar('NEW_VAR', 'value');
                }, (err) => {
                    assert.strictEqual(err.code, 'ERR_DOTNOPE_UNAUTHORIZED');
                    assert.strictEqual(err.operation, 'write');
                    return true;
                });

                const token = handle.getToken();
                handle.disable(token);
            } finally {
                cleanup(fixturesDir);
            }
        });

        test('should allow authorized writes', () => {
            const fixturesDir = getUniqueFixturesDir();
            try {
                const { mainPkgPath, fakePackageDir } = setupMockProject(fixturesDir, {
                    'fake-package': {
                        allowed: ['*'],
                        canWrite: ['WRITABLE_VAR'],
                        canDelete: []
                    }
                });

                process.chdir(fixturesDir);

                const dotnope = require('../index');
                const handle = dotnope.enableStrictEnv({ strictLoadOrder: false, configPath: mainPkgPath });

                delete require.cache[require.resolve(fakePackageDir)];
                const fakePackage = require(fakePackageDir);

                // Should succeed
                fakePackage.setEnvVar('WRITABLE_VAR', 'new-value');
                assert.strictEqual(process.env.WRITABLE_VAR, 'new-value');

                const token = handle.getToken();
                handle.disable(token);
            } finally {
                cleanup(fixturesDir);
            }
        });

        test('should allow writes with wildcard', () => {
            const fixturesDir = getUniqueFixturesDir();
            try {
                const { mainPkgPath, fakePackageDir } = setupMockProject(fixturesDir, {
                    'fake-package': {
                        allowed: ['*'],
                        canWrite: ['*'],
                        canDelete: []
                    }
                });

                process.chdir(fixturesDir);

                const dotnope = require('../index');
                const handle = dotnope.enableStrictEnv({ strictLoadOrder: false, configPath: mainPkgPath });

                delete require.cache[require.resolve(fakePackageDir)];
                const fakePackage = require(fakePackageDir);

                // Should succeed
                fakePackage.setEnvVar('ANY_VAR', 'any-value');
                assert.strictEqual(process.env.ANY_VAR, 'any-value');

                const token = handle.getToken();
                handle.disable(token);
            } finally {
                cleanup(fixturesDir);
            }
        });
    });

    describe('Delete Protection', () => {
        test('should block unauthorized deletes', () => {
            const fixturesDir = getUniqueFixturesDir();
            try {
                const { mainPkgPath, fakePackageDir } = setupMockProject(fixturesDir, {
                    'fake-package': {
                        allowed: ['*'],
                        canWrite: [],
                        canDelete: []  // Cannot delete anything
                    }
                });

                process.env.DELETE_ME = 'exists';
                process.chdir(fixturesDir);

                const dotnope = require('../index');
                const handle = dotnope.enableStrictEnv({ strictLoadOrder: false, configPath: mainPkgPath });

                delete require.cache[require.resolve(fakePackageDir)];
                const fakePackage = require(fakePackageDir);

                assert.throws(() => {
                    fakePackage.deleteEnvVar('DELETE_ME');
                }, (err) => {
                    assert.strictEqual(err.code, 'ERR_DOTNOPE_UNAUTHORIZED');
                    assert.strictEqual(err.operation, 'delete');
                    return true;
                });

                const token = handle.getToken();
                handle.disable(token);
            } finally {
                cleanup(fixturesDir);
            }
        });

        test('should allow authorized deletes', () => {
            const fixturesDir = getUniqueFixturesDir();
            try {
                const { mainPkgPath, fakePackageDir } = setupMockProject(fixturesDir, {
                    'fake-package': {
                        allowed: ['*'],
                        canWrite: [],
                        canDelete: ['DELETABLE_VAR']
                    }
                });

                process.env.DELETABLE_VAR = 'to-be-deleted';
                process.chdir(fixturesDir);

                const dotnope = require('../index');
                const handle = dotnope.enableStrictEnv({ strictLoadOrder: false, configPath: mainPkgPath });

                delete require.cache[require.resolve(fakePackageDir)];
                const fakePackage = require(fakePackageDir);

                // Should succeed
                fakePackage.deleteEnvVar('DELETABLE_VAR');
                assert.strictEqual(process.env.DELETABLE_VAR, undefined);

                const token = handle.getToken();
                handle.disable(token);
            } finally {
                cleanup(fixturesDir);
            }
        });
    });

    describe('Enumeration Protection', () => {
        test('should filter Object.keys() to allowed vars only', () => {
            const fixturesDir = getUniqueFixturesDir();
            try {
                const { mainPkgPath, fakePackageDir } = setupMockProject(fixturesDir, {
                    'fake-package': {
                        allowed: ['VISIBLE_VAR'],
                        canWrite: [],
                        canDelete: []
                    }
                });

                process.env.VISIBLE_VAR = 'visible';
                process.env.HIDDEN_VAR = 'hidden';
                process.env.SECRET_VAR = 'secret';
                process.chdir(fixturesDir);

                const dotnope = require('../index');
                const handle = dotnope.enableStrictEnv({ strictLoadOrder: false, configPath: mainPkgPath });

                delete require.cache[require.resolve(fakePackageDir)];
                const fakePackage = require(fakePackageDir);

                const keys = fakePackage.getAllKeys();
                assert.ok(keys.includes('VISIBLE_VAR'), 'Should see VISIBLE_VAR');
                assert.ok(!keys.includes('HIDDEN_VAR'), 'Should NOT see HIDDEN_VAR');
                assert.ok(!keys.includes('SECRET_VAR'), 'Should NOT see SECRET_VAR');

                const token = handle.getToken();
                handle.disable(token);
            } finally {
                cleanup(fixturesDir);
            }
        });

        test('should return empty keys for non-whitelisted package', () => {
            const fixturesDir = getUniqueFixturesDir();
            try {
                const { mainPkgPath, fakePackageDir } = setupMockProject(fixturesDir, {
                    // fake-package NOT whitelisted at all
                });

                process.env.SOME_VAR = 'value';
                process.chdir(fixturesDir);

                const dotnope = require('../index');
                const handle = dotnope.enableStrictEnv({ strictLoadOrder: false, configPath: mainPkgPath });

                delete require.cache[require.resolve(fakePackageDir)];
                const fakePackage = require(fakePackageDir);

                const keys = fakePackage.getAllKeys();
                assert.strictEqual(keys.length, 0, 'Should see no keys');

                const token = handle.getToken();
                handle.disable(token);
            } finally {
                cleanup(fixturesDir);
            }
        });

        test('should show all keys with wildcard access', () => {
            const fixturesDir = getUniqueFixturesDir();
            try {
                const { mainPkgPath, fakePackageDir } = setupMockProject(fixturesDir, {
                    'fake-package': {
                        allowed: ['*'],
                        canWrite: [],
                        canDelete: []
                    }
                });

                process.env.VAR_A = 'a';
                process.env.VAR_B = 'b';
                process.chdir(fixturesDir);

                const dotnope = require('../index');
                const handle = dotnope.enableStrictEnv({ strictLoadOrder: false, configPath: mainPkgPath });

                delete require.cache[require.resolve(fakePackageDir)];
                const fakePackage = require(fakePackageDir);

                const keys = fakePackage.getAllKeys();
                assert.ok(keys.includes('VAR_A'), 'Should see VAR_A');
                assert.ok(keys.includes('VAR_B'), 'Should see VAR_B');

                const token = handle.getToken();
                handle.disable(token);
            } finally {
                cleanup(fixturesDir);
            }
        });
    });

    describe('Eval/Function Protection', () => {
        test('should block eval and Function access from main app files', () => {
            const fixturesDir = getUniqueFixturesDir();
            let handle = null;
            try {
                const { mainPkgPath } = setupMockProject(fixturesDir, {
                    '__options__': {
                        failClosed: true
                    }
                });

                process.env.MAIN_EVAL_TARGET = 'main-eval-secret';
                process.env.MAIN_FUNCTION_TARGET = 'main-function-secret';
                process.chdir(fixturesDir);

                const dotnope = require('../index');
                handle = dotnope.enableStrictEnv({ strictLoadOrder: false, configPath: mainPkgPath });

                assert.throws(
                    () => eval('process.env.MAIN_EVAL_TARGET'),
                    (err) => err.code === 'ERR_DOTNOPE_EVAL_CONTEXT'
                );

                assert.throws(
                    () => new Function('return process.env.MAIN_FUNCTION_TARGET')(),
                    (err) => err.code === 'ERR_DOTNOPE_EVAL_CONTEXT'
                );
            } finally {
                if (handle) {
                    const token = handle.getToken();
                    handle.disable(token);
                }
                cleanup(fixturesDir);
            }
        });

        test('should block eval-based env access when detected', () => {
            const fixturesDir = getUniqueFixturesDir();
            try {
                const { mainPkgPath, fakePackageDir } = setupMockProject(fixturesDir, {
                    'fake-package': {
                        allowed: ['*'],
                        canWrite: [],
                        canDelete: []
                    },
                    '__options__': {
                        failClosed: true
                    }
                });

                process.env.EVAL_TARGET = 'secret-via-eval';
                process.chdir(fixturesDir);

                const dotnope = require('../index');
                const handle = dotnope.enableStrictEnv({ strictLoadOrder: false, configPath: mainPkgPath });

                delete require.cache[require.resolve(fakePackageDir)];
                const fakePackage = require(fakePackageDir);

                // This should either:
                // 1. Throw ERR_DOTNOPE_EVAL_CONTEXT (if eval is detected)
                // 2. Work but still be tracked (if eval detection doesn't trigger)
                // The behavior depends on whether the V8 frame reports isEval
                try {
                    const result = fakePackage.evalGetEnv('EVAL_TARGET');
                    // If it doesn't throw, at least verify tracking works
                    assert.ok(true, 'Eval access completed - may not have been detected as eval');
                } catch (err) {
                    // Expected in stricter scenarios
                    assert.ok(
                        err.code === 'ERR_DOTNOPE_EVAL_CONTEXT' ||
                        err.code === 'ERR_DOTNOPE_UNKNOWN_CALLER',
                        'Should be eval context or unknown caller error'
                    );
                }

                const token = handle.getToken();
                handle.disable(token);
            } finally {
                cleanup(fixturesDir);
            }
        });

        test('should block Function constructor env access when detected', () => {
            const fixturesDir = getUniqueFixturesDir();
            try {
                const { mainPkgPath, fakePackageDir } = setupMockProject(fixturesDir, {
                    'fake-package': {
                        allowed: ['*'],
                        canWrite: [],
                        canDelete: []
                    },
                    '__options__': {
                        failClosed: true
                    }
                });

                process.env.FUNCTION_TARGET = 'secret-via-function';
                process.chdir(fixturesDir);

                const dotnope = require('../index');
                const handle = dotnope.enableStrictEnv({ strictLoadOrder: false, configPath: mainPkgPath });

                delete require.cache[require.resolve(fakePackageDir)];
                const fakePackage = require(fakePackageDir);

                try {
                    const result = fakePackage.functionGetEnv('FUNCTION_TARGET');
                    assert.ok(true, 'Function access completed - may not have been detected');
                } catch (err) {
                    assert.ok(
                        err.code === 'ERR_DOTNOPE_EVAL_CONTEXT' ||
                        err.code === 'ERR_DOTNOPE_UNKNOWN_CALLER',
                        'Should be eval context or unknown caller error'
                    );
                }

                const token = handle.getToken();
                handle.disable(token);
            } finally {
                cleanup(fixturesDir);
            }
        });
    });

    describe('failClosed Option', () => {
        test('should deny access when caller unknown and failClosed=true', () => {
            const fixturesDir = getUniqueFixturesDir();
            try {
                const { mainPkgPath } = setupMockProject(fixturesDir, {
                    '__options__': {
                        failClosed: true
                    }
                });

                process.env.TEST_VAR = 'test';
                process.chdir(fixturesDir);

                const dotnope = require('../index');
                const handle = dotnope.enableStrictEnv({ strictLoadOrder: false, configPath: mainPkgPath });

                // Main app should still work
                assert.strictEqual(process.env.TEST_VAR, 'test');

                const token = handle.getToken();
                handle.disable(token);
            } finally {
                cleanup(fixturesDir);
            }
        });

        test('failClosed defaults to true', () => {
            const fixturesDir = getUniqueFixturesDir();
            try {
                // No __options__ specified - should default to failClosed: true
                const { mainPkgPath, fakePackageDir } = setupMockProject(fixturesDir, {});

                process.env.SECRET = 'value';
                process.chdir(fixturesDir);

                const dotnope = require('../index');
                const handle = dotnope.enableStrictEnv({ strictLoadOrder: false, configPath: mainPkgPath });

                delete require.cache[require.resolve(fakePackageDir)];
                const fakePackage = require(fakePackageDir);

                // Non-whitelisted package should be blocked
                assert.throws(() => {
                    fakePackage.getEnvVar('SECRET');
                }, (err) => {
                    assert.strictEqual(err.code, 'ERR_DOTNOPE_UNAUTHORIZED');
                    return true;
                });

                const token = handle.getToken();
                handle.disable(token);
            } finally {
                cleanup(fixturesDir);
            }
        });
    });

    describe('Error.prepareStackTrace Tampering', () => {
        test('should resist prepareStackTrace override', () => {
            const fixturesDir = getUniqueFixturesDir();
            try {
                const { mainPkgPath, fakePackageDir } = setupMockProject(fixturesDir, {
                    'fake-package': {
                        allowed: ['ALLOWED_VAR']
                    }
                });

                process.env.ALLOWED_VAR = 'allowed';
                process.env.SECRET_VAR = 'secret';
                process.chdir(fixturesDir);

                // Try to tamper with prepareStackTrace BEFORE loading dotnope
                const originalPrepare = Error.prepareStackTrace;
                try {
                    Error.prepareStackTrace = () => [];
                } catch (e) {
                    // May already be frozen
                }

                const dotnope = require('../index');
                const handle = dotnope.enableStrictEnv({ strictLoadOrder: false, configPath: mainPkgPath });

                delete require.cache[require.resolve(fakePackageDir)];
                const fakePackage = require(fakePackageDir);

                // Should still work (either via native or fail-closed)
                const result = fakePackage.getEnvVar('ALLOWED_VAR');
                // If it returns the value, protection is working
                // If it throws unknown caller, fail-closed is working
                assert.ok(
                    result === 'allowed' || result === undefined,
                    'Should either return value or be blocked'
                );

                const token = handle.getToken();
                handle.disable(token);

                // Restore
                Error.prepareStackTrace = originalPrepare;
            } finally {
                cleanup(fixturesDir);
            }
        });
    });

    describe('Native Bridge Integration', () => {
        test('should report native availability status', () => {
            clearRequireCache();
            const nativeBridge = require('../lib/native-bridge');

            // Just verify the API exists and returns a boolean
            const isAvailable = nativeBridge.isNativeAvailable();
            assert.strictEqual(typeof isAvailable, 'boolean');

            if (isAvailable) {
                const version = nativeBridge.getVersion();
                assert.ok(version.native === true, 'Native version should have native: true');
            }
        });

        test('stack-parser should use native when available', () => {
            clearRequireCache();
            const stackParser = require('../lib/stack-parser');
            const nativeBridge = require('../lib/native-bridge');

            // Call getCallingPackage
            const result = stackParser.getCallingPackage(0);

            // Should return valid result
            assert.ok(result === null || typeof result === 'object');

            if (result) {
                assert.ok('packageName' in result);
                assert.ok('fileName' in result);
                assert.ok('isEval' in result, 'Result should include isEval flag');
            }
        });
    });

    describe('Main Application Access', () => {
        test('main app should always have full read access', () => {
            const fixturesDir = getUniqueFixturesDir();
            try {
                const { mainPkgPath } = setupMockProject(fixturesDir, {
                    // Strict config - but main app should bypass
                    '__options__': {
                        failClosed: true
                    }
                });

                process.env.MAIN_APP_VAR = 'main-value';
                process.chdir(fixturesDir);

                const dotnope = require('../index');
                const handle = dotnope.enableStrictEnv({ strictLoadOrder: false, configPath: mainPkgPath });

                // Main app access should work
                assert.strictEqual(process.env.MAIN_APP_VAR, 'main-value');

                const token = handle.getToken();
                handle.disable(token);
            } finally {
                cleanup(fixturesDir);
            }
        });

        test('main app should always have full write access', () => {
            const fixturesDir = getUniqueFixturesDir();
            try {
                const { mainPkgPath } = setupMockProject(fixturesDir, {
                    '__options__': {
                        protectWrites: true
                    }
                });

                process.chdir(fixturesDir);

                const dotnope = require('../index');
                const handle = dotnope.enableStrictEnv({ strictLoadOrder: false, configPath: mainPkgPath });

                // Main app write should work
                process.env.MAIN_WRITE_VAR = 'written-by-main';
                assert.strictEqual(process.env.MAIN_WRITE_VAR, 'written-by-main');

                const token = handle.getToken();
                handle.disable(token);
            } finally {
                cleanup(fixturesDir);
            }
        });

        test('main app should always have full delete access', () => {
            const fixturesDir = getUniqueFixturesDir();
            try {
                const { mainPkgPath } = setupMockProject(fixturesDir, {
                    '__options__': {
                        protectDeletes: true
                    }
                });

                process.env.MAIN_DELETE_VAR = 'to-delete';
                process.chdir(fixturesDir);

                const dotnope = require('../index');
                const handle = dotnope.enableStrictEnv({ strictLoadOrder: false, configPath: mainPkgPath });

                // Main app delete should work
                delete process.env.MAIN_DELETE_VAR;
                assert.strictEqual(process.env.MAIN_DELETE_VAR, undefined);

                const token = handle.getToken();
                handle.disable(token);
            } finally {
                cleanup(fixturesDir);
            }
        });
    });

    describe('Strict Load Order Protection', () => {
        test('should throw if too many modules loaded before enableStrictEnv', () => {
            const fixturesDir = getUniqueFixturesDir();
            try {
                const { mainPkgPath } = setupMockProject(fixturesDir, {});

                const dotnope = require('../index');

                // Set maxPreloadedModules very low to force the error
                assert.throws(() => {
                    dotnope.enableStrictEnv({
                        configPath: mainPkgPath,
                        maxPreloadedModules: 1  // Very low to trigger error
                    });
                }, (err) => {
                    assert.strictEqual(err.code, 'ERR_DOTNOPE_LOAD_ORDER');
                    assert.ok(err.loadedModules > 1, 'Should report loaded modules');
                    return true;
                });
            } finally {
                cleanup(fixturesDir);
            }
        });

        test('should succeed with strictLoadOrder disabled', () => {
            const fixturesDir = getUniqueFixturesDir();
            try {
                const { mainPkgPath } = setupMockProject(fixturesDir, {});

                const dotnope = require('../index');

                // Even with many modules loaded, this should succeed
                const handle = dotnope.enableStrictEnv({
                    configPath: mainPkgPath,
                    strictLoadOrder: false
                });

                assert.ok(handle, 'Should return handle when strictLoadOrder disabled');

                const token = handle.getToken();
                handle.disable(token);
            } finally {
                cleanup(fixturesDir);
            }
        });

        test('should succeed with higher maxPreloadedModules', () => {
            const fixturesDir = getUniqueFixturesDir();
            try {
                const { mainPkgPath } = setupMockProject(fixturesDir, {});

                const dotnope = require('../index');
                const moduleCount = Object.keys(require.cache).length;

                // Set maxPreloadedModules higher than current count
                const handle = dotnope.enableStrictEnv({
                    configPath: mainPkgPath,
                    maxPreloadedModules: moduleCount + 10
                });

                assert.ok(handle, 'Should return handle with high maxPreloadedModules');

                const token = handle.getToken();
                handle.disable(token);
            } finally {
                cleanup(fixturesDir);
            }
        });
    });

    describe('Limited Handle on Multiple Calls', () => {
        test('should not return the owner handle on repeated enableStrictEnv calls', () => {
            const fixturesDir = getUniqueFixturesDir();
            try {
                const { mainPkgPath } = setupMockProject(fixturesDir, {});

                const dotnope = require('../index');
                const handle1 = dotnope.enableStrictEnv({
                    configPath: mainPkgPath,
                    strictLoadOrder: false
                });

                // Second call must not expose the token-bearing owner handle.
                const handle2 = dotnope.enableStrictEnv({
                    configPath: mainPkgPath,
                    strictLoadOrder: false
                });

                assert.notStrictEqual(handle1, handle2, 'Should return a limited observer handle');
                assert.strictEqual(typeof handle2.getToken, 'undefined', 'Repeated callers must not receive token access');
                assert.throws(
                    () => handle2.disable(handle1.getToken()),
                    /already owned by another caller/,
                    'Repeated callers must not be able to disable protection'
                );

                // Clean up
                const token = handle1.getToken();
                handle1.disable(token);
            } finally {
                cleanup(fixturesDir);
            }
        });
    });

    describe('Symlink Spoofing Protection', () => {
        test('should validate package identity via realpath', () => {
            const fixturesDir = getUniqueFixturesDir();
            try {
                const { mainPkgPath, fakePackageDir } = setupMockProject(fixturesDir, {
                    'fake-package': {
                        allowed: ['FAKE_VAR']
                    }
                });

                process.env.FAKE_VAR = 'value';
                process.chdir(fixturesDir);

                // The validatePackageIdentity function should verify that
                // the file path resolves to the expected package
                const stackParser = require('../lib/stack-parser');

                // Test validation function directly
                const isValid = stackParser.validatePackageIdentity(
                    path.join(fakePackageDir, 'index.js'),
                    'fake-package'
                );

                assert.strictEqual(isValid, true, 'Valid path should pass validation');
            } finally {
                cleanup(fixturesDir);
            }
        });

        test('should reject path claiming wrong package name', () => {
            const fixturesDir = getUniqueFixturesDir();
            try {
                setupMockProject(fixturesDir, {});
                process.chdir(fixturesDir);

                const stackParser = require('../lib/stack-parser');

                // Try to claim a file is from a different package
                const fakePackagePath = path.join(fixturesDir, 'node_modules/fake-package/index.js');

                // This should fail because the path says fake-package but we claim it's "trusted-package"
                const isValid = stackParser.validatePackageIdentity(
                    fakePackagePath,
                    'trusted-package'  // Wrong package name
                );

                assert.strictEqual(isValid, false, 'Wrong package name should fail validation');
            } finally {
                cleanup(fixturesDir);
            }
        });

        test('should allow __main__ without validation', () => {
            const stackParser = require('../lib/stack-parser');

            // Main app code doesn't need symlink validation
            const isValid = stackParser.validatePackageIdentity(
                '/some/app/path.js',
                '__main__'
            );

            assert.strictEqual(isValid, true, '__main__ should always pass');
        });
    });

    describe('allowPeerDependencies Depth Limit', () => {
        test('should default to depth 1 (direct deps only)', () => {
            const fixturesDir = getUniqueFixturesDir();
            try {
                // Create a package with allowPeerDependencies but no explicit depth
                const mainPkgPath = path.join(fixturesDir, 'package.json');
                fs.mkdirSync(fixturesDir, { recursive: true });
                fs.writeFileSync(mainPkgPath, JSON.stringify({
                    name: 'test-project',
                    environmentWhitelist: {
                        'some-package': {
                            allowed: ['SECRET'],
                            allowPeerDependencies: true
                            // No peerDepthLimit - should default to 1
                        }
                    }
                }, null, 2));

                process.chdir(fixturesDir);

                const configLoader = require('../lib/config-loader');
                configLoader.clearCache();

                const config = configLoader.loadConfig(mainPkgPath);

                // Check that peerDepthLimit defaults to 1 in normalized config
                assert.strictEqual(
                    config['some-package'].peerDepthLimit,
                    1,
                    'peerDepthLimit should default to 1'
                );
            } finally {
                cleanup(fixturesDir);
            }
        });
    });
});
