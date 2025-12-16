/**
 * test-async.js - Async context protection tests
 *
 * Tests that dotnope correctly tracks package attribution through
 * various async patterns including Promises, async/await, and Promise chains.
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
    return path.join(__dirname, `fixtures-async-${uniqueId}`);
}

// Setup mock project structure
function setupMockProject(fixturesDir, whitelist = {}) {
    // Create directories
    fs.mkdirSync(fixturesDir, { recursive: true });
    fs.mkdirSync(path.join(fixturesDir, 'node_modules', 'async-package'), { recursive: true });

    // Create main package.json
    const mainPkgPath = path.join(fixturesDir, 'package.json');
    fs.writeFileSync(mainPkgPath, JSON.stringify({
        name: 'test-app',
        version: '1.0.0',
        environmentWhitelist: whitelist
    }, null, 2));

    // Create async-package
    const asyncPackageDir = path.join(fixturesDir, 'node_modules', 'async-package');
    fs.writeFileSync(path.join(asyncPackageDir, 'package.json'), JSON.stringify({
        name: 'async-package',
        version: '1.0.0',
        main: 'index.js'
    }, null, 2));

    fs.writeFileSync(path.join(asyncPackageDir, 'index.js'), `
'use strict';

module.exports = {
    // Access env in Promise.then callback
    accessEnvInThen(envVar) {
        return Promise.resolve().then(() => process.env[envVar]);
    },

    // Access env in async/await
    async accessEnvAsync(envVar) {
        await Promise.resolve();
        return process.env[envVar];
    },

    // Access env in Promise.all
    accessEnvInPromiseAll(envVar) {
        return Promise.all([
            Promise.resolve(1),
            Promise.resolve().then(() => process.env[envVar])
        ]);
    },

    // Chained promises
    accessEnvChained(envVar) {
        return Promise.resolve()
            .then(() => 'step1')
            .then(() => 'step2')
            .then(() => process.env[envVar]);
    },

    // Nested async
    async accessEnvNestedAsync(envVar) {
        const inner = async () => {
            await Promise.resolve();
            return process.env[envVar];
        };
        await Promise.resolve();
        return inner();
    },

    // Promise race
    accessEnvInRace(envVar) {
        return Promise.race([
            new Promise(resolve => setTimeout(() => resolve('slow'), 100)),
            Promise.resolve().then(() => process.env[envVar])
        ]);
    },

    // Create promise and access later
    createDeferredAccess(envVar) {
        let resolveOuter;
        const promise = new Promise(resolve => { resolveOuter = resolve; });

        setTimeout(() => {
            resolveOuter(process.env[envVar]);
        }, 10);

        return promise;
    }
};
`);

    return { mainPkgPath, asyncPackageDir };
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
        if (key.includes('dotnope') || key.includes('fixtures-async')) {
            delete require.cache[key];
        }
    });
}

describe('Async Context Protection', () => {
    let originalCwd;
    let originalEnv;

    beforeEach(() => {
        originalCwd = process.cwd();
        originalEnv = { ...process.env };
        clearRequireCache();
    });

    afterEach(() => {
        process.chdir(originalCwd);
        // Restore env
        Object.keys(process.env).forEach(key => {
            if (!originalEnv.hasOwnProperty(key)) {
                delete process.env[key];
            }
        });
        Object.assign(process.env, originalEnv);
    });

    test('should track package through Promise.then()', async () => {
        const fixturesDir = getUniqueFixturesDir();
        try {
            const { mainPkgPath, asyncPackageDir } = setupMockProject(fixturesDir, {
                'async-package': {
                    allowed: ['ASYNC_TEST_VAR']
                }
            });

            process.env.ASYNC_TEST_VAR = 'async-value';
            process.chdir(fixturesDir);

            const dotnope = require('../index');
            const handle = dotnope.enableStrictEnv({
                configPath: mainPkgPath,
                suppressWarnings: true
            });

            delete require.cache[require.resolve(asyncPackageDir)];
            const asyncPkg = require(asyncPackageDir);

            const result = await asyncPkg.accessEnvInThen('ASYNC_TEST_VAR');
            assert.strictEqual(result, 'async-value', 'Should allow access in then()');

            const token = handle.getToken();
            handle.disable(token);
        } finally {
            cleanup(fixturesDir);
        }
    });

    test('should track package through async/await', async () => {
        const fixturesDir = getUniqueFixturesDir();
        try {
            const { mainPkgPath, asyncPackageDir } = setupMockProject(fixturesDir, {
                'async-package': {
                    allowed: ['ASYNC_AWAIT_VAR']
                }
            });

            process.env.ASYNC_AWAIT_VAR = 'await-value';
            process.chdir(fixturesDir);

            const dotnope = require('../index');
            const handle = dotnope.enableStrictEnv({
                configPath: mainPkgPath,
                suppressWarnings: true
            });

            delete require.cache[require.resolve(asyncPackageDir)];
            const asyncPkg = require(asyncPackageDir);

            const result = await asyncPkg.accessEnvAsync('ASYNC_AWAIT_VAR');
            assert.strictEqual(result, 'await-value', 'Should allow access in async function');

            const token = handle.getToken();
            handle.disable(token);
        } finally {
            cleanup(fixturesDir);
        }
    });

    test('should track package through Promise.all()', async () => {
        const fixturesDir = getUniqueFixturesDir();
        try {
            const { mainPkgPath, asyncPackageDir } = setupMockProject(fixturesDir, {
                'async-package': {
                    allowed: ['PROMISE_ALL_VAR']
                }
            });

            process.env.PROMISE_ALL_VAR = 'all-value';
            process.chdir(fixturesDir);

            const dotnope = require('../index');
            const handle = dotnope.enableStrictEnv({
                configPath: mainPkgPath,
                suppressWarnings: true
            });

            delete require.cache[require.resolve(asyncPackageDir)];
            const asyncPkg = require(asyncPackageDir);

            const [first, second] = await asyncPkg.accessEnvInPromiseAll('PROMISE_ALL_VAR');
            assert.strictEqual(first, 1);
            assert.strictEqual(second, 'all-value', 'Should allow access in Promise.all');

            const token = handle.getToken();
            handle.disable(token);
        } finally {
            cleanup(fixturesDir);
        }
    });

    test('should track package through chained promises', async () => {
        const fixturesDir = getUniqueFixturesDir();
        try {
            const { mainPkgPath, asyncPackageDir } = setupMockProject(fixturesDir, {
                'async-package': {
                    allowed: ['CHAINED_VAR']
                }
            });

            process.env.CHAINED_VAR = 'chained-value';
            process.chdir(fixturesDir);

            const dotnope = require('../index');
            const handle = dotnope.enableStrictEnv({
                configPath: mainPkgPath,
                suppressWarnings: true
            });

            delete require.cache[require.resolve(asyncPackageDir)];
            const asyncPkg = require(asyncPackageDir);

            const result = await asyncPkg.accessEnvChained('CHAINED_VAR');
            assert.strictEqual(result, 'chained-value', 'Should allow access in chained promises');

            const token = handle.getToken();
            handle.disable(token);
        } finally {
            cleanup(fixturesDir);
        }
    });

    test('should block unauthorized async access', async () => {
        const fixturesDir = getUniqueFixturesDir();
        try {
            const { mainPkgPath, asyncPackageDir } = setupMockProject(fixturesDir, {
                'async-package': {
                    allowed: ['ALLOWED_VAR']
                    // UNAUTHORIZED_VAR not allowed
                }
            });

            process.env.UNAUTHORIZED_VAR = 'secret';
            process.chdir(fixturesDir);

            const dotnope = require('../index');
            const handle = dotnope.enableStrictEnv({
                configPath: mainPkgPath,
                suppressWarnings: true
            });

            delete require.cache[require.resolve(asyncPackageDir)];
            const asyncPkg = require(asyncPackageDir);

            await assert.rejects(
                asyncPkg.accessEnvInThen('UNAUTHORIZED_VAR'),
                { code: 'ERR_DOTNOPE_UNAUTHORIZED' },
                'Should reject unauthorized async access'
            );

            const token = handle.getToken();
            handle.disable(token);
        } finally {
            cleanup(fixturesDir);
        }
    });

    test('should track nested async correctly', async () => {
        const fixturesDir = getUniqueFixturesDir();
        try {
            const { mainPkgPath, asyncPackageDir } = setupMockProject(fixturesDir, {
                'async-package': {
                    allowed: ['NESTED_VAR']
                }
            });

            process.env.NESTED_VAR = 'nested-value';
            process.chdir(fixturesDir);

            const dotnope = require('../index');
            const handle = dotnope.enableStrictEnv({
                configPath: mainPkgPath,
                suppressWarnings: true
            });

            delete require.cache[require.resolve(asyncPackageDir)];
            const asyncPkg = require(asyncPackageDir);

            const result = await asyncPkg.accessEnvNestedAsync('NESTED_VAR');
            assert.strictEqual(result, 'nested-value', 'Should track through nested async calls');

            const token = handle.getToken();
            handle.disable(token);
        } finally {
            cleanup(fixturesDir);
        }
    });
});

describe('Promise Hooks Memory Management', () => {
    test('should expose promise tracking stats (if native available)', async () => {
        const fixturesDir = getUniqueFixturesDir();
        try {
            const { mainPkgPath } = setupMockProject(fixturesDir, {});

            process.chdir(fixturesDir);

            const dotnope = require('../index');
            const nativeBridge = require('../lib/native-bridge');
            const handle = dotnope.enableStrictEnv({
                configPath: mainPkgPath,
                suppressWarnings: true
            });

            if (nativeBridge.isNativeAvailable()) {
                const stats = nativeBridge.getPromiseStats();
                assert.ok(stats, 'Should have promise stats');
                assert.ok('trackedPromises' in stats, 'Should have trackedPromises count');
                assert.ok('pendingCleanup' in stats, 'Should have pendingCleanup count');
                assert.ok('cleanupThreshold' in stats, 'Should have cleanupThreshold');
            }

            const token = handle.getToken();
            handle.disable(token);
        } finally {
            cleanup(fixturesDir);
        }
    });
});
