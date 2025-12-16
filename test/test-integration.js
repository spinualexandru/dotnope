'use strict';

const { test, describe, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// Generate unique fixture directory per test to avoid race conditions
function getUniqueFixturesDir() {
    const id = crypto.randomBytes(8).toString('hex');
    return path.join(__dirname, `fixtures-${id}`);
}

/**
 * Clear all dotnope-related require caches
 */
function clearRequireCache() {
    Object.keys(require.cache).forEach(key => {
        if (key.includes('dotnope') || key.includes('fixtures')) {
            delete require.cache[key];
        }
    });
}

/**
 * Set up a mock package structure to test the full flow
 */
function setupMockProject(fixturesDir, whitelistConfig) {
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

    // Create the fake package's index.js that reads env vars
    fs.writeFileSync(
        path.join(fakePackageDir, 'index.js'),
        `'use strict';
module.exports = {
    getEnvVar: function(name) {
        return process.env[name];
    },
    checkEnvVar: function(name) {
        return name in process.env;
    }
};`
    );

    return { mainPkgPath, fakePackageDir };
}

function cleanup(fixturesDir) {
    if (fs.existsSync(fixturesDir)) {
        fs.rmSync(fixturesDir, { recursive: true, force: true });
    }
}

describe('integration tests', { concurrency: false }, () => {
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

    test('should throw error when non-whitelisted package reads env var', () => {
        const fixturesDir = getUniqueFixturesDir();
        try {
            const { mainPkgPath, fakePackageDir } = setupMockProject(fixturesDir, {
                // fake-package is NOT whitelisted
            });

            process.env.SECRET_KEY = 'super-secret';
            process.chdir(fixturesDir);

            const dotnope = require('../index');
            dotnope.enableStrictEnv({ configPath: mainPkgPath });

            delete require.cache[require.resolve(fakePackageDir)];
            const fakePackage = require(fakePackageDir);

            assert.throws(() => {
                fakePackage.getEnvVar('SECRET_KEY');
            }, (err) => {
                assert.strictEqual(err.code, 'ERR_DOTNOPE_UNAUTHORIZED');
                assert.strictEqual(err.packageName, 'fake-package');
                assert.strictEqual(err.envVar, 'SECRET_KEY');
                return true;
            });

            dotnope.disableStrictEnv();
        } finally {
            cleanup(fixturesDir);
        }
    });

    test('should allow whitelisted package to read whitelisted env var', () => {
        const fixturesDir = getUniqueFixturesDir();
        try {
            const { mainPkgPath, fakePackageDir } = setupMockProject(fixturesDir, {
                'fake-package': {
                    allowed: ['ALLOWED_VAR'],
                    allowPeerDependencies: false
                }
            });

            process.env.ALLOWED_VAR = 'allowed-value';
            process.chdir(fixturesDir);

            const dotnope = require('../index');
            dotnope.enableStrictEnv({ configPath: mainPkgPath });

            delete require.cache[require.resolve(fakePackageDir)];
            const fakePackage = require(fakePackageDir);

            const value = fakePackage.getEnvVar('ALLOWED_VAR');
            assert.strictEqual(value, 'allowed-value');

            dotnope.disableStrictEnv();
        } finally {
            cleanup(fixturesDir);
        }
    });

    test('should throw when whitelisted package reads non-whitelisted var', () => {
        const fixturesDir = getUniqueFixturesDir();
        try {
            const { mainPkgPath, fakePackageDir } = setupMockProject(fixturesDir, {
                'fake-package': {
                    allowed: ['ALLOWED_VAR'],
                    allowPeerDependencies: false
                }
            });

            process.env.ALLOWED_VAR = 'allowed';
            process.env.FORBIDDEN_VAR = 'forbidden';
            process.chdir(fixturesDir);

            const dotnope = require('../index');
            dotnope.enableStrictEnv({ configPath: mainPkgPath });

            delete require.cache[require.resolve(fakePackageDir)];
            const fakePackage = require(fakePackageDir);

            // Allowed var works
            assert.strictEqual(fakePackage.getEnvVar('ALLOWED_VAR'), 'allowed');

            // Forbidden var throws
            assert.throws(() => {
                fakePackage.getEnvVar('FORBIDDEN_VAR');
            }, (err) => {
                assert.strictEqual(err.code, 'ERR_DOTNOPE_UNAUTHORIZED');
                assert.strictEqual(err.envVar, 'FORBIDDEN_VAR');
                return true;
            });

            dotnope.disableStrictEnv();
        } finally {
            cleanup(fixturesDir);
        }
    });

    test('should provide helpful error message with fix suggestion', () => {
        const fixturesDir = getUniqueFixturesDir();
        try {
            const { mainPkgPath, fakePackageDir } = setupMockProject(fixturesDir, {});

            process.env.MY_SECRET = 'secret';
            process.chdir(fixturesDir);

            const dotnope = require('../index');
            dotnope.enableStrictEnv({ configPath: mainPkgPath });

            delete require.cache[require.resolve(fakePackageDir)];
            const fakePackage = require(fakePackageDir);

            try {
                fakePackage.getEnvVar('MY_SECRET');
                assert.fail('Should have thrown');
            } catch (err) {
                assert.ok(err.message.includes('environmentWhitelist'), `Message should include 'environmentWhitelist'`);
                assert.ok(err.message.includes('"fake-package"'), `Message should include package name`);
                assert.ok(err.message.includes('"MY_SECRET"'), `Message should include env var name`);
            }

            dotnope.disableStrictEnv();
        } finally {
            cleanup(fixturesDir);
        }
    });

    test('should work with "in" operator check', () => {
        const fixturesDir = getUniqueFixturesDir();
        try {
            const { mainPkgPath, fakePackageDir } = setupMockProject(fixturesDir, {
                // fake-package NOT whitelisted
            });

            process.env.CHECK_VAR = 'exists';
            process.chdir(fixturesDir);

            const dotnope = require('../index');
            dotnope.enableStrictEnv({ configPath: mainPkgPath });

            delete require.cache[require.resolve(fakePackageDir)];
            const fakePackage = require(fakePackageDir);

            // Using 'in' operator should also throw
            assert.throws(() => {
                fakePackage.checkEnvVar('CHECK_VAR');
            }, (err) => {
                assert.strictEqual(err.code, 'ERR_DOTNOPE_UNAUTHORIZED');
                return true;
            });

            dotnope.disableStrictEnv();
        } finally {
            cleanup(fixturesDir);
        }
    });

    test('native module should be loaded', () => {
        const dotnope = require('../index');
        assert.strictEqual(dotnope.hasNativeModule(), true);
    });

    test('should track access stats with native module', () => {
        const fixturesDir = getUniqueFixturesDir();
        try {
            const { mainPkgPath, fakePackageDir } = setupMockProject(fixturesDir, {
                'fake-package': {
                    allowed: ['*'],
                    allowPeerDependencies: false
                }
            });

            process.env.TRACK_VAR = 'tracked';
            process.chdir(fixturesDir);

            const dotnope = require('../index');
            const handle = dotnope.enableStrictEnv({ configPath: mainPkgPath });

            delete require.cache[require.resolve(fakePackageDir)];
            const fakePackage = require(fakePackageDir);

            // Access multiple times
            fakePackage.getEnvVar('TRACK_VAR');
            fakePackage.getEnvVar('TRACK_VAR');
            fakePackage.getEnvVar('TRACK_VAR');

            // Check stats
            const stats = handle.getAccessStats();
            if (stats) {
                assert.ok('fake-package:TRACK_VAR' in stats, `Stats should contain fake-package:TRACK_VAR`);
                assert.strictEqual(stats['fake-package:TRACK_VAR'], 3);
            }

            dotnope.disableStrictEnv();
        } finally {
            cleanup(fixturesDir);
        }
    });
});
