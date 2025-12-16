'use strict';

const { test, describe, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// Generate unique fixture directory per test
function getUniqueFixturesDir() {
    const id = crypto.randomBytes(8).toString('hex');
    return path.join(__dirname, `fixtures-basic-${id}`);
}

// Helper to create a temporary package.json for testing
function createTestPackageJson(fixturesDir, config) {
    fs.mkdirSync(fixturesDir, { recursive: true });
    const pkgPath = path.join(fixturesDir, 'package.json');
    fs.writeFileSync(pkgPath, JSON.stringify(config, null, 2));
    return pkgPath;
}

// Clean up test fixtures
function cleanup(fixturesDir) {
    if (fs.existsSync(fixturesDir)) {
        fs.rmSync(fixturesDir, { recursive: true, force: true });
    }
}

// Clear dotnope module cache
function clearDotnopeCache() {
    Object.keys(require.cache).forEach(key => {
        if (key.includes('dotnope') && !key.includes('node_modules')) {
            delete require.cache[key];
        }
    });
}

describe('dotnope', () => {
    let originalEnv;

    beforeEach(() => {
        clearDotnopeCache();
        originalEnv = { ...process.env };
    });

    afterEach(() => {
        clearDotnopeCache();
        process.env = originalEnv;
    });

    describe('enableStrictEnv', () => {
        test('should enable strict mode successfully', () => {
            const fixturesDir = getUniqueFixturesDir();
            try {
                const pkgPath = createTestPackageJson(fixturesDir, {
                    name: 'test-app',
                    environmentWhitelist: {}
                });

                const dotnope = require('../index');
                const handle = dotnope.enableStrictEnv({ configPath: pkgPath });

                assert.ok(handle);
                assert.strictEqual(typeof handle.disable, 'function');
                assert.strictEqual(typeof handle.getAccessStats, 'function');
                assert.strictEqual(dotnope.isEnabled(), true);

                const token = handle.getToken();
                handle.disable(token);
            } finally {
                cleanup(fixturesDir);
            }
        });

        test('should warn if already enabled', () => {
            const fixturesDir = getUniqueFixturesDir();
            try {
                const pkgPath = createTestPackageJson(fixturesDir, {
                    name: 'test-app',
                    environmentWhitelist: {}
                });

                const warnMessages = [];
                const originalWarn = console.warn;
                console.warn = (msg) => warnMessages.push(msg);

                try {
                    const dotnope = require('../index');
                    const handle = dotnope.enableStrictEnv({ configPath: pkgPath });
                    dotnope.enableStrictEnv({ configPath: pkgPath });

                    assert.ok(warnMessages.some(m => m.includes('Already enabled')));

                    const token = handle.getToken();
                    handle.disable(token);
                } finally {
                    console.warn = originalWarn;
                }
            } finally {
                cleanup(fixturesDir);
            }
        });
    });

    describe('environment variable access', () => {
        test('should allow main application to access any env var', () => {
            const fixturesDir = getUniqueFixturesDir();
            try {
                const pkgPath = createTestPackageJson(fixturesDir, {
                    name: 'test-app',
                    environmentWhitelist: {}
                });

                process.env.TEST_VAR = 'test-value';

                const dotnope = require('../index');
                const handle = dotnope.enableStrictEnv({ configPath: pkgPath });

                // Main app should always have access
                assert.strictEqual(process.env.TEST_VAR, 'test-value');

                const token = handle.getToken();
                handle.disable(token);
            } finally {
                cleanup(fixturesDir);
            }
        });

        test('should allow whitelisted package to access whitelisted var', () => {
            const fixturesDir = getUniqueFixturesDir();
            try {
                const pkgPath = createTestPackageJson(fixturesDir, {
                    name: 'test-app',
                    environmentWhitelist: {
                        '__main__': {
                            allowed: ['TEST_VAR']
                        }
                    }
                });

                process.env.TEST_VAR = 'allowed-value';

                const dotnope = require('../index');
                const handle = dotnope.enableStrictEnv({ configPath: pkgPath });

                // Should be able to access
                assert.strictEqual(process.env.TEST_VAR, 'allowed-value');

                const token = handle.getToken();
                handle.disable(token);
            } finally {
                cleanup(fixturesDir);
            }
        });

        test('should support wildcard (*) for all env vars', () => {
            const fixturesDir = getUniqueFixturesDir();
            try {
                const pkgPath = createTestPackageJson(fixturesDir, {
                    name: 'test-app',
                    environmentWhitelist: {
                        '__main__': {
                            allowed: ['*']
                        }
                    }
                });

                process.env.ANY_VAR = 'any-value';
                process.env.ANOTHER_VAR = 'another-value';

                const dotnope = require('../index');
                const handle = dotnope.enableStrictEnv({ configPath: pkgPath });

                assert.strictEqual(process.env.ANY_VAR, 'any-value');
                assert.strictEqual(process.env.ANOTHER_VAR, 'another-value');

                const token = handle.getToken();
                handle.disable(token);
            } finally {
                cleanup(fixturesDir);
            }
        });

        test('should support shorthand array format', () => {
            const fixturesDir = getUniqueFixturesDir();
            try {
                const pkgPath = createTestPackageJson(fixturesDir, {
                    name: 'test-app',
                    environmentWhitelist: {
                        '__main__': ['TEST_VAR', 'OTHER_VAR']
                    }
                });

                process.env.TEST_VAR = 'test';
                process.env.OTHER_VAR = 'other';

                const dotnope = require('../index');
                const handle = dotnope.enableStrictEnv({ configPath: pkgPath });

                assert.strictEqual(process.env.TEST_VAR, 'test');
                assert.strictEqual(process.env.OTHER_VAR, 'other');

                const token = handle.getToken();
                handle.disable(token);
            } finally {
                cleanup(fixturesDir);
            }
        });
    });

    describe('disableStrictEnv', () => {
        test('should restore original process.env behavior', () => {
            const fixturesDir = getUniqueFixturesDir();
            try {
                const pkgPath = createTestPackageJson(fixturesDir, {
                    name: 'test-app',
                    environmentWhitelist: {}
                });

                const dotnope = require('../index');
                const handle = dotnope.enableStrictEnv({ configPath: pkgPath });

                assert.strictEqual(dotnope.isEnabled(), true);

                // Use token-protected disable
                const token = handle.getToken();
                handle.disable(token);

                assert.strictEqual(dotnope.isEnabled(), false);
            } finally {
                cleanup(fixturesDir);
            }
        });
    });

});

describe('config-loader', () => {
    afterEach(() => {
        clearDotnopeCache();
    });

    test('should throw if no package.json found', () => {
        const configLoader = require('../lib/config-loader');
        configLoader.clearCache();

        assert.throws(() => {
            configLoader.loadConfig('/nonexistent/path/package.json');
        }, /not found/);
    });

    test('should parse environmentWhitelist correctly', () => {
        const fixturesDir = getUniqueFixturesDir();
        try {
            const pkgPath = createTestPackageJson(fixturesDir, {
                name: 'test',
                environmentWhitelist: {
                    'axios': {
                        allowed: ['HTTP_PROXY'],
                        allowPeerDependencies: true
                    },
                    'dotenv': ['VAR1', 'VAR2']
                }
            });

            const configLoader = require('../lib/config-loader');
            configLoader.clearCache();
            const config = configLoader.loadConfig(pkgPath);

            assert.deepStrictEqual(config.axios, {
                allowed: ['HTTP_PROXY'],
                canWrite: [],
                canDelete: [],
                allowPeerDependencies: true
            });

            assert.deepStrictEqual(config.dotenv, {
                allowed: ['VAR1', 'VAR2'],
                canWrite: [],
                canDelete: [],
                allowPeerDependencies: false
            });
        } finally {
            cleanup(fixturesDir);
        }
    });
});

describe('stack-parser', () => {
    let stackParser;

    beforeEach(() => {
        clearDotnopeCache();
        stackParser = require('../lib/stack-parser');
    });

    afterEach(() => {
        stackParser.clearCache();
    });

    test('should extract package name from node_modules path', () => {
        const result = stackParser.extractPackageName(
            '/project/node_modules/express/lib/router.js'
        );
        assert.strictEqual(result, 'express');
    });

    test('should handle scoped packages', () => {
        const result = stackParser.extractPackageName(
            '/project/node_modules/@babel/core/lib/index.js'
        );
        assert.strictEqual(result, '@babel/core');
    });

    test('should return __main__ for non-node_modules paths', () => {
        const result = stackParser.extractPackageName(
            '/project/src/app.js'
        );
        assert.strictEqual(result, '__main__');
    });

    test('should handle nested node_modules', () => {
        const result = stackParser.extractPackageName(
            '/project/node_modules/a/node_modules/b/index.js'
        );
        // Should return the innermost package
        assert.strictEqual(result, 'b');
    });
});

describe('dependency-resolver', () => {
    let depResolver;

    beforeEach(() => {
        clearDotnopeCache();
        depResolver = require('../lib/dependency-resolver');
    });

    afterEach(() => {
        depResolver.clearCache();
    });

    test('isPackageAllowed should return true for __main__', () => {
        const config = {};
        const result = depResolver.isPackageAllowed('__main__', 'ANY_VAR', config);
        assert.strictEqual(result, true);
    });

    test('isPackageAllowed should return false for unlisted package', () => {
        const config = {
            'other-package': {
                allowed: ['SOME_VAR'],
                allowPeerDependencies: false
            }
        };
        const result = depResolver.isPackageAllowed('unknown-pkg', 'SOME_VAR', config);
        assert.strictEqual(result, false);
    });

    test('isPackageAllowed should return true for whitelisted var', () => {
        const config = {
            'my-package': {
                allowed: ['ALLOWED_VAR'],
                allowPeerDependencies: false
            }
        };
        const result = depResolver.isPackageAllowed('my-package', 'ALLOWED_VAR', config);
        assert.strictEqual(result, true);
    });

    test('isPackageAllowed should support wildcard', () => {
        const config = {
            'my-package': {
                allowed: ['*'],
                allowPeerDependencies: false
            }
        };
        const result = depResolver.isPackageAllowed('my-package', 'ANY_VAR', config);
        assert.strictEqual(result, true);
    });
});
