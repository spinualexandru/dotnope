/**
 * test-workers.js - Worker thread protection tests
 *
 * Tests that dotnope correctly handles worker threads, including
 * explicit opt-in requirements and config sharing.
 */

'use strict';

const { describe, test, beforeEach, afterEach } = require('node:test');
const assert = require('assert');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { Worker, isMainThread } = require('worker_threads');

// Test fixtures directory
function getUniqueFixturesDir() {
    const uniqueId = crypto.randomBytes(8).toString('hex');
    return path.join(__dirname, `fixtures-workers-${uniqueId}`);
}

// Setup mock project structure
function setupMockProject(fixturesDir, whitelist = {}) {
    fs.mkdirSync(fixturesDir, { recursive: true });

    const mainPkgPath = path.join(fixturesDir, 'package.json');
    fs.writeFileSync(mainPkgPath, JSON.stringify({
        name: 'test-app',
        version: '1.0.0',
        environmentWhitelist: whitelist
    }, null, 2));

    return { mainPkgPath };
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
        if (key.includes('dotnope') || key.includes('fixtures-workers')) {
            delete require.cache[key];
        }
    });
}

// Run code in a worker and get the result
function runInWorker(code, workerData = {}) {
    return new Promise((resolve, reject) => {
        const workerCode = `
const { parentPort, workerData } = require('worker_threads');

(async () => {
    try {
        ${code}
    } catch (err) {
        parentPort.postMessage({ error: err.message, code: err.code });
    }
})();
`;

        const worker = new Worker(workerCode, {
            eval: true,
            workerData
        });

        worker.on('message', (msg) => {
            resolve(msg);
        });

        worker.on('error', (err) => {
            reject(err);
        });

        worker.on('exit', (code) => {
            if (code !== 0) {
                reject(new Error(`Worker exited with code ${code}`));
            }
        });

        // Timeout after 5 seconds
        setTimeout(() => {
            worker.terminate();
            reject(new Error('Worker timed out'));
        }, 5000);
    });
}

describe('Worker Thread Protection', () => {
    let originalCwd;
    let originalEnv;

    beforeEach(() => {
        originalCwd = process.cwd();
        originalEnv = { ...process.env };
        clearRequireCache();
    });

    afterEach(() => {
        process.chdir(originalCwd);
        Object.keys(process.env).forEach(key => {
            if (!originalEnv.hasOwnProperty(key)) {
                delete process.env[key];
            }
        });
        Object.assign(process.env, originalEnv);
    });

    test('should detect main thread vs worker thread', () => {
        const dotnope = require('../index');
        assert.strictEqual(dotnope.isRunningInMainThread(), true, 'Should detect main thread');
    });

    test('should block enableStrictEnv in worker without opt-in', async () => {
        const dotnopeModulePath = path.resolve(__dirname, '../index.js');

        const result = await runInWorker(`
            const dotnope = require(${JSON.stringify(dotnopeModulePath)});

            try {
                dotnope.enableStrictEnv();
                parentPort.postMessage({ success: false, message: 'Should have thrown' });
            } catch (err) {
                parentPort.postMessage({
                    success: true,
                    errorCode: err.code,
                    errorMessage: err.message
                });
            }
        `);

        assert.strictEqual(result.success, true, 'Should have thrown error');
        assert.strictEqual(result.errorCode, 'ERR_DOTNOPE_WORKER_NOT_ALLOWED',
            'Should have correct error code');
    });

    test('should allow enableStrictEnv in worker with allowInWorker', async () => {
        const fixturesDir = getUniqueFixturesDir();
        try {
            const { mainPkgPath } = setupMockProject(fixturesDir, {
                'test-package': {
                    allowed: ['WORKER_TEST_VAR']
                }
            });

            process.env.WORKER_TEST_VAR = 'worker-value';

            const dotnopeModulePath = path.resolve(__dirname, '../index.js');
            const configLoaderPath = path.resolve(__dirname, '../lib/config-loader.js');

            // Load config in main thread to pass to worker
            const dotnope = require('../index');
            process.chdir(fixturesDir);
            const handle = dotnope.enableStrictEnv({
                configPath: mainPkgPath,
                suppressWarnings: true
            });

            const workerConfig = dotnope.getSerializableConfig();

            const token = handle.getToken();
            handle.disable(token);

            const result = await runInWorker(`
                const dotnope = require(${JSON.stringify(dotnopeModulePath)});
                const workerConfig = workerData.config;

                try {
                    const handle = dotnope.enableStrictEnv({
                        allowInWorker: true,
                        workerConfig: workerConfig,
                        suppressWarnings: true
                    });

                    // Main app should have access
                    const value = process.env.WORKER_TEST_VAR;

                    const token = handle.getToken();
                    handle.disable(token);

                    parentPort.postMessage({
                        success: true,
                        value: value
                    });
                } catch (err) {
                    parentPort.postMessage({
                        success: false,
                        error: err.message,
                        code: err.code
                    });
                }
            `, { config: workerConfig });

            assert.strictEqual(result.success, true,
                `Should succeed with allowInWorker: ${result.error || ''}`);
        } finally {
            cleanup(fixturesDir);
        }
    });

    test('should report isWorkerAllowed correctly', async () => {
        const dotnopeModulePath = path.resolve(__dirname, '../index.js');

        // In main thread
        const dotnope = require('../index');
        assert.strictEqual(dotnope.isWorkerAllowed(), false,
            'Should be false in main thread before enableStrictEnv');

        // In worker with allowInWorker
        const result = await runInWorker(`
            const dotnope = require(${JSON.stringify(dotnopeModulePath)});

            const handle = dotnope.enableStrictEnv({
                allowInWorker: true,
                suppressWarnings: true
            });

            const isAllowed = dotnope.isWorkerAllowed();
            const token = handle.getToken();
            handle.disable(token);

            parentPort.postMessage({ isWorkerAllowed: isAllowed });
        `);

        assert.strictEqual(result.isWorkerAllowed, true,
            'Should be true in worker with allowInWorker');
    });
});

describe('Worker Thread Native Support', () => {
    test('should detect worker thread via native bridge', () => {
        const nativeBridge = require('../lib/native-bridge');

        // In main thread, should NOT be worker
        const isWorker = nativeBridge.isWorkerThread();
        assert.strictEqual(isWorker, false, 'Main thread should not be detected as worker');
    });

    test('should track isolates correctly', () => {
        const nativeBridge = require('../lib/native-bridge');

        if (nativeBridge.isNativeAvailable()) {
            const count = nativeBridge.getIsolateCount();
            assert.ok(count >= 1, 'Should have at least 1 isolate');
        }
    });
});
