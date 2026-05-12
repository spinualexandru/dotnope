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
            workerData,
            execArgv: []
        });

        const timeout = setTimeout(() => {
            worker.terminate();
            reject(new Error('Worker timed out'));
        }, 5000);

        worker.on('message', (msg) => {
            clearTimeout(timeout);
            resolve(msg);
        });

        worker.on('error', (err) => {
            clearTimeout(timeout);
            reject(err);
        });

        worker.on('exit', (code) => {
            clearTimeout(timeout);
            if (code !== 0) {
                reject(new Error(`Worker exited with code ${code}`));
            }
        });
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
                // Note: strictLoadOrder: false because worker has modules loaded
                dotnope.enableStrictEnv({ strictLoadOrder: false });
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
            // Load config in main thread to pass to worker
            const dotnope = require('../index');
            process.chdir(fixturesDir);
            const handle = dotnope.enableStrictEnv({
                strictLoadOrder: false,
                configPath: mainPkgPath,
                suppressWarnings: true
            });

            const workerConfig = dotnope.getSerializableConfig();

            const token = handle.getToken();
            handle.disable(token);

            const workerPath = path.join(fixturesDir, 'explicit-worker.js');
            fs.writeFileSync(workerPath, `
'use strict';
const { parentPort, workerData } = require('worker_threads');
const dotnope = require(workerData.dotnopeModulePath);

try {
    const handle = dotnope.enableStrictEnv({
        strictLoadOrder: false,
        allowInWorker: true,
        workerConfig: workerData.config,
        suppressWarnings: true
    });

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
`);

            const result = await new Promise((resolve, reject) => {
                const worker = new Worker(workerPath, {
                    workerData: {
                        config: workerConfig,
                        dotnopeModulePath
                    },
                    execArgv: []
                });

                worker.on('message', resolve);
                worker.on('error', reject);
                worker.on('exit', (code) => {
                    if (code !== 0) {
                        reject(new Error(`Worker exited with code ${code}`));
                    }
                });
            });

            assert.strictEqual(result.success, true,
                `Should succeed with allowInWorker: ${result.error || ''}`);
        } finally {
            cleanup(fixturesDir);
        }
    });

    test('should auto-protect workers created after enableStrictEnv', async () => {
        const fixturesDir = getUniqueFixturesDir();
        try {
            const { mainPkgPath } = setupMockProject(fixturesDir, {});
            const packageDir = path.join(fixturesDir, 'node_modules', 'evil-package');
            fs.mkdirSync(packageDir, { recursive: true });
            const workerPath = path.join(packageDir, 'worker.js');
            fs.writeFileSync(workerPath, `
'use strict';
const { parentPort } = require('worker_threads');

try {
    const value = process.env.DOTNOPE_WORKER_SECRET;
    parentPort.postMessage({ success: false, value });
} catch (err) {
    parentPort.postMessage({ success: true, code: err.code });
}
`);

            process.env.DOTNOPE_WORKER_SECRET = 'worker-secret';
            process.env.WATCH_REPORT_DEPENDENCIES = '1';

            const dotnope = require('../index');
            const { Worker: CapturedWorker } = require('worker_threads');
            const handle = dotnope.enableStrictEnv({
                strictLoadOrder: false,
                configPath: mainPkgPath,
                suppressWarnings: true
            });

            const result = await new Promise((resolve, reject) => {
                const worker = new CapturedWorker(workerPath, { execArgv: [] });
                worker.on('message', resolve);
                worker.on('error', reject);
                worker.on('exit', (code) => {
                    if (code !== 0) {
                        reject(new Error(`Worker exited with code ${code}`));
                    }
                });
            });

            assert.strictEqual(result.success, true, 'Worker env access should be blocked');
            assert.strictEqual(result.code, 'ERR_DOTNOPE_UNAUTHORIZED');

            const token = handle.getToken();
            handle.disable(token);
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
                strictLoadOrder: false,
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
