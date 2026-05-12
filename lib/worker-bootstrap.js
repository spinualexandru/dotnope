'use strict';

const Module = require('module');

const payload = process.env.DOTNOPE_WORKER_CONFIG;

if (payload) {
    let activated = false;
    const originalCompile = Module.prototype._compile;

    function activateDotnope() {
        if (activated) {
            return;
        }
        activated = true;

        if (Module.prototype._compile === compileWithDotnope) {
            Module.prototype._compile = originalCompile;
        }

        const dotnope = require('./dotnope');
        const workerConfig = JSON.parse(payload);

        dotnope.enableStrictEnv({
            strictLoadOrder: false,
            allowInWorker: true,
            workerConfig,
            suppressWarnings: true
        });
    }

    function compileWithDotnope(content, filename) {
        activateDotnope();
        return originalCompile.call(this, content, filename);
    }

    Module.prototype._compile = compileWithDotnope;
    process.nextTick(activateDotnope);
}
