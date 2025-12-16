'use strict';

const {
    enableStrictEnv,
    disableStrictEnv,
    getAccessStats,
    isEnabled,
    isPreloadActive,
    emitSecurityWarnings,
    isRunningInMainThread,
    isWorkerAllowed,
    getSerializableConfig
} = require('./lib/dotnope');

module.exports = {
    enableStrictEnv,
    disableStrictEnv,
    getAccessStats,
    isEnabled,
    isPreloadActive,
    emitSecurityWarnings,
    isRunningInMainThread,
    isWorkerAllowed,
    getSerializableConfig
};
