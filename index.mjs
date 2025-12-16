import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const dotnope = require('./lib/dotnope.js');

export const enableStrictEnv = dotnope.enableStrictEnv;
export const disableStrictEnv = dotnope.disableStrictEnv;
export const getAccessStats = dotnope.getAccessStats;
export const isEnabled = dotnope.isEnabled;
export const hasNativeModule = dotnope.hasNativeModule;

export default dotnope;
