#!/usr/bin/env node
'use strict';

// Enable dotnope FIRST - before any other requires
const dotnope = require('../index');
dotnope.enableStrictEnv();

// Set some fake secrets (in real apps these come from your environment)
process.env.AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
process.env.NPM_TOKEN = 'npm_XXXXXXXXXXXXXXXXXXXX';
process.env.GITHUB_TOKEN = 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
process.env.NODE_ENV = 'production';
process.env.PORT = '8080';

// Now load our dependencies
const config = require('legit-config');
const analytics = require('sketchy-analytics');

console.log('='.repeat(60));
console.log('dotnope example');
console.log('='.repeat(60));
console.log();

// This works - legit-config is whitelisted for NODE_ENV and PORT
console.log('[app] Loading config from whitelisted package...');
console.log(`[app] Environment: ${config.getEnv()}`);
console.log(`[app] Port: ${config.getPort()}`);
console.log('[app] Config loaded successfully!\n');

// This will throw - sketchy-analytics is NOT whitelisted
console.log('[app] Calling analytics.track()...\n');
try {
    analytics.track('page_view');
    console.log('[app] Analytics completed (THIS SHOULD NOT HAPPEN)\n');
} catch (err) {
    console.log('!'.repeat(60));
    console.log('BLOCKED! dotnope caught the malicious access:');
    console.log('!'.repeat(60));
    console.log();
    console.log(`Error code: ${err.code}`);
    console.log(`Package: ${err.packageName}`);
    console.log(`Tried to read: ${err.envVar}`);
    console.log();
    console.log('Your secrets are safe.');
}

dotnope.disableStrictEnv();
