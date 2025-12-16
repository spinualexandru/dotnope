#!/usr/bin/env node
/**
 * dotnope-run - Launch Node.js with LD_PRELOAD protection
 *
 * This CLI helper launches a Node.js script with the dotnope preload library
 * active, providing protection against native addon getenv() bypass.
 *
 * Usage:
 *   npx dotnope-run your-app.js [args...]
 *   dotnope-run -- node your-app.js [args...]
 */

'use strict';

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const { generatePreloadEnv, findPreloadLibrary, isPreloadActive } = require('../lib/preload-generator');

// Parse arguments
const args = process.argv.slice(2);

// Show help
if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    console.log(`
dotnope-run - Launch Node.js with native getenv() protection

Usage:
  npx dotnope-run <script.js> [args...]    Run a Node.js script with protection
  npx dotnope-run -- <command> [args...]   Run any command with protection
  npx dotnope-run --check                  Check if preload library is available
  npx dotnope-run --status                 Show current protection status

Options:
  --help, -h      Show this help message
  --check         Check if the preload library is available
  --status        Show current protection status
  --verbose, -v   Show verbose output
  --log <file>    Log preload library activity to file

Examples:
  npx dotnope-run server.js
  npx dotnope-run --verbose app.js --port 3000
  npx dotnope-run -- node --inspect app.js

Note: This tool only works on Linux with LD_PRELOAD support.
`);
    process.exit(0);
}

// Check command
if (args.includes('--check')) {
    const preloadPath = findPreloadLibrary();
    if (preloadPath) {
        console.log('[dotnope-run] Preload library found:', preloadPath);
        process.exit(0);
    } else {
        console.error('[dotnope-run] Preload library NOT found!');
        console.error('[dotnope-run] Build with: make -C native/preload');
        process.exit(1);
    }
}

// Status command
if (args.includes('--status')) {
    console.log('[dotnope-run] Protection Status:');
    console.log('  Platform:', process.platform);
    console.log('  LD_PRELOAD active:', isPreloadActive() ? 'Yes' : 'No');
    console.log('  Preload library:', findPreloadLibrary() || 'Not found');
    console.log('  Current LD_PRELOAD:', process.env.LD_PRELOAD || '(not set)');
    console.log('  Current DOTNOPE_POLICY:', process.env.DOTNOPE_POLICY || '(not set)');
    process.exit(0);
}

// Check platform
if (process.platform !== 'linux') {
    console.error('[dotnope-run] Error: LD_PRELOAD is only supported on Linux.');
    console.error('[dotnope-run] On other platforms, use dotnope without native addon protection.');
    process.exit(1);
}

// Parse flags
let verbose = false;
let logFile = null;
const filteredArgs = [];

for (let i = 0; i < args.length; i++) {
    if (args[i] === '--verbose' || args[i] === '-v') {
        verbose = true;
    } else if (args[i] === '--log' && args[i + 1]) {
        logFile = args[++i];
    } else if (args[i] === '--') {
        // Everything after -- is the command
        filteredArgs.push(...args.slice(i + 1));
        break;
    } else {
        filteredArgs.push(args[i]);
    }
}

if (filteredArgs.length === 0) {
    console.error('[dotnope-run] Error: No script or command specified.');
    console.error('[dotnope-run] Run "npx dotnope-run --help" for usage.');
    process.exit(1);
}

// Find package.json
function findPackageJson() {
    let dir = process.cwd();
    while (dir !== path.dirname(dir)) {
        const pkgPath = path.join(dir, 'package.json');
        if (fs.existsSync(pkgPath)) {
            return pkgPath;
        }
        dir = path.dirname(dir);
    }
    return null;
}

const pkgPath = findPackageJson();
if (!pkgPath) {
    console.error('[dotnope-run] Error: Could not find package.json');
    console.error('[dotnope-run] Run from within a Node.js project directory.');
    process.exit(1);
}

// Generate preload environment
let preloadEnv;
try {
    preloadEnv = generatePreloadEnv(pkgPath);
} catch (err) {
    console.error('[dotnope-run] Error:', err.message);
    process.exit(1);
}

// Add logging if requested
if (logFile) {
    preloadEnv.DOTNOPE_LOG = logFile;
}

if (verbose) {
    console.log('[dotnope-run] Package.json:', pkgPath);
    console.log('[dotnope-run] LD_PRELOAD:', preloadEnv.LD_PRELOAD);
    console.log('[dotnope-run] DOTNOPE_POLICY:', preloadEnv.DOTNOPE_POLICY || '(allow all)');
    if (logFile) {
        console.log('[dotnope-run] Logging to:', logFile);
    }
    console.log('[dotnope-run] Running:', filteredArgs.join(' '));
    console.log('');
}

// Determine the command to run
let command, commandArgs;

// Check if first arg is a .js file
if (filteredArgs[0].endsWith('.js') || filteredArgs[0].endsWith('.mjs') || filteredArgs[0].endsWith('.cjs')) {
    // Run with node
    command = process.execPath; // Use same node that's running this script
    commandArgs = filteredArgs;
} else {
    // Run command directly
    command = filteredArgs[0];
    commandArgs = filteredArgs.slice(1);
}

// Spawn the process with preload environment
const child = spawn(command, commandArgs, {
    stdio: 'inherit',
    env: {
        ...process.env,
        ...preloadEnv
    }
});

// Forward exit code
child.on('exit', (code, signal) => {
    if (signal) {
        process.kill(process.pid, signal);
    } else {
        process.exit(code || 0);
    }
});

child.on('error', (err) => {
    console.error('[dotnope-run] Failed to start process:', err.message);
    process.exit(1);
});
