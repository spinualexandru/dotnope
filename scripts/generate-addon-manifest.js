#!/usr/bin/env node
/**
 * generate-addon-manifest.js - Generate integrity manifest for native addon
 *
 * This script should be run after building the native addon to create
 * a manifest file containing the SHA-256 hash of the addon for integrity
 * verification at runtime.
 *
 * Usage: node scripts/generate-addon-manifest.js
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ADDON_PATH = path.join(__dirname, '../build/Release/dotnope_native.node');
const MANIFEST_PATH = path.join(__dirname, '../addon-manifest.json');

function generateManifest() {
    // Check if addon exists
    if (!fs.existsSync(ADDON_PATH)) {
        console.error('[generate-addon-manifest] Native addon not found at:', ADDON_PATH);
        console.error('[generate-addon-manifest] Run "npm run build:native" first.');
        process.exit(1);
    }

    // Read addon file
    const addonBuffer = fs.readFileSync(ADDON_PATH);

    // Generate SHA-256 hash
    const hash = crypto.createHash('sha256').update(addonBuffer).digest('hex');

    // Get file stats
    const stats = fs.statSync(ADDON_PATH);

    // Get Node.js ABI version
    const nodeAbi = process.versions.modules;
    const nodeVersion = process.version;

    // Create manifest
    const manifest = {
        version: '1.0.0',
        generatedAt: new Date().toISOString(),
        addon: {
            path: 'build/Release/dotnope_native.node',
            hash: hash,
            algorithm: 'sha256',
            size: stats.size,
            mtime: stats.mtime.toISOString()
        },
        node: {
            version: nodeVersion,
            abi: nodeAbi,
            platform: process.platform,
            arch: process.arch
        }
    };

    // Write manifest
    fs.writeFileSync(MANIFEST_PATH, JSON.stringify(manifest, null, 2) + '\n');

    console.log('[generate-addon-manifest] Generated manifest:');
    console.log('  Hash:', hash);
    console.log('  Size:', stats.size, 'bytes');
    console.log('  Node ABI:', nodeAbi);
    console.log('  Platform:', process.platform, process.arch);
    console.log('  Saved to:', MANIFEST_PATH);
}

generateManifest();
