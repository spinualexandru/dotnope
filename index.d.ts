/**
 * Options for enableStrictEnv
 */
export interface StrictEnvOptions {
    /**
     * Custom path to package.json containing environmentWhitelist config.
     * If not specified, searches for package.json from current working directory.
     */
    configPath?: string;
}

/**
 * Handle returned by enableStrictEnv
 */
export interface StrictEnvHandle {
    /**
     * Disable strict environment checking and restore original process.env
     */
    disable(): void;

    /**
     * Get access statistics for environment variable reads.
     * Returns null if native module is not available.
     * Keys are in format "packageName:envVar"
     */
    getAccessStats(): Record<string, number> | null;
}

/**
 * Configuration for a single package's environment access
 */
export interface PackageEnvConfig {
    /**
     * List of allowed environment variable names.
     * Use "*" to allow access to all environment variables.
     */
    allowed: string[];

    /**
     * If true, all dependencies of this package are also allowed
     * to access the same environment variables.
     */
    allowPeerDependencies?: boolean;
}

/**
 * Environment whitelist configuration.
 * Add this to your package.json under "environmentWhitelist" key.
 */
export interface EnvironmentWhitelistConfig {
    [packageName: string]: PackageEnvConfig | string[];
}

/**
 * Error thrown when unauthorized environment access is detected
 */
export interface StrictEnvError extends Error {
    code: 'ERR_DOTNOPE_UNAUTHORIZED';
    packageName: string;
    envVar: string;
    fileName: string;
    lineNumber: number;
    functionName: string;
}

/**
 * Enable strict environment variable access control.
 *
 * When enabled, any package that tries to read an environment variable
 * must be explicitly whitelisted in your package.json's "environmentWhitelist"
 * configuration. Unauthorized access will throw an error with details about
 * which package attempted the access.
 *
 * IMPORTANT: Call this as early as possible in your application,
 * before other modules have a chance to read environment variables.
 *
 * @param options - Configuration options
 * @returns Handle to disable strict mode or get statistics
 * @throws Error if package.json cannot be found or parsed
 *
 * @example
 * ```javascript
 * // In your app's entry point (must be first!)
 * const { enableStrictEnv } = require('dotnope');
 * enableStrictEnv();
 *
 * // Now load other modules
 * const express = require('express');
 * ```
 *
 * @example
 * ```javascript
 * // package.json configuration:
 * {
 *   "environmentWhitelist": {
 *     "dotenv": {
 *       "allowed": ["*"]
 *     },
 *     "axios": {
 *       "allowed": ["HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"],
 *       "allowPeerDependencies": true
 *     }
 *   }
 * }
 * ```
 */
export function enableStrictEnv(options?: StrictEnvOptions): StrictEnvHandle;

/**
 * Disable strict environment variable access control.
 * Restores original process.env behavior and clears all caches.
 */
export function disableStrictEnv(): void;

/**
 * Get access statistics for environment variable reads.
 * Only available when the native module is loaded.
 *
 * @returns Object mapping "packageName:envVar" to access count, or null if native module unavailable
 */
export function getAccessStats(): Record<string, number> | null;

/**
 * Check if strict mode is currently enabled.
 *
 * @returns true if enableStrictEnv() has been called and not disabled
 */
export function isEnabled(): boolean;

/**
 * Check if the native C++ module is available.
 * The native module provides better performance but is optional.
 *
 * @returns true if native module loaded successfully
 */
export function hasNativeModule(): boolean;

declare const _default: {
    enableStrictEnv: typeof enableStrictEnv;
    disableStrictEnv: typeof disableStrictEnv;
    getAccessStats: typeof getAccessStats;
    isEnabled: typeof isEnabled;
    hasNativeModule: typeof hasNativeModule;
};

export default _default;
