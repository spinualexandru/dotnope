/**
 * promise_hooks.h - V8 Promise hooks for async context tracking
 *
 * Tracks promise creation and resolution to maintain attribution
 * across async boundaries.
 */

#ifndef DOTNOPE_PROMISE_HOOKS_H
#define DOTNOPE_PROMISE_HOOKS_H

#include <napi.h>

namespace dotnope {
namespace PromiseHooks {

/**
 * Enable promise hooks for async context tracking
 *
 * @param info CallbackInfo (no parameters)
 * @returns Boolean indicating success
 */
Napi::Value Enable(const Napi::CallbackInfo& info);

/**
 * Disable promise hooks (JavaScript callback version)
 *
 * @param info CallbackInfo (no parameters)
 * @returns Boolean indicating success
 */
Napi::Value Disable(const Napi::CallbackInfo& info);

/**
 * Disable promise hooks (internal cleanup version)
 * Use this for cleanup from C++ code
 */
void DisableInternal(Napi::Env env);

/**
 * Get the async context for the current execution
 *
 * Returns the package name that initiated the current async chain,
 * if it can be determined.
 *
 * @param info CallbackInfo (no parameters)
 * @returns String package name or null
 */
Napi::Value GetAsyncContext(const Napi::CallbackInfo& info);

/**
 * Check if promise hooks are currently enabled
 */
bool IsEnabled();

/**
 * Get tracking statistics for debugging/monitoring
 *
 * @param info CallbackInfo (no parameters)
 * @returns Object with trackedPromises, pendingCleanup, enabled, etc.
 */
Napi::Value GetStats(const Napi::CallbackInfo& info);

} // namespace PromiseHooks
} // namespace dotnope

#endif // DOTNOPE_PROMISE_HOOKS_H
