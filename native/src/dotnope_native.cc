/**
 * dotnope_native - Native addon for enhanced environment variable protection
 *
 * This module provides:
 * 1. V8-level stack trace capture (bypasses Error.prepareStackTrace tampering)
 * 2. Promise hooks for async context tracking
 * 3. Isolate management for worker thread protection
 */

#include <napi.h>
#include "stack_trace.h"
#include "promise_hooks.h"
#include "isolate_manager.h"

namespace dotnope {

/**
 * Get version information
 */
Napi::Value GetVersion(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    Napi::Object result = Napi::Object::New(env);
    result.Set("major", Napi::Number::New(env, 1));
    result.Set("minor", Napi::Number::New(env, 0));
    result.Set("patch", Napi::Number::New(env, 0));
    result.Set("native", Napi::Boolean::New(env, true));
    return result;
}

/**
 * Check if we're running in a worker thread
 */
Napi::Value IsWorkerThread(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    // Check if we're in a worker by looking for the worker_threads module
    // Workers have different isolates
    return Napi::Boolean::New(env, IsolateManager::IsWorkerThread());
}

/**
 * Initialize the native module
 * Accepts optional modulePath parameter for internal file detection
 */
Napi::Value Initialize(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    // Check if module path was provided
    if (info.Length() > 0 && info[0].IsString()) {
        std::string modulePath = info[0].As<Napi::String>().Utf8Value();
        StackTrace::SetModulePath(modulePath);
    }

    // Register this isolate
    IsolateManager::RegisterIsolate();

    // Return success
    return Napi::Boolean::New(env, true);
}

/**
 * Cleanup the native module
 */
Napi::Value Cleanup(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    // Disable promise hooks if enabled
    PromiseHooks::DisableInternal(env);

    // Unregister this isolate
    IsolateManager::UnregisterIsolate();

    return Napi::Boolean::New(env, true);
}

/**
 * Module initialization
 */
Napi::Object Init(Napi::Env env, Napi::Object exports) {
    // Version and status
    exports.Set("getVersion", Napi::Function::New(env, GetVersion));
    exports.Set("isWorkerThread", Napi::Function::New(env, IsWorkerThread));

    // Lifecycle
    exports.Set("initialize", Napi::Function::New(env, Initialize));
    exports.Set("cleanup", Napi::Function::New(env, Cleanup));

    // Stack trace functions
    exports.Set("captureStackTrace", Napi::Function::New(env, StackTrace::Capture));
    exports.Set("getCallerInfo", Napi::Function::New(env, StackTrace::GetCallerInfo));

    // Promise hooks for async tracking
    exports.Set("enablePromiseHooks", Napi::Function::New(env, PromiseHooks::Enable));
    exports.Set("disablePromiseHooks", Napi::Function::New(env, PromiseHooks::Disable));
    exports.Set("getAsyncContext", Napi::Function::New(env, PromiseHooks::GetAsyncContext));
    exports.Set("getPromiseStats", Napi::Function::New(env, PromiseHooks::GetStats));

    // Isolate management
    exports.Set("getIsolateCount", Napi::Function::New(env, IsolateManager::GetIsolateCount));

    return exports;
}

// Register the module
// Use NODE_API_MODULE for context-aware addon (works in worker threads)
NODE_API_MODULE(dotnope_native, Init)

} // namespace dotnope
