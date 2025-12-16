/**
 * stack_trace.h - V8 stack trace capture
 *
 * Provides reliable stack trace capture using V8 C++ API directly,
 * bypassing JavaScript's Error.prepareStackTrace which can be tampered with.
 */

#ifndef DOTNOPE_STACK_TRACE_H
#define DOTNOPE_STACK_TRACE_H

#include <napi.h>

namespace dotnope {
namespace StackTrace {

/**
 * Set the module's base path for internal file detection
 * This allows the native addon to recognize dotnope's own files
 * even when running from a development directory.
 *
 * @param basePath The absolute path to the module's root directory
 */
void SetModulePath(const std::string& basePath);

/**
 * Capture the current stack trace
 *
 * Returns an array of stack frame objects with:
 * - scriptName: string (file path)
 * - functionName: string
 * - lineNumber: number
 * - columnNumber: number
 * - isEval: boolean
 * - isConstructor: boolean
 * - isNative: boolean
 *
 * @param info CallbackInfo with optional skipFrames parameter
 * @returns Array of stack frame objects
 */
Napi::Value Capture(const Napi::CallbackInfo& info);

/**
 * Get caller information (simplified single-frame capture)
 *
 * Returns an object with:
 * - packageName: string (extracted from path)
 * - fileName: string
 * - lineNumber: number
 * - functionName: string
 * - isEval: boolean
 *
 * @param info CallbackInfo with optional skipFrames parameter
 * @returns Caller info object or null if cannot determine
 */
Napi::Value GetCallerInfo(const Napi::CallbackInfo& info);

/**
 * Extract package name from a file path
 *
 * @param filePath The file path to analyze
 * @returns Package name or "__main__" if not in node_modules
 */
std::string ExtractPackageName(const std::string& filePath);

} // namespace StackTrace
} // namespace dotnope

#endif // DOTNOPE_STACK_TRACE_H
