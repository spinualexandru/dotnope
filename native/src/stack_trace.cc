/**
 * stack_trace.cc - V8 stack trace capture implementation
 */

#include "stack_trace.h"
#include <v8.h>
#include <string>
#include <algorithm>

namespace dotnope {
namespace StackTrace {

// Dynamic module base path (set during initialization)
static std::string g_modulePath;

// Internal file names to skip (relative to module root)
static const char* INTERNAL_FILES[] = {
    "/lib/proxy.js",
    "/lib/stack-parser.js",
    "/lib/dotnope.js",
    "/lib/config-loader.js",
    "/lib/dependency-resolver.js",
    "/lib/native-bridge.js",
    "/lib/preload-generator.js",
    "/index.js",
    "/index.mjs"
};
static const size_t INTERNAL_FILE_COUNT = sizeof(INTERNAL_FILES) / sizeof(INTERNAL_FILES[0]);

// Fallback patterns for installed module (node_modules/dotnope/...)
static const char* INTERNAL_PATTERNS[] = {
    "node_modules/dotnope/lib/",
    "node_modules/dotnope/index"
};
static const size_t INTERNAL_PATTERN_COUNT = sizeof(INTERNAL_PATTERNS) / sizeof(INTERNAL_PATTERNS[0]);

/**
 * Set the module's base path for internal file detection
 */
void SetModulePath(const std::string& basePath) {
    g_modulePath = basePath;
}

/**
 * Check if a file path is internal to dotnope
 */
static bool IsInternalPath(const std::string& path) {
    // Check against dynamic module path if set
    if (!g_modulePath.empty()) {
        for (size_t i = 0; i < INTERNAL_FILE_COUNT; ++i) {
            std::string fullPath = g_modulePath + INTERNAL_FILES[i];
            if (path == fullPath) {
                return true;
            }
        }
    }

    // Fallback to pattern matching for installed module
    for (size_t i = 0; i < INTERNAL_PATTERN_COUNT; ++i) {
        if (path.find(INTERNAL_PATTERNS[i]) != std::string::npos) {
            return true;
        }
    }
    return false;
}

/**
 * Check if a path starts with node: or internal/
 */
static bool IsNodeInternal(const std::string& path) {
    return path.rfind("node:", 0) == 0 ||
           path.rfind("internal/", 0) == 0;
}

/**
 * Extract package name from a file path
 */
std::string ExtractPackageName(const std::string& filePath) {
    // Find the last occurrence of node_modules
    const std::string nodeModules = "node_modules/";
    size_t pos = filePath.rfind(nodeModules);

    if (pos == std::string::npos) {
        // Not in node_modules - this is the main application
        return "__main__";
    }

    // Extract the part after node_modules/
    std::string afterNodeModules = filePath.substr(pos + nodeModules.length());

    // Find the first path separator
    size_t slashPos = afterNodeModules.find('/');
    if (slashPos == std::string::npos) {
        return afterNodeModules;
    }

    // Check for scoped package (@scope/package)
    if (afterNodeModules[0] == '@') {
        // Find the second slash for scoped packages
        size_t secondSlash = afterNodeModules.find('/', slashPos + 1);
        if (secondSlash != std::string::npos) {
            return afterNodeModules.substr(0, secondSlash);
        }
        return afterNodeModules;
    }

    // Regular package - return up to the first slash
    return afterNodeModules.substr(0, slashPos);
}

/**
 * Convert V8 string to std::string
 */
static std::string V8StringToStd(v8::Isolate* isolate, v8::Local<v8::String> v8Str) {
    if (v8Str.IsEmpty()) {
        return "";
    }
    // Cast to Local<Value> for newer V8 API compatibility
    v8::Local<v8::Value> v8Val = v8Str.template As<v8::Value>();
    v8::String::Utf8Value utf8(isolate, v8Val);
    return *utf8 ? std::string(*utf8) : "";
}

/**
 * Capture the current stack trace using V8 API
 */
Napi::Value Capture(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    // Get optional skip frames parameter
    int skipFrames = 0;
    if (info.Length() > 0 && info[0].IsNumber()) {
        skipFrames = info[0].As<Napi::Number>().Int32Value();
    }

    // Get the V8 isolate
    v8::Isolate* isolate = v8::Isolate::GetCurrent();
    if (!isolate) {
        return env.Null();
    }

    // Capture stack trace with detailed information
    v8::Local<v8::StackTrace> stack = v8::StackTrace::CurrentStackTrace(
        isolate,
        50,  // Max frames
        v8::StackTrace::kDetailed
    );

    if (stack.IsEmpty()) {
        return env.Null();
    }

    int frameCount = stack->GetFrameCount();
    Napi::Array result = Napi::Array::New(env);
    uint32_t resultIndex = 0;

    for (int i = skipFrames; i < frameCount; ++i) {
        v8::Local<v8::StackFrame> frame = stack->GetFrame(isolate, i);
        if (frame.IsEmpty()) {
            continue;
        }

        // Get script name
        v8::Local<v8::String> scriptNameV8 = frame->GetScriptName();
        std::string scriptName = V8StringToStd(isolate, scriptNameV8);

        // Skip internal Node.js modules
        if (IsNodeInternal(scriptName)) {
            continue;
        }

        // Skip dotnope's own files
        if (IsInternalPath(scriptName)) {
            continue;
        }

        // Get function name
        v8::Local<v8::String> funcNameV8 = frame->GetFunctionName();
        std::string functionName = V8StringToStd(isolate, funcNameV8);
        if (functionName.empty()) {
            functionName = "<anonymous>";
        }

        // Create frame object
        Napi::Object frameObj = Napi::Object::New(env);
        frameObj.Set("scriptName", Napi::String::New(env, scriptName));
        frameObj.Set("functionName", Napi::String::New(env, functionName));
        frameObj.Set("lineNumber", Napi::Number::New(env, frame->GetLineNumber()));
        frameObj.Set("columnNumber", Napi::Number::New(env, frame->GetColumn()));
        frameObj.Set("isEval", Napi::Boolean::New(env, frame->IsEval()));
        frameObj.Set("isConstructor", Napi::Boolean::New(env, frame->IsConstructor()));

        // Extract package name
        std::string packageName = ExtractPackageName(scriptName);
        frameObj.Set("packageName", Napi::String::New(env, packageName));

        result.Set(resultIndex++, frameObj);
    }

    return result;
}

/**
 * Get caller information (first non-internal frame)
 */
Napi::Value GetCallerInfo(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    // Get optional skip frames parameter
    int skipFrames = 0;
    if (info.Length() > 0 && info[0].IsNumber()) {
        skipFrames = info[0].As<Napi::Number>().Int32Value();
    }

    // Add skip for this function itself
    skipFrames += 1;

    // Get the V8 isolate
    v8::Isolate* isolate = v8::Isolate::GetCurrent();
    if (!isolate) {
        return env.Null();
    }

    // Capture stack trace
    v8::Local<v8::StackTrace> stack = v8::StackTrace::CurrentStackTrace(
        isolate,
        50,
        v8::StackTrace::kDetailed
    );

    if (stack.IsEmpty()) {
        return env.Null();
    }

    int frameCount = stack->GetFrameCount();

    for (int i = skipFrames; i < frameCount; ++i) {
        v8::Local<v8::StackFrame> frame = stack->GetFrame(isolate, i);
        if (frame.IsEmpty()) {
            continue;
        }

        // Get script name
        v8::Local<v8::String> scriptNameV8 = frame->GetScriptName();
        std::string scriptName = V8StringToStd(isolate, scriptNameV8);

        // Skip frames with no script name
        if (scriptName.empty()) {
            continue;
        }

        // Skip internal Node.js modules
        if (IsNodeInternal(scriptName)) {
            continue;
        }

        // Skip dotnope's own files
        if (IsInternalPath(scriptName)) {
            continue;
        }

        // Get function name
        v8::Local<v8::String> funcNameV8 = frame->GetFunctionName();
        std::string functionName = V8StringToStd(isolate, funcNameV8);
        if (functionName.empty()) {
            functionName = "<anonymous>";
        }

        // Extract package name
        std::string packageName = ExtractPackageName(scriptName);

        // Create result object
        Napi::Object result = Napi::Object::New(env);
        result.Set("packageName", Napi::String::New(env, packageName));
        result.Set("fileName", Napi::String::New(env, scriptName));
        result.Set("lineNumber", Napi::Number::New(env, frame->GetLineNumber()));
        result.Set("columnNumber", Napi::Number::New(env, frame->GetColumn()));
        result.Set("functionName", Napi::String::New(env, functionName));
        result.Set("isEval", Napi::Boolean::New(env, frame->IsEval()));
        result.Set("isConstructor", Napi::Boolean::New(env, frame->IsConstructor()));

        return result;
    }

    // Could not determine caller
    return env.Null();
}

} // namespace StackTrace
} // namespace dotnope
