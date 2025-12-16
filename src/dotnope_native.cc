#include <napi.h>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <vector>
#include <mutex>

/**
 * DotnopeCache - High-performance native cache for environment variable access control
 *
 * Provides O(1) lookup for whitelist checking and thread-safe access tracking.
 */
class DotnopeCache : public Napi::ObjectWrap<DotnopeCache> {
public:
    static Napi::Object Init(Napi::Env env, Napi::Object exports) {
        Napi::Function func = DefineClass(env, "DotnopeCache", {
            InstanceMethod("setWhitelist", &DotnopeCache::SetWhitelist),
            InstanceMethod("isAllowed", &DotnopeCache::IsAllowed),
            InstanceMethod("addPeerDeps", &DotnopeCache::AddPeerDeps),
            InstanceMethod("trackAccess", &DotnopeCache::TrackAccess),
            InstanceMethod("getAccessCount", &DotnopeCache::GetAccessCount),
            InstanceMethod("clear", &DotnopeCache::Clear),
            InstanceMethod("getWhitelistSize", &DotnopeCache::GetWhitelistSize)
        });

        Napi::FunctionReference* constructor = new Napi::FunctionReference();
        *constructor = Napi::Persistent(func);
        env.SetInstanceData(constructor);

        exports.Set("DotnopeCache", func);
        return exports;
    }

    DotnopeCache(const Napi::CallbackInfo& info)
        : Napi::ObjectWrap<DotnopeCache>(info) {}

private:
    // Package name -> Set of allowed env var names
    std::unordered_map<std::string, std::unordered_set<std::string>> whitelist_;

    // Package name -> Set of env vars allowed via peer dependencies
    std::unordered_map<std::string, std::unordered_set<std::string>> peerDepsAllowed_;

    // "packageName:envVar" -> access count
    std::unordered_map<std::string, uint64_t> accessCounts_;

    // Thread safety
    std::mutex mutex_;

    /**
     * Set the whitelist for a package
     * @param packageName - Name of the package
     * @param allowed - Array of allowed env var names
     */
    Napi::Value SetWhitelist(const Napi::CallbackInfo& info) {
        Napi::Env env = info.Env();

        if (info.Length() < 2 || !info[0].IsString() || !info[1].IsArray()) {
            Napi::TypeError::New(env, "Expected (packageName: string, allowed: string[])")
                .ThrowAsJavaScriptException();
            return env.Null();
        }

        std::string packageName = info[0].As<Napi::String>().Utf8Value();
        Napi::Array allowed = info[1].As<Napi::Array>();

        std::lock_guard<std::mutex> lock(mutex_);

        std::unordered_set<std::string> envVars;
        for (uint32_t i = 0; i < allowed.Length(); i++) {
            Napi::Value item = allowed.Get(i);
            if (item.IsString()) {
                envVars.insert(item.As<Napi::String>().Utf8Value());
            }
        }

        whitelist_[packageName] = std::move(envVars);

        return env.Undefined();
    }

    /**
     * Check if a package is allowed to access an env var
     * @param packageName - Name of the package
     * @param envVar - Environment variable name
     * @returns boolean
     */
    Napi::Value IsAllowed(const Napi::CallbackInfo& info) {
        Napi::Env env = info.Env();

        if (info.Length() < 2 || !info[0].IsString() || !info[1].IsString()) {
            return Napi::Boolean::New(env, false);
        }

        std::string packageName = info[0].As<Napi::String>().Utf8Value();
        std::string envVar = info[1].As<Napi::String>().Utf8Value();

        std::lock_guard<std::mutex> lock(mutex_);

        // Check direct whitelist
        auto it = whitelist_.find(packageName);
        if (it != whitelist_.end()) {
            // Check for wildcard or specific env var
            if (it->second.find("*") != it->second.end() ||
                it->second.find(envVar) != it->second.end()) {
                return Napi::Boolean::New(env, true);
            }
        }

        // Check if allowed via peer dependencies
        auto peerIt = peerDepsAllowed_.find(packageName);
        if (peerIt != peerDepsAllowed_.end()) {
            if (peerIt->second.find("*") != peerIt->second.end() ||
                peerIt->second.find(envVar) != peerIt->second.end()) {
                return Napi::Boolean::New(env, true);
            }
        }

        return Napi::Boolean::New(env, false);
    }

    /**
     * Grant peer dependencies the same permissions as parent package
     * @param packageName - Parent package name
     * @param deps - Array of dependency names
     */
    Napi::Value AddPeerDeps(const Napi::CallbackInfo& info) {
        Napi::Env env = info.Env();

        if (info.Length() < 2 || !info[0].IsString() || !info[1].IsArray()) {
            return env.Undefined();
        }

        std::string packageName = info[0].As<Napi::String>().Utf8Value();
        Napi::Array deps = info[1].As<Napi::Array>();

        std::lock_guard<std::mutex> lock(mutex_);

        // Get allowed env vars for the parent package
        auto parentIt = whitelist_.find(packageName);
        if (parentIt == whitelist_.end()) {
            return env.Undefined();
        }

        // Grant same permissions to all peer dependencies
        for (uint32_t i = 0; i < deps.Length(); i++) {
            Napi::Value item = deps.Get(i);
            if (item.IsString()) {
                std::string depName = item.As<Napi::String>().Utf8Value();
                // Merge parent's permissions into peer dep's allowed set
                peerDepsAllowed_[depName].insert(
                    parentIt->second.begin(),
                    parentIt->second.end()
                );
            }
        }

        return env.Undefined();
    }

    /**
     * Track an access attempt for statistics
     * @param packageName - Package that accessed
     * @param envVar - Environment variable accessed
     */
    Napi::Value TrackAccess(const Napi::CallbackInfo& info) {
        Napi::Env env = info.Env();

        if (info.Length() < 2 || !info[0].IsString() || !info[1].IsString()) {
            return env.Undefined();
        }

        std::string packageName = info[0].As<Napi::String>().Utf8Value();
        std::string envVar = info[1].As<Napi::String>().Utf8Value();

        std::lock_guard<std::mutex> lock(mutex_);

        std::string key = packageName + ":" + envVar;
        accessCounts_[key]++;

        return env.Undefined();
    }

    /**
     * Get all access counts
     * @returns Object mapping "packageName:envVar" to count
     */
    Napi::Value GetAccessCount(const Napi::CallbackInfo& info) {
        Napi::Env env = info.Env();

        std::lock_guard<std::mutex> lock(mutex_);

        Napi::Object result = Napi::Object::New(env);

        for (const auto& pair : accessCounts_) {
            result.Set(pair.first, Napi::Number::New(env, static_cast<double>(pair.second)));
        }

        return result;
    }

    /**
     * Clear all caches
     */
    Napi::Value Clear(const Napi::CallbackInfo& info) {
        std::lock_guard<std::mutex> lock(mutex_);

        whitelist_.clear();
        peerDepsAllowed_.clear();
        accessCounts_.clear();

        return info.Env().Undefined();
    }

    /**
     * Get whitelist size (for debugging)
     */
    Napi::Value GetWhitelistSize(const Napi::CallbackInfo& info) {
        std::lock_guard<std::mutex> lock(mutex_);
        return Napi::Number::New(info.Env(), static_cast<double>(whitelist_.size()));
    }
};

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    return DotnopeCache::Init(env, exports);
}

NODE_API_MODULE(dotnope_native, Init)
