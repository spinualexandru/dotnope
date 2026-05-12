/**
 * dotnope_preload.c - LD_PRELOAD library for libc getenv interposition
 *
 * This library intercepts getenv/setenv/unsetenv calls from native code,
 * allowing dotnope to control environment variable access even from
 * C/C++ native addons.
 *
 * Usage:
 *   LD_PRELOAD=/path/to/libdotnope_preload.so node app.js
 *
 * Configuration is read from DOTNOPE_POLICY environment variable or
 * from a Unix domain socket for dynamic policy updates.
 */

/* _GNU_SOURCE is defined via CFLAGS in Makefile */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>

/* Original libc functions */
static char* (*real_getenv)(const char*) = NULL;
static int (*real_setenv)(const char*, const char*, int) = NULL;
static int (*real_unsetenv)(const char*) = NULL;

/* File access functions for proc environ protection */
static int (*real_open)(const char*, int, ...) = NULL;
static int (*real_openat)(int, const char*, int, ...) = NULL;
static FILE* (*real_fopen)(const char*, const char*) = NULL;
static int (*real_access)(const char*, int) = NULL;
static int (*real___open_2)(const char*, int) = NULL;  /* FORTIFY_SOURCE variant */

/* Thread-safe initialization */
static pthread_once_t init_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t policy_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Scoped allow list (expandable via shared memory or socket) */
#define MAX_ALLOWED_VARS 256
#define MAX_POLICY_PACKAGES 128
#define MAX_PACKAGE_NAME 256
static char* allowed_vars[MAX_ALLOWED_VARS];
static int allowed_count = 0;
typedef struct {
    char* package_name;
    char* allowed_vars[MAX_ALLOWED_VARS];
    int allowed_count;
} package_policy_t;
static package_policy_t package_policies[MAX_POLICY_PACKAGES];
static int package_policy_count = 0;
static int policy_loaded = 0;

/* Logging */
static int log_enabled = 0;
static FILE* log_file = NULL;

/**
 * Log an access attempt
 */
static void log_access(const char* op, const char* name, int allowed) {
    if (!log_enabled || !log_file) return;

    fprintf(log_file, "[dotnope_preload] %s %s: %s\n",
            op, name, allowed ? "ALLOWED" : "BLOCKED");
    fflush(log_file);
}

static char* trim_token(char* token) {
    while (*token == ' ') token++;
    char* end = token + strlen(token);
    while (end > token && *(end - 1) == ' ') {
        end--;
        *end = '\0';
    }
    return token;
}

static void add_legacy_allowed_var(const char* name) {
    if (allowed_count < MAX_ALLOWED_VARS && name && *name) {
        allowed_vars[allowed_count++] = strdup(name);
    }
}

static package_policy_t* add_package_policy(const char* package_name) {
    if (package_policy_count >= MAX_POLICY_PACKAGES || !package_name || !*package_name) {
        return NULL;
    }

    package_policy_t* policy = &package_policies[package_policy_count++];
    policy->package_name = strdup(package_name);
    policy->allowed_count = 0;
    return policy;
}

static void add_package_allowed_var(package_policy_t* policy, const char* name) {
    if (policy && policy->allowed_count < MAX_ALLOWED_VARS && name && *name) {
        policy->allowed_vars[policy->allowed_count++] = strdup(name);
    }
}

static void extract_package_from_path(const char* path, char* out, size_t out_size) {
    if (!path || !*path) {
        snprintf(out, out_size, "__unknown__");
        return;
    }

    const char* marker = "/node_modules/";
    const char* match = NULL;
    const char* cursor = path;

    while ((cursor = strstr(cursor, marker)) != NULL) {
        match = cursor;
        cursor += strlen(marker);
    }

    if (!match) {
        snprintf(out, out_size, "__main__");
        return;
    }

    const char* start = match + strlen(marker);
    if (strncmp(start, ".pnpm/", 6) == 0) {
        const char* nested = strstr(start, "/node_modules/");
        if (nested) {
            start = nested + strlen(marker);
        }
    }

    const char* end = NULL;
    if (start[0] == '@') {
        const char* first_slash = strchr(start, '/');
        end = first_slash ? strchr(first_slash + 1, '/') : NULL;
    } else {
        end = strchr(start, '/');
    }

    size_t len = end ? (size_t)(end - start) : strlen(start);
    if (len >= out_size) {
        len = out_size - 1;
    }

    memcpy(out, start, len);
    out[len] = '\0';
}

static void get_calling_package(void* caller, char* out, size_t out_size) {
    Dl_info info;

    if (caller && dladdr(caller, &info) && info.dli_fname) {
        extract_package_from_path(info.dli_fname, out, out_size);
        return;
    }

    snprintf(out, out_size, "__unknown__");
}

/**
 * Load policy from environment variable or file
 * Format: package=VAR1|VAR2;other-package=*, or legacy comma list
 */
static void load_policy(void) {
    if (policy_loaded) return;

    pthread_mutex_lock(&policy_mutex);

    if (policy_loaded) {
        pthread_mutex_unlock(&policy_mutex);
        return;
    }

    /* Check for logging */
    const char* log_env = real_getenv ? real_getenv("DOTNOPE_LOG") : getenv("DOTNOPE_LOG");
    if (log_env && *log_env) {
        log_enabled = 1;
        if (strcmp(log_env, "1") == 0 || strcmp(log_env, "stderr") == 0) {
            log_file = stderr;
        } else {
            log_file = fopen(log_env, "a");
            if (!log_file) log_file = stderr;
        }
    }

    /* Get policy */
    const char* policy = real_getenv ? real_getenv("DOTNOPE_POLICY") : getenv("DOTNOPE_POLICY");

    if (!policy || !*policy) {
        /* No policy - allow all (for compatibility) */
        add_legacy_allowed_var("*");
        policy_loaded = 1;
        pthread_mutex_unlock(&policy_mutex);
        return;
    }

    /* Parse policy */
    char* policy_copy = strdup(policy);
    if (strchr(policy_copy, '=') == NULL) {
        char* saveptr = NULL;
        char* token = strtok_r(policy_copy, ",", &saveptr);

        while (token && allowed_count < MAX_ALLOWED_VARS) {
            add_legacy_allowed_var(trim_token(token));
            token = strtok_r(NULL, ",", &saveptr);
        }
    } else {
        char* package_saveptr = NULL;
        char* package_entry = strtok_r(policy_copy, ";", &package_saveptr);

        while (package_entry && package_policy_count < MAX_POLICY_PACKAGES) {
            char* equals = strchr(package_entry, '=');
            if (equals) {
                *equals = '\0';
                char* package_name = trim_token(package_entry);
                char* vars = equals + 1;
                package_policy_t* package_policy = add_package_policy(package_name);

                char* var_saveptr = NULL;
                char* var_name = strtok_r(vars, "|", &var_saveptr);
                while (var_name && package_policy && package_policy->allowed_count < MAX_ALLOWED_VARS) {
                    add_package_allowed_var(package_policy, trim_token(var_name));
                    var_name = strtok_r(NULL, "|", &var_saveptr);
                }
            }
            package_entry = strtok_r(NULL, ";", &package_saveptr);
        }
    }

    free(policy_copy);
    policy_loaded = 1;

    if (log_enabled) {
        fprintf(log_file, "[dotnope_preload] Loaded policy with %d scoped packages and %d legacy vars\n",
                package_policy_count, allowed_count);
        fflush(log_file);
    }

    pthread_mutex_unlock(&policy_mutex);
}

/**
 * Check if a variable is allowed
 */
static int is_allowed(const char* name, void* caller) {
    if (!policy_loaded) {
        load_policy();
    }

    /* Always allow some essential variables */
    if (strcmp(name, "PATH") == 0 ||
        strcmp(name, "HOME") == 0 ||
        strcmp(name, "USER") == 0 ||
        strcmp(name, "SHELL") == 0 ||
        strcmp(name, "TERM") == 0 ||
        strcmp(name, "LANG") == 0 ||
        strcmp(name, "LC_ALL") == 0 ||
        strncmp(name, "DOTNOPE_", 8) == 0) {
        return 1;
    }

    char package_name[MAX_PACKAGE_NAME];
    get_calling_package(caller, package_name, sizeof(package_name));

    pthread_mutex_lock(&policy_mutex);

    for (int i = 0; i < allowed_count; i++) {
        if (strcmp(allowed_vars[i], "*") == 0) {
            pthread_mutex_unlock(&policy_mutex);
            return 1;
        }
        if (strcmp(allowed_vars[i], name) == 0) {
            pthread_mutex_unlock(&policy_mutex);
            return 1;
        }
    }

    for (int i = 0; i < package_policy_count; i++) {
        package_policy_t* policy = &package_policies[i];
        if (strcmp(policy->package_name, package_name) != 0) {
            continue;
        }

        for (int j = 0; j < policy->allowed_count; j++) {
            if (strcmp(policy->allowed_vars[j], "*") == 0 ||
                strcmp(policy->allowed_vars[j], name) == 0) {
                pthread_mutex_unlock(&policy_mutex);
                return 1;
            }
        }
    }

    pthread_mutex_unlock(&policy_mutex);
    return 0;
}

/**
 * Check if a path is protected, such as proc environ files
 * This prevents native code from reading environment variables directly from /proc
 */
static int is_protected_path(const char* path) {
    if (!path) return 0;

    /* Get our own PID for self-reference detection */
    pid_t my_pid = getpid();
    char self_environ[64];
    snprintf(self_environ, sizeof(self_environ), "/proc/%d/environ", my_pid);

    /* Block direct /proc/self/environ access */
    if (strcmp(path, "/proc/self/environ") == 0) return 1;

    /* Block /proc/PID/environ for our own process */
    if (strcmp(path, self_environ) == 0) return 1;

    /* Block any path containing /proc/ and environ together */
    /* This catches variations like /proc/self/fd/../environ */
    if (strstr(path, "/proc/") != NULL && strstr(path, "environ") != NULL) {
        return 1;
    }

    return 0;
}

/**
 * Initialize by loading real libc functions
 */
static void init_real_functions(void) {
    real_getenv = dlsym(RTLD_NEXT, "getenv");
    real_setenv = dlsym(RTLD_NEXT, "setenv");
    real_unsetenv = dlsym(RTLD_NEXT, "unsetenv");

    /* File access functions for /proc protection */
    real_open = dlsym(RTLD_NEXT, "open");
    real_openat = dlsym(RTLD_NEXT, "openat");
    real_fopen = dlsym(RTLD_NEXT, "fopen");
    real_access = dlsym(RTLD_NEXT, "access");
    real___open_2 = dlsym(RTLD_NEXT, "__open_2");  /* May be NULL on some systems */

    if (!real_getenv || !real_setenv || !real_unsetenv) {
        fprintf(stderr, "[dotnope_preload] Failed to load libc functions\n");
        _exit(1);
    }

    if (!real_open || !real_fopen) {
        fprintf(stderr, "[dotnope_preload] Warning: Failed to load file access functions\n");
    }

    load_policy();
}

/**
 * Hooked getenv
 */
char* getenv(const char* name) {
    pthread_once(&init_once, init_real_functions);

    if (!name) return NULL;

    int allowed = is_allowed(name, __builtin_return_address(0));
    log_access("getenv", name, allowed);

    if (!allowed) {
        return NULL;
    }

    return real_getenv(name);
}

/**
 * Hooked setenv
 */
int setenv(const char* name, const char* value, int overwrite) {
    pthread_once(&init_once, init_real_functions);

    if (!name) {
        errno = EINVAL;
        return -1;
    }

    int allowed = is_allowed(name, __builtin_return_address(0));
    log_access("setenv", name, allowed);

    if (!allowed) {
        errno = EPERM;
        return -1;
    }

    return real_setenv(name, value, overwrite);
}

/**
 * Hooked unsetenv
 */
int unsetenv(const char* name) {
    pthread_once(&init_once, init_real_functions);

    if (!name) {
        errno = EINVAL;
        return -1;
    }

    int allowed = is_allowed(name, __builtin_return_address(0));
    log_access("unsetenv", name, allowed);

    if (!allowed) {
        errno = EPERM;
        return -1;
    }

    return real_unsetenv(name);
}

/**
 * Hooked open - block proc environ access
 */
int open(const char* pathname, int flags, ...) {
    pthread_once(&init_once, init_real_functions);

    if (!real_open) {
        errno = ENOSYS;
        return -1;
    }

    if (is_protected_path(pathname)) {
        log_access("open", pathname, 0);
        errno = EACCES;
        return -1;
    }

    /* Handle variadic mode argument for O_CREAT */
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode_t mode = va_arg(args, mode_t);
        va_end(args);
        return real_open(pathname, flags, mode);
    }

    return real_open(pathname, flags);
}

/**
 * Hooked open64 - 64-bit variant (often same as open on modern systems)
 */
int open64(const char* pathname, int flags, ...) {
    pthread_once(&init_once, init_real_functions);

    if (!real_open) {
        errno = ENOSYS;
        return -1;
    }

    if (is_protected_path(pathname)) {
        log_access("open64", pathname, 0);
        errno = EACCES;
        return -1;
    }

    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode_t mode = va_arg(args, mode_t);
        va_end(args);
        return real_open(pathname, flags, mode);
    }

    return real_open(pathname, flags);
}

/**
 * Hooked __open_2 - FORTIFY_SOURCE variant used by glibc
 */
int __open_2(const char* pathname, int flags) {
    pthread_once(&init_once, init_real_functions);

    if (is_protected_path(pathname)) {
        log_access("__open_2", pathname, 0);
        errno = EACCES;
        return -1;
    }

    if (real___open_2) {
        return real___open_2(pathname, flags);
    }
    /* Fallback to regular open */
    if (real_open) {
        return real_open(pathname, flags);
    }

    errno = ENOSYS;
    return -1;
}

/**
 * Hooked openat - block proc environ via dirfd-relative paths
 */
int openat(int dirfd, const char* pathname, int flags, ...) {
    pthread_once(&init_once, init_real_functions);

    if (!real_openat) {
        errno = ENOSYS;
        return -1;
    }

    if (is_protected_path(pathname)) {
        log_access("openat", pathname, 0);
        errno = EACCES;
        return -1;
    }

    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode_t mode = va_arg(args, mode_t);
        va_end(args);
        return real_openat(dirfd, pathname, flags, mode);
    }

    return real_openat(dirfd, pathname, flags);
}

/**
 * Hooked fopen - block proc environ via stdio
 */
FILE* fopen(const char* pathname, const char* mode) {
    pthread_once(&init_once, init_real_functions);

    if (!real_fopen) {
        errno = ENOSYS;
        return NULL;
    }

    if (is_protected_path(pathname)) {
        log_access("fopen", pathname, 0);
        errno = EACCES;
        return NULL;
    }

    return real_fopen(pathname, mode);
}

/**
 * Hooked fopen64 - 64-bit variant
 */
FILE* fopen64(const char* pathname, const char* mode) {
    pthread_once(&init_once, init_real_functions);

    if (!real_fopen) {
        errno = ENOSYS;
        return NULL;
    }

    if (is_protected_path(pathname)) {
        log_access("fopen64", pathname, 0);
        errno = EACCES;
        return NULL;
    }

    return real_fopen(pathname, mode);
}

/**
 * Hooked access - block checking if proc environ exists
 */
int access(const char* pathname, int mode) {
    pthread_once(&init_once, init_real_functions);

    if (!real_access) {
        errno = ENOSYS;
        return -1;
    }

    if (is_protected_path(pathname)) {
        log_access("access", pathname, 0);
        errno = EACCES;
        return -1;
    }

    return real_access(pathname, mode);
}

/**
 * Constructor - called when library is loaded
 */
__attribute__((constructor))
static void dotnope_preload_init(void) {
    pthread_once(&init_once, init_real_functions);
}

/**
 * Destructor - cleanup when library is unloaded
 */
__attribute__((destructor))
static void dotnope_preload_cleanup(void) {
    pthread_mutex_lock(&policy_mutex);

    for (int i = 0; i < allowed_count; i++) {
        free(allowed_vars[i]);
        allowed_vars[i] = NULL;
    }
    allowed_count = 0;

    for (int i = 0; i < package_policy_count; i++) {
        free(package_policies[i].package_name);
        package_policies[i].package_name = NULL;
        for (int j = 0; j < package_policies[i].allowed_count; j++) {
            free(package_policies[i].allowed_vars[j]);
            package_policies[i].allowed_vars[j] = NULL;
        }
        package_policies[i].allowed_count = 0;
    }
    package_policy_count = 0;

    if (log_file && log_file != stderr) {
        fclose(log_file);
    }

    pthread_mutex_unlock(&policy_mutex);
}
