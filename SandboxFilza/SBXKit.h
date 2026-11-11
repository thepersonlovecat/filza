//
//  SBXKit.h
//  SandboxFilza
//
//  Sandbox escape primitives extracted verbatim from terminal_worse
//  (src/TerminalSBX.m, GPL-3.0):
//    - worse_query  (Taj C / forcequitOS, GPL-3.0)
//    - class-13 fallback (Veilpath / bad_query lineage)
//    - pathleak inode enumeration (forcequitOS, GPL-3.0)
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// One container returned by enumeration (app, daemon, plugin, system group).
@interface SBXContainer : NSObject
@property (nonatomic, copy, readonly) NSString *path;
/// Bundle ID / MCM identifier when known, else empty string.
@property (nonatomic, copy, readonly) NSString *identifier;
- (instancetype)initWithPath:(NSString *)path identifier:(NSString *)identifier;
@end

@interface SBXKit : NSObject

/// Ordered mount-point table (same roots as terminal_worse's sbx_mount_points).
/// Keys: name, root, children (YES = enumerate per-container), class.
+ (NSArray<NSDictionary *> *)mountPoints;

/// Resolve and return the usable app group identifier, or nil.
+ (nullable NSString *)resolveGroup;

/// Enumerate the containers under a mount point.
/// Tries list-dir (when the parent grants a token) then falls back to
/// fsgetpath inode scanning, mirroring sbx_automount.
+ (NSArray<SBXContainer *> *)containersForMountPoint:(NSDictionary *)mountPoint;

/// Consume a sandbox extension for an absolute path.
/// On success returns YES; `engine` (optional) is "worse_query", "fallback",
/// "cached" or "own-sandbox". Mirrors sbx_grant_path.
+ (BOOL)grantPath:(NSString *)path create:(BOOL)create engine:(NSString * _Nullable * _Nullable)engine;

/// Grant a path for browsing a file/dir item (follows symlinks, falls back
/// to the parent directory). Mirrors sbx_grant_item.
+ (BOOL)grantItem:(NSString *)path;

/// Release every consumed extension.
+ (void)releaseAll;

/// List a directory's entry names (sorted), or nil when opendir fails.
+ (nullable NSArray<NSString *> *)listDir:(NSString *)path;

/// Read a container's bundle ID from xattr / MCM metadata plist.
+ (nullable NSString *)bundleIDForContainer:(NSString *)containerPath;

+ (BOOL)isOwnPath:(NSString *)path;
+ (BOOL)pathExists:(NSString *)path;
+ (BOOL)pathIsDir:(NSString *)path;

/// Human-readable error for a negative sbx query return code.
+ (NSString *)errorTextForCode:(int64_t)code;

/// Count of active handles (for a status footer).
+ (NSUInteger)activeHandles;

/// Returns the last engine string used for a successful grant ("worse_query",
/// "fallback", "cached", "own-sandbox"), nil when nothing granted yet.
+ (nullable NSString *)lastEngine;

@end

NS_ASSUME_NONNULL_END
