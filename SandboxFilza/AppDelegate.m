//
//  AppDelegate.m
//  SandboxFilza
//
//  App group resolution starts on launch (the group container is sometimes
//  not visible during the first few hundred milliseconds — the retry loop in
//  SBXKit handles that).  The first mount-point grant runs off-main so the
//  UI appears instantly.
//

#import "AppDelegate.h"
#import "FileBrowserViewController.h"
#import "SBXKit.h"

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    UIWindow *window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    UINavigationController *nav =
        [[UINavigationController alloc] initWithRootViewController:[[FileBrowserViewController alloc] initWithPath:nil]];
    nav.navigationBar.prefersLargeTitles = YES;
    window.rootViewController = nav;
    self.window = window;
    [window makeKeyAndVisible];

    // Warm the escape primitives in the background so the first container
    // open doesn't wait for app-group resolution.
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_BACKGROUND, 0), ^{
        NSString *group = [SBXKit resolveGroup];
        NSLog(@"[SandboxFilza] app group resolved: %@", group ?: @"(none)");
    });

    return YES;
}

@end
