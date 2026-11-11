//
//  FileBrowserViewController.h
//  SandboxFilza
//

#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface FileBrowserViewController : UITableViewController

/// Absolute path this view is browsing. May be nil for the root view,
/// which lists the seven mount-point roots.
- (instancetype)initWithPath:(nullable NSString *)path;

/// Push a viewer for a file (text preview / hexdump for binary files).
- (void)openFileAtPath:(NSString *)path;

@end

NS_ASSUME_NONNULL_END
