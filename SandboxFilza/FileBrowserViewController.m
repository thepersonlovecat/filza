//
//  FileBrowserViewController.m
//  SandboxFilza
//
//  Root view lists the seven sandbox escape roots (apps, daemons, plugins,
//  system, systemgroups, appgroups, appgroups27).  Any other view lists one
//  directory.  Entering a container grants a sandbox extension via SBXKit
//  (worse_query / class-13 fallback) before opendir.
//

#import "FileBrowserViewController.h"
#import "SBXKit.h"

#include <sys/stat.h>

// ---------------------------------------------------------------------------
// Row model
// ---------------------------------------------------------------------------

@interface BrowserRow : NSObject
@property (nonatomic, copy) NSString *name;   // display name
@property (nonatomic, copy) NSString *path;   // absolute path
@property (nonatomic, assign) BOOL isDir;
@property (nonatomic, assign) BOOL isSymlink;
@property (nonatomic, assign, getter=isUnavailable) BOOL unavailable; // grant failed
@property (nonatomic, copy, nullable) NSString *subtitle;             // bundle ID / size
@end

@implementation BrowserRow
@end

// ---------------------------------------------------------------------------
// Text/hex viewer
// ---------------------------------------------------------------------------

@interface TextPreviewViewController : UIViewController
- (instancetype)initWithPath:(NSString *)path;
@end

@implementation TextPreviewViewController {
    NSString *_path;
    UITextView *_textView;
    UIActivityIndicatorView *_spinner;
}

- (instancetype)initWithPath:(NSString *)path {
    self = [super init];
    if (self) {
        _path = path;
        self.title = path.lastPathComponent;
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor systemBackgroundColor];

    _textView = [[UITextView alloc] initWithFrame:self.view.bounds];
    _textView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    _textView.editable = NO;
    _textView.font = [UIFont fontWithName:@"Menlo-Regular" size:12.0] ?: [UIFont systemFontOfSize:12.0];
    _textView.textContainerInset = UIEdgeInsetsMake(12, 12, 12, 12);
    [self.view addSubview:_textView];

    _spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
    _spinner.center = CGPointMake(self.view.bounds.size.width / 2, self.view.bounds.size.height / 3);
    _spinner.autoresizingMask = UIViewAutoresizingFlexibleTopMargin | UIViewAutoresizingFlexibleLeftMargin
                              | UIViewAutoresizingFlexibleRightMargin | UIViewAutoresizingFlexibleBottomMargin;
    [_spinner startAnimating];
    [self.view addSubview:_spinner];

    self.navigationItem.rightBarButtonItem = [[UIBarButtonItem alloc] initWithTitle:@"Share"
                                                                              style:UIBarButtonItemStylePlain
                                                                             target:self
                                                                             action:@selector(shareFile:)];
}

- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSData *data = [NSData dataWithContentsOfFile:self->_path options:NSDataReadingMappedIfSafe error:NULL];

        NSMutableString *text = [NSMutableString string];
        if (data.length == 0) {
            [text appendString:@"(empty file)"];
        } else {
            // Sniff: printable-ish for the first 4 KiB -> text preview,
            // otherwise hexdump the first 4 KiB.
            NSUInteger sniff = MIN(data.length, (NSUInteger)4096);
            const char *bytes = data.bytes;
            BOOL looksText = YES;
            for (NSUInteger i = 0; i < sniff; i++) {
                unsigned char c = (unsigned char)bytes[i];
                if (c == 0 || (c < 9 && c != 0) || (c > 13 && c < 32 && c != 27)) { looksText = NO; break; }
            }
            if (looksText) {
                NSString *head = [[NSString alloc] initWithData:[data subdataWithRange:NSMakeRange(0, sniff)]
                                                       encoding:NSUTF8StringEncoding];
                if (head) {
                    [text appendString:head];
                    if (data.length > sniff) {
                        [text appendFormat:@"\n\n… (%@ total, showing first %lu bytes)",
                         [NSByteCountFormatter stringFromByteCount:(long long)data.length
                                                        countStyle:NSByteCountFormatterCountStyleFile],
                         (unsigned long)sniff];
                    }
                } else {
                    looksText = NO;
                }
            }
            if (!looksText) {
                [text setString:[self hexDump:data limit:4096]];
            }
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            self->_textView.text = text;
            [self->_spinner stopAnimating];
            self->_spinner.hidden = YES;
        });
    });
}

- (NSString *)hexDump:(NSData *)data limit:(NSUInteger)limit {
    NSMutableString *out = [NSMutableString string];
    NSUInteger n = MIN(data.length, limit);
    const unsigned char *b = data.bytes;
    for (NSUInteger off = 0; off < n; off += 16) {
        [out appendFormat:@"%08lx  ", (unsigned long)off];
        for (NSUInteger i = 0; i < 16; i++) {
            if (off + i < n) [out appendFormat:@"%02x ", b[off + i]];
            else [out appendString:@"   "];
            if (i == 7) [out appendString:@" "];
        }
        [out appendString:@" |"];
        for (NSUInteger i = 0; i < 16 && off + i < n; i++) {
            unsigned char c = b[off + i];
            [out appendFormat:@"%c", (c >= 0x20 && c < 0x7f) ? c : '.'];
        }
        [out appendString:@"|\n"];
    }
    if (data.length > limit) {
        [out appendFormat:@"… (%@ total, showing first %lu bytes)",
         [NSByteCountFormatter stringFromByteCount:(long long)data.length
                                        countStyle:NSByteCountFormatterCountStyleFile],
         (unsigned long)limit];
    }
    return out;
}

- (void)shareFile:(id)sender {
    NSURL *url = [NSURL fileURLWithPath:_path];
    UIActivityViewController *vc = [[UIActivityViewController alloc] initWithActivityItems:@[url] applicationActivities:nil];
    if (self.presentationController) {
        [self presentViewController:vc animated:YES completion:nil];
    }
}

@end

// ---------------------------------------------------------------------------
// File browser
// ---------------------------------------------------------------------------

@implementation FileBrowserViewController {
    NSString *_path;          // nil = root
    NSMutableArray<BrowserRow *> *_rows;
    NSString *_status;        // root view: last grant engine / handle count
}

- (instancetype)initWithPath:(NSString *)path {
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    if (self) {
        _path = [path copy];
        _rows = [NSMutableArray array];
        if (path) self.title = path.lastPathComponent ?: @"/";
        else self.title = @"Sandbox";
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.tableView.rowHeight = UITableViewAutomaticDimension;
    self.tableView.estimatedRowHeight = 44.0;
    [self reloadEntries];
}

- (void)setTitle:(NSString *)title {
    [super setTitle:title];
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

- (void)reloadEntries {
    [_rows removeAllObjects];
    _status = nil;

    if (_path == nil) {
        // Root: the seven escape roots, exactly the terminal_worse table.
        NSArray<NSDictionary *> *points = [SBXKit mountPoints];
        for (NSDictionary *mp in points) {
            BrowserRow *row = [BrowserRow new];
            row.name = [NSString stringWithFormat:@"%@  (%@)", mp[@"name"], [SBXKit pathExists:mp[@"root"]] ? @"ok" : @"missing"];
            row.path = mp[@"root"];
            row.isDir = YES;
            row.subtitle = mp[@"root"];
            [_rows addObject:row];
        }
        _status = [NSString stringWithFormat:@"App group: %@ · handles: %@",
                   [SBXKit resolveGroup] ?: @"(none)",
                   [SBXKit activeHandles] ? [NSString stringWithFormat:@"%lu", (unsigned long)[SBXKit activeHandles]] : @"0"];
        [self.tableView reloadData];
        return;
    }

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        // Grant before listing: containers under enumerated roots may not be
        // directly readable without a token.
        [SBXKit grantPath:self->_path create:NO engine:nil];

        NSArray<NSString *> *entries = [SBXKit listDir:self->_path];
        if (entries == nil) {
            dispatch_async(dispatch_get_main_queue(), ^{
                self->_status = [NSString stringWithFormat:@"Cannot list %@ (no sandbox extension for this path)", self->_path];
                [self.tableView reloadData];
            });
            return;
        }

        NSMutableArray<BrowserRow *> *rows = [NSMutableArray array];
        for (NSString *name in entries) {
            NSString *child = [self->_path stringByAppendingPathComponent:name];
            BrowserRow *row = [BrowserRow new];
            row.name = name;
            row.path = child;

            struct stat st;
            if (lstat(child.fileSystemRepresentation, &st) == 0) {
                row.isSymlink = S_ISLNK(st.st_mode) != 0;
                row.isDir = S_ISDIR(st.st_mode) != 0;
            }
            if (row.isDir) {
                NSString *bid = [SBXKit bundleIDForContainer:child];
                if (bid) row.subtitle = bid;
            } else if (!row.isSymlink) {
                row.subtitle = [NSByteCountFormatter stringFromByteCount:(long long)st.st_size
                                                              countStyle:NSByteCountFormatterCountStyleFile];
            }
            [rows addObject:row];
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            [self->_rows removeAllObjects];
            [self->_rows addObjectsFromArray:rows];
            [self.tableView reloadData];
        });
    });
}

// ---------------------------------------------------------------------------
// Table view
// ---------------------------------------------------------------------------

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return (NSInteger)_rows.count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    static NSString *reuse = @"row";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:reuse];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:reuse];
    }
    BrowserRow *row = _rows[indexPath.row];

    UIImage *base = row.isDir ? [UIImage systemImageNamed:@"folder"] : [UIImage systemImageNamed:@"doc"];
    if (row.isSymlink) base = [UIImage systemImageNamed:@"link"];
    cell.imageView.image = base;
    cell.textLabel.text = row.name;
    cell.detailTextLabel.text = row.subtitle;
    cell.detailTextLabel.textColor = [UIColor secondaryLabelColor];
    cell.accessoryType = row.isDir ? UITableViewCellAccessoryDisclosureIndicator : UITableViewCellAccessoryNone;
    cell.textLabel.adjustsFontSizeToFitWidth = NO;
    cell.textLabel.lineBreakMode = NSLineBreakByTruncatingMiddle;
    return cell;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    BrowserRow *row = _rows[indexPath.row];
    if (!row) return;

    if (row.isDir) {
        FileBrowserViewController *vc = [[FileBrowserViewController alloc] initWithPath:row.path];
        [self.navigationController pushViewController:vc animated:YES];
    } else {
        [self openFileAtPath:row.path];
    }
}

// Long-press: grant again with verbose engine info.
- (UISwipeActionsConfiguration *)tableView:(UITableView *)tableView
trailingSwipeActionsConfigurationForRowAtIndexPath:(NSIndexPath *)indexPath API_AVAILABLE(ios(11.0)) {
    return nil;
}

- (void)openFileAtPath:(NSString *)path {
    // Follow symlink for viewing, grant the parent directory.
    [SBXKit grantItem:path];
    TextPreviewViewController *vc = [[TextPreviewViewController alloc] initWithPath:path];
    [self.navigationController pushViewController:vc animated:YES];
}

- (UIView *)tableView:(UITableView *)tableView viewForFooterInSection:(NSInteger)section {
    if (_status.length == 0) return nil;
    UILabel *label = [[UILabel alloc] initWithFrame:CGRectMake(0, 0, 0, 0)];
    label.text = _status;
    label.font = [UIFont systemFontOfSize:12.0];
    label.textColor = [UIColor secondaryLabelColor];
    label.numberOfLines = 2;
    return label;
}

- (CGFloat)tableView:(UITableView *)tableView heightForFooterInSection:(NSInteger)section {
    return _status.length > 0 ? 40.0 : 0.0;
}

@end
