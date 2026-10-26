// SPDX-License-Identifier: MIT
// System log export: the probe daemon (root, outside every sandbox profile) reads the unified log since boot and writes it as gzip text into
// a subdirectory of the render server's pipeline-cache directory. CacheExport.h ships that directory with the UFS log whenever it settles,
// so the host gets every process's os_log lines (PosterBoard, WidgetRenderer, wifid, ...) without a second export channel.
// Each pass rewrites the file through a temporary name; one daemon instance writes (the job runs under several labels).
#import <Foundation/Foundation.h>
#include <fcntl.h>
#include <objc/message.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>
#include <string>
#include <string.h>

namespace {

constexpr const char *kDirectory = "/private/var/mobile/Library/Caches/com.apple.backboardd/m2v/zz-oslog";
constexpr const char *kLock = "/private/var/tmp/sheng-oslog.lock";
constexpr unsigned kPasses = 40, kPeriodSeconds = 45;
constexpr uint64_t kLineLimit = 600000;

const char *levelName(NSInteger level) {
    switch (level) {
    case 1: return "debug";
    case 2: return "info";
    case 3: return "notice";
    case 4: return "error";
    case 5: return "fault";
    default: return "-";
    }
}

// One pass: every log entry since the latest boot, "seconds pid process subsystem:category level message".
void writePass(unsigned pass) {
    @autoreleasepool {
        const std::string directory = kDirectory, temporary = directory + "/.oslog.txt.gz", final = directory + "/oslog.txt.gz";
        gzFile out = gzopen(temporary.c_str(), "wb6");
        if (!out) return;
        gzprintf(out, "# sheng oslog pass %u\n", pass);
        Class storeClass = NSClassFromString(@"OSLogStore");
        NSError *error = nil;
        // OSLogStoreSystem (0) is unavailable in the iOS SDK headers; the class answers it at run time with the logging entitlements.
        id store = storeClass ? ((id (*)(Class, SEL, NSInteger, NSError **))objc_msgSend)(storeClass, @selector(storeWithScope:error:), 0, &error)
                              : nil;
        if (!store) {
            gzprintf(out, "# no store: %s\n", (error ? error.description : @"OSLogStore missing").UTF8String);
        } else {
            id position = ((id (*)(id, SEL, NSTimeInterval))objc_msgSend)(store, @selector(positionWithTimeIntervalSinceLatestBoot:), 0);
            id entries = ((id (*)(id, SEL, NSUInteger, id, id, NSError **))objc_msgSend)(
                store, @selector(entriesEnumeratorWithOptions:position:predicate:error:), 0, position, nil, &error);
            if (!entries) gzprintf(out, "# no entries: %s\n", (error ? error.description : @"nil").UTF8String);
            NSDate *start = nil;
            uint64_t lines = 0;
            // A small plain-text excerpt for the kernel's diagnostic page: the *latest* PosterBoard/PBF logger line
            // (subsystem/category only — matching the process picked up PosterBoard's Metal noise). The boot page
            // cannot gunzip the full file, so this stays plain and bounded.
            NSString *poster = nil;
            for (id entry in entries) {
                @autoreleasepool {
                    if (++lines > kLineLimit) {
                        gzprintf(out, "# line limit\n");
                        break;
                    }
                    NSDate *date = [entry valueForKey:@"date"];
                    if (!start) start = date;
                    const double at = [date timeIntervalSinceDate:start];
                    NSString *message = [entry valueForKey:@"composedMessage"];
                    const bool isLog = [entry respondsToSelector:@selector(level)];
                    NSString *process = [entry respondsToSelector:@selector(process)] ? [entry valueForKey:@"process"] : @"?";
                    NSString *subsystem = [entry respondsToSelector:@selector(subsystem)] ? [entry valueForKey:@"subsystem"] : @"";
                    NSString *category = [entry respondsToSelector:@selector(category)] ? [entry valueForKey:@"category"] : @"";
                    const int pid = [entry respondsToSelector:@selector(processIdentifier)] ? [[entry valueForKey:@"processIdentifier"] intValue] : 0;
                    const NSInteger level = isLog ? [[entry valueForKey:@"level"] integerValue] : 0;
                    gzprintf(out, "%9.3f %5d %s %s:%s %s %s\n", at, pid, process.UTF8String ?: "?", subsystem.UTF8String ?: "",
                             category.UTF8String ?: "", levelName(level), message.UTF8String ?: "");
                    if ([subsystem containsString:@"PosterBoard"] || [subsystem containsString:@"PBF"] || [subsystem containsString:@"Poster"] ||
                        [category containsString:@"Poster"] || [category containsString:@"DataStore"]) {
                        poster = [NSString stringWithFormat:@"%s %@ %@", levelName(level), category, message ?: @"?"];
                    }
                }
            }
            gzprintf(out, "# %llu entries\n", (unsigned long long)lines);
            if (poster.length) {
                NSData *plain = [poster dataUsingEncoding:NSUTF8StringEncoding];
                const std::string ptemporary = directory + "/.pb.txt", pfinal = directory + "/pb.txt";
                NSString *ptemporaryPath = [NSString stringWithUTF8String:ptemporary.c_str()];
                if ([plain writeToFile:ptemporaryPath atomically:NO]) {
                    chmod(ptemporary.c_str(), 0644);
                    rename(ptemporary.c_str(), pfinal.c_str());
                }
            }
        }
        if (gzclose(out) == Z_OK) {
            chmod(temporary.c_str(), 0644);
            rename(temporary.c_str(), final.c_str());
        }
    }
}

}  // namespace

// Runs the passes (blocks for kPasses * kPeriodSeconds); returns at once if another instance holds the lock or the cache directory is absent.
extern "C" void nativeOsLogExport() {
    const int lock = open(kLock, O_CREAT | O_RDWR, 0600);
    if (lock < 0 || flock(lock, LOCK_EX | LOCK_NB) != 0) return;
    for (unsigned pass = 1; pass <= kPasses; ++pass) {
        mkdir(kDirectory, 0755);
        struct stat st = {};
        if (stat(kDirectory, &st) == 0 && S_ISDIR(st.st_mode)) writePass(pass);
        sleep(kPeriodSeconds);
    }
}

// Latest one-line PosterBoard/PBF log entry, for the plugin's boot-page diagnostic: the render server calls it every ~10 s
// (its predicate keeps the enumeration to the matching entries). Returns 1 with text, 0 when nothing matched, <0 on refusal.
extern "C" int nativeOsLogLatest(char *out, unsigned cap) {
    @autoreleasepool {
        if (!out || !cap) return -1;
        out[0] = 0;
        Class storeClass = NSClassFromString(@"OSLogStore");
        NSError *error = nil;
        id store = storeClass ? ((id (*)(Class, SEL, NSInteger, NSError **))objc_msgSend)(storeClass, @selector(storeWithScope:error:), 0, &error) : nil;
        if (!store) return -1;
        id position = ((id (*)(id, SEL, NSTimeInterval))objc_msgSend)(store, @selector(positionWithTimeIntervalSinceLatestBoot:), 0);
        NSString *latest = nil;
        @try {
            NSPredicate *predicate = [NSPredicate predicateWithFormat:
                @"subsystem CONTAINS 'PosterBoard' OR subsystem CONTAINS 'PBF' OR category CONTAINS 'Poster' OR category CONTAINS 'DataStore'"];
            id entries = ((id (*)(id, SEL, NSUInteger, id, id, NSError **))objc_msgSend)(
                store, @selector(entriesEnumeratorWithOptions:position:predicate:error:), 0, position, predicate, &error);
            if (!entries) return -2;
            for (id entry in entries) {
                NSString *message = [entry valueForKey:@"composedMessage"];
                NSString *category = [entry respondsToSelector:@selector(category)] ? [entry valueForKey:@"category"] : @"";
                latest = [NSString stringWithFormat:@"%@ %@", category ?: @"", message ?: @"?"];
            }
        } @catch (NSException *exception) {
            (void)exception;
            return -3;
        }
        if (!latest) return 0;
        strlcpy(out, latest.UTF8String ?: "", cap);
        return 1;
    }
}
