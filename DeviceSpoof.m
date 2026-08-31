// =============================================================================
//  DeviceSpoof.m
//  Multi-Layer Device Spoofing — iOS arm64 (No Jailbreak)
//
//  FIX v2:
//   - Static UUID: generated ONCE at startup, same value returned every call
//     (prevents app internal data mismatch / freeze when called repeatedly)
//   - Keychain hook REMOVED: apps can read their own internal keys normally
//     (prevents black screen / freeze caused by missing renderer keys)
//
//  Frameworks : Foundation, UIKit, AdSupport
//  Compiled with: ARC enabled, no warnings
// =============================================================================

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <AdSupport/AdSupport.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <string.h>
#include <errno.h>

#pragma mark - Static UUID Storage (generated once, reused every call)

/// One IDFV per session — set at constructor time, never changes.
static NSUUID *ds_static_idfv = nil;
/// One IDFA per session — set at constructor time, never changes.
static NSUUID *ds_static_idfa = nil;

#pragma mark - C-Level stat() Filter (hides jailbreak / frida paths)

static const char * const kSuspiciousPaths[] = {
    "/Library/MobileSubstrate",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/Applications/Cydia.app",
    "/Applications/Sileo.app",
    "/Applications/Zebra.app",
    "/Applications/Filza.app",
    "/usr/bin/ssh",
    "/usr/sbin/sshd",
    "/bin/bash",
    "/bin/sh",
    "/usr/libexec/sftp-server",
    "/etc/apt",
    "/var/lib/cydia",
    "/var/lib/apt",
    "/private/var/lib/apt",
    "/private/var/lib/cydia",
    "/private/var/stash",
    "/usr/lib/libcycript.dylib",
    "/usr/lib/frida",
    "/usr/local/lib/frida",
    "/var/root/frida",
    "/tmp/frida",
    "/usr/bin/frida",
    "/usr/sbin/frida",
    "/usr/local/bin/frida",
    "FridaGadget",
    "frida-agent",
    "Substrate",
    NULL
};

static BOOL ds_path_is_suspicious(const char *path) {
    if (!path) return NO;
    for (int i = 0; kSuspiciousPaths[i] != NULL; i++) {
        if (strstr(path, kSuspiciousPaths[i]) != NULL) return YES;
    }
    return NO;
}

static int (*real_stat)(const char * __restrict, struct stat * __restrict)  = NULL;
static int (*real_lstat)(const char * __restrict, struct stat * __restrict) = NULL;

static int ds_stat(const char * __restrict path, struct stat * __restrict buf) {
    if (ds_path_is_suspicious(path)) { errno = ENOENT; return -1; }
    return real_stat ? real_stat(path, buf) : -1;
}

static int ds_lstat(const char * __restrict path, struct stat * __restrict buf) {
    if (ds_path_is_suspicious(path)) { errno = ENOENT; return -1; }
    return real_lstat ? real_lstat(path, buf) : -1;
}

#pragma mark - DYLD_INTERPOSE

#define DYLD_INTERPOSE(_repl, _orig) \
    __attribute__((used)) static struct { \
        const void *replacement; const void *original; \
    } _interpose_##_orig \
    __attribute__((section("__DATA,__interpose"))) = { \
        (const void *)(unsigned long)&(_repl), \
        (const void *)(unsigned long)&(_orig) \
    };

DYLD_INTERPOSE(ds_stat,  stat)
DYLD_INTERPOSE(ds_lstat, lstat)

#pragma mark - UIDevice Swizzle (IDFV + name + model)

@interface UIDevice (DSSwizzle)
- (NSUUID *)ds_identifierForVendor;
- (NSString *)ds_name;
- (NSString *)ds_model;
@end

@implementation UIDevice (DSSwizzle)

- (NSUUID *)ds_identifierForVendor { return ds_static_idfv; }
- (NSString *)ds_name              { return @"iPhone"; }
- (NSString *)ds_model             { return @"iPhone"; }

@end

#pragma mark - ASIdentifierManager Swizzle (IDFA)

@interface ASIdentifierManager (DSSwizzle)
- (NSUUID *)ds_advertisingIdentifier;
- (BOOL)ds_isAdvertisingTrackingEnabled;
@end

@implementation ASIdentifierManager (DSSwizzle)

- (NSUUID *)ds_advertisingIdentifier    { return ds_static_idfa; }
- (BOOL)ds_isAdvertisingTrackingEnabled { return NO; }

@end

#pragma mark - Swizzle Utility

static void ds_swizzle(Class cls, SEL orig, SEL repl) {
    if (!cls || !orig || !repl) return;
    Method origM = class_getInstanceMethod(cls, orig);
    Method replM = class_getInstanceMethod(cls, repl);
    if (!origM || !replM) return;
    BOOL added = class_addMethod(cls, orig,
                                 method_getImplementation(replM),
                                 method_getTypeEncoding(replM));
    if (added) {
        class_replaceMethod(cls, repl,
                            method_getImplementation(origM),
                            method_getTypeEncoding(origM));
    } else {
        method_exchangeImplementations(origM, replM);
    }
    NSLog(@"[DeviceSpoof] swizzled %@ %s <-> %s",
          NSStringFromClass(cls), sel_getName(orig), sel_getName(repl));
}

#pragma mark - Constructor (priority 101 — earliest load)

__attribute__((constructor(101)))
static void DeviceSpoof_Initialize(void) {
    @autoreleasepool {
        // 1. Generate static UUIDs ONCE for this session
        ds_static_idfv = [NSUUID UUID];
        ds_static_idfa = [NSUUID UUID];
        NSLog(@"[DeviceSpoof] IDFV=%@  IDFA=%@",
              ds_static_idfv.UUIDString, ds_static_idfa.UUIDString);

        // 2. Resolve real stat/lstat for passthrough
        real_stat  = (int (*)(const char * __restrict, struct stat * __restrict))
                      dlsym(RTLD_NEXT, "stat");
        real_lstat = (int (*)(const char * __restrict, struct stat * __restrict))
                      dlsym(RTLD_NEXT, "lstat");

        // 3. UIDevice swizzles
        Class dev = [UIDevice class];
        ds_swizzle(dev, @selector(identifierForVendor), @selector(ds_identifierForVendor));
        ds_swizzle(dev, @selector(name),                @selector(ds_name));
        ds_swizzle(dev, @selector(model),               @selector(ds_model));

        // 4. ASIdentifierManager swizzles
        Class asm_ = objc_getClass("ASIdentifierManager");
        if (asm_) {
            ds_swizzle(asm_, @selector(advertisingIdentifier),       @selector(ds_advertisingIdentifier));
            ds_swizzle(asm_, @selector(isAdvertisingTrackingEnabled), @selector(ds_isAdvertisingTrackingEnabled));
        }

        NSLog(@"[DeviceSpoof] v2 ready — static UUID, keychain passthrough.");
    }
}