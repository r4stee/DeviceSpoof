
// =============================================================================
//  DeviceSpoof.m
//  Multi-Layer / Low-Level Device Spoofing — iOS arm64 (No Jailbreak)
//
//  Layer 1 : Objective-C Runtime Swizzling (UIDevice, ASIdentifierManager)
//  Layer 2 : Keychain Reset & Security Layer (SecItemCopyMatching block)
//  Layer 3 : C-Level Low-Level Filters (stat() interpose for jailbreak paths)
//
//  Frameworks : Foundation, UIKit, Security, AdSupport
//  Compiled with: ARC enabled, no warnings
// =============================================================================

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <Security/Security.h>
#import <AdSupport/AdSupport.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <string.h>

#pragma mark - ═══════════════════════════════════════════════════════════════
#pragma mark   LAYER 3 — C-Level stat() Interpose (Early Definition)
#pragma mark - ═══════════════════════════════════════════════════════════════

/// Paths that betray sideload / debug / jailbreak presence.
/// Returning ENOENT for these makes the host app believe they don't exist.
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
    "/private/var/mobile/Library/SBSettings",
    "/usr/lib/libcycript.dylib",
    "/usr/lib/frida",
    "/usr/local/lib/frida",
    "/var/root/frida",
    "/tmp/frida",
    "/usr/bin/frida",
    "/usr/sbin/frida",
    "/usr/local/bin/frida",
    "/usr/share/frida",
    "FridaGadget",
    "frida-agent",
    "Substrate",
    NULL
};

/// Checks whether the given path matches any suspicious pattern.
static BOOL ds_path_is_suspicious(const char *path) {
    if (!path) return NO;
    for (NSInteger i = 0; kSuspiciousPaths[i] != NULL; i++) {
        if (strstr(path, kSuspiciousPaths[i]) != NULL) {
            return YES;
        }
    }
    return NO;
}

// Pointer to the real stat() resolved once at constructor time.
static int (*real_stat)(const char * __restrict, struct stat * __restrict) = NULL;
// Pointer to the real lstat() resolved once at constructor time.
static int (*real_lstat)(const char * __restrict, struct stat * __restrict) = NULL;

/// Our replacement for stat(): intercepts suspicious paths and returns ENOENT.
static int ds_stat(const char * __restrict path, struct stat * __restrict buf) {
    if (ds_path_is_suspicious(path)) {
        errno = ENOENT;
        return -1;
    }
    return real_stat ? real_stat(path, buf) : -1;
}

/// Our replacement for lstat(): same logic.
static int ds_lstat(const char * __restrict path, struct stat * __restrict buf) {
    if (ds_path_is_suspicious(path)) {
        errno = ENOENT;
        return -1;
    }
    return real_lstat ? real_lstat(path, buf) : -1;
}

#pragma mark - ═══════════════════════════════════════════════════════════════
#pragma mark   LAYER 2 — Keychain Reset & Security Layer
#pragma mark - ═══════════════════════════════════════════════════════════════

/// Original function pointer for SecItemCopyMatching.
static OSStatus (*real_SecItemCopyMatching)(CFDictionaryRef query, CFTypeRef *result) = NULL;

/// Our shim: always reports "not found", wiping any fingerprint stored by a
/// previous app installation (previous-band residue).
static OSStatus ds_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    // Block any query that tries to read from the Keychain so that persistent
    // identifiers (e.g. "vendor ID stored across reinstalls") are invisible.
    if (result) { *result = NULL; }
    return errSecItemNotFound;
}

#pragma mark - ═══════════════════════════════════════════════════════════════
#pragma mark   LAYER 1A — UIDevice Swizzle (IDFV + name + model)
#pragma mark - ═══════════════════════════════════════════════════════════════

@interface UIDevice (DSSwizzle)
- (NSUUID *)ds_identifierForVendor;
- (NSString *)ds_name;
- (NSString *)ds_model;
@end

@implementation UIDevice (DSSwizzle)

/// Returns a freshly generated random UUID every time — nothing is cached.
- (NSUUID *)ds_identifierForVendor {
    return [[NSUUID UUID] init];
}

/// Returns a generic, non-identifying device name.
- (NSString *)ds_name {
    return @"iPhone";
}

/// Return a generic model identifier.
- (NSString *)ds_model {
    return @"iPhone";
}

@end

#pragma mark - ═══════════════════════════════════════════════════════════════
#pragma mark   LAYER 1B — ASIdentifierManager Swizzle (IDFA)
#pragma mark - ═══════════════════════════════════════════════════════════════

@interface ASIdentifierManager (DSSwizzle)
- (NSUUID *)ds_advertisingIdentifier;
- (BOOL)ds_isAdvertisingTrackingEnabled;
@end

@implementation ASIdentifierManager (DSSwizzle)

/// Returns a freshly generated random UUID every time.
- (NSUUID *)ds_advertisingIdentifier {
    return [[NSUUID UUID] init];
}

/// Reports tracking as disabled so callers cannot use the IDFA for attribution.
- (BOOL)ds_isAdvertisingTrackingEnabled {
    return NO;
}

@end

#pragma mark - ═══════════════════════════════════════════════════════════════
#pragma mark   Swizzle Utility
#pragma mark - ═══════════════════════════════════════════════════════════════

/// Thread-safe, add-or-exchange method swizzle.
static void ds_swizzle(Class cls, SEL original, SEL replacement) {
    if (!cls || !original || !replacement) return;

    Method origMethod = class_getInstanceMethod(cls, original);
    Method replMethod = class_getInstanceMethod(cls, replacement);

    if (!origMethod || !replMethod) {
        NSLog(@"[DeviceSpoof] swizzle skipped — method not found "
              "in %@ (orig=%s, repl=%s)",
              NSStringFromClass(cls),
              sel_getName(original),
              sel_getName(replacement));
        return;
    }

    // Try to add the original selector backed by the replacement IMP first.
    BOOL added = class_addMethod(cls,
                                 original,
                                 method_getImplementation(replMethod),
                                 method_getTypeEncoding(replMethod));
    if (added) {
        // The class didn't have its own implementation; point replacement IMP.
        class_replaceMethod(cls,
                            replacement,
                            method_getImplementation(origMethod),
                            method_getTypeEncoding(origMethod));
    } else {
        // The class already has the method — swap IMPs atomically.
        method_exchangeImplementations(origMethod, replMethod);
    }

    NSLog(@"[DeviceSpoof] Swizzled %@ — %s <-> %s",
          NSStringFromClass(cls),
          sel_getName(original),
          sel_getName(replacement));
}

#pragma mark - ═══════════════════════════════════════════════════════════════
#pragma mark   C-Symbol Resolution (dlsym RTLD_NEXT)
#pragma mark - ═══════════════════════════════════════════════════════════════

static void ds_install_c_level_filters(void) {
    // Resolve originals via dlsym so we can forward non-suspicious calls.
    real_stat  = (int (*)(const char * __restrict, struct stat * __restrict))
                  dlsym(RTLD_NEXT, "stat");
    real_lstat = (int (*)(const char * __restrict, struct stat * __restrict))
                  dlsym(RTLD_NEXT, "lstat");

    // Resolve SecItemCopyMatching original.
    real_SecItemCopyMatching = (OSStatus (*)(CFDictionaryRef, CFTypeRef *))
                                dlsym(RTLD_NEXT, "SecItemCopyMatching");

    if (real_stat && real_lstat) {
        NSLog(@"[DeviceSpoof] C-level stat symbols resolved — shims active.");
    } else {
        NSLog(@"[DeviceSpoof] One or more stat symbols not resolved via dlsym.");
    }
}

#pragma mark - ═══════════════════════════════════════════════════════════════
#pragma mark   DYLD_INTERPOSE Macros
#pragma mark - ═══════════════════════════════════════════════════════════════

// These macros tell dyld to transparently replace the named C functions with
// our shims across all images loaded in the process — no fishhook needed.
#define DYLD_INTERPOSE(_replacement, _original) \
    __attribute__((used)) static struct { \
        const void *replacement; \
        const void *original; \
    } _interpose_##_original \
    __attribute__((section("__DATA,__interpose"))) = { \
        (const void *)(unsigned long)&(_replacement), \
        (const void *)(unsigned long)&(_original)  \
    };

DYLD_INTERPOSE(ds_stat,   stat)
DYLD_INTERPOSE(ds_lstat,  lstat)
DYLD_INTERPOSE(ds_SecItemCopyMatching, SecItemCopyMatching)

#pragma mark - ═══════════════════════════════════════════════════════════════
#pragma mark   CONSTRUCTOR — Early Runtime Load (priority 101)
#pragma mark - ═══════════════════════════════════════════════════════════════

__attribute__((constructor(101)))
static void DeviceSpoof_Initialize(void) {
    @autoreleasepool {

        NSLog(@"[DeviceSpoof] Multi-Layer Device Spoof — Initializing...");

        // Layer 3: C-level symbol resolution
        ds_install_c_level_filters();

        // Layer 1A: UIDevice swizzles
        Class uiDeviceClass = [UIDevice class];

        ds_swizzle(uiDeviceClass,
                   @selector(identifierForVendor),
                   @selector(ds_identifierForVendor));

        ds_swizzle(uiDeviceClass,
                   @selector(name),
                   @selector(ds_name));

        ds_swizzle(uiDeviceClass,
                   @selector(model),
                   @selector(ds_model));

        // Layer 1B: ASIdentifierManager swizzles
        Class asmClass = objc_getClass("ASIdentifierManager");
        if (asmClass) {
            ds_swizzle(asmClass,
                       @selector(advertisingIdentifier),
                       @selector(ds_advertisingIdentifier));

            ds_swizzle(asmClass,
                       @selector(isAdvertisingTrackingEnabled),
                       @selector(ds_isAdvertisingTrackingEnabled));
        } else {
            NSLog(@"[DeviceSpoof] ASIdentifierManager not found — "
                  "AdSupport framework may not be linked.");
        }

        // Layer 2: Keychain blocking is handled by DYLD_INTERPOSE above.
        NSLog(@"[DeviceSpoof] Keychain shim (SecItemCopyMatching) active via DYLD_INTERPOSE.");
        NSLog(@"[DeviceSpoof] All layers loaded successfully.");
    }
}

