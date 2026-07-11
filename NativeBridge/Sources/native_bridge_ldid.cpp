//
//  native_bridge_ldid.cpp
//  AltSign
//
//  zsign-backed shim. Historically this wrapped rileytestut/ldid, whose
//  Sign() emits a SHA-1-primary CodeDirectory that iOS 16+ rejects with
//  0xe8008001 ("failed to verify code signature"). It now keeps the exact
//  same C ABI symbol (native_bridge_ldid_sign) so LdidBridge.swift / ALTSigner
//  need no changes, and delegates to the zsign implementation, which emits a
//  modern SHA-256-primary CodeDirectory that iOS 26 accepts.
//
#include "native_bridge_ldid.h"
#include "native_bridge_zsign.h"

extern "C" int native_bridge_ldid_sign(
    const char *appPath,
    const uint8_t *keyData,
    int32_t keyLen,
    const char *(*entitlement_callback)(const char *relativePath, void *context),
    void *entitlement_context,
    void (*progress_callback)(void *context),
    void *progress_context,
    char **errorMessage
){
    return native_bridge_zsign_sign(
        appPath, keyData, keyLen,
        entitlement_callback, entitlement_context,
        progress_callback, progress_context,
        errorMessage);
}
