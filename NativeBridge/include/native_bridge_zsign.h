//
//  native_bridge_zsign.h
//  AltSign
//
//  zsign-backed drop-in replacement for native_bridge_ldid.h.
//  Identical C ABI so LdidBridge.swift / ALTSigner.swift need only point here.
//

#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int native_bridge_zsign_sign(
    const char *appPath,
    const uint8_t *keyData,
    int32_t keyLen,
    const char *(*entitlement_callback)(const char *relativePath, void *context),
    void *entitlement_context,
    void (*progress_callback)(void *context),
    void *progress_context,
    char **errorMessage
);

#ifdef __cplusplus
}
#endif
