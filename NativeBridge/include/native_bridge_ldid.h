//
//  native_bridge_ldid.h
//  AltSign
//
//  Created by Magesh K on 07/07/26.
//  Copyright © 2026 SideStore. All rights reserved.
//


#pragma once
#include "native_bridge_common.h"

#ifdef __cplusplus
extern "C" {
#endif



int native_bridge_ldid_sign(
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
