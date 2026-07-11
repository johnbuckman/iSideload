//
//  native_bridge_common.h
//  AltSign
//
//  Created by Magesh K on 25/02/26.
//

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// frees strdup / char* returned across bridge
void native_bridge_free_string(char *ptr);

// frees arbitrary buffers allocated by NativeBridge (malloc/new → malloc-backed)
void native_bridge_free(void *ptr);

#ifdef __cplusplus
}
#endif
