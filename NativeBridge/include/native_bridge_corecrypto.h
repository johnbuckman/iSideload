//
//  native_bridge_corecrypto.h
//  AltSign
//
//  Created by Magesh K on 25/02/26.
//

#pragma once
#include "native_bridge_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void* ccsrp_context;

const void* native_bridge_ccsrp_gp_rfc5054_2048(void);   // RFC-5054 2048-bit MODP group
const void* native_bridge_ccsha256_di(void);             // SHA-256 digest info

ccsrp_context native_bridge_ccsrp_client_new(void);      // allocate & init ctx
void native_bridge_ccsrp_client_free(ccsrp_context ctx); // free ctx

size_t native_bridge_ccsrp_exchange_size(ccsrp_context ctx); // size of A/B messages


/* Generate client public key A, written into A_bytes (must be exchange_size() bytes) */
int native_bridge_ccsrp_client_start_authentication(
    ccsrp_context ctx,
    void *A_bytes,
    void *rng              // NULL -> use ccrng() default
);

/* Process server challenge; writes M1 verification message into M_bytes */
int native_bridge_ccsrp_client_process_challenge(
    ccsrp_context ctx,
    const void *salt,
    size_t salt_len,
    const void *B,         // server public key
    size_t B_len,
    const char *username,
    const void *password,
    size_t password_len,
    void *M_bytes          // output: client proof M1
);

/* Verify server proof M2; returns 0 on success */
int native_bridge_ccsrp_client_verify_session(
    ccsrp_context ctx,
    const void *M2
);

/* ── SRP session key ── */
const void* native_bridge_ccsrp_get_session_key(ccsrp_context ctx);        // raw key bytes
size_t native_bridge_ccsrp_get_session_key_length(ccsrp_context ctx);      // key length in bytes

#ifdef __cplusplus
}
#endif
