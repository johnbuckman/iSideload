//
//  native_bridge_corecrypto.cpp
//  AltSign
//

#include "native_bridge_corecrypto.h"

#include <stdlib.h>
#include <string.h>

#define CORECRYPTO_USE_TRANSPARENT_UNION 1
#define CC_INTERNAL_SDK 1
#define CC_USE_L4 0

extern "C" {

#include <corecrypto/ccdigest.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccsrp.h>
#include <corecrypto/ccsrp_gp.h>
#include <corecrypto/ccrng.h>


// ============================================================
// MARK: - SRP
// ============================================================

const void* native_bridge_ccsrp_gp_rfc5054_2048(void)
{
    return ccsrp_gp_rfc5054_2048();
}

const void* native_bridge_ccsha256_di(void)
{
    return ccsha256_di();
}

ccsrp_context native_bridge_ccsrp_client_new(void)
{
    ccsrp_const_gp_t gp = ccsrp_gp_rfc5054_2048();
    const struct ccdigest_info *di = ccsha256_di();

    size_t size = 4096;                             // conservative upper bound for the SRP workspace
    ccsrp_ctx_t ctx = (ccsrp_ctx_t)malloc(size);
    if (!ctx) return nullptr;

    ccsrp_ctx_init(ctx, di, gp);
    ccsrp_client_set_noUsernameInX(ctx, true);      // Apple GSA omits username from x derivation
    return ctx;
}

void native_bridge_ccsrp_client_free(ccsrp_context ctx)
{
    if (ctx) free(ctx);
}

size_t native_bridge_ccsrp_exchange_size(ccsrp_context ctx)
{
    return ccsrp_exchange_size((ccsrp_ctx_t)ctx);
}

int native_bridge_ccsrp_client_start_authentication(
    ccsrp_context ctx,
    void *A_bytes,
    void *rng)
{
    struct ccrng_state *rng_state = (struct ccrng_state*)rng;
    if (!rng_state) {
        // Use the system default RNG when no explicit RNG is provided
        int err = 0;
        rng_state = ccrng(&err);
    }
    return ccsrp_client_start_authentication(
        (ccsrp_ctx_t)ctx,
        rng_state,
        A_bytes
    );
}

int native_bridge_ccsrp_client_process_challenge(
    ccsrp_context ctx,
    const void *salt,
    size_t salt_len,
    const void *B,
    size_t B_len,
    const char *username,
    const void *password,
    size_t password_len,
    void *M_bytes
){
    return ccsrp_client_process_challenge(
        (ccsrp_ctx_t)ctx,
        username,
        password_len,
        password,
        salt_len,
        salt,
        B,
        M_bytes
    );
}

int native_bridge_ccsrp_client_verify_session(
    ccsrp_context ctx,
    const void *M2
){
    return ccsrp_client_verify_session(
        (ccsrp_ctx_t)ctx,
        (const uint8_t*)M2
    );
}

const void* native_bridge_ccsrp_get_session_key(ccsrp_context ctx)
{
    size_t len = 0;
    return ccsrp_get_session_key((ccsrp_ctx_t)ctx, &len);
}

size_t native_bridge_ccsrp_get_session_key_length(ccsrp_context ctx)
{
    return ccsrp_get_session_key_length((ccsrp_ctx_t)ctx);
}

} // extern "C"
