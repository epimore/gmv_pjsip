#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Stable C shim around PJPROJECT auth APIs so Rust safe layer does not depend
 * on bindgen's enum/struct layout names. */
int gmv_pjsip_auth_alg_md5(void);
int gmv_pjsip_auth_alg_sha256(void);
int gmv_pjsip_auth_alg_sha512_256(void);
int gmv_pjsip_auth_plain_password_type(void);
int gmv_pjsip_auth_digest_type(void);
int gmv_pjsip_auth_is_algorithm_supported(int algorithm_type);

/* Returns PJ_SUCCESS(0) on success. out must have room for the hex digest plus
 * a trailing NUL. Supports qop=NULL/empty, cnonce=NULL/empty, nc=NULL/empty. */
int gmv_pjsip_auth_create_digest2(
    char *out,
    unsigned out_len,
    const char *username,
    const char *realm,
    const char *secret_or_ha1,
    int data_type,
    const char *method,
    const char *uri,
    const char *nonce,
    const char *nc,
    const char *cnonce,
    const char *qop,
    int algorithm_type);

#ifdef __cplusplus
}
#endif
