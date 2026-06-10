#include "shim.h"

#include <string.h>
#include <pjlib.h>
#include <pjsip/sip_auth.h>

static pj_str_t gmv_pj_str(const char *s) {
    pj_str_t out;
    out.ptr = (char *)(s ? s : "");
    out.slen = s ? (pj_ssize_t)strlen(s) : 0;
    return out;
}

static const pj_str_t *gmv_pj_str_opt(const char *s, pj_str_t *storage) {
    if (!s || !*s) {
        return NULL;
    }
    *storage = gmv_pj_str(s);
    return storage;
}

int gmv_pjsip_auth_alg_md5(void) {
    return (int)PJSIP_AUTH_ALGORITHM_MD5;
}

int gmv_pjsip_auth_alg_sha256(void) {
    return (int)PJSIP_AUTH_ALGORITHM_SHA256;
}

int gmv_pjsip_auth_alg_sha512_256(void) {
    return (int)PJSIP_AUTH_ALGORITHM_SHA512_256;
}

int gmv_pjsip_auth_plain_password_type(void) {
    return (int)PJSIP_CRED_DATA_PLAIN_PASSWD;
}

int gmv_pjsip_auth_digest_type(void) {
    return (int)PJSIP_CRED_DATA_DIGEST;
}

int gmv_pjsip_auth_is_algorithm_supported(int algorithm_type) {
    return pjsip_auth_is_algorithm_supported((pjsip_auth_algorithm_type)algorithm_type);
}

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
    int algorithm_type) {
    if (!out || out_len == 0 || !username || !realm || !secret_or_ha1 || !method || !uri || !nonce) {
        return PJ_EINVAL;
    }

    pjsip_cred_info cred;
    pj_bzero(&cred, sizeof(cred));
    cred.realm = gmv_pj_str(realm);
    cred.scheme = gmv_pj_str("digest");
    cred.username = gmv_pj_str(username);
    cred.data_type = data_type;
    cred.data = gmv_pj_str(secret_or_ha1);
    cred.algorithm_type = (pjsip_auth_algorithm_type)algorithm_type;

    char digest_buf[160];
    pj_bzero(digest_buf, sizeof(digest_buf));
    pj_str_t result;
    result.ptr = digest_buf;
    result.slen = 0;

    pj_str_t nonce_s = gmv_pj_str(nonce);
    pj_str_t uri_s = gmv_pj_str(uri);
    pj_str_t realm_s = gmv_pj_str(realm);
    pj_str_t method_s = gmv_pj_str(method);
    pj_str_t nc_s, cnonce_s, qop_s;

    pj_status_t status = pjsip_auth_create_digest2(
        &result,
        &nonce_s,
        gmv_pj_str_opt(nc, &nc_s),
        gmv_pj_str_opt(cnonce, &cnonce_s),
        gmv_pj_str_opt(qop, &qop_s),
        &uri_s,
        &realm_s,
        &cred,
        &method_s,
        (pjsip_auth_algorithm_type)algorithm_type);

    if (status != PJ_SUCCESS) {
        return status;
    }

    if (result.slen < 0 || (unsigned)result.slen + 1 > out_len) {
        return PJ_ETOOSMALL;
    }

    memcpy(out, result.ptr, (size_t)result.slen);
    out[result.slen] = '\0';
    return PJ_SUCCESS;
}
