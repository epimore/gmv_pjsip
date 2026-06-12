#include "shim.h"

#include <stdlib.h>
#include <string.h>
#include <pjlib.h>
#include <pjlib-util.h>
#include <pjsip.h>
#include <pjsip/sip_auth.h>
#include <pjsip/sip_parser.h>
#include <pjsip/sip_transport_tcp.h>
#include <pjsip/sip_transport_udp.h>
#include <pjsip/sip_util.h>

#define GMV_SIP_DEFAULT_BIND_ADDRESS "127.0.0.1"
#define GMV_SIP_DEFAULT_AUTH_REALM "3402000000"
#define GMV_SIP_DEFAULT_POLL_TIMEOUT_MS 10u
#define GMV_SIP_DEFAULT_AUTH_LOOKUP_TIMEOUT_MS 3000u
#define GMV_SIP_DEFAULT_MAX_PENDING_AUTH 20000u
#define GMV_SIP_NONCE_TTL_MS 300000u
#define GMV_SIP_BIND_ADDRESS_CAPACITY 64u
#define GMV_SIP_ADDRESS_CAPACITY (PJ_INET6_ADDRSTRLEN + 16u)
#define GMV_SIP_CONTENT_TYPE_CAPACITY 128u
#define GMV_SIP_CONTACT_CAPACITY 512u
#define GMV_SIP_AUTH_REALM_CAPACITY 128u
#define GMV_SIP_DEVICE_ID_CAPACITY 128u
#define GMV_SIP_AUTH_SECRET_CAPACITY 512u
#define GMV_SIP_NONCE_CAPACITY 33u
#define GMV_SIP_CONFIG_HAS(config, field) \
    ((config)->size >= \
     offsetof(gmv_sip_runtime_config_t, field) + sizeof((config)->field))

typedef struct gmv_pending_auth {
    uint64_t lookup_id;
    char device_id[GMV_SIP_DEVICE_ID_CAPACITY];
    char realm[GMV_SIP_AUTH_REALM_CAPACITY];
    uint64_t deadline_ms;
    pjsip_rx_data *rdata;
    pjsip_transaction *transaction;
    struct gmv_pending_auth *next;
} gmv_pending_auth_t;

typedef struct gmv_auth_command {
    uint64_t lookup_id;
    int32_t result;
    int32_t credential_type;
    int32_t algorithm_type;
    char username[GMV_SIP_DEVICE_ID_CAPACITY];
    char realm[GMV_SIP_AUTH_REALM_CAPACITY];
    char secret[GMV_SIP_AUTH_SECRET_CAPACITY];
    struct gmv_auth_command *next;
} gmv_auth_command_t;

typedef struct gmv_nonce_usage {
    char username[GMV_SIP_DEVICE_ID_CAPACITY];
    char cnonce[GMV_SIP_DEVICE_ID_CAPACITY];
    uint32_t last_nc;
    int used_without_qop;
    struct gmv_nonce_usage *next;
} gmv_nonce_usage_t;

typedef struct gmv_auth_nonce {
    char value[GMV_SIP_NONCE_CAPACITY];
    uint64_t expires_at_ms;
    uint32_t usage_count;
    gmv_nonce_usage_t *usages;
    struct gmv_auth_nonce *next;
} gmv_auth_nonce_t;

typedef struct gmv_outbound_operation {
    gmv_sip_runtime_t *runtime;
    uint64_t operation_id;
} gmv_outbound_operation_t;

struct gmv_sip_runtime {
    char bind_address[GMV_SIP_BIND_ADDRESS_CAPACITY];
    char auth_realm[GMV_SIP_AUTH_REALM_CAPACITY];
    uint16_t requested_port;
    uint8_t enable_udp;
    uint8_t enable_tcp;
    uint32_t async_count;
    uint32_t poll_timeout_ms;
    int32_t auth_algorithm_type;
    uint32_t max_pending_auth;
    uint32_t auth_lookup_timeout_ms;
    gmv_sip_event_callback event_callback;
    void *event_user_data;

    pj_caching_pool caching_pool;
    pjsip_endpoint *endpoint;
    pjsip_transport *udp_transport;
    pjsip_tpfactory *tcp_factory;
    pj_pool_t *thread_pool;
    pj_thread_t *thread;
    pj_atomic_t *stop_requested;
    pj_mutex_t *command_mutex;
    pjsip_module module;
    pjsip_auth_srv auth_server;

    uint16_t udp_port;
    uint16_t tcp_port;
    int32_t last_status;
    uint64_t event_sequence;
    uint64_t lookup_sequence;
    uint64_t nonce_cleanup_at_ms;
    uint32_t pending_auth_count;
    gmv_pending_auth_t *pending_auth;
    gmv_auth_command_t *command_head;
    gmv_auth_command_t *command_tail;
    gmv_auth_command_t *active_auth_command;
    gmv_auth_nonce_t *auth_nonces;
    int pj_initialized;
    int caching_pool_initialized;
    int module_registered;
    int started;
};

static gmv_sip_runtime_t *g_active_runtime;

/*
 * PJSIP_AUTH_ALGORITHM_SHA256 and PJSIP_AUTH_ALGORITHM_SHA512_256 are
 * enum constants, not preprocessor macros. Do not test them with #if defined().
 * Version validation is performed in build.rs for pkg-config and explicit
 * PJSIP_INCLUDE_DIR builds. If an older PJPROJECT header is used, normal C
 * compilation will still fail at the enum/function references below.
 */

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
    result.slen = (pj_ssize_t)sizeof(digest_buf);

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

static gmv_sip_string_view_t gmv_string_view(const pj_str_t *value) {
    gmv_sip_string_view_t view;
    view.ptr = value && value->ptr ? value->ptr : NULL;
    view.len = value && value->slen > 0 ? (size_t)value->slen : 0;
    return view;
}

static gmv_sip_string_view_t gmv_bytes_view(const void *data, size_t len) {
    gmv_sip_string_view_t view;
    view.ptr = data && len > 0 ? (const char *)data : NULL;
    view.len = data && len > 0 ? len : 0;
    return view;
}

static gmv_sip_string_view_t gmv_c_string_view(const char *value) {
    if (!value || !*value) {
        return gmv_bytes_view(NULL, 0);
    }
    return gmv_bytes_view(value, strlen(value));
}

static int gmv_copy_view(
    char *out,
    size_t out_len,
    gmv_sip_string_view_t value) {
    if (!out || out_len == 0 || value.len >= out_len ||
        (value.len > 0 && !value.ptr) ||
        (value.len > 0 && memchr(value.ptr, '\0', value.len))) {
        return 0;
    }
    if (value.len > 0) {
        memcpy(out, value.ptr, value.len);
    }
    out[value.len] = '\0';
    return 1;
}

static uint64_t gmv_now_ms(void) {
    pj_time_val now;
    pj_gettimeofday(&now);
    return ((uint64_t)now.sec * 1000u) + (uint64_t)now.msec;
}

static pj_status_t gmv_auth_lookup(
    pj_pool_t *pool,
    const pjsip_auth_lookup_cred_param *param,
    pjsip_cred_info *cred_info) {
    gmv_sip_runtime_t *runtime = g_active_runtime;
    gmv_auth_command_t *command =
        runtime ? runtime->active_auth_command : NULL;
    if (!pool || !param || !cred_info || !command ||
        command->result != GMV_SIP_AUTH_CREDENTIAL ||
        pj_strcmp2(&param->acc_name, command->username) != 0 ||
        pj_strcmp2(&param->realm, command->realm) != 0) {
        return PJSIP_EAUTHACCNOTFOUND;
    }

    pj_bzero(cred_info, sizeof(*cred_info));
    pj_strdup2(pool, &cred_info->realm, command->realm);
    cred_info->scheme = pj_str("digest");
    pj_strdup2(pool, &cred_info->username, command->username);
    cred_info->data_type = command->credential_type;
    pj_strdup2(pool, &cred_info->data, command->secret);
    cred_info->algorithm_type =
        (pjsip_auth_algorithm_type)command->algorithm_type;
    return PJ_SUCCESS;
}

static int32_t gmv_transport_type(const pjsip_transport *transport) {
    if (!transport) {
        return GMV_SIP_TRANSPORT_UNKNOWN;
    }
    if (transport->key.type == PJSIP_TRANSPORT_UDP) {
        return GMV_SIP_TRANSPORT_UDP;
    }
    if (transport->key.type == PJSIP_TRANSPORT_TCP) {
        return GMV_SIP_TRANSPORT_TCP;
    }
    return GMV_SIP_TRANSPORT_UNKNOWN;
}

static pjsip_generic_string_hdr *gmv_generic_header(
    const pjsip_rx_data *rdata,
    const char *name) {
    if (!rdata || !rdata->msg_info.msg) {
        return NULL;
    }
    pj_str_t header_name = pj_str((char *)name);
    return (pjsip_generic_string_hdr *)pjsip_msg_find_hdr_by_name(
        rdata->msg_info.msg,
        &header_name,
        NULL);
}

static void gmv_add_string_header(
    pjsip_tx_data *tdata,
    const char *name,
    const char *value) {
    pj_str_t header_name = pj_str((char *)name);
    pj_str_t header_value = pj_str((char *)value);
    pjsip_generic_string_hdr *header =
        pjsip_generic_string_hdr_create(
            tdata->pool,
            &header_name,
            &header_value);
    pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr *)header);
}

static int32_t gmv_register_expires(const pjsip_rx_data *rdata) {
    if (!rdata || !rdata->msg_info.msg) {
        return -1;
    }
    pjsip_contact_hdr *contact =
        (pjsip_contact_hdr *)pjsip_msg_find_hdr(
            rdata->msg_info.msg,
            PJSIP_H_CONTACT,
            NULL);
    if (contact &&
        contact->expires != PJSIP_EXPIRES_NOT_SPECIFIED) {
        return (int32_t)contact->expires;
    }
    pjsip_expires_hdr *expires =
        (pjsip_expires_hdr *)pjsip_msg_find_hdr(
            rdata->msg_info.msg,
            PJSIP_H_EXPIRES,
            NULL);
    return expires ? expires->ivalue : 3600;
}

static void gmv_emit_event_ex(
    gmv_sip_runtime_t *runtime,
    int32_t event_type,
    int32_t transport,
    int32_t status_code,
    int32_t pj_status,
    const pj_str_t *method,
    const pjsip_rx_data *rdata,
    uint64_t lookup_id,
    const pj_str_t *device_id,
    const pj_str_t *realm) {
    if (!runtime || !runtime->event_callback) {
        return;
    }

    gmv_sip_event_t event;
    char content_type[GMV_SIP_CONTENT_TYPE_CAPACITY];
    char contact[GMV_SIP_CONTACT_CAPACITY];
    char local_address[GMV_SIP_ADDRESS_CAPACITY];
    char remote_address[GMV_SIP_ADDRESS_CAPACITY];
    memset(&event, 0, sizeof(event));
    memset(content_type, 0, sizeof(content_type));
    memset(contact, 0, sizeof(contact));
    memset(local_address, 0, sizeof(local_address));
    memset(remote_address, 0, sizeof(remote_address));
    event.size = (uint32_t)sizeof(event);
    event.version = GMV_SIP_ABI_VERSION;
    event.event_type = event_type;
    event.transport = transport;
    event.status_code = status_code;
    event.pj_status = pj_status;
    event.method = gmv_string_view(method);
    event.event_id = ++runtime->event_sequence;
    event.expires_seconds = -1;
    event.lookup_id = lookup_id;
    event.device_id = gmv_string_view(device_id);
    event.realm = gmv_string_view(realm);

    if (rdata) {
        if (rdata->msg_info.cid) {
            event.call_id = gmv_string_view(&rdata->msg_info.cid->id);
        }
        if (rdata->msg_info.cseq && rdata->msg_info.cseq->cseq > 0) {
            event.cseq = (uint32_t)rdata->msg_info.cseq->cseq;
        }
        if (rdata->msg_info.ctype) {
            const pjsip_media_type *media = &rdata->msg_info.ctype->media;
            int written = pj_ansi_snprintf(
                content_type,
                sizeof(content_type),
                "%.*s/%.*s",
                (int)media->type.slen,
                media->type.ptr,
                (int)media->subtype.slen,
                media->subtype.ptr);
            if (written > 0 && (size_t)written < sizeof(content_type)) {
                event.content_type = gmv_c_string_view(content_type);
            }
        }
        if (rdata->msg_info.msg && rdata->msg_info.msg->body) {
            const pjsip_msg_body *body = rdata->msg_info.msg->body;
            event.body = gmv_bytes_view(body->data, body->len);
        }
        if (rdata->tp_info.transport &&
            pj_sockaddr_print(
                &rdata->tp_info.transport->local_addr,
                local_address,
                sizeof(local_address),
                1)) {
            event.local_address = gmv_c_string_view(local_address);
        }
        if (pj_sockaddr_print(
                &rdata->pkt_info.src_addr,
                remote_address,
                sizeof(remote_address),
                1)) {
            event.remote_address = gmv_c_string_view(remote_address);
        }
        if (rdata->msg_info.msg &&
            rdata->msg_info.msg->type == PJSIP_REQUEST_MSG &&
            rdata->msg_info.msg->line.req.method.id ==
                PJSIP_REGISTER_METHOD) {
            pjsip_contact_hdr *contact_hdr =
                (pjsip_contact_hdr *)pjsip_msg_find_hdr(
                    rdata->msg_info.msg,
                    PJSIP_H_CONTACT,
                    NULL);
            if (contact_hdr) {
                if (contact_hdr->star) {
                    contact[0] = '*';
                    contact[1] = '\0';
                    event.contact = gmv_c_string_view(contact);
                } else if (contact_hdr->uri) {
                    int written = pjsip_uri_print(
                        PJSIP_URI_IN_CONTACT_HDR,
                        contact_hdr->uri,
                        contact,
                        (int)sizeof(contact));
                    if (written > 0 &&
                        (size_t)written < sizeof(contact)) {
                        contact[written] = '\0';
                        event.contact = gmv_c_string_view(contact);
                    }
                }
            }
            event.expires_seconds = gmv_register_expires(rdata);
            pjsip_generic_string_hdr *user_agent =
                gmv_generic_header(rdata, "User-Agent");
            pjsip_generic_string_hdr *gb_version =
                gmv_generic_header(rdata, "X-GB-Ver");
            if (user_agent) {
                event.user_agent =
                    gmv_string_view(&user_agent->hvalue);
            }
            if (gb_version) {
                event.gb_version =
                    gmv_string_view(&gb_version->hvalue);
            }
        }
    }

    runtime->event_callback(&event, runtime->event_user_data);
}

static void gmv_emit_event(
    gmv_sip_runtime_t *runtime,
    int32_t event_type,
    int32_t transport,
    int32_t status_code,
    int32_t pj_status,
    const pj_str_t *method,
    const pjsip_rx_data *rdata) {
    gmv_emit_event_ex(
        runtime,
        event_type,
        transport,
        status_code,
        pj_status,
        method,
        rdata,
        0,
        NULL,
        NULL);
}

static void gmv_outbound_callback(void *token, pjsip_event *event) {
    gmv_outbound_operation_t *operation =
        (gmv_outbound_operation_t *)token;
    if (!operation || !operation->runtime || !event ||
        !operation->runtime->event_callback ||
        event->type != PJSIP_EVENT_TSX_STATE) {
        return;
    }
    pjsip_transaction *transaction = event->body.tsx_state.tsx;
    if (!transaction || transaction->status_code < 200) {
        return;
    }

    gmv_sip_event_t outbound;
    pj_str_t method = pj_str("MESSAGE");
    memset(&outbound, 0, sizeof(outbound));
    outbound.size = (uint32_t)sizeof(outbound);
    outbound.version = GMV_SIP_ABI_VERSION;
    outbound.event_type = GMV_SIP_EVENT_OUTBOUND_RESPONSE;
    outbound.status_code = transaction->status_code;
    outbound.pj_status = transaction->status_code >= 200 &&
            transaction->status_code < 700
        ? PJ_SUCCESS
        : transaction->status_code;
    outbound.method = gmv_string_view(&method);
    outbound.event_id = ++operation->runtime->event_sequence;
    outbound.operation_id = operation->operation_id;

    pjsip_tx_data *last_tx = transaction->last_tx;
    if (last_tx && last_tx->msg) {
        pjsip_cid_hdr *call_id = PJSIP_MSG_CID_HDR(last_tx->msg);
        pjsip_cseq_hdr *cseq = PJSIP_MSG_CSEQ_HDR(last_tx->msg);
        if (call_id) {
            outbound.call_id = gmv_string_view(&call_id->id);
        }
        if (cseq && cseq->cseq > 0) {
            outbound.cseq = (uint32_t)cseq->cseq;
        }
    }
    operation->runtime->event_callback(
        &outbound,
        operation->runtime->event_user_data);
}

static pjsip_authorization_hdr *gmv_auth_header(pjsip_rx_data *rdata) {
    if (!rdata || !rdata->msg_info.msg) {
        return NULL;
    }
    return (pjsip_authorization_hdr *)pjsip_msg_find_hdr(
        rdata->msg_info.msg,
        PJSIP_H_AUTHORIZATION,
        NULL);
}

static pj_str_t gmv_register_device_id(pjsip_rx_data *rdata) {
    pj_str_t empty = pj_str("");
    pjsip_authorization_hdr *auth = gmv_auth_header(rdata);
    if (auth && pj_stricmp2(&auth->scheme, "Digest") == 0) {
        return auth->credential.digest.username;
    }
    if (!rdata || !rdata->msg_info.from || !rdata->msg_info.from->uri) {
        return empty;
    }

    pjsip_uri *uri = pjsip_uri_get_uri(rdata->msg_info.from->uri);
    if (!uri || !PJSIP_URI_SCHEME_IS_SIP(uri)) {
        return empty;
    }
    return ((pjsip_sip_uri *)uri)->user;
}

static void gmv_free_nonce(gmv_auth_nonce_t *nonce) {
    while (nonce && nonce->usages) {
        gmv_nonce_usage_t *usage = nonce->usages;
        nonce->usages = usage->next;
        free(usage);
    }
    free(nonce);
}

static int gmv_nonce_status(
    gmv_sip_runtime_t *runtime,
    const pj_str_t *nonce) {
    uint64_t now = gmv_now_ms();
    int matched_expired = 0;
    gmv_auth_nonce_t **cursor = &runtime->auth_nonces;
    while (*cursor) {
        gmv_auth_nonce_t *item = *cursor;
        int matched = nonce && pj_strcmp2(nonce, item->value) == 0;
        if (item->expires_at_ms <= now) {
            *cursor = item->next;
            matched_expired |= matched;
            gmv_free_nonce(item);
            continue;
        }
        if (matched) {
            return 1;
        }
        cursor = &item->next;
    }
    return matched_expired ? -1 : 0;
}

static int gmv_parse_nonce_count(const pj_str_t *value, uint32_t *out) {
    if (!value || !out || value->slen != 8) {
        return 0;
    }
    uint32_t parsed = 0;
    for (pj_ssize_t i = 0; i < value->slen; ++i) {
        char ch = value->ptr[i];
        uint32_t digit;
        if (ch >= '0' && ch <= '9') {
            digit = (uint32_t)(ch - '0');
        } else if (ch >= 'a' && ch <= 'f') {
            digit = (uint32_t)(ch - 'a' + 10);
        } else if (ch >= 'A' && ch <= 'F') {
            digit = (uint32_t)(ch - 'A' + 10);
        } else {
            return 0;
        }
        parsed = (parsed << 4u) | digit;
    }
    *out = parsed;
    return parsed > 0;
}

static int gmv_authorization_uri_matches(
    pjsip_rx_data *rdata,
    const pjsip_authorization_hdr *auth) {
    if (!rdata || !rdata->msg_info.msg || !auth ||
        auth->credential.digest.uri.slen <= 0) {
        return 0;
    }
    const pj_str_t *value = &auth->credential.digest.uri;
    char *buffer =
        (char *)pj_pool_alloc(rdata->tp_info.pool, value->slen + 1);
    if (!buffer) {
        return 0;
    }
    memcpy(buffer, value->ptr, (size_t)value->slen);
    buffer[value->slen] = '\0';
    pjsip_uri *authorization_uri = pjsip_parse_uri(
        rdata->tp_info.pool,
        buffer,
        (pj_size_t)value->slen,
        0);
    return authorization_uri &&
        pjsip_uri_cmp(
            PJSIP_URI_IN_REQ_URI,
            authorization_uri,
            rdata->msg_info.msg->line.req.uri) == PJ_SUCCESS;
}

static int gmv_authorization_shape_valid(
    pjsip_rx_data *rdata,
    const pjsip_authorization_hdr *auth) {
    if (!gmv_authorization_uri_matches(rdata, auth)) {
        return 0;
    }
    const pjsip_digest_credential *digest = &auth->credential.digest;
    if (digest->qop.slen == 0) {
        return 1;
    }
    uint32_t nonce_count = 0;
    return pj_stricmp2(&digest->qop, "auth") == 0 &&
        digest->cnonce.slen > 0 &&
        gmv_parse_nonce_count(&digest->nc, &nonce_count);
}

static int gmv_commit_nonce_usage(
    gmv_sip_runtime_t *runtime,
    const pjsip_authorization_hdr *auth) {
    const pjsip_digest_credential *digest = &auth->credential.digest;
    gmv_auth_nonce_t *nonce = runtime->auth_nonces;
    while (nonce &&
           pj_strcmp2(&digest->nonce, nonce->value) != 0) {
        nonce = nonce->next;
    }
    if (!nonce || nonce->expires_at_ms <= gmv_now_ms()) {
        return 0;
    }

    gmv_nonce_usage_t *usage = nonce->usages;
    while (usage) {
        if (pj_strcmp2(&digest->username, usage->username) == 0 &&
            pj_strcmp2(&digest->cnonce, usage->cnonce) == 0) {
            break;
        }
        usage = usage->next;
    }
    if (!usage) {
        if (nonce->usage_count >= 64u) {
            return 0;
        }
        usage = (gmv_nonce_usage_t *)calloc(1, sizeof(*usage));
        if (!usage ||
            !gmv_copy_view(
                usage->username,
                sizeof(usage->username),
                gmv_string_view(&digest->username)) ||
            !gmv_copy_view(
                usage->cnonce,
                sizeof(usage->cnonce),
                gmv_string_view(&digest->cnonce))) {
            free(usage);
            return 0;
        }
        usage->next = nonce->usages;
        nonce->usages = usage;
        ++nonce->usage_count;
    }

    if (digest->qop.slen == 0) {
        if (usage->used_without_qop) {
            return 0;
        }
        usage->used_without_qop = 1;
        return 1;
    }

    uint32_t nonce_count = 0;
    if (!gmv_parse_nonce_count(&digest->nc, &nonce_count) ||
        nonce_count <= usage->last_nc) {
        return 0;
    }
    usage->last_nc = nonce_count;
    return 1;
}

static pj_status_t gmv_issue_nonce(
    gmv_sip_runtime_t *runtime,
    char nonce[GMV_SIP_NONCE_CAPACITY]) {
    gmv_auth_nonce_t *item =
        (gmv_auth_nonce_t *)calloc(1, sizeof(*item));
    if (!item) {
        return PJ_ENOMEM;
    }

    pj_create_random_string(nonce, GMV_SIP_NONCE_CAPACITY - 1u);
    nonce[GMV_SIP_NONCE_CAPACITY - 1u] = '\0';
    memcpy(item->value, nonce, GMV_SIP_NONCE_CAPACITY);
    item->expires_at_ms = gmv_now_ms() + GMV_SIP_NONCE_TTL_MS;
    item->next = runtime->auth_nonces;
    runtime->auth_nonces = item;
    return PJ_SUCCESS;
}

static void gmv_add_register_response_headers(
    pjsip_rx_data *rdata,
    pjsip_tx_data *tdata,
    int status_code) {
    if (!rdata || !tdata || !rdata->msg_info.msg ||
        rdata->msg_info.msg->type != PJSIP_REQUEST_MSG ||
        rdata->msg_info.msg->line.req.method.id !=
            PJSIP_REGISTER_METHOD) {
        return;
    }

    pjsip_generic_string_hdr *gb_version =
        gmv_generic_header(rdata, "X-GB-Ver");
    if (gb_version) {
        pjsip_msg_add_hdr(
            tdata->msg,
            (pjsip_hdr *)pjsip_hdr_clone(
                tdata->pool,
                (pjsip_hdr *)gb_version));
    }

    if (status_code == PJSIP_SC_OK) {
        pjsip_contact_hdr *contact =
            (pjsip_contact_hdr *)pjsip_msg_find_hdr(
                rdata->msg_info.msg,
                PJSIP_H_CONTACT,
                NULL);
        if (contact) {
            pjsip_contact_hdr *response_contact =
                (pjsip_contact_hdr *)pjsip_hdr_clone(
                    tdata->pool,
                    (pjsip_hdr *)contact);
            int32_t expires = gmv_register_expires(rdata);
            if (expires >= 0) {
                response_contact->expires = (pj_uint32_t)expires;
            }
            pjsip_msg_add_hdr(
                tdata->msg,
                (pjsip_hdr *)response_contact);
        }
    }
}

static void gmv_add_options_response_headers(
    pjsip_rx_data *rdata,
    pjsip_tx_data *tdata,
    int status_code) {
    if (!rdata || !tdata || status_code != PJSIP_SC_OK ||
        !rdata->msg_info.msg ||
        rdata->msg_info.msg->type != PJSIP_REQUEST_MSG ||
        rdata->msg_info.msg->line.req.method.id !=
            PJSIP_OPTIONS_METHOD) {
        return;
    }

    gmv_add_string_header(
        tdata,
        "Allow",
        "REGISTER, MESSAGE, OPTIONS");
    gmv_add_string_header(tdata, "Supported", "gb28181");
    gmv_add_string_header(tdata, "User-Agent", "GMV-PJSIP/0.1");

    pjsip_generic_string_hdr *gb_version =
        gmv_generic_header(rdata, "X-GB-Ver");
    if (gb_version) {
        pjsip_msg_add_hdr(
            tdata->msg,
            (pjsip_hdr *)pjsip_hdr_clone(
                tdata->pool,
                (pjsip_hdr *)gb_version));
    } else {
        gmv_add_string_header(tdata, "X-GB-Ver", "3.0");
    }
}

static pj_status_t gmv_send_response(
    gmv_sip_runtime_t *runtime,
    pjsip_rx_data *rdata,
    pjsip_transaction *transaction,
    int status_code,
    int challenge,
    pj_bool_t stale) {
    pjsip_tx_data *tdata = NULL;
    pj_status_t status = pjsip_endpt_create_response(
        runtime->endpoint,
        rdata,
        status_code,
        NULL,
        &tdata);
    if (status != PJ_SUCCESS) {
        return status;
    }
    gmv_add_register_response_headers(rdata, tdata, status_code);
    gmv_add_options_response_headers(rdata, tdata, status_code);

    if (challenge) {
        char nonce_buf[GMV_SIP_NONCE_CAPACITY];
        pj_str_t nonce;
        pj_str_t qop = pj_str("auth");
        status = gmv_issue_nonce(runtime, nonce_buf);
        if (status == PJ_SUCCESS) {
            nonce = pj_str(nonce_buf);
            status = pjsip_auth_srv_challenge2(
                &runtime->auth_server,
                &qop,
                &nonce,
                NULL,
                stale,
                tdata,
                (pjsip_auth_algorithm_type)runtime->auth_algorithm_type);
        }
        if (status != PJ_SUCCESS) {
            pjsip_tx_data_dec_ref(tdata);
            return status;
        }
    }

    pjsip_transaction *tsx = transaction;
    if (!tsx) {
        status = pjsip_tsx_create_uas(&runtime->module, rdata, &tsx);
        if (status != PJ_SUCCESS) {
            pjsip_tx_data_dec_ref(tdata);
            return status;
        }
        pjsip_tsx_recv_msg(tsx, rdata);
    }

    status = pjsip_tsx_send_msg(tsx, tdata);
    if (status != PJ_SUCCESS) {
        pjsip_tx_data_dec_ref(tdata);
        pjsip_tsx_terminate(tsx, status_code);
    }
    return status;
}

static void gmv_emit_auth_event(
    gmv_sip_runtime_t *runtime,
    int32_t event_type,
    int status_code,
    int32_t pj_status,
    const gmv_pending_auth_t *pending) {
    const pj_str_t method = pj_str("REGISTER");
    pj_str_t device_id = pj_str((char *)pending->device_id);
    pj_str_t realm = pj_str((char *)pending->realm);
    gmv_emit_event_ex(
        runtime,
        event_type,
        gmv_transport_type(pending->rdata->tp_info.transport),
        status_code,
        pj_status,
        &method,
        pending->rdata,
        pending->lookup_id,
        &device_id,
        &realm);
}

static void gmv_free_pending_auth(gmv_pending_auth_t *pending) {
    if (!pending) {
        return;
    }
    if (pending->rdata) {
        pjsip_rx_data_free_cloned(pending->rdata);
    }
    if (pending->transaction && pending->transaction->grp_lock) {
        pj_grp_lock_dec_ref(pending->transaction->grp_lock);
    }
    free(pending);
}

static pj_status_t gmv_queue_register_lookup(
    gmv_sip_runtime_t *runtime,
    pjsip_rx_data *rdata,
    const pj_str_t *device_id,
    const pj_str_t *realm) {
    if (runtime->pending_auth_count >= runtime->max_pending_auth) {
        return PJ_ETOOMANY;
    }

    uint64_t lookup_id = 0;
    gmv_pending_auth_t *existing = runtime->pending_auth;
    while (existing) {
        if (pj_strcmp2(device_id, existing->device_id) == 0 &&
            pj_strcmp2(realm, existing->realm) == 0) {
            lookup_id = existing->lookup_id;
            break;
        }
        existing = existing->next;
    }

    gmv_pending_auth_t *pending =
        (gmv_pending_auth_t *)calloc(1, sizeof(*pending));
    if (!pending) {
        return PJ_ENOMEM;
    }
    if (!gmv_copy_view(
            pending->device_id,
            sizeof(pending->device_id),
            gmv_string_view(device_id)) ||
        !gmv_copy_view(
            pending->realm,
            sizeof(pending->realm),
            gmv_string_view(realm))) {
        free(pending);
        return PJ_ETOOSMALL;
    }

    pj_status_t status = pjsip_rx_data_clone(rdata, 0, &pending->rdata);
    if (status != PJ_SUCCESS) {
        free(pending);
        return status;
    }

    status = pjsip_tsx_create_uas(
        &runtime->module,
        rdata,
        &pending->transaction);
    if (status != PJ_SUCCESS) {
        gmv_free_pending_auth(pending);
        return status;
    }
    status = pj_grp_lock_add_ref(pending->transaction->grp_lock);
    if (status != PJ_SUCCESS) {
        pjsip_tsx_terminate(
            pending->transaction,
            PJSIP_SC_INTERNAL_SERVER_ERROR);
        pending->transaction = NULL;
        gmv_free_pending_auth(pending);
        return status;
    }
    pjsip_tsx_recv_msg(pending->transaction, rdata);

    pending->lookup_id =
        lookup_id ? lookup_id : ++runtime->lookup_sequence;
    pending->deadline_ms =
        gmv_now_ms() + runtime->auth_lookup_timeout_ms;
    pending->next = runtime->pending_auth;
    runtime->pending_auth = pending;
    ++runtime->pending_auth_count;

    if (!lookup_id) {
        gmv_emit_auth_event(
            runtime,
            GMV_SIP_EVENT_AUTH_LOOKUP_REQUIRED,
            0,
            PJ_SUCCESS,
            pending);
    }
    return PJ_SUCCESS;
}

static void gmv_complete_pending_auth(
    gmv_sip_runtime_t *runtime,
    gmv_pending_auth_t *pending,
    gmv_auth_command_t *command) {
    pjsip_authorization_hdr *auth = gmv_auth_header(pending->rdata);
    int response_code = PJSIP_SC_FORBIDDEN;
    int challenge = 0;
    pj_status_t auth_status = PJ_SUCCESS;

    if (command->result == GMV_SIP_AUTH_BYPASS) {
        response_code = PJSIP_SC_OK;
    } else if (command->result == GMV_SIP_AUTH_CREDENTIAL) {
        if (!auth) {
            response_code = PJSIP_SC_UNAUTHORIZED;
            challenge = 1;
        } else {
            runtime->active_auth_command = command;
            auth_status = pjsip_auth_srv_verify(
                &runtime->auth_server,
                pending->rdata,
                &response_code);
            runtime->active_auth_command = NULL;
            if (auth_status == PJ_SUCCESS &&
                !gmv_commit_nonce_usage(runtime, auth)) {
                auth_status = PJSIP_EAUTHINVALIDDIGEST;
                response_code = PJSIP_SC_FORBIDDEN;
            }
        }
    }

    pj_status_t send_status = gmv_send_response(
        runtime,
        pending->rdata,
        pending->transaction,
        response_code,
        challenge,
        PJ_FALSE);
    runtime->last_status = send_status;
    if (send_status == PJ_SUCCESS) {
        gmv_emit_auth_event(
            runtime,
            GMV_SIP_EVENT_RESPONSE_SENT,
            response_code,
            auth_status,
            pending);
        if (response_code == PJSIP_SC_OK) {
            gmv_emit_auth_event(
                runtime,
                gmv_register_expires(pending->rdata) == 0
                    ? GMV_SIP_EVENT_UNREGISTERED
                    : GMV_SIP_EVENT_REGISTERED,
                response_code,
                PJ_SUCCESS,
                pending);
        } else if (response_code != PJSIP_SC_UNAUTHORIZED) {
            gmv_emit_auth_event(
                runtime,
                GMV_SIP_EVENT_AUTH_REJECTED,
                response_code,
                auth_status,
                pending);
        }
    } else {
        gmv_emit_auth_event(
            runtime,
            GMV_SIP_EVENT_RUNTIME_FAULT,
            response_code,
            send_status,
            pending);
    }
}

static void gmv_process_auth_command(
    gmv_sip_runtime_t *runtime,
    gmv_auth_command_t *command) {
    gmv_pending_auth_t **cursor = &runtime->pending_auth;
    while (*cursor) {
        gmv_pending_auth_t *pending = *cursor;
        if (pending->lookup_id != command->lookup_id) {
            cursor = &pending->next;
            continue;
        }
        *cursor = pending->next;
        --runtime->pending_auth_count;
        gmv_complete_pending_auth(runtime, pending, command);
        gmv_free_pending_auth(pending);
    }
}

static void gmv_process_auth_commands(gmv_sip_runtime_t *runtime) {
    gmv_auth_command_t *commands = NULL;
    pj_mutex_lock(runtime->command_mutex);
    commands = runtime->command_head;
    runtime->command_head = NULL;
    runtime->command_tail = NULL;
    pj_mutex_unlock(runtime->command_mutex);

    while (commands) {
        gmv_auth_command_t *command = commands;
        commands = command->next;
        gmv_process_auth_command(runtime, command);
        free(command);
    }
}

static void gmv_process_auth_timeouts(gmv_sip_runtime_t *runtime) {
    uint64_t now = gmv_now_ms();
    if (now >= runtime->nonce_cleanup_at_ms) {
        gmv_nonce_status(runtime, NULL);
        runtime->nonce_cleanup_at_ms = now + 1000u;
    }
    gmv_pending_auth_t **cursor = &runtime->pending_auth;
    while (*cursor) {
        gmv_pending_auth_t *pending = *cursor;
        if (pending->deadline_ms > now) {
            cursor = &pending->next;
            continue;
        }
        *cursor = pending->next;
        --runtime->pending_auth_count;
        pj_status_t status = gmv_send_response(
            runtime,
            pending->rdata,
            pending->transaction,
            504,
            0,
            PJ_FALSE);
        gmv_emit_auth_event(
            runtime,
            status == PJ_SUCCESS
                ? GMV_SIP_EVENT_AUTH_REJECTED
                : GMV_SIP_EVENT_RUNTIME_FAULT,
            504,
            status,
            pending);
        gmv_free_pending_auth(pending);
    }
}

static pj_bool_t gmv_handle_register(
    gmv_sip_runtime_t *runtime,
    pjsip_rx_data *rdata) {
    pjsip_authorization_hdr *auth = gmv_auth_header(rdata);
    pj_str_t device_id = gmv_register_device_id(rdata);
    pj_str_t realm = pj_str(runtime->auth_realm);

    if (device_id.slen <= 0 ||
        (size_t)device_id.slen >= GMV_SIP_DEVICE_ID_CAPACITY) {
        pj_status_t status = gmv_send_response(
            runtime,
            rdata,
            NULL,
            PJSIP_SC_BAD_REQUEST,
            0,
            PJ_FALSE);
        runtime->last_status = status;
        return PJ_TRUE;
    }

    if (auth) {
        if (pj_stricmp2(&auth->scheme, "Digest") != 0) {
            pj_status_t status = gmv_send_response(
                runtime,
                rdata,
                NULL,
                PJSIP_SC_UNAUTHORIZED,
                1,
                PJ_FALSE);
            runtime->last_status = status;
            return PJ_TRUE;
        }
        realm = auth->credential.digest.realm;
        if (pj_strcmp2(&realm, runtime->auth_realm) != 0) {
            pj_status_t status = gmv_send_response(
                runtime,
                rdata,
                NULL,
                PJSIP_SC_FORBIDDEN,
                0,
                PJ_FALSE);
            runtime->last_status = status;
            return PJ_TRUE;
        }
        if (!gmv_authorization_shape_valid(rdata, auth)) {
            pj_status_t status = gmv_send_response(
                runtime,
                rdata,
                NULL,
                PJSIP_SC_FORBIDDEN,
                0,
                PJ_FALSE);
            runtime->last_status = status;
            return PJ_TRUE;
        }

        int nonce_status =
            gmv_nonce_status(runtime, &auth->credential.digest.nonce);
        if (nonce_status != 1) {
            pj_status_t status = gmv_send_response(
                runtime,
                rdata,
                NULL,
                PJSIP_SC_UNAUTHORIZED,
                1,
                nonce_status < 0 ? PJ_TRUE : PJ_FALSE);
            runtime->last_status = status;
            return PJ_TRUE;
        }
    }

    pj_status_t status =
        gmv_queue_register_lookup(runtime, rdata, &device_id, &realm);
    if (status != PJ_SUCCESS) {
        int response_code =
            status == PJ_ETOOMANY
                ? PJSIP_SC_SERVICE_UNAVAILABLE
                : PJSIP_SC_INTERNAL_SERVER_ERROR;
        pj_status_t response_status = gmv_send_response(
            runtime,
            rdata,
            NULL,
            response_code,
            0,
            PJ_FALSE);
        runtime->last_status =
            response_status == PJ_SUCCESS ? status : response_status;
    }
    return PJ_TRUE;
}

static pj_bool_t gmv_on_rx_request(pjsip_rx_data *rdata) {
    gmv_sip_runtime_t *runtime = g_active_runtime;
    if (!runtime || !rdata || !rdata->msg_info.msg) {
        return PJ_FALSE;
    }

    pjsip_method *method = &rdata->msg_info.msg->line.req.method;
    pj_bool_t is_register = method->id == PJSIP_REGISTER_METHOD;
    pj_bool_t is_options = method->id == PJSIP_OPTIONS_METHOD;
    pj_bool_t is_message =
        method->name.slen == 7 && pj_stricmp2(&method->name, "MESSAGE") == 0;
    if (!is_register && !is_options && !is_message) {
        return PJ_FALSE;
    }

    int32_t transport = gmv_transport_type(rdata->tp_info.transport);
    gmv_emit_event(
        runtime,
        GMV_SIP_EVENT_REQUEST_RECEIVED,
        transport,
        0,
        PJ_SUCCESS,
        &method->name,
        rdata);

    if (is_register) {
        return gmv_handle_register(runtime, rdata);
    }

    pj_status_t status = gmv_send_response(
        runtime,
        rdata,
        NULL,
        PJSIP_SC_OK,
        0,
        PJ_FALSE);
    runtime->last_status = status;
    if (status == PJ_SUCCESS) {
        gmv_emit_event(
            runtime,
            GMV_SIP_EVENT_RESPONSE_SENT,
            transport,
            PJSIP_SC_OK,
            status,
            &method->name,
            rdata);
    } else {
        gmv_emit_event(
            runtime,
            GMV_SIP_EVENT_RUNTIME_FAULT,
            transport,
            0,
            status,
            &method->name,
            rdata);
    }
    return PJ_TRUE;
}

static int gmv_event_thread(void *arg) {
    gmv_sip_runtime_t *runtime = (gmv_sip_runtime_t *)arg;
    while (pj_atomic_get(runtime->stop_requested) == 0) {
        gmv_process_auth_commands(runtime);
        gmv_process_auth_timeouts(runtime);

        pj_time_val timeout;
        timeout.sec = (long)(runtime->poll_timeout_ms / 1000u);
        timeout.msec = (long)(runtime->poll_timeout_ms % 1000u);
        pj_status_t status =
            pjsip_endpt_handle_events(runtime->endpoint, &timeout);
        if (status != PJ_SUCCESS) {
            runtime->last_status = status;
            gmv_emit_event(
                runtime,
                GMV_SIP_EVENT_RUNTIME_FAULT,
                GMV_SIP_TRANSPORT_UNKNOWN,
                0,
                status,
                NULL,
                NULL);
            break;
        }
    }
    return 0;
}

static void gmv_runtime_release(gmv_sip_runtime_t *runtime) {
    if (!runtime) {
        return;
    }

    if (runtime->thread) {
        if (runtime->stop_requested) {
            pj_atomic_set(runtime->stop_requested, 1);
        }
        pj_thread_join(runtime->thread);
        pj_thread_destroy(runtime->thread);
        runtime->thread = NULL;
    }
    while (runtime->pending_auth) {
        gmv_pending_auth_t *pending = runtime->pending_auth;
        runtime->pending_auth = pending->next;
        if (pending->transaction) {
            pjsip_tsx_terminate(
                pending->transaction,
                PJSIP_SC_SERVICE_UNAVAILABLE);
        }
        gmv_free_pending_auth(pending);
    }
    runtime->pending_auth_count = 0;
    while (runtime->command_head) {
        gmv_auth_command_t *command = runtime->command_head;
        runtime->command_head = command->next;
        free(command);
    }
    runtime->command_tail = NULL;
    while (runtime->auth_nonces) {
        gmv_auth_nonce_t *nonce = runtime->auth_nonces;
        runtime->auth_nonces = nonce->next;
        gmv_free_nonce(nonce);
    }
    if (runtime->command_mutex) {
        pj_mutex_destroy(runtime->command_mutex);
        runtime->command_mutex = NULL;
    }
    if (runtime->stop_requested) {
        pj_atomic_destroy(runtime->stop_requested);
        runtime->stop_requested = NULL;
    }
    if (runtime->thread_pool && runtime->endpoint) {
        pjsip_endpt_release_pool(runtime->endpoint, runtime->thread_pool);
        runtime->thread_pool = NULL;
    }

    if (runtime->tcp_factory) {
        runtime->tcp_factory->destroy(runtime->tcp_factory);
        runtime->tcp_factory = NULL;
    }
    if (runtime->udp_transport) {
        /* UDP shutdown releases the permanent reference acquired at startup. */
        pjsip_transport_shutdown(runtime->udp_transport);
        runtime->udp_transport = NULL;
    }
    if (runtime->module_registered && runtime->endpoint) {
        pjsip_endpt_unregister_module(runtime->endpoint, &runtime->module);
        runtime->module_registered = 0;
    }
    if (runtime->endpoint) {
        pjsip_endpt_destroy(runtime->endpoint);
        runtime->endpoint = NULL;
    }
    if (runtime->caching_pool_initialized) {
        pj_caching_pool_destroy(&runtime->caching_pool);
        runtime->caching_pool_initialized = 0;
    }
    if (runtime->pj_initialized) {
        pj_shutdown();
        runtime->pj_initialized = 0;
    }

    if (g_active_runtime == runtime) {
        g_active_runtime = NULL;
    }
    runtime->thread_pool = NULL;
    runtime->stop_requested = NULL;
    runtime->udp_port = 0;
    runtime->tcp_port = 0;
    runtime->started = 0;
}

uint32_t gmv_sip_abi_version(void) {
    return GMV_SIP_ABI_VERSION;
}

void gmv_sip_runtime_config_init(gmv_sip_runtime_config_t *config) {
    static const char default_address[] = GMV_SIP_DEFAULT_BIND_ADDRESS;
    static const char default_realm[] = GMV_SIP_DEFAULT_AUTH_REALM;
    if (!config) {
        return;
    }
    memset(config, 0, sizeof(*config));
    config->size = (uint32_t)sizeof(*config);
    config->version = GMV_SIP_ABI_VERSION;
    config->bind_address.ptr = default_address;
    config->bind_address.len = sizeof(default_address) - 1u;
    config->enable_udp = 1;
    config->enable_tcp = 1;
    config->async_count = 1;
    config->poll_timeout_ms = GMV_SIP_DEFAULT_POLL_TIMEOUT_MS;
    config->auth_realm.ptr = default_realm;
    config->auth_realm.len = sizeof(default_realm) - 1u;
    config->auth_algorithm_type = PJSIP_AUTH_ALGORITHM_MD5;
    config->max_pending_auth = GMV_SIP_DEFAULT_MAX_PENDING_AUTH;
    config->auth_lookup_timeout_ms =
        GMV_SIP_DEFAULT_AUTH_LOOKUP_TIMEOUT_MS;
}

int32_t gmv_sip_runtime_create(
    const gmv_sip_runtime_config_t *config,
    gmv_sip_runtime_t **out_runtime) {
    if (!out_runtime) {
        return PJ_EINVAL;
    }
    *out_runtime = NULL;

    if (!config ||
        config->size < offsetof(gmv_sip_runtime_config_t, auth_realm) ||
        config->version != GMV_SIP_ABI_VERSION ||
        (!config->enable_udp && !config->enable_tcp) ||
        (config->bind_address.len > 0 && !config->bind_address.ptr) ||
        config->bind_address.len >= GMV_SIP_BIND_ADDRESS_CAPACITY) {
        return PJ_EINVAL;
    }

    gmv_sip_runtime_t *runtime =
        (gmv_sip_runtime_t *)calloc(1, sizeof(*runtime));
    if (!runtime) {
        return PJ_ENOMEM;
    }

    const char *address = GMV_SIP_DEFAULT_BIND_ADDRESS;
    size_t address_len = strlen(address);
    if (config->bind_address.len > 0) {
        address = config->bind_address.ptr;
        address_len = config->bind_address.len;
    }
    memcpy(runtime->bind_address, address, address_len);
    runtime->bind_address[address_len] = '\0';
    runtime->requested_port = config->port;
    runtime->enable_udp = config->enable_udp ? 1u : 0u;
    runtime->enable_tcp = config->enable_tcp ? 1u : 0u;
    runtime->async_count =
        config->async_count == 0 ? 1u : config->async_count;
    runtime->poll_timeout_ms = config->poll_timeout_ms == 0
        ? GMV_SIP_DEFAULT_POLL_TIMEOUT_MS
        : config->poll_timeout_ms;
    runtime->event_callback = config->event_callback;
    runtime->event_user_data = config->event_user_data;

    const char *auth_realm = GMV_SIP_DEFAULT_AUTH_REALM;
    size_t auth_realm_len = strlen(auth_realm);
    if (GMV_SIP_CONFIG_HAS(config, auth_realm) &&
        config->auth_realm.len > 0) {
        if (!config->auth_realm.ptr ||
            config->auth_realm.len >= GMV_SIP_AUTH_REALM_CAPACITY) {
            free(runtime);
            return PJ_EINVAL;
        }
        auth_realm = config->auth_realm.ptr;
        auth_realm_len = config->auth_realm.len;
    }
    memcpy(runtime->auth_realm, auth_realm, auth_realm_len);
    runtime->auth_realm[auth_realm_len] = '\0';

    runtime->auth_algorithm_type =
        GMV_SIP_CONFIG_HAS(config, auth_algorithm_type)
            ? config->auth_algorithm_type
            : PJSIP_AUTH_ALGORITHM_MD5;
    if (!pjsip_auth_is_algorithm_supported(
            (pjsip_auth_algorithm_type)runtime->auth_algorithm_type)) {
        free(runtime);
        return PJSIP_EINVALIDALGORITHM;
    }
    runtime->max_pending_auth =
        GMV_SIP_CONFIG_HAS(config, max_pending_auth) &&
            config->max_pending_auth > 0
        ? config->max_pending_auth
        : GMV_SIP_DEFAULT_MAX_PENDING_AUTH;
    runtime->auth_lookup_timeout_ms =
        GMV_SIP_CONFIG_HAS(config, auth_lookup_timeout_ms) &&
            config->auth_lookup_timeout_ms > 0
        ? config->auth_lookup_timeout_ms
        : GMV_SIP_DEFAULT_AUTH_LOOKUP_TIMEOUT_MS;
    runtime->last_status = PJ_SUCCESS;
    *out_runtime = runtime;
    return PJ_SUCCESS;
}

int32_t gmv_sip_runtime_start(gmv_sip_runtime_t *runtime) {
    if (!runtime) {
        return PJ_EINVAL;
    }
    if (runtime->started) {
        return PJ_SUCCESS;
    }
    if (g_active_runtime && g_active_runtime != runtime) {
        return PJ_EBUSY;
    }

    pj_status_t status = pj_init();
    if (status != PJ_SUCCESS) {
        runtime->last_status = status;
        return status;
    }
    runtime->pj_initialized = 1;

    status = pjlib_util_init();
    if (status != PJ_SUCCESS) {
        goto on_error;
    }

    pj_caching_pool_init(
        &runtime->caching_pool,
        &pj_pool_factory_default_policy,
        0);
    runtime->caching_pool_initialized = 1;

    status = pjsip_endpt_create(
        &runtime->caching_pool.factory,
        "gmv-sip",
        &runtime->endpoint);
    if (status != PJ_SUCCESS) {
        goto on_error;
    }

    status = pjsip_tsx_layer_init_module(runtime->endpoint);
    if (status != PJ_SUCCESS) {
        goto on_error;
    }

    memset(&runtime->module, 0, sizeof(runtime->module));
    runtime->module.name = pj_str("mod-gmv-runtime");
    runtime->module.id = -1;
    runtime->module.priority = PJSIP_MOD_PRIORITY_APPLICATION;
    runtime->module.on_rx_request = &gmv_on_rx_request;
    status = pjsip_endpt_register_module(runtime->endpoint, &runtime->module);
    if (status != PJ_SUCCESS) {
        goto on_error;
    }
    runtime->module_registered = 1;

    pj_str_t bind_address = pj_str(runtime->bind_address);
    pj_sockaddr_in local_address;
    status = pj_sockaddr_in_init(
        &local_address,
        &bind_address,
        runtime->requested_port);
    if (status != PJ_SUCCESS) {
        goto on_error;
    }

    if (runtime->enable_udp) {
        status = pjsip_udp_transport_start(
            runtime->endpoint,
            &local_address,
            NULL,
            runtime->async_count,
            &runtime->udp_transport);
        if (status != PJ_SUCCESS) {
            goto on_error;
        }
        runtime->udp_port =
            pj_sockaddr_get_port(&runtime->udp_transport->local_addr);
    }

    if (runtime->enable_tcp) {
        pj_sockaddr_in tcp_address = local_address;
        if (runtime->requested_port == 0 && runtime->udp_port != 0) {
            pj_sockaddr_set_port(&tcp_address, runtime->udp_port);
        }
        status = pjsip_tcp_transport_start(
            runtime->endpoint,
            &tcp_address,
            runtime->async_count,
            &runtime->tcp_factory);
        if (status != PJ_SUCCESS) {
            goto on_error;
        }
        runtime->tcp_port =
            pj_sockaddr_get_port(&runtime->tcp_factory->local_addr);
    }

    runtime->thread_pool = pjsip_endpt_create_pool(
        runtime->endpoint,
        "gmv-thread",
        4096,
        4096);
    if (!runtime->thread_pool) {
        status = PJ_ENOMEM;
        goto on_error;
    }

    pjsip_auth_srv_init_param auth_param;
    pj_bzero(&auth_param, sizeof(auth_param));
    pj_str_t auth_realm = pj_str(runtime->auth_realm);
    auth_param.realm = &auth_realm;
    auth_param.lookup2 = &gmv_auth_lookup;
    status = pjsip_auth_srv_init2(
        runtime->thread_pool,
        &runtime->auth_server,
        &auth_param);
    if (status != PJ_SUCCESS) {
        goto on_error;
    }

    status = pj_mutex_create_simple(
        runtime->thread_pool,
        "gmv-auth-command",
        &runtime->command_mutex);
    if (status != PJ_SUCCESS) {
        goto on_error;
    }

    status = pj_atomic_create(
        runtime->thread_pool,
        0,
        &runtime->stop_requested);
    if (status != PJ_SUCCESS) {
        goto on_error;
    }

    g_active_runtime = runtime;
    status = pj_thread_create(
        runtime->thread_pool,
        "gmv-sip",
        &gmv_event_thread,
        runtime,
        0,
        0,
        &runtime->thread);
    if (status != PJ_SUCCESS) {
        goto on_error;
    }

    runtime->started = 1;
    runtime->last_status = PJ_SUCCESS;
    return PJ_SUCCESS;

on_error:
    runtime->last_status = status;
    gmv_runtime_release(runtime);
    return status;
}

int32_t gmv_sip_runtime_stop(gmv_sip_runtime_t *runtime) {
    if (!runtime) {
        return PJ_EINVAL;
    }
    if (!runtime->started && !runtime->pj_initialized) {
        return PJ_SUCCESS;
    }
    gmv_runtime_release(runtime);
    runtime->last_status = PJ_SUCCESS;
    return PJ_SUCCESS;
}

int32_t gmv_sip_runtime_complete_auth_lookup(
    gmv_sip_runtime_t *runtime,
    const gmv_sip_auth_lookup_completion_t *completion) {
    if (!runtime || !completion ||
        completion->size < sizeof(*completion) ||
        completion->version != GMV_SIP_ABI_VERSION ||
        completion->lookup_id == 0 ||
        !runtime->started ||
        !runtime->command_mutex) {
        return PJ_EINVAL;
    }
    if (completion->result < GMV_SIP_AUTH_CREDENTIAL ||
        completion->result > GMV_SIP_AUTH_NOT_FOUND) {
        return PJ_EINVAL;
    }

    gmv_auth_command_t *command =
        (gmv_auth_command_t *)calloc(1, sizeof(*command));
    if (!command) {
        return PJ_ENOMEM;
    }
    command->lookup_id = completion->lookup_id;
    command->result = completion->result;
    command->credential_type = completion->credential_type;
    command->algorithm_type = completion->algorithm_type;

    if (command->result == GMV_SIP_AUTH_CREDENTIAL) {
        if (!gmv_copy_view(
                command->username,
                sizeof(command->username),
                completion->username) ||
            !gmv_copy_view(
                command->realm,
                sizeof(command->realm),
                completion->realm) ||
            !gmv_copy_view(
                command->secret,
                sizeof(command->secret),
                completion->secret) ||
            !command->username[0] ||
            !command->realm[0] ||
            !command->secret[0] ||
            !pjsip_auth_is_algorithm_supported(
                (pjsip_auth_algorithm_type)command->algorithm_type)) {
            free(command);
            return PJ_EINVAL;
        }
    }

    pj_mutex_lock(runtime->command_mutex);
    if (runtime->command_tail) {
        runtime->command_tail->next = command;
    } else {
        runtime->command_head = command;
    }
    runtime->command_tail = command;
    pj_mutex_unlock(runtime->command_mutex);
    return PJ_SUCCESS;
}

int32_t gmv_sip_runtime_send_message(
    gmv_sip_runtime_t *runtime,
    const gmv_sip_outbound_message_t *message) {
    if (!runtime || !message ||
        message->size < sizeof(*message) ||
        message->version != GMV_SIP_ABI_VERSION ||
        message->operation_id == 0 ||
        !message->target_uri.ptr || message->target_uri.len == 0 ||
        !message->from_uri.ptr || message->from_uri.len == 0 ||
        !message->content_type.ptr || message->content_type.len == 0 ||
        !runtime->started || !runtime->endpoint) {
        return PJ_EINVAL;
    }

    const char *slash = memchr(
        message->content_type.ptr,
        '/',
        message->content_type.len);
    if (!slash || slash == message->content_type.ptr ||
        slash == message->content_type.ptr +
            message->content_type.len - 1) {
        return PJ_EINVAL;
    }

    pj_str_t target = {
        (char *)message->target_uri.ptr,
        (pj_ssize_t)message->target_uri.len
    };
    pj_str_t from = {
        (char *)message->from_uri.ptr,
        (pj_ssize_t)message->from_uri.len
    };
    pj_str_t type = {
        (char *)message->content_type.ptr,
        (pj_ssize_t)(slash - message->content_type.ptr)
    };
    pj_str_t subtype = {
        (char *)(slash + 1),
        (pj_ssize_t)(
            message->content_type.len -
            (size_t)(slash - message->content_type.ptr) - 1u)
    };
    pj_str_t body = {
        (char *)message->body.ptr,
        (pj_ssize_t)message->body.len
    };

    pjsip_tx_data *tdata = NULL;
    pjsip_method method;
    pj_str_t method_name = pj_str("MESSAGE");
    pjsip_method_init_np(&method, &method_name);
    pj_status_t status = pjsip_endpt_create_request(
        runtime->endpoint,
        &method,
        &target,
        &from,
        &target,
        NULL,
        NULL,
        -1,
        NULL,
        &tdata);
    if (status != PJ_SUCCESS) {
        return status;
    }
    tdata->msg->body = pjsip_msg_body_create(
        tdata->pool,
        &type,
        &subtype,
        &body);
    if (!tdata->msg->body) {
        pjsip_tx_data_dec_ref(tdata);
        return PJ_ENOMEM;
    }

    gmv_outbound_operation_t *operation =
        PJ_POOL_ZALLOC_T(tdata->pool, gmv_outbound_operation_t);
    operation->runtime = runtime;
    operation->operation_id = message->operation_id;
    status = pjsip_endpt_send_request(
        runtime->endpoint,
        tdata,
        -1,
        operation,
        &gmv_outbound_callback);
    runtime->last_status = status;
    return status;
}

void gmv_sip_runtime_destroy(gmv_sip_runtime_t *runtime) {
    if (!runtime) {
        return;
    }
    gmv_runtime_release(runtime);
    free(runtime);
}

uint16_t gmv_sip_runtime_udp_port(const gmv_sip_runtime_t *runtime) {
    return runtime ? runtime->udp_port : 0;
}

uint16_t gmv_sip_runtime_tcp_port(const gmv_sip_runtime_t *runtime) {
    return runtime ? runtime->tcp_port : 0;
}

int32_t gmv_sip_runtime_last_status(const gmv_sip_runtime_t *runtime) {
    return runtime ? runtime->last_status : PJ_EINVAL;
}

int32_t gmv_sip_error_message(
    int32_t status,
    char *buffer,
    size_t buffer_len) {
    if (!buffer || buffer_len == 0) {
        return PJ_EINVAL;
    }
    pj_str_t message = pj_strerror(status, buffer, buffer_len);
    if (message.slen < 0 || (size_t)message.slen >= buffer_len) {
        buffer[buffer_len - 1u] = '\0';
        return PJ_ETOOSMALL;
    }
    buffer[message.slen] = '\0';
    return PJ_SUCCESS;
}
