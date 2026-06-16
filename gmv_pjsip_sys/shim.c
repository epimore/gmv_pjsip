#include "shim.h"

#include <stdlib.h>
#include <string.h>
#include <pjlib.h>
#include <pjlib-util.h>
#include <pjmedia.h>
#include <pjsip.h>
#include <pjsip_simple.h>
#include <pjsip_ua.h>
#include <pjsip/sip_auth.h>
#include <pjsip/sip_parser.h>
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
#define GMV_SIP_CALL_ID_CAPACITY 256u
#define GMV_SIP_REASON_CAPACITY 128u
#define GMV_SIP_SUBJECT_CAPACITY 512u
#define GMV_SIP_CONFIG_HAS(config, field) \
    ((config)->size >= \
     offsetof(gmv_sip_runtime_config_t, field) + sizeof((config)->field))

typedef struct gmv_pending_auth {
    uint64_t lookup_id;
    char device_id[GMV_SIP_DEVICE_ID_CAPACITY];
    char realm[GMV_SIP_AUTH_REALM_CAPACITY];
    uint64_t deadline_ms;
    char *packet;
    size_t packet_len;
    pjsip_transport *transport;
    pj_sockaddr source_address;
    int source_address_len;
    char source_name[PJ_INET6_ADDRSTRLEN];
    int source_port;
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

typedef struct gmv_dialog_operation {
    gmv_sip_runtime_t *runtime;
    uint64_t operation_id;
} gmv_dialog_operation_t;

typedef struct gmv_receive_command {
    uint64_t association_id;
    int32_t transport;
    char local_address[GMV_SIP_BIND_ADDRESS_CAPACITY];
    uint16_t local_port;
    char remote_address[GMV_SIP_BIND_ADDRESS_CAPACITY];
    uint16_t remote_port;
    size_t data_len;
    unsigned char *data;
    struct gmv_receive_command *next;
} gmv_receive_command_t;

typedef struct gmv_send_completion_command {
    uint64_t send_id;
    int64_t sent_bytes;
    struct gmv_send_completion_command *next;
} gmv_send_completion_command_t;

typedef struct gmv_close_command {
    uint64_t association_id;
    int32_t transport;
    int32_t status;
    struct gmv_close_command *next;
} gmv_close_command_t;

typedef struct gmv_message_command {
    uint64_t operation_id;
    uint64_t association_id;
    int32_t transport;
    char target_uri[1024];
    char from_uri[1024];
    char content_type[GMV_SIP_CONTENT_TYPE_CAPACITY];
    unsigned char *body;
    size_t body_len;
    struct gmv_message_command *next;
} gmv_message_command_t;

typedef struct gmv_invite_command {
    uint64_t operation_id;
    uint64_t association_id;
    int32_t transport;
    char target_uri[1024];
    char to_uri[1024];
    char from_uri[1024];
    char contact_uri[1024];
    char subject[GMV_SIP_SUBJECT_CAPACITY];
    char *sdp;
    size_t sdp_len;
    struct gmv_invite_command *next;
} gmv_invite_command_t;

typedef struct gmv_dialog_command {
    uint64_t operation_id;
    int32_t method;
    char call_id[GMV_SIP_CALL_ID_CAPACITY];
    char content_type[GMV_SIP_CONTENT_TYPE_CAPACITY];
    unsigned char *body;
    size_t body_len;
    struct gmv_dialog_command *next;
} gmv_dialog_command_t;

typedef struct gmv_invite_response_command {
    uint16_t status_code;
    char call_id[GMV_SIP_CALL_ID_CAPACITY];
    char reason[GMV_SIP_REASON_CAPACITY];
    struct gmv_invite_response_command *next;
} gmv_invite_response_command_t;

typedef struct gmv_subscribe_command {
    uint64_t operation_id;
    uint64_t association_id;
    int32_t transport;
    char target_uri[1024];
    char from_uri[1024];
    char contact_uri[1024];
    char call_id[GMV_SIP_CALL_ID_CAPACITY];
    char event[GMV_SIP_CONTENT_TYPE_CAPACITY];
    uint32_t expires;
    char content_type[GMV_SIP_CONTENT_TYPE_CAPACITY];
    unsigned char *body;
    size_t body_len;
    struct gmv_subscribe_command *next;
} gmv_subscribe_command_t;

typedef struct gmv_custom_transport gmv_custom_transport_t;
typedef struct gmv_invite_call gmv_invite_call_t;
typedef struct gmv_subscription_call gmv_subscription_call_t;

typedef struct gmv_pending_send {
    uint64_t send_id;
    gmv_custom_transport_t *transport;
    pjsip_tx_data *tdata;
    void *token;
    pjsip_transport_callback callback;
    struct gmv_pending_send *next;
} gmv_pending_send_t;

struct gmv_custom_transport {
    pjsip_transport base;
    gmv_sip_runtime_t *runtime;
    uint64_t transport_id;
    uint64_t association_id;
    int32_t protocol;
    unsigned char *remainder;
    size_t remainder_len;
    size_t remainder_capacity;
    struct gmv_custom_transport *next;
};

struct gmv_invite_call {
    gmv_sip_runtime_t *runtime;
    uint64_t operation_id;
    uint64_t dialog_operation_id;
    int32_t transport;
    uint64_t association_id;
    char call_id[GMV_SIP_CALL_ID_CAPACITY];
    pjsip_inv_session *invite;
    int invite_final_emitted;
    struct gmv_invite_call *next;
};

struct gmv_subscription_call {
    gmv_sip_runtime_t *runtime;
    uint64_t operation_id;
    int32_t transport;
    uint64_t association_id;
    uint32_t expires;
    char call_id[GMV_SIP_CALL_ID_CAPACITY];
    char event[GMV_SIP_CONTENT_TYPE_CAPACITY];
    char content_type[GMV_SIP_CONTENT_TYPE_CAPACITY];
    unsigned char *body;
    size_t body_len;
    pjsip_evsub *subscription;
    struct gmv_subscription_call *next;
};

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
    uint32_t log_level;
    gmv_sip_event_callback event_callback;
    void *event_user_data;
    gmv_sip_send_callback send_callback;
    void *send_user_data;
    gmv_sip_log_callback log_callback;
    void *log_user_data;
    pj_log_func *previous_log_func;
    int previous_log_level;
    int log_configured;

    pj_caching_pool caching_pool;
    pjsip_endpoint *endpoint;
    pj_pool_t *thread_pool;
    pj_pool_t *receive_pool;
    pjsip_rx_data receive_data;
    pj_mutex_t *command_mutex;
    pjsip_module module;
    pjsip_auth_srv auth_server;

    int32_t last_status;
    uint64_t event_sequence;
    uint64_t lookup_sequence;
    uint64_t nonce_cleanup_at_ms;
    uint32_t pending_auth_count;
    gmv_pending_auth_t *pending_auth;
    gmv_auth_command_t *command_head;
    gmv_auth_command_t *command_tail;
    gmv_receive_command_t *receive_head;
    gmv_receive_command_t *receive_tail;
    gmv_send_completion_command_t *completion_head;
    gmv_send_completion_command_t *completion_tail;
    gmv_close_command_t *close_head;
    gmv_close_command_t *close_tail;
    gmv_message_command_t *message_head;
    gmv_message_command_t *message_tail;
    gmv_invite_command_t *invite_head;
    gmv_invite_command_t *invite_tail;
    gmv_dialog_command_t *dialog_head;
    gmv_dialog_command_t *dialog_tail;
    gmv_invite_response_command_t *invite_response_head;
    gmv_invite_response_command_t *invite_response_tail;
    gmv_subscribe_command_t *subscribe_head;
    gmv_subscribe_command_t *subscribe_tail;
    gmv_auth_command_t *active_auth_command;
    gmv_auth_nonce_t *auth_nonces;
    gmv_custom_transport_t *transports;
    gmv_pending_send_t *pending_sends;
    gmv_invite_call_t *invite_calls;
    gmv_subscription_call_t *subscriptions;
    uint64_t transport_sequence;
    uint64_t send_sequence;
    int pj_initialized;
    int caching_pool_initialized;
    int module_registered;
    int started;
};

static gmv_sip_runtime_t *g_active_runtime;
static gmv_sip_runtime_t *g_log_runtime;

static void gmv_pjsip_log_writer(int level, const char *data, int len) {
    gmv_sip_runtime_t *runtime = g_log_runtime;
    if (!runtime || !runtime->log_callback || !data || len <= 0) {
        return;
    }
    gmv_sip_string_view_t message;
    message.ptr = data;
    message.len = (size_t)len;
    runtime->log_callback(level, message, runtime->log_user_data);
}

static pj_status_t gmv_send_message_on_owner(
    gmv_sip_runtime_t *runtime,
    const gmv_message_command_t *message);
static pj_status_t gmv_send_invite_on_owner(
    gmv_sip_runtime_t *runtime,
    const gmv_invite_command_t *command);
static pj_status_t gmv_send_dialog_on_owner(
    gmv_sip_runtime_t *runtime,
    const gmv_dialog_command_t *command);
static pj_status_t gmv_respond_invite_on_owner(
    gmv_sip_runtime_t *runtime,
    const gmv_invite_response_command_t *command);
static pj_status_t gmv_send_subscribe_on_owner(
    gmv_sip_runtime_t *runtime,
    const gmv_subscribe_command_t *command);
static pj_bool_t gmv_handle_incoming_invite(
    gmv_sip_runtime_t *runtime,
    pjsip_rx_data *rdata);

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

static pj_status_t gmv_custom_transport_shutdown(pjsip_transport *transport) {
    PJ_UNUSED_ARG(transport);
    return PJ_SUCCESS;
}

static pj_status_t gmv_custom_transport_destroy(pjsip_transport *base) {
    gmv_custom_transport_t *transport =
        (gmv_custom_transport_t *)base;
    free(transport->remainder);
    transport->remainder = NULL;
    transport->remainder_len = 0;
    transport->remainder_capacity = 0;
    if (base->lock) {
        pj_lock_destroy(base->lock);
        base->lock = NULL;
    }
    if (base->ref_cnt) {
        pj_atomic_destroy(base->ref_cnt);
        base->ref_cnt = NULL;
    }
    pjsip_endpt_release_pool(base->endpt, base->pool);
    return PJ_SUCCESS;
}

static void gmv_remove_pending_send(
    gmv_sip_runtime_t *runtime,
    gmv_pending_send_t *pending) {
    gmv_pending_send_t **cursor = &runtime->pending_sends;
    while (*cursor) {
        if (*cursor == pending) {
            *cursor = pending->next;
            return;
        }
        cursor = &(*cursor)->next;
    }
}

static pj_status_t gmv_custom_transport_send(
    pjsip_transport *base,
    pjsip_tx_data *tdata,
    const pj_sockaddr_t *remote_address,
    int address_length,
    void *token,
    pjsip_transport_callback callback) {
    gmv_custom_transport_t *transport =
        (gmv_custom_transport_t *)base;
    gmv_sip_runtime_t *runtime = transport->runtime;
    PJ_UNUSED_ARG(address_length);

    if (!runtime || !runtime->send_callback || base->is_shutdown) {
        return PJSIP_ESHUTDOWN;
    }

    pj_status_t status = pjsip_tx_data_encode(tdata);
    if (status != PJ_SUCCESS) {
        return status;
    }
    pj_ssize_t data_len = tdata->buf.cur - tdata->buf.start;
    if (data_len <= 0) {
        return PJ_EINVAL;
    }

    gmv_pending_send_t *pending =
        (gmv_pending_send_t *)calloc(1, sizeof(*pending));
    if (!pending) {
        return PJ_ENOMEM;
    }
    pending->send_id = ++runtime->send_sequence;
    pending->transport = transport;
    pending->tdata = tdata;
    pending->token = token;
    pending->callback = callback;
    pjsip_tx_data_add_ref(tdata);
    pending->next = runtime->pending_sends;
    runtime->pending_sends = pending;

    char local[GMV_SIP_BIND_ADDRESS_CAPACITY];
    char remote[GMV_SIP_BIND_ADDRESS_CAPACITY];
    memset(local, 0, sizeof(local));
    memset(remote, 0, sizeof(remote));
    pj_sockaddr_print(&base->local_addr, local, sizeof(local), 0);
    const pj_sockaddr_t *destination = remote_address;
    if (!destination || !pj_sockaddr_has_addr(destination)) {
        destination = &base->key.rem_addr;
    }
    pj_sockaddr_print(destination, remote, sizeof(remote), 0);

    gmv_sip_send_packet_t packet;
    memset(&packet, 0, sizeof(packet));
    packet.size = (uint32_t)sizeof(packet);
    packet.version = GMV_SIP_ABI_VERSION;
    packet.send_id = pending->send_id;
    packet.transport_id = transport->transport_id;
    packet.association_id = transport->association_id;
    packet.transport = transport->protocol;
    packet.data = gmv_bytes_view(tdata->buf.start, (size_t)data_len);
    packet.local_address = gmv_c_string_view(local);
    packet.local_port =
        (uint16_t)pj_sockaddr_get_port(&base->local_addr);
    packet.remote_address = gmv_c_string_view(remote);
    packet.remote_port =
        (uint16_t)pj_sockaddr_get_port(destination);

    status = runtime->send_callback(&packet, runtime->send_user_data);
    if (status != PJ_SUCCESS) {
        gmv_remove_pending_send(runtime, pending);
        pjsip_tx_data_dec_ref(tdata);
        free(pending);
        return PJ_ETOOMANY;
    }
    return PJ_EPENDING;
}

static pj_status_t gmv_init_address(
    pj_sockaddr *address,
    const char *host,
    uint16_t port) {
    pj_str_t host_string = pj_str((char *)host);
    return pj_sockaddr_init(
        pj_AF_INET(),
        address,
        &host_string,
        port);
}

static pj_status_t gmv_create_custom_transport(
    gmv_sip_runtime_t *runtime,
    int32_t protocol,
    uint64_t association_id,
    const char *local_address,
    uint16_t local_port,
    const char *remote_address,
    uint16_t remote_port,
    gmv_custom_transport_t **out_transport) {
    pj_pool_t *pool = pjsip_endpt_create_pool(
        runtime->endpoint,
        protocol == GMV_SIP_TRANSPORT_UDP ? "gmv-udp" : "gmv-tcp",
        4096,
        4096);
    if (!pool) {
        return PJ_ENOMEM;
    }

    gmv_custom_transport_t *transport =
        PJ_POOL_ZALLOC_T(pool, gmv_custom_transport_t);
    pjsip_transport *base = &transport->base;
    transport->runtime = runtime;
    transport->transport_id = ++runtime->transport_sequence;
    transport->association_id = association_id;
    transport->protocol = protocol;
    base->pool = pool;
    pj_ansi_snprintf(
        base->obj_name,
        sizeof(base->obj_name),
        protocol == GMV_SIP_TRANSPORT_UDP
            ? "gmv-udp-%llu"
            : "gmv-tcp-%llu",
        (unsigned long long)transport->transport_id);

    pj_status_t status = pj_atomic_create(pool, 0, &base->ref_cnt);
    if (status != PJ_SUCCESS) {
        goto on_error;
    }
    status = pj_lock_create_recursive_mutex(
        pool,
        base->obj_name,
        &base->lock);
    if (status != PJ_SUCCESS) {
        goto on_error;
    }

    base->key.type = protocol == GMV_SIP_TRANSPORT_UDP
        ? PJSIP_TRANSPORT_UDP
        : PJSIP_TRANSPORT_TCP;
    base->type_name = protocol == GMV_SIP_TRANSPORT_UDP
        ? "UDP"
        : "TCP";
    base->info = protocol == GMV_SIP_TRANSPORT_UDP
        ? "GMV custom UDP transport"
        : "GMV custom TCP transport";
    base->flag = protocol == GMV_SIP_TRANSPORT_UDP
        ? PJSIP_TRANSPORT_DATAGRAM
        : PJSIP_TRANSPORT_RELIABLE;
    base->addr_len = sizeof(pj_sockaddr_in);
    base->dir = protocol == GMV_SIP_TRANSPORT_UDP
        ? PJSIP_TP_DIR_NONE
        : PJSIP_TP_DIR_INCOMING;
    base->endpt = runtime->endpoint;
    base->tpmgr = pjsip_endpt_get_tpmgr(runtime->endpoint);
    base->send_msg = &gmv_custom_transport_send;
    base->do_shutdown = &gmv_custom_transport_shutdown;
    base->destroy = &gmv_custom_transport_destroy;

    status = gmv_init_address(
        &base->local_addr,
        local_address,
        local_port);
    if (status != PJ_SUCCESS) {
        goto on_error;
    }
    base->has_addr_name = PJ_TRUE;
    pj_strdup2(pool, &base->local_name.host, local_address);
    base->local_name.port = local_port;

    if (protocol == GMV_SIP_TRANSPORT_TCP) {
        status = gmv_init_address(
            &base->key.rem_addr,
            remote_address,
            remote_port);
        if (status != PJ_SUCCESS) {
            goto on_error;
        }
        pj_strdup2(pool, &base->remote_name.host, remote_address);
        base->remote_name.port = remote_port;
    }

    status = pjsip_transport_register(base->tpmgr, base);
    if (status != PJ_SUCCESS) {
        goto on_error;
    }
    status = pjsip_transport_add_ref(base);
    if (status != PJ_SUCCESS) {
        pjsip_transport_shutdown2(base, PJ_TRUE);
        goto on_error;
    }

    transport->next = runtime->transports;
    runtime->transports = transport;
    *out_transport = transport;
    return PJ_SUCCESS;

on_error:
    if (base->lock) {
        pj_lock_destroy(base->lock);
    }
    if (base->ref_cnt) {
        pj_atomic_destroy(base->ref_cnt);
    }
    pjsip_endpt_release_pool(runtime->endpoint, pool);
    return status;
}

static gmv_custom_transport_t *gmv_find_transport(
    gmv_sip_runtime_t *runtime,
    int32_t protocol,
    uint64_t association_id) {
    gmv_custom_transport_t *transport = runtime->transports;
    while (transport) {
        if (transport->protocol == protocol &&
            (protocol == GMV_SIP_TRANSPORT_UDP ||
             transport->association_id == association_id)) {
            return transport;
        }
        transport = transport->next;
    }
    return NULL;
}

static void gmv_fail_transport_sends(
    gmv_sip_runtime_t *runtime,
    gmv_custom_transport_t *transport,
    int32_t status) {
    gmv_pending_send_t **cursor = &runtime->pending_sends;
    while (*cursor) {
        gmv_pending_send_t *pending = *cursor;
        if (pending->transport != transport) {
            cursor = &pending->next;
            continue;
        }
        *cursor = pending->next;
        if (pending->callback) {
            pending->callback(
                &transport->base,
                pending->token,
                -(pj_ssize_t)status);
        }
        pjsip_tx_data_dec_ref(pending->tdata);
        free(pending);
    }
}

static void gmv_close_custom_transport(
    gmv_sip_runtime_t *runtime,
    gmv_custom_transport_t *transport,
    int32_t status) {
    gmv_custom_transport_t **cursor = &runtime->transports;
    while (*cursor) {
        if (*cursor == transport) {
            *cursor = transport->next;
            break;
        }
        cursor = &(*cursor)->next;
    }
    gmv_fail_transport_sends(
        runtime,
        transport,
        status == PJ_SUCCESS ? PJSIP_ESHUTDOWN : status);
    pjsip_transport_shutdown2(&transport->base, PJ_TRUE);
    pjsip_transport_dec_ref(&transport->base);
}

static pj_status_t gmv_save_remainder(
    gmv_custom_transport_t *transport,
    const char *data,
    size_t data_len) {
    if (data_len == 0) {
        transport->remainder_len = 0;
        return PJ_SUCCESS;
    }
    if (transport->remainder_capacity < data_len) {
        unsigned char *next =
            (unsigned char *)realloc(transport->remainder, data_len);
        if (!next) {
            return PJ_ENOMEM;
        }
        transport->remainder = next;
        transport->remainder_capacity = data_len;
    }
    memcpy(transport->remainder, data, data_len);
    transport->remainder_len = data_len;
    return PJ_SUCCESS;
}

static pj_status_t gmv_deliver_receive_buffer(
    gmv_sip_runtime_t *runtime,
    gmv_custom_transport_t *transport,
    size_t data_len,
    const char *remote_address,
    uint16_t remote_port,
    size_t *consumed) {
    pjsip_rx_data *rdata = &runtime->receive_data;
    rdata->tp_info.pool = runtime->receive_pool;
    rdata->tp_info.transport = &transport->base;
    pj_gettimeofday(&rdata->pkt_info.timestamp);
    pj_status_t status = gmv_init_address(
        &rdata->pkt_info.src_addr,
        remote_address,
        remote_port);
    if (status != PJ_SUCCESS) {
        return status;
    }
    rdata->pkt_info.src_addr_len = sizeof(pj_sockaddr_in);
    pj_ansi_strxcpy(
        rdata->pkt_info.src_name,
        remote_address,
        sizeof(rdata->pkt_info.src_name));
    rdata->pkt_info.src_port = remote_port;
    rdata->pkt_info.len = (pj_ssize_t)data_len;
    rdata->pkt_info.zero = 0;

    pj_ssize_t processed = pjsip_tpmgr_receive_packet(
        transport->base.tpmgr,
        rdata);
    if (processed < 0 || (size_t)processed > data_len) {
        status = PJ_EINVALIDOP;
    } else {
        *consumed = (size_t)processed;
        status = PJ_SUCCESS;
    }
    pj_pool_reset(runtime->receive_pool);
    return status;
}

static pj_status_t gmv_receive_on_transport(
    gmv_sip_runtime_t *runtime,
    gmv_custom_transport_t *transport,
    const unsigned char *data,
    size_t data_len,
    const char *remote_address,
    uint16_t remote_port) {
    if (!data || data_len == 0) {
        return PJ_EINVAL;
    }
    pjsip_rx_data *rdata = &runtime->receive_data;

    if (transport->protocol == GMV_SIP_TRANSPORT_UDP) {
        if (data_len > PJSIP_MAX_PKT_LEN) {
            return PJSIP_ERXOVERFLOW;
        }
        memcpy(rdata->pkt_info.packet, data, data_len);
        size_t consumed = 0;
        pj_status_t status = gmv_deliver_receive_buffer(
            runtime,
            transport,
            data_len,
            remote_address,
            remote_port,
            &consumed);
        return status == PJ_SUCCESS && consumed == data_len
            ? PJ_SUCCESS
            : PJ_EINVALIDOP;
    }

    size_t offset = 0;
    do {
        size_t prefix_len = transport->remainder_len;
        if (prefix_len > PJSIP_MAX_PKT_LEN) {
            return PJSIP_ERXOVERFLOW;
        }
        if (prefix_len > 0) {
            memcpy(
                rdata->pkt_info.packet,
                transport->remainder,
                prefix_len);
        }
        size_t copy_len = data_len - offset;
        size_t available = PJSIP_MAX_PKT_LEN - prefix_len;
        if (copy_len > available) {
            copy_len = available;
        }
        if (copy_len > 0) {
            memcpy(
                rdata->pkt_info.packet + prefix_len,
                data + offset,
                copy_len);
        }
        size_t combined_len = prefix_len + copy_len;
        size_t consumed = 0;
        pj_status_t status = gmv_deliver_receive_buffer(
            runtime,
            transport,
            combined_len,
            remote_address,
            remote_port,
            &consumed);
        if (status != PJ_SUCCESS) {
            return status;
        }
        status = gmv_save_remainder(
            transport,
            rdata->pkt_info.packet + consumed,
            combined_len - consumed);
        if (status != PJ_SUCCESS) {
            return status;
        }
        offset += copy_len;
        if (consumed == 0 &&
            combined_len == PJSIP_MAX_PKT_LEN &&
            offset < data_len) {
            return PJSIP_ERXOVERFLOW;
        }
    } while (offset < data_len);

    return PJ_SUCCESS;
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

static gmv_sip_string_view_t gmv_print_header_value(
    const pjsip_hdr *header,
    char *buffer,
    size_t capacity) {
    gmv_sip_string_view_t empty = {NULL, 0};
    if (!header || !buffer || capacity == 0) {
        return empty;
    }
    int written = pjsip_hdr_print_on(
        (void *)header,
        buffer,
        (pj_size_t)capacity - 1u);
    if (written <= 0 || (size_t)written >= capacity) {
        return empty;
    }
    buffer[written] = '\0';
    char *value = strchr(buffer, ':');
    if (!value) {
        return empty;
    }
    ++value;
    while (*value == ' ' || *value == '\t') {
        ++value;
    }
    gmv_sip_string_view_t view = {
        value,
        strlen(value)
    };
    return view;
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

static int32_t gmv_message_expires(const pjsip_rx_data *rdata) {
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
    return expires ? expires->ivalue : -1;
}

static int32_t gmv_register_expires(const pjsip_rx_data *rdata) {
    int32_t expires = gmv_message_expires(rdata);
    return expires >= 0 ? expires : 3600;
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
    const pj_str_t *realm,
    uint64_t operation_id) {
    if (!runtime || !runtime->event_callback) {
        return;
    }

    gmv_sip_event_t event;
    char content_type[GMV_SIP_CONTENT_TYPE_CAPACITY];
    char contact[GMV_SIP_CONTACT_CAPACITY];
    char local_address[GMV_SIP_ADDRESS_CAPACITY];
    char remote_address[GMV_SIP_ADDRESS_CAPACITY];
    char from_header[1024];
    char to_header[1024];
    char subject_header[GMV_SIP_SUBJECT_CAPACITY];
    char event_header_value[GMV_SIP_CONTENT_TYPE_CAPACITY];
    char subscription_state_value[GMV_SIP_CONTENT_TYPE_CAPACITY];
    memset(&event, 0, sizeof(event));
    memset(content_type, 0, sizeof(content_type));
    memset(contact, 0, sizeof(contact));
    memset(local_address, 0, sizeof(local_address));
    memset(remote_address, 0, sizeof(remote_address));
    memset(from_header, 0, sizeof(from_header));
    memset(to_header, 0, sizeof(to_header));
    memset(subject_header, 0, sizeof(subject_header));
    memset(event_header_value, 0, sizeof(event_header_value));
    memset(
        subscription_state_value,
        0,
        sizeof(subscription_state_value));
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
    event.operation_id = operation_id;

    if (rdata) {
        if (rdata->tp_info.transport) {
            gmv_custom_transport_t *transport =
                (gmv_custom_transport_t *)rdata->tp_info.transport;
            event.association_id = transport->association_id;
        }
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
        event.from_header = gmv_print_header_value(
            (const pjsip_hdr *)rdata->msg_info.from,
            from_header,
            sizeof(from_header));
        event.to_header = gmv_print_header_value(
            (const pjsip_hdr *)rdata->msg_info.to,
            to_header,
            sizeof(to_header));
        pjsip_generic_string_hdr *subject =
            gmv_generic_header(rdata, "Subject");
        pjsip_generic_string_hdr *event_header =
            gmv_generic_header(rdata, "Event");
        pjsip_generic_string_hdr *subscription_state =
            gmv_generic_header(rdata, "Subscription-State");
        if (subject) {
            event.subject = gmv_print_header_value(
                (const pjsip_hdr *)subject,
                subject_header,
                sizeof(subject_header));
        }
        if (event_header) {
            event.event = gmv_print_header_value(
                (const pjsip_hdr *)event_header,
                event_header_value,
                sizeof(event_header_value));
        }
        if (subscription_state) {
            event.subscription_state = gmv_print_header_value(
                (const pjsip_hdr *)subscription_state,
                subscription_state_value,
                sizeof(subscription_state_value));
        }
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
        event.expires_seconds = gmv_message_expires(rdata);
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
        NULL,
        0);
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

    pjsip_rx_data *rdata = NULL;
    if (event->body.tsx_state.type == PJSIP_EVENT_RX_MSG) {
        rdata = event->body.tsx_state.src.rdata;
    }
    gmv_emit_event_ex(
        operation->runtime,
        GMV_SIP_EVENT_OUTBOUND_RESPONSE,
        rdata
            ? gmv_transport_type(rdata->tp_info.transport)
            : GMV_SIP_TRANSPORT_UNKNOWN,
        transaction->status_code,
        PJ_SUCCESS,
        &transaction->method.name,
        rdata,
        0,
        NULL,
        NULL,
        operation->operation_id);
}

static pjsip_rx_data *gmv_event_rdata(pjsip_event *event) {
    if (!event ||
        event->type != PJSIP_EVENT_TSX_STATE ||
        event->body.tsx_state.type != PJSIP_EVENT_RX_MSG) {
        return NULL;
    }
    return event->body.tsx_state.src.rdata;
}

static void gmv_emit_transaction_event(
    gmv_sip_runtime_t *runtime,
    pjsip_transaction *transaction,
    pjsip_event *event,
    uint64_t operation_id) {
    if (!runtime || !transaction || operation_id == 0 ||
        transaction->status_code < 100) {
        return;
    }
    pjsip_rx_data *rdata = gmv_event_rdata(event);
    int32_t pj_status =
        transaction->status_code >= 200 &&
                transaction->status_code < 700
            ? PJ_SUCCESS
            : transaction->status_code;
    gmv_emit_event_ex(
        runtime,
        GMV_SIP_EVENT_OUTBOUND_RESPONSE,
        rdata
            ? gmv_transport_type(rdata->tp_info.transport)
            : GMV_SIP_TRANSPORT_UNKNOWN,
        transaction->status_code,
        pj_status,
        &transaction->method.name,
        rdata,
        0,
        NULL,
        NULL,
        operation_id);
}

static gmv_invite_call_t *gmv_invite_call_from_session(
    pjsip_inv_session *invite) {
    gmv_sip_runtime_t *runtime = g_active_runtime;
    if (!runtime || !invite || runtime->module.id < 0) {
        return NULL;
    }
    return (gmv_invite_call_t *)
        invite->mod_data[runtime->module.id];
}

static void gmv_remove_invite_call(
    gmv_sip_runtime_t *runtime,
    gmv_invite_call_t *call) {
    if (!runtime || !call) {
        return;
    }
    gmv_invite_call_t **cursor = &runtime->invite_calls;
    while (*cursor) {
        if (*cursor == call) {
            *cursor = call->next;
            free(call);
            return;
        }
        cursor = &(*cursor)->next;
    }
}

static void gmv_invite_on_state_changed(
    pjsip_inv_session *invite,
    pjsip_event *event) {
    PJ_UNUSED_ARG(event);
    gmv_invite_call_t *call =
        gmv_invite_call_from_session(invite);
    if (!call || invite->state != PJSIP_INV_STATE_DISCONNECTED ||
        !call->invite_final_emitted ||
        call->dialog_operation_id != 0) {
        return;
    }
    invite->mod_data[call->runtime->module.id] = NULL;
    call->invite = NULL;
    gmv_remove_invite_call(call->runtime, call);
}

static void gmv_invite_on_new_session(
    pjsip_inv_session *invite,
    pjsip_event *event) {
    PJ_UNUSED_ARG(invite);
    PJ_UNUSED_ARG(event);
}

static void gmv_invite_on_tsx_state_changed(
    pjsip_inv_session *invite,
    pjsip_transaction *transaction,
    pjsip_event *event) {
    gmv_invite_call_t *call =
        gmv_invite_call_from_session(invite);
    if (!call || !transaction) {
        return;
    }
    if (transaction->role == PJSIP_ROLE_UAS) {
        pjsip_rx_data *rdata = gmv_event_rdata(event);
        if (rdata &&
            (transaction->method.id == PJSIP_CANCEL_METHOD ||
             transaction->method.id == PJSIP_BYE_METHOD)) {
            gmv_emit_event(
                call->runtime,
                GMV_SIP_EVENT_REQUEST_RECEIVED,
                gmv_transport_type(rdata->tp_info.transport),
                0,
                PJ_SUCCESS,
                &transaction->method.name,
                rdata);
        }
        return;
    }
    if (transaction->role != PJSIP_ROLE_UAC) {
        return;
    }
    if (transaction->method.id == PJSIP_INVITE_METHOD) {
        if (transaction->status_code >= 200 &&
            call->invite_final_emitted) {
            return;
        }
        gmv_emit_transaction_event(
            call->runtime,
            transaction,
            event,
            call->operation_id);
        if (transaction->status_code >= 200) {
            call->invite_final_emitted = 1;
            if (invite->state == PJSIP_INV_STATE_DISCONNECTED) {
                invite->mod_data[call->runtime->module.id] = NULL;
                call->invite = NULL;
                gmv_remove_invite_call(call->runtime, call);
            }
        }
        return;
    }
    if ((transaction->method.id == PJSIP_BYE_METHOD ||
         transaction->method.id == PJSIP_CANCEL_METHOD) &&
        call->dialog_operation_id != 0) {
        uint64_t operation_id = call->dialog_operation_id;
        gmv_emit_transaction_event(
            call->runtime,
            transaction,
            event,
            operation_id);
        if (transaction->status_code >= 200) {
            call->dialog_operation_id = 0;
            if (invite->state == PJSIP_INV_STATE_DISCONNECTED) {
                invite->mod_data[call->runtime->module.id] = NULL;
                call->invite = NULL;
                gmv_remove_invite_call(call->runtime, call);
            }
        }
    }
}

static gmv_subscription_call_t *gmv_subscription_from_evsub(
    pjsip_evsub *subscription) {
    gmv_sip_runtime_t *runtime = g_active_runtime;
    if (!runtime || !subscription || runtime->module.id < 0) {
        return NULL;
    }
    return (gmv_subscription_call_t *)pjsip_evsub_get_mod_data(
        subscription,
        (unsigned)runtime->module.id);
}

static void gmv_remove_subscription(
    gmv_sip_runtime_t *runtime,
    gmv_subscription_call_t *call) {
    if (!runtime || !call) {
        return;
    }
    gmv_subscription_call_t **cursor = &runtime->subscriptions;
    while (*cursor) {
        if (*cursor == call) {
            *cursor = call->next;
            free(call->body);
            free(call);
            return;
        }
        cursor = &(*cursor)->next;
    }
}

static pj_status_t gmv_set_subscription_body(
    pjsip_tx_data *tdata,
    const char *content_type,
    const unsigned char *body,
    size_t body_len) {
    if (!tdata || !content_type || !*content_type ||
        !body || body_len == 0) {
        return PJ_SUCCESS;
    }
    const char *slash = strchr(content_type, '/');
    size_t content_type_len = strlen(content_type);
    if (!slash || slash == content_type ||
        slash == content_type + content_type_len - 1) {
        return PJ_EINVAL;
    }
    pj_str_t type = {
        (char *)content_type,
        (pj_ssize_t)(slash - content_type)
    };
    pj_str_t subtype = {
        (char *)(slash + 1),
        (pj_ssize_t)(
            content_type_len -
            (size_t)(slash - content_type) - 1u)
    };
    unsigned char *body_copy =
        (unsigned char *)pj_pool_alloc(tdata->pool, body_len);
    if (!body_copy) {
        return PJ_ENOMEM;
    }
    memcpy(body_copy, body, body_len);
    pj_str_t value = {
        (char *)body_copy,
        (pj_ssize_t)body_len
    };
    tdata->msg->body = pjsip_msg_body_create(
        tdata->pool,
        &type,
        &subtype,
        &value);
    return tdata->msg->body ? PJ_SUCCESS : PJ_ENOMEM;
}

static pj_status_t gmv_start_subscription_request(
    gmv_subscription_call_t *call,
    uint32_t expires) {
    pjsip_tx_data *tdata = NULL;
    pj_status_t status = pjsip_evsub_initiate(
        call->subscription,
        pjsip_get_subscribe_method(),
        expires,
        &tdata);
    if (status == PJ_SUCCESS) {
        status = gmv_set_subscription_body(
            tdata,
            call->content_type,
            call->body,
            call->body_len);
    }
    if (status == PJ_SUCCESS) {
        status = pjsip_evsub_send_request(
            call->subscription,
            tdata);
    } else if (tdata) {
        pjsip_tx_data_dec_ref(tdata);
    }
    return status;
}

static void gmv_subscription_on_state(
    pjsip_evsub *subscription,
    pjsip_event *event) {
    PJ_UNUSED_ARG(event);
    gmv_subscription_call_t *call =
        gmv_subscription_from_evsub(subscription);
    if (!call ||
        pjsip_evsub_get_state(subscription) !=
            PJSIP_EVSUB_STATE_TERMINATED ||
        call->operation_id != 0) {
        return;
    }
    pjsip_evsub_set_mod_data(
        subscription,
        (unsigned)call->runtime->module.id,
        NULL);
    call->subscription = NULL;
    gmv_remove_subscription(call->runtime, call);
}

static void gmv_subscription_on_tsx_state(
    pjsip_evsub *subscription,
    pjsip_transaction *transaction,
    pjsip_event *event) {
    gmv_subscription_call_t *call =
        gmv_subscription_from_evsub(subscription);
    if (!call || !transaction ||
        transaction->role != PJSIP_ROLE_UAC ||
        pjsip_method_cmp(
            &transaction->method,
            pjsip_get_subscribe_method()) != 0 ||
        call->operation_id == 0) {
        return;
    }
    gmv_emit_transaction_event(
        call->runtime,
        transaction,
        event,
        call->operation_id);
    if (transaction->status_code >= 200) {
        call->operation_id = 0;
        if (pjsip_evsub_get_state(subscription) ==
                PJSIP_EVSUB_STATE_TERMINATED) {
            pjsip_evsub_set_mod_data(
                subscription,
                (unsigned)call->runtime->module.id,
                NULL);
            call->subscription = NULL;
            gmv_remove_subscription(call->runtime, call);
        }
    }
}

static void gmv_subscription_on_rx_notify(
    pjsip_evsub *subscription,
    pjsip_rx_data *rdata,
    int *status_code,
    pj_str_t **status_text,
    pjsip_hdr *response_headers,
    pjsip_msg_body **response_body) {
    PJ_UNUSED_ARG(status_text);
    PJ_UNUSED_ARG(response_headers);
    PJ_UNUSED_ARG(response_body);
    gmv_subscription_call_t *call =
        gmv_subscription_from_evsub(subscription);
    if (!call || !rdata) {
        if (status_code) {
            *status_code = PJSIP_SC_CALL_TSX_DOES_NOT_EXIST;
        }
        return;
    }
    if (status_code) {
        *status_code = PJSIP_SC_OK;
    }
    pj_str_t method = pj_str("NOTIFY");
    gmv_emit_event(
        call->runtime,
        GMV_SIP_EVENT_REQUEST_RECEIVED,
        gmv_transport_type(rdata->tp_info.transport),
        0,
        PJ_SUCCESS,
        &method,
        rdata);
}

static void gmv_subscription_on_client_refresh(
    pjsip_evsub *subscription) {
    gmv_subscription_call_t *call =
        gmv_subscription_from_evsub(subscription);
    if (!call || call->operation_id != 0) {
        return;
    }
    pj_status_t status =
        gmv_start_subscription_request(call, call->expires);
    if (status != PJ_SUCCESS) {
        call->runtime->last_status = status;
        gmv_emit_event(
            call->runtime,
            GMV_SIP_EVENT_RUNTIME_FAULT,
            call->transport,
            0,
            status,
            NULL,
            NULL);
    }
}

static pjsip_evsub_user gmv_subscription_callbacks = {
    &gmv_subscription_on_state,
    &gmv_subscription_on_tsx_state,
    NULL,
    &gmv_subscription_on_rx_notify,
    &gmv_subscription_on_client_refresh,
    NULL
};

static void gmv_on_tsx_state(
    pjsip_transaction *transaction,
    pjsip_event *event) {
    gmv_sip_runtime_t *runtime = g_active_runtime;
    if (!runtime || !transaction || runtime->module.id < 0) {
        return;
    }
    gmv_dialog_operation_t *operation =
        (gmv_dialog_operation_t *)
            transaction->mod_data[runtime->module.id];
    if (!operation) {
        return;
    }
    gmv_emit_transaction_event(
        operation->runtime,
        transaction,
        event,
        operation->operation_id);
    if (transaction->status_code >= 200 ||
        transaction->state == PJSIP_TSX_STATE_TERMINATED ||
        transaction->state == PJSIP_TSX_STATE_DESTROYED) {
        transaction->mod_data[runtime->module.id] = NULL;
        free(operation);
    }
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
    const gmv_pending_auth_t *pending,
    const pjsip_rx_data *rdata) {
    const pj_str_t method = pj_str("REGISTER");
    pj_str_t device_id = pj_str((char *)pending->device_id);
    pj_str_t realm = pj_str((char *)pending->realm);
    gmv_emit_event_ex(
        runtime,
        event_type,
        gmv_transport_type(rdata->tp_info.transport),
        status_code,
        pj_status,
        &method,
        rdata,
        pending->lookup_id,
        &device_id,
        &realm,
        0);
}

static pjsip_rx_data *gmv_rebuild_pending_rdata(
    gmv_sip_runtime_t *runtime,
    const gmv_pending_auth_t *pending) {
    if (!runtime->receive_pool ||
        !pending->packet ||
        pending->packet_len == 0 ||
        pending->packet_len > PJSIP_MAX_PKT_LEN) {
        return NULL;
    }
    pj_pool_reset(runtime->receive_pool);
    pjsip_rx_data *rdata = &runtime->receive_data;
    pj_bzero(&rdata->msg_info, sizeof(rdata->msg_info));
    pj_list_init(&rdata->msg_info.parse_err);
    rdata->tp_info.pool = runtime->receive_pool;
    rdata->tp_info.transport = pending->transport;
    memcpy(
        rdata->pkt_info.packet,
        pending->packet,
        pending->packet_len);
    rdata->pkt_info.packet[pending->packet_len] = '\0';
    rdata->pkt_info.len = (pj_ssize_t)pending->packet_len;
    rdata->pkt_info.src_addr = pending->source_address;
    rdata->pkt_info.src_addr_len = pending->source_address_len;
    pj_ansi_strxcpy(
        rdata->pkt_info.src_name,
        pending->source_name,
        sizeof(rdata->pkt_info.src_name));
    rdata->pkt_info.src_port = pending->source_port;
    pj_gettimeofday(&rdata->pkt_info.timestamp);
    rdata->msg_info.msg_buf = rdata->pkt_info.packet;
    rdata->msg_info.len = (int)pending->packet_len;
    if (!pjsip_parse_rdata(
            rdata->pkt_info.packet,
            pending->packet_len,
            rdata) ||
        !pj_list_empty(&rdata->msg_info.parse_err)) {
        return NULL;
    }
    return rdata;
}

static void gmv_free_pending_auth(gmv_pending_auth_t *pending) {
    if (!pending) {
        return;
    }
    free(pending->packet);
    if (pending->transport) {
        pjsip_transport_dec_ref(pending->transport);
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

    if (!rdata->msg_info.msg_buf ||
        rdata->msg_info.len <= 0 ||
        rdata->msg_info.len > PJSIP_MAX_PKT_LEN) {
        gmv_free_pending_auth(pending);
        return PJ_EINVAL;
    }
    pending->packet_len = (size_t)rdata->msg_info.len;
    pending->packet =
        (char *)malloc(pending->packet_len + 1u);
    if (!pending->packet) {
        gmv_free_pending_auth(pending);
        return PJ_ENOMEM;
    }
    memcpy(
        pending->packet,
        rdata->msg_info.msg_buf,
        pending->packet_len);
    pending->packet[pending->packet_len] = '\0';
    pending->transport = rdata->tp_info.transport;
    pj_status_t status =
        pjsip_transport_add_ref(pending->transport);
    if (status != PJ_SUCCESS) {
        pending->transport = NULL;
        gmv_free_pending_auth(pending);
        return status;
    }
    pending->source_address = rdata->pkt_info.src_addr;
    pending->source_address_len = rdata->pkt_info.src_addr_len;
    pj_ansi_strxcpy(
        pending->source_name,
        rdata->pkt_info.src_name,
        sizeof(pending->source_name));
    pending->source_port = rdata->pkt_info.src_port;

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
            pending,
            rdata);
    }
    return PJ_SUCCESS;
}

static void gmv_complete_pending_auth(
    gmv_sip_runtime_t *runtime,
    gmv_pending_auth_t *pending,
    gmv_auth_command_t *command) {
    pjsip_rx_data *rdata =
        gmv_rebuild_pending_rdata(runtime, pending);
    if (!rdata) {
        runtime->last_status = PJSIP_EINVALIDMSG;
        pjsip_tsx_terminate(
            pending->transaction,
            PJSIP_SC_INTERNAL_SERVER_ERROR);
        return;
    }
    pjsip_authorization_hdr *auth = gmv_auth_header(rdata);
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
                rdata,
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
        rdata,
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
            pending,
            rdata);
        if (response_code == PJSIP_SC_OK) {
            gmv_emit_auth_event(
                runtime,
                gmv_register_expires(rdata) == 0
                    ? GMV_SIP_EVENT_UNREGISTERED
                    : GMV_SIP_EVENT_REGISTERED,
                response_code,
                PJ_SUCCESS,
                pending,
                rdata);
        } else if (response_code != PJSIP_SC_UNAUTHORIZED) {
            gmv_emit_auth_event(
                runtime,
                GMV_SIP_EVENT_AUTH_REJECTED,
                response_code,
                auth_status,
                pending,
                rdata);
        }
    } else {
        gmv_emit_auth_event(
            runtime,
            GMV_SIP_EVENT_RUNTIME_FAULT,
            response_code,
            send_status,
            pending,
            rdata);
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
        pjsip_rx_data *rdata =
            gmv_rebuild_pending_rdata(runtime, pending);
        pj_status_t status = rdata
            ? gmv_send_response(
                runtime,
                rdata,
                pending->transaction,
                504,
                0,
                PJ_FALSE)
            : PJSIP_EINVALIDMSG;
        if (rdata) {
            gmv_emit_auth_event(
                runtime,
                status == PJ_SUCCESS
                    ? GMV_SIP_EVENT_AUTH_REJECTED
                    : GMV_SIP_EVENT_RUNTIME_FAULT,
                504,
                status,
                pending,
                rdata);
        } else {
            pjsip_tsx_terminate(
                pending->transaction,
                PJSIP_SC_INTERNAL_SERVER_ERROR);
        }
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
    pj_bool_t is_invite = method->id == PJSIP_INVITE_METHOD;
    pj_bool_t is_ack = method->id == PJSIP_ACK_METHOD;
    pj_bool_t is_bye = method->id == PJSIP_BYE_METHOD;
    pj_bool_t is_cancel = method->id == PJSIP_CANCEL_METHOD;
    if (!is_register && !is_options && !is_message &&
        !is_invite && !is_ack && !is_bye && !is_cancel) {
        return PJ_FALSE;
    }

    int32_t transport = gmv_transport_type(rdata->tp_info.transport);
    if (is_invite) {
        return gmv_handle_incoming_invite(runtime, rdata);
    }
    gmv_emit_event(
        runtime,
        GMV_SIP_EVENT_REQUEST_RECEIVED,
        transport,
        0,
        PJ_SUCCESS,
        &method->name,
        rdata);

    if (is_ack || is_bye || is_cancel) {
        return PJ_FALSE;
    }
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

static pj_bool_t gmv_handle_incoming_invite(
    gmv_sip_runtime_t *runtime,
    pjsip_rx_data *rdata) {
    pjsip_dialog *dialog = NULL;
    pj_status_t status = pjsip_dlg_create_uas_and_inc_lock(
        pjsip_ua_instance(),
        rdata,
        NULL,
        &dialog);
    if (status != PJ_SUCCESS) {
        runtime->last_status = status;
        return PJ_FALSE;
    }

    pjsip_inv_session *invite = NULL;
    status = pjsip_inv_create_uas(
        dialog,
        rdata,
        NULL,
        0,
        &invite);
    if (status != PJ_SUCCESS) {
        pjsip_dlg_respond(
            dialog,
            rdata,
            PJSIP_SC_INTERNAL_SERVER_ERROR,
            NULL,
            NULL,
            NULL);
        pjsip_dlg_dec_lock(dialog);
        runtime->last_status = status;
        return PJ_TRUE;
    }

    pjsip_tpselector selector;
    memset(&selector, 0, sizeof(selector));
    selector.type = PJSIP_TPSELECTOR_TRANSPORT;
    selector.u.transport = rdata->tp_info.transport;
    status = pjsip_dlg_set_transport(dialog, &selector);
    if (status != PJ_SUCCESS) {
        pjsip_inv_terminate(
            invite,
            PJSIP_SC_INTERNAL_SERVER_ERROR,
            PJ_FALSE);
        pjsip_dlg_dec_lock(dialog);
        runtime->last_status = status;
        return PJ_TRUE;
    }

    pjsip_tx_data *tdata = NULL;
    status = pjsip_inv_initial_answer(
        invite,
        rdata,
        PJSIP_SC_TRYING,
        NULL,
        NULL,
        &tdata);
    if (status == PJ_SUCCESS) {
        status = pjsip_inv_send_msg(invite, tdata);
    }
    if (status != PJ_SUCCESS) {
        pjsip_inv_terminate(
            invite,
            PJSIP_SC_INTERNAL_SERVER_ERROR,
            PJ_FALSE);
        pjsip_dlg_dec_lock(dialog);
        runtime->last_status = status;
        return PJ_TRUE;
    }

    gmv_invite_call_t *call =
        (gmv_invite_call_t *)calloc(1, sizeof(*call));
    pj_status_t call_status = call ? PJ_SUCCESS : PJ_ENOMEM;
    if (call &&
        !gmv_copy_view(
            call->call_id,
            sizeof(call->call_id),
            gmv_string_view(&dialog->call_id->id))) {
        call_status = PJ_ETOOSMALL;
    }
    if (call_status != PJ_SUCCESS) {
        free(call);
        pjsip_inv_terminate(
            invite,
            PJSIP_SC_INTERNAL_SERVER_ERROR,
            PJ_FALSE);
        pjsip_dlg_dec_lock(dialog);
        runtime->last_status = call_status;
        return PJ_TRUE;
    }
    call->runtime = runtime;
    call->transport = gmv_transport_type(rdata->tp_info.transport);
    call->association_id =
        ((gmv_custom_transport_t *)rdata->tp_info.transport)->association_id;
    call->invite = invite;
    call->invite_final_emitted = 1;
    invite->mod_data[runtime->module.id] = call;
    call->next = runtime->invite_calls;
    runtime->invite_calls = call;

    pj_str_t method = pj_str("INVITE");
    gmv_emit_event_ex(
        runtime,
        GMV_SIP_EVENT_INCOMING_INVITE,
        call->transport,
        PJSIP_SC_TRYING,
        PJ_SUCCESS,
        &method,
        rdata,
        0,
        NULL,
        NULL,
        0);
    pjsip_dlg_dec_lock(dialog);
    runtime->last_status = PJ_SUCCESS;
    return PJ_TRUE;
}

static void gmv_free_receive_command(gmv_receive_command_t *command) {
    if (!command) {
        return;
    }
    free(command->data);
    free(command);
}

static void gmv_process_receive_commands(
    gmv_sip_runtime_t *runtime,
    gmv_receive_command_t *commands) {
    while (commands) {
        gmv_receive_command_t *command = commands;
        commands = command->next;

        gmv_custom_transport_t *transport = gmv_find_transport(
            runtime,
            command->transport,
            command->association_id);
        pj_status_t status = PJ_SUCCESS;
        if (!transport &&
            command->transport == GMV_SIP_TRANSPORT_TCP) {
            status = gmv_create_custom_transport(
                runtime,
                command->transport,
                command->association_id,
                command->local_address,
                command->local_port,
                command->remote_address,
                command->remote_port,
                &transport);
        }
        if (!transport && status == PJ_SUCCESS) {
            status = PJ_ENOTFOUND;
        }
        if (status == PJ_SUCCESS) {
            status = gmv_receive_on_transport(
                runtime,
                transport,
                command->data,
                command->data_len,
                command->remote_address,
                command->remote_port);
        }
        if (status != PJ_SUCCESS) {
            runtime->last_status = status;
            gmv_emit_event(
                runtime,
                GMV_SIP_EVENT_RUNTIME_FAULT,
                command->transport,
                0,
                status,
                NULL,
                NULL);
        }
        gmv_free_receive_command(command);
    }
}

static void gmv_process_send_completions(
    gmv_sip_runtime_t *runtime,
    gmv_send_completion_command_t *commands) {
    while (commands) {
        gmv_send_completion_command_t *command = commands;
        commands = command->next;

        gmv_pending_send_t **cursor = &runtime->pending_sends;
        gmv_pending_send_t *pending = NULL;
        while (*cursor) {
            if ((*cursor)->send_id == command->send_id) {
                pending = *cursor;
                *cursor = pending->next;
                break;
            }
            cursor = &(*cursor)->next;
        }
        if (pending) {
            if (pending->callback) {
                pending->callback(
                    &pending->transport->base,
                    pending->token,
                    (pj_ssize_t)command->sent_bytes);
            }
            pjsip_tx_data_dec_ref(pending->tdata);
            free(pending);
        }
        free(command);
    }
}

static void gmv_process_close_commands(
    gmv_sip_runtime_t *runtime,
    gmv_close_command_t *commands) {
    while (commands) {
        gmv_close_command_t *command = commands;
        commands = command->next;
        gmv_custom_transport_t *transport = gmv_find_transport(
            runtime,
            command->transport,
            command->association_id);
        if (transport &&
            transport->protocol == GMV_SIP_TRANSPORT_TCP) {
            gmv_close_custom_transport(
                runtime,
                transport,
                command->status);
        }
        free(command);
    }
}

static void gmv_free_message_command(gmv_message_command_t *command) {
    if (!command) {
        return;
    }
    free(command->body);
    free(command);
}

static void gmv_free_invite_command(gmv_invite_command_t *command) {
    if (!command) {
        return;
    }
    free(command->sdp);
    free(command);
}

static void gmv_free_dialog_command(gmv_dialog_command_t *command) {
    if (!command) {
        return;
    }
    free(command->body);
    free(command);
}

static void gmv_free_invite_response_command(
    gmv_invite_response_command_t *command) {
    free(command);
}

static void gmv_free_subscribe_command(
    gmv_subscribe_command_t *command) {
    if (!command) {
        return;
    }
    free(command->body);
    free(command);
}

static void gmv_emit_command_fault(
    gmv_sip_runtime_t *runtime,
    uint64_t operation_id,
    pj_status_t status) {
    if (!runtime || !runtime->event_callback) {
        return;
    }
    gmv_sip_event_t event;
    memset(&event, 0, sizeof(event));
    event.size = (uint32_t)sizeof(event);
    event.version = GMV_SIP_ABI_VERSION;
    event.event_type = GMV_SIP_EVENT_RUNTIME_FAULT;
    event.pj_status = status;
    event.event_id = ++runtime->event_sequence;
    event.operation_id = operation_id;
    runtime->event_callback(&event, runtime->event_user_data);
}

static void gmv_process_message_commands(
    gmv_sip_runtime_t *runtime,
    gmv_message_command_t *commands) {
    while (commands) {
        gmv_message_command_t *command = commands;
        commands = command->next;
        pj_status_t status =
            gmv_send_message_on_owner(runtime, command);
        runtime->last_status = status;
        if (status != PJ_SUCCESS) {
            gmv_emit_command_fault(
                runtime,
                command->operation_id,
                status);
        }
        gmv_free_message_command(command);
    }
}

static void gmv_process_invite_commands(
    gmv_sip_runtime_t *runtime,
    gmv_invite_command_t *commands) {
    while (commands) {
        gmv_invite_command_t *command = commands;
        commands = command->next;
        pj_status_t status =
            gmv_send_invite_on_owner(runtime, command);
        runtime->last_status = status;
        if (status != PJ_SUCCESS) {
            gmv_emit_command_fault(
                runtime,
                command->operation_id,
                status);
        }
        gmv_free_invite_command(command);
    }
}

static void gmv_process_dialog_commands(
    gmv_sip_runtime_t *runtime,
    gmv_dialog_command_t *commands) {
    while (commands) {
        gmv_dialog_command_t *command = commands;
        commands = command->next;
        pj_status_t status =
            gmv_send_dialog_on_owner(runtime, command);
        runtime->last_status = status;
        if (status != PJ_SUCCESS) {
            gmv_emit_command_fault(
                runtime,
                command->operation_id,
                status);
        }
        gmv_free_dialog_command(command);
    }
}

static void gmv_process_invite_response_commands(
    gmv_sip_runtime_t *runtime,
    gmv_invite_response_command_t *commands) {
    while (commands) {
        gmv_invite_response_command_t *command = commands;
        commands = command->next;
        pj_status_t status =
            gmv_respond_invite_on_owner(runtime, command);
        runtime->last_status = status;
        gmv_free_invite_response_command(command);
    }
}

static void gmv_process_subscribe_commands(
    gmv_sip_runtime_t *runtime,
    gmv_subscribe_command_t *commands) {
    while (commands) {
        gmv_subscribe_command_t *command = commands;
        commands = command->next;
        pj_status_t status =
            gmv_send_subscribe_on_owner(runtime, command);
        runtime->last_status = status;
        if (status != PJ_SUCCESS) {
            gmv_emit_command_fault(
                runtime,
                command->operation_id,
                status);
        }
        gmv_free_subscribe_command(command);
    }
}

static void gmv_process_io_commands(gmv_sip_runtime_t *runtime) {
    gmv_receive_command_t *receive_commands;
    gmv_send_completion_command_t *completion_commands;
    gmv_close_command_t *close_commands;
    gmv_message_command_t *message_commands;
    gmv_invite_command_t *invite_commands;
    gmv_dialog_command_t *dialog_commands;
    gmv_invite_response_command_t *invite_response_commands;
    gmv_subscribe_command_t *subscribe_commands;

    pj_mutex_lock(runtime->command_mutex);
    receive_commands = runtime->receive_head;
    runtime->receive_head = NULL;
    runtime->receive_tail = NULL;
    completion_commands = runtime->completion_head;
    runtime->completion_head = NULL;
    runtime->completion_tail = NULL;
    close_commands = runtime->close_head;
    runtime->close_head = NULL;
    runtime->close_tail = NULL;
    message_commands = runtime->message_head;
    runtime->message_head = NULL;
    runtime->message_tail = NULL;
    invite_commands = runtime->invite_head;
    runtime->invite_head = NULL;
    runtime->invite_tail = NULL;
    dialog_commands = runtime->dialog_head;
    runtime->dialog_head = NULL;
    runtime->dialog_tail = NULL;
    invite_response_commands = runtime->invite_response_head;
    runtime->invite_response_head = NULL;
    runtime->invite_response_tail = NULL;
    subscribe_commands = runtime->subscribe_head;
    runtime->subscribe_head = NULL;
    runtime->subscribe_tail = NULL;
    pj_mutex_unlock(runtime->command_mutex);

    gmv_process_send_completions(runtime, completion_commands);
    gmv_process_close_commands(runtime, close_commands);
    gmv_process_message_commands(runtime, message_commands);
    gmv_process_invite_commands(runtime, invite_commands);
    gmv_process_dialog_commands(runtime, dialog_commands);
    gmv_process_invite_response_commands(
        runtime,
        invite_response_commands);
    gmv_process_subscribe_commands(runtime, subscribe_commands);
    gmv_process_receive_commands(runtime, receive_commands);
}

static void gmv_runtime_release(gmv_sip_runtime_t *runtime) {
    if (!runtime) {
        return;
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
    while (runtime->receive_head) {
        gmv_receive_command_t *command = runtime->receive_head;
        runtime->receive_head = command->next;
        gmv_free_receive_command(command);
    }
    runtime->receive_tail = NULL;
    while (runtime->completion_head) {
        gmv_send_completion_command_t *command =
            runtime->completion_head;
        runtime->completion_head = command->next;
        free(command);
    }
    runtime->completion_tail = NULL;
    while (runtime->close_head) {
        gmv_close_command_t *command = runtime->close_head;
        runtime->close_head = command->next;
        free(command);
    }
    runtime->close_tail = NULL;
    while (runtime->message_head) {
        gmv_message_command_t *command = runtime->message_head;
        runtime->message_head = command->next;
        gmv_free_message_command(command);
    }
    runtime->message_tail = NULL;
    while (runtime->invite_head) {
        gmv_invite_command_t *command = runtime->invite_head;
        runtime->invite_head = command->next;
        gmv_free_invite_command(command);
    }
    runtime->invite_tail = NULL;
    while (runtime->dialog_head) {
        gmv_dialog_command_t *command = runtime->dialog_head;
        runtime->dialog_head = command->next;
        gmv_free_dialog_command(command);
    }
    runtime->dialog_tail = NULL;
    while (runtime->invite_response_head) {
        gmv_invite_response_command_t *command =
            runtime->invite_response_head;
        runtime->invite_response_head = command->next;
        gmv_free_invite_response_command(command);
    }
    runtime->invite_response_tail = NULL;
    while (runtime->subscribe_head) {
        gmv_subscribe_command_t *command =
            runtime->subscribe_head;
        runtime->subscribe_head = command->next;
        gmv_free_subscribe_command(command);
    }
    runtime->subscribe_tail = NULL;
    while (runtime->invite_calls) {
        gmv_invite_call_t *call = runtime->invite_calls;
        runtime->invite_calls = call->next;
        if (call->invite) {
            call->invite->mod_data[runtime->module.id] = NULL;
            pjsip_inv_terminate(
                call->invite,
                PJSIP_SC_SERVICE_UNAVAILABLE,
                PJ_FALSE);
        }
        free(call);
    }
    while (runtime->subscriptions) {
        gmv_subscription_call_t *call =
            runtime->subscriptions;
        runtime->subscriptions = call->next;
        if (call->subscription) {
            pjsip_evsub_set_mod_data(
                call->subscription,
                (unsigned)runtime->module.id,
                NULL);
            pjsip_evsub_terminate(
                call->subscription,
                PJ_FALSE);
        }
        free(call->body);
        free(call);
    }
    while (runtime->auth_nonces) {
        gmv_auth_nonce_t *nonce = runtime->auth_nonces;
        runtime->auth_nonces = nonce->next;
        gmv_free_nonce(nonce);
    }
    while (runtime->transports) {
        gmv_close_custom_transport(
            runtime,
            runtime->transports,
            PJSIP_ESHUTDOWN);
    }
    while (runtime->pending_sends) {
        gmv_pending_send_t *pending = runtime->pending_sends;
        runtime->pending_sends = pending->next;
        if (pending->callback) {
            pending->callback(
                &pending->transport->base,
                pending->token,
                -(pj_ssize_t)PJSIP_ESHUTDOWN);
        }
        pjsip_tx_data_dec_ref(pending->tdata);
        free(pending);
    }
    if (runtime->command_mutex) {
        pj_mutex_destroy(runtime->command_mutex);
        runtime->command_mutex = NULL;
    }
    if (runtime->receive_pool && runtime->endpoint) {
        pjsip_endpt_release_pool(
            runtime->endpoint,
            runtime->receive_pool);
        runtime->receive_pool = NULL;
    }
    if (runtime->thread_pool && runtime->endpoint) {
        pjsip_endpt_release_pool(runtime->endpoint, runtime->thread_pool);
        runtime->thread_pool = NULL;
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
    if (runtime->log_configured) {
        pj_log_set_log_func(runtime->previous_log_func);
        pj_log_set_level(runtime->previous_log_level);
        if (g_log_runtime == runtime) {
            g_log_runtime = NULL;
        }
        runtime->log_configured = 0;
    }

    if (g_active_runtime == runtime) {
        g_active_runtime = NULL;
    }
    runtime->thread_pool = NULL;
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
    config->log_level = 0;
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
        !GMV_SIP_CONFIG_HAS(config, log_user_data) ||
        !config->send_callback ||
        config->log_level > PJ_LOG_MAX_LEVEL ||
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
    runtime->send_callback = config->send_callback;
    runtime->send_user_data = config->send_user_data;
    runtime->log_level = config->log_level;
    runtime->log_callback = config->log_callback;
    runtime->log_user_data = config->log_user_data;

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

    runtime->previous_log_func = pj_log_get_log_func();
    runtime->previous_log_level = pj_log_get_level();
    g_log_runtime = runtime;
    pj_log_set_log_func(&gmv_pjsip_log_writer);
    pj_log_set_level((int)runtime->log_level);
    runtime->log_configured = 1;

    pj_status_t status = pj_init();
    if (status != PJ_SUCCESS) {
        runtime->last_status = status;
        gmv_runtime_release(runtime);
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

    status = pjsip_ua_init_module(runtime->endpoint, NULL);
    if (status != PJ_SUCCESS) {
        goto on_error;
    }

    status = pjsip_100rel_init_module(runtime->endpoint);
    if (status != PJ_SUCCESS) {
        goto on_error;
    }

    status = pjsip_timer_init_module(runtime->endpoint);
    if (status != PJ_SUCCESS) {
        goto on_error;
    }

    pjsip_inv_callback invite_callbacks;
    memset(&invite_callbacks, 0, sizeof(invite_callbacks));
    invite_callbacks.on_state_changed =
        &gmv_invite_on_state_changed;
    invite_callbacks.on_new_session =
        &gmv_invite_on_new_session;
    invite_callbacks.on_tsx_state_changed =
        &gmv_invite_on_tsx_state_changed;
    status = pjsip_inv_usage_init(
        runtime->endpoint,
        &invite_callbacks);
    if (status != PJ_SUCCESS) {
        goto on_error;
    }

    status = pjsip_evsub_init_module(runtime->endpoint);
    if (status != PJ_SUCCESS) {
        goto on_error;
    }

    memset(&runtime->module, 0, sizeof(runtime->module));
    runtime->module.name = pj_str("mod-gmv-runtime");
    runtime->module.id = -1;
    runtime->module.priority =
        PJSIP_MOD_PRIORITY_DIALOG_USAGE - 1;
    runtime->module.on_rx_request = &gmv_on_rx_request;
    runtime->module.on_tsx_state = &gmv_on_tsx_state;
    status = pjsip_endpt_register_module(runtime->endpoint, &runtime->module);
    if (status != PJ_SUCCESS) {
        goto on_error;
    }
    runtime->module_registered = 1;

    pj_str_t catalog_event = pj_str("Catalog");
    pj_str_t catalog_accept =
        pj_str("Application/MANSCDP+xml");
    status = pjsip_evsub_register_pkg(
        &runtime->module,
        &catalog_event,
        3600,
        1,
        &catalog_accept);
    if (status != PJ_SUCCESS) {
        goto on_error;
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

    runtime->receive_pool = pjsip_endpt_create_pool(
        runtime->endpoint,
        "gmv-receive",
        PJSIP_POOL_RDATA_LEN,
        PJSIP_POOL_RDATA_INC);
    if (!runtime->receive_pool) {
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

    if (runtime->enable_udp) {
        gmv_custom_transport_t *udp_transport = NULL;
        status = gmv_create_custom_transport(
            runtime,
            GMV_SIP_TRANSPORT_UDP,
            0,
            runtime->bind_address,
            runtime->requested_port,
            "0.0.0.0",
            0,
            &udp_transport);
        if (status != PJ_SUCCESS) {
            goto on_error;
        }
    }

    g_active_runtime = runtime;
    runtime->started = 1;
    runtime->last_status = PJ_SUCCESS;
    return PJ_SUCCESS;

on_error:
    runtime->last_status = status;
    gmv_runtime_release(runtime);
    return status;
}

int32_t gmv_sip_runtime_poll(gmv_sip_runtime_t *runtime) {
    if (!runtime || !runtime->started || !runtime->endpoint) {
        return PJ_EINVAL;
    }

    gmv_process_io_commands(runtime);
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
        return status;
    }

    runtime->last_status = PJ_SUCCESS;
    return PJ_SUCCESS;
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

static pj_status_t gmv_send_message_on_owner(
    gmv_sip_runtime_t *runtime,
    const gmv_message_command_t *message) {
    if (!runtime || !message ||
        message->operation_id == 0 ||
        !message->target_uri[0] ||
        !message->from_uri[0] ||
        !message->content_type[0] ||
        !runtime->started || !runtime->endpoint) {
        return PJ_EINVAL;
    }

    pj_str_t target = pj_str((char *)message->target_uri);
    pj_str_t from = pj_str((char *)message->from_uri);
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
    status = gmv_set_subscription_body(
        tdata,
        message->content_type,
        message->body,
        message->body_len);
    if (status != PJ_SUCCESS) {
        pjsip_tx_data_dec_ref(tdata);
        return status;
    }

    gmv_custom_transport_t *transport =
        gmv_find_transport(
            runtime,
            message->transport,
            message->association_id);
    if (!transport) {
        pjsip_tx_data_dec_ref(tdata);
        return PJSIP_EUNSUPTRANSPORT;
    }
    pjsip_tpselector selector;
    memset(&selector, 0, sizeof(selector));
    selector.type = PJSIP_TPSELECTOR_TRANSPORT;
    selector.u.transport = &transport->base;
    status = pjsip_tx_data_set_transport(tdata, &selector);
    if (status != PJ_SUCCESS) {
        pjsip_tx_data_dec_ref(tdata);
        return status;
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

static gmv_invite_call_t *gmv_find_invite_call(
    gmv_sip_runtime_t *runtime,
    const char *call_id) {
    if (!runtime || !call_id || !*call_id) {
        return NULL;
    }
    gmv_invite_call_t *call = runtime->invite_calls;
    while (call) {
        if (strcmp(call->call_id, call_id) == 0) {
            return call;
        }
        call = call->next;
    }
    return NULL;
}

static pj_status_t gmv_send_invite_on_owner(
    gmv_sip_runtime_t *runtime,
    const gmv_invite_command_t *command) {
    if (!runtime || !command ||
        command->operation_id == 0 ||
        !command->target_uri[0] ||
        !command->to_uri[0] ||
        !command->from_uri[0] ||
        !command->contact_uri[0] ||
        !command->sdp ||
        command->sdp_len == 0 ||
        !runtime->started ||
        !runtime->endpoint) {
        return PJ_EINVAL;
    }

    gmv_custom_transport_t *transport = gmv_find_transport(
        runtime,
        command->transport,
        command->association_id);
    if (!transport) {
        return PJSIP_EUNSUPTRANSPORT;
    }

    pj_str_t target = pj_str((char *)command->target_uri);
    pj_str_t to = pj_str((char *)command->to_uri);
    pj_str_t from = pj_str((char *)command->from_uri);
    pj_str_t contact = pj_str((char *)command->contact_uri);
    pjsip_dialog *dialog = NULL;
    pj_status_t status = pjsip_dlg_create_uac(
        pjsip_ua_instance(),
        &from,
        &contact,
        &to,
        &target,
        &dialog);
    if (status != PJ_SUCCESS) {
        return status;
    }

    char *sdp_buffer =
        (char *)pj_pool_alloc(
            runtime->thread_pool,
            command->sdp_len + 1u);
    memcpy(sdp_buffer, command->sdp, command->sdp_len);
    sdp_buffer[command->sdp_len] = '\0';
    pjmedia_sdp_session *local_sdp = NULL;
    status = pjmedia_sdp_parse(
        runtime->thread_pool,
        sdp_buffer,
        command->sdp_len,
        &local_sdp);
    if (status != PJ_SUCCESS) {
        pjsip_dlg_terminate(dialog);
        return status;
    }

    pjsip_inv_session *invite = NULL;
    status = pjsip_inv_create_uac(
        dialog,
        local_sdp,
        0,
        &invite);
    if (status != PJ_SUCCESS) {
        pjsip_dlg_terminate(dialog);
        return status;
    }

    status = pjsip_dlg_add_usage(
        dialog,
        &runtime->module,
        NULL);
    if (status != PJ_SUCCESS) {
        pjsip_inv_terminate(
            invite,
            PJSIP_SC_INTERNAL_SERVER_ERROR,
            PJ_FALSE);
        return status;
    }

    pjsip_tpselector selector;
    memset(&selector, 0, sizeof(selector));
    selector.type = PJSIP_TPSELECTOR_TRANSPORT;
    selector.u.transport = &transport->base;
    status = pjsip_dlg_set_transport(dialog, &selector);
    if (status != PJ_SUCCESS) {
        pjsip_inv_terminate(
            invite,
            PJSIP_SC_INTERNAL_SERVER_ERROR,
            PJ_FALSE);
        return status;
    }

    gmv_invite_call_t *call =
        (gmv_invite_call_t *)calloc(1, sizeof(*call));
    if (!call) {
        pjsip_inv_terminate(
            invite,
            PJSIP_SC_INTERNAL_SERVER_ERROR,
            PJ_FALSE);
        return PJ_ENOMEM;
    }
    call->runtime = runtime;
    call->operation_id = command->operation_id;
    call->transport = command->transport;
    call->association_id = command->association_id;
    call->invite = invite;
    if (!gmv_copy_view(
            call->call_id,
            sizeof(call->call_id),
            gmv_string_view(&dialog->call_id->id))) {
        free(call);
        pjsip_inv_terminate(
            invite,
            PJSIP_SC_INTERNAL_SERVER_ERROR,
            PJ_FALSE);
        return PJ_ETOOSMALL;
    }
    invite->mod_data[runtime->module.id] = call;
    call->next = runtime->invite_calls;
    runtime->invite_calls = call;

    pjsip_tx_data *tdata = NULL;
    status = pjsip_inv_invite(invite, &tdata);
    if (status == PJ_SUCCESS) {
        status = gmv_set_subscription_body(
            tdata,
            "application/sdp",
            (const unsigned char *)command->sdp,
            command->sdp_len);
    }
    if (status == PJ_SUCCESS && command->subject[0]) {
        gmv_add_string_header(
            tdata,
            "Subject",
            command->subject);
    }
    if (status == PJ_SUCCESS) {
        status = pjsip_inv_send_msg(invite, tdata);
    }
    if (status != PJ_SUCCESS) {
        invite->mod_data[runtime->module.id] = NULL;
        call->invite = NULL;
        gmv_remove_invite_call(runtime, call);
        pjsip_inv_terminate(
            invite,
            PJSIP_SC_INTERNAL_SERVER_ERROR,
            PJ_FALSE);
    }
    return status;
}

static pj_status_t gmv_send_dialog_on_owner(
    gmv_sip_runtime_t *runtime,
    const gmv_dialog_command_t *command) {
    if (!runtime || !command ||
        command->operation_id == 0 ||
        !command->call_id[0] ||
        !runtime->started) {
        return PJ_EINVAL;
    }
    gmv_invite_call_t *call =
        gmv_find_invite_call(runtime, command->call_id);
    if (!call || !call->invite) {
        return PJ_ENOTFOUND;
    }

    if (command->method == GMV_SIP_DIALOG_BYE) {
        if (call->dialog_operation_id != 0) {
            return PJ_EBUSY;
        }
        call->dialog_operation_id = command->operation_id;
        pjsip_tx_data *tdata = NULL;
        pj_status_t status = pjsip_inv_end_session(
            call->invite,
            PJSIP_SC_OK,
            NULL,
            &tdata);
        if (status == PJ_SUCCESS && tdata) {
            status = pjsip_inv_send_msg(call->invite, tdata);
        }
        if (status != PJ_SUCCESS) {
            call->dialog_operation_id = 0;
        }
        return status;
    }

    if (command->method != GMV_SIP_DIALOG_INFO ||
        !command->content_type[0] ||
        !command->body ||
        command->body_len == 0) {
        return PJ_EINVAL;
    }
    const char *slash = strchr(command->content_type, '/');
    size_t content_type_len = strlen(command->content_type);
    if (!slash || slash == command->content_type ||
        slash == command->content_type + content_type_len - 1) {
        return PJ_EINVAL;
    }

    pjsip_method method;
    pj_str_t method_name = pj_str("INFO");
    pjsip_method_init_np(&method, &method_name);
    pjsip_tx_data *tdata = NULL;
    pj_status_t status = pjsip_dlg_create_request(
        call->invite->dlg,
        &method,
        -1,
        &tdata);
    if (status != PJ_SUCCESS) {
        return status;
    }
    pj_str_t type = {
        (char *)command->content_type,
        (pj_ssize_t)(slash - command->content_type)
    };
    pj_str_t subtype = {
        (char *)(slash + 1),
        (pj_ssize_t)(
            content_type_len -
            (size_t)(slash - command->content_type) - 1u)
    };
    pj_str_t body = {
        (char *)command->body,
        (pj_ssize_t)command->body_len
    };
    tdata->msg->body = pjsip_msg_body_create(
        tdata->pool,
        &type,
        &subtype,
        &body);
    if (!tdata->msg->body) {
        pjsip_tx_data_dec_ref(tdata);
        return PJ_ENOMEM;
    }

    gmv_dialog_operation_t *operation =
        (gmv_dialog_operation_t *)calloc(1, sizeof(*operation));
    if (!operation) {
        pjsip_tx_data_dec_ref(tdata);
        return PJ_ENOMEM;
    }
    operation->runtime = runtime;
    operation->operation_id = command->operation_id;
    status = pjsip_dlg_send_request(
        call->invite->dlg,
        tdata,
        runtime->module.id,
        operation);
    if (status != PJ_SUCCESS) {
        free(operation);
    }
    return status;
}

static pj_status_t gmv_respond_invite_on_owner(
    gmv_sip_runtime_t *runtime,
    const gmv_invite_response_command_t *command) {
    if (!runtime || !command ||
        command->status_code < 300 ||
        command->status_code > 699 ||
        !command->call_id[0] ||
        !runtime->started) {
        return PJ_EINVAL;
    }
    gmv_invite_call_t *call =
        gmv_find_invite_call(runtime, command->call_id);
    if (!call || !call->invite || call->operation_id != 0) {
        return PJ_ENOTFOUND;
    }

    pj_str_t reason = pj_str((char *)command->reason);
    pjsip_tx_data *tdata = NULL;
    pj_status_t status = pjsip_inv_answer(
        call->invite,
        command->status_code,
        command->reason[0] ? &reason : NULL,
        NULL,
        &tdata);
    if (status == PJ_SUCCESS) {
        status = pjsip_inv_send_msg(call->invite, tdata);
    }
    return status;
}

static gmv_subscription_call_t *gmv_find_subscription(
    gmv_sip_runtime_t *runtime,
    const char *call_id) {
    if (!runtime || !call_id || !*call_id) {
        return NULL;
    }
    gmv_subscription_call_t *call = runtime->subscriptions;
    while (call) {
        if (strcmp(call->call_id, call_id) == 0) {
            return call;
        }
        call = call->next;
    }
    return NULL;
}

static pj_status_t gmv_replace_subscription_body(
    gmv_subscription_call_t *call,
    const gmv_subscribe_command_t *command) {
    unsigned char *body = NULL;
    if (command->body_len > 0) {
        body = (unsigned char *)malloc(command->body_len);
        if (!body) {
            return PJ_ENOMEM;
        }
        memcpy(body, command->body, command->body_len);
    }
    free(call->body);
    call->body = body;
    call->body_len = command->body_len;
    memcpy(
        call->content_type,
        command->content_type,
        sizeof(call->content_type));
    call->expires = command->expires;
    return PJ_SUCCESS;
}

static pj_status_t gmv_send_subscribe_on_owner(
    gmv_sip_runtime_t *runtime,
    const gmv_subscribe_command_t *command) {
    if (!runtime || !command ||
        command->operation_id == 0 ||
        !command->event[0] ||
        !runtime->started ||
        !runtime->endpoint) {
        return PJ_EINVAL;
    }

    if (command->call_id[0]) {
        gmv_subscription_call_t *call =
            gmv_find_subscription(runtime, command->call_id);
        if (!call || !call->subscription) {
            return PJ_ENOTFOUND;
        }
        if (call->operation_id != 0 ||
            strcmp(call->event, command->event) != 0) {
            return PJ_EBUSY;
        }
        pj_status_t status =
            gmv_replace_subscription_body(call, command);
        if (status != PJ_SUCCESS) {
            return status;
        }
        call->operation_id = command->operation_id;
        status = gmv_start_subscription_request(
            call,
            command->expires);
        if (status != PJ_SUCCESS) {
            call->operation_id = 0;
        }
        return status;
    }

    if (!command->target_uri[0] ||
        !command->from_uri[0] ||
        !command->contact_uri[0] ||
        command->expires == 0) {
        return PJ_EINVAL;
    }
    gmv_custom_transport_t *transport = gmv_find_transport(
        runtime,
        command->transport,
        command->association_id);
    if (!transport) {
        return PJSIP_EUNSUPTRANSPORT;
    }

    pj_str_t target = pj_str((char *)command->target_uri);
    pj_str_t from = pj_str((char *)command->from_uri);
    pj_str_t contact = pj_str((char *)command->contact_uri);
    pjsip_dialog *dialog = NULL;
    pj_status_t status = pjsip_dlg_create_uac(
        pjsip_ua_instance(),
        &from,
        &contact,
        &target,
        &target,
        &dialog);
    if (status != PJ_SUCCESS) {
        return status;
    }

    pj_str_t event = pj_str((char *)command->event);
    pjsip_evsub *subscription = NULL;
    status = pjsip_evsub_create_uac(
        dialog,
        &gmv_subscription_callbacks,
        &event,
        PJSIP_EVSUB_NO_EVENT_ID,
        &subscription);
    if (status != PJ_SUCCESS) {
        pjsip_dlg_terminate(dialog);
        return status;
    }

    pjsip_tpselector selector;
    memset(&selector, 0, sizeof(selector));
    selector.type = PJSIP_TPSELECTOR_TRANSPORT;
    selector.u.transport = &transport->base;
    status = pjsip_dlg_set_transport(dialog, &selector);
    if (status != PJ_SUCCESS) {
        pjsip_evsub_terminate(subscription, PJ_FALSE);
        return status;
    }

    gmv_subscription_call_t *call =
        (gmv_subscription_call_t *)calloc(1, sizeof(*call));
    if (!call) {
        pjsip_evsub_terminate(subscription, PJ_FALSE);
        return PJ_ENOMEM;
    }
    call->runtime = runtime;
    call->operation_id = command->operation_id;
    call->transport = command->transport;
    call->association_id = command->association_id;
    call->subscription = subscription;
    if (!gmv_copy_view(
            call->call_id,
            sizeof(call->call_id),
            gmv_string_view(&dialog->call_id->id)) ||
        !gmv_copy_view(
            call->event,
            sizeof(call->event),
            gmv_c_string_view(command->event))) {
        free(call);
        pjsip_evsub_terminate(subscription, PJ_FALSE);
        return PJ_ETOOSMALL;
    }
    status = gmv_replace_subscription_body(call, command);
    if (status != PJ_SUCCESS) {
        free(call);
        pjsip_evsub_terminate(subscription, PJ_FALSE);
        return status;
    }

    pjsip_evsub_set_mod_data(
        subscription,
        (unsigned)runtime->module.id,
        call);
    call->next = runtime->subscriptions;
    runtime->subscriptions = call;
    status = gmv_start_subscription_request(
        call,
        command->expires);
    if (status != PJ_SUCCESS) {
        pjsip_evsub_set_mod_data(
            subscription,
            (unsigned)runtime->module.id,
            NULL);
        call->subscription = NULL;
        gmv_remove_subscription(runtime, call);
        pjsip_evsub_terminate(subscription, PJ_FALSE);
    }
    return status;
}

int32_t gmv_sip_runtime_send_message(
    gmv_sip_runtime_t *runtime,
    const gmv_sip_outbound_message_t *message) {
    if (!runtime || !message ||
        message->size < sizeof(*message) ||
        message->version != GMV_SIP_ABI_VERSION ||
        message->operation_id == 0 ||
        (message->transport != GMV_SIP_TRANSPORT_UDP &&
         message->transport != GMV_SIP_TRANSPORT_TCP) ||
        (message->transport == GMV_SIP_TRANSPORT_TCP &&
         message->association_id == 0) ||
        !message->target_uri.ptr || message->target_uri.len == 0 ||
        !message->from_uri.ptr || message->from_uri.len == 0 ||
        !message->content_type.ptr || message->content_type.len == 0 ||
        (message->body.len > 0 && !message->body.ptr) ||
        !runtime->started || !runtime->command_mutex) {
        return PJ_EINVAL;
    }

    gmv_message_command_t *command =
        (gmv_message_command_t *)calloc(1, sizeof(*command));
    if (!command) {
        return PJ_ENOMEM;
    }
    command->operation_id = message->operation_id;
    command->association_id = message->association_id;
    command->transport = message->transport;
    if (!gmv_copy_view(
            command->target_uri,
            sizeof(command->target_uri),
            message->target_uri) ||
        !gmv_copy_view(
            command->from_uri,
            sizeof(command->from_uri),
            message->from_uri) ||
        !gmv_copy_view(
            command->content_type,
            sizeof(command->content_type),
            message->content_type)) {
        gmv_free_message_command(command);
        return PJ_ETOOSMALL;
    }
    if (message->body.len > 0) {
        command->body =
            (unsigned char *)malloc(message->body.len);
        if (!command->body) {
            gmv_free_message_command(command);
            return PJ_ENOMEM;
        }
        memcpy(
            command->body,
            message->body.ptr,
            message->body.len);
        command->body_len = message->body.len;
    }

    pj_mutex_lock(runtime->command_mutex);
    if (runtime->message_tail) {
        runtime->message_tail->next = command;
    } else {
        runtime->message_head = command;
    }
    runtime->message_tail = command;
    pj_mutex_unlock(runtime->command_mutex);
    return PJ_SUCCESS;
}

int32_t gmv_sip_runtime_send_invite(
    gmv_sip_runtime_t *runtime,
    const gmv_sip_outbound_invite_t *invite) {
    if (!runtime || !invite ||
        invite->size < sizeof(*invite) ||
        invite->version != GMV_SIP_ABI_VERSION ||
        invite->operation_id == 0 ||
        (invite->transport != GMV_SIP_TRANSPORT_UDP &&
         invite->transport != GMV_SIP_TRANSPORT_TCP) ||
        (invite->transport == GMV_SIP_TRANSPORT_TCP &&
         invite->association_id == 0) ||
        !invite->target_uri.ptr || invite->target_uri.len == 0 ||
        !invite->to_uri.ptr || invite->to_uri.len == 0 ||
        !invite->from_uri.ptr || invite->from_uri.len == 0 ||
        !invite->contact_uri.ptr || invite->contact_uri.len == 0 ||
        !invite->sdp.ptr || invite->sdp.len == 0 ||
        invite->sdp.len > PJSIP_MAX_PKT_LEN ||
        !runtime->started || !runtime->command_mutex) {
        return PJ_EINVAL;
    }

    gmv_invite_command_t *command =
        (gmv_invite_command_t *)calloc(1, sizeof(*command));
    if (!command) {
        return PJ_ENOMEM;
    }
    command->operation_id = invite->operation_id;
    command->association_id = invite->association_id;
    command->transport = invite->transport;
    if (!gmv_copy_view(
            command->target_uri,
            sizeof(command->target_uri),
            invite->target_uri) ||
        !gmv_copy_view(
            command->to_uri,
            sizeof(command->to_uri),
            invite->to_uri) ||
        !gmv_copy_view(
            command->from_uri,
            sizeof(command->from_uri),
            invite->from_uri) ||
        !gmv_copy_view(
            command->contact_uri,
            sizeof(command->contact_uri),
            invite->contact_uri) ||
        !gmv_copy_view(
            command->subject,
            sizeof(command->subject),
            invite->subject)) {
        gmv_free_invite_command(command);
        return PJ_ETOOSMALL;
    }
    command->sdp = (char *)malloc(invite->sdp.len + 1u);
    if (!command->sdp) {
        gmv_free_invite_command(command);
        return PJ_ENOMEM;
    }
    memcpy(command->sdp, invite->sdp.ptr, invite->sdp.len);
    command->sdp[invite->sdp.len] = '\0';
    command->sdp_len = invite->sdp.len;

    pj_mutex_lock(runtime->command_mutex);
    if (runtime->invite_tail) {
        runtime->invite_tail->next = command;
    } else {
        runtime->invite_head = command;
    }
    runtime->invite_tail = command;
    pj_mutex_unlock(runtime->command_mutex);
    return PJ_SUCCESS;
}

int32_t gmv_sip_runtime_send_dialog_request(
    gmv_sip_runtime_t *runtime,
    const gmv_sip_dialog_request_t *request) {
    if (!runtime || !request ||
        request->size < sizeof(*request) ||
        request->version != GMV_SIP_ABI_VERSION ||
        request->operation_id == 0 ||
        (request->method != GMV_SIP_DIALOG_BYE &&
         request->method != GMV_SIP_DIALOG_INFO) ||
        !request->call_id.ptr || request->call_id.len == 0 ||
        (request->method == GMV_SIP_DIALOG_INFO &&
         (!request->content_type.ptr ||
          request->content_type.len == 0 ||
          !request->body.ptr ||
          request->body.len == 0)) ||
        request->body.len > PJSIP_MAX_PKT_LEN ||
        !runtime->started || !runtime->command_mutex) {
        return PJ_EINVAL;
    }

    gmv_dialog_command_t *command =
        (gmv_dialog_command_t *)calloc(1, sizeof(*command));
    if (!command) {
        return PJ_ENOMEM;
    }
    command->operation_id = request->operation_id;
    command->method = request->method;
    if (!gmv_copy_view(
            command->call_id,
            sizeof(command->call_id),
            request->call_id) ||
        !gmv_copy_view(
            command->content_type,
            sizeof(command->content_type),
            request->content_type)) {
        gmv_free_dialog_command(command);
        return PJ_ETOOSMALL;
    }
    if (request->body.len > 0) {
        command->body =
            (unsigned char *)malloc(request->body.len);
        if (!command->body) {
            gmv_free_dialog_command(command);
            return PJ_ENOMEM;
        }
        memcpy(
            command->body,
            request->body.ptr,
            request->body.len);
        command->body_len = request->body.len;
    }

    pj_mutex_lock(runtime->command_mutex);
    if (runtime->dialog_tail) {
        runtime->dialog_tail->next = command;
    } else {
        runtime->dialog_head = command;
    }
    runtime->dialog_tail = command;
    pj_mutex_unlock(runtime->command_mutex);
    return PJ_SUCCESS;
}

int32_t gmv_sip_runtime_respond_invite(
    gmv_sip_runtime_t *runtime,
    const gmv_sip_invite_response_t *response) {
    if (!runtime || !response ||
        response->size < sizeof(*response) ||
        response->version != GMV_SIP_ABI_VERSION ||
        response->status_code < 300 ||
        response->status_code > 699 ||
        !response->call_id.ptr ||
        response->call_id.len == 0 ||
        !runtime->started ||
        !runtime->command_mutex) {
        return PJ_EINVAL;
    }

    gmv_invite_response_command_t *command =
        (gmv_invite_response_command_t *)calloc(
            1,
            sizeof(*command));
    if (!command) {
        return PJ_ENOMEM;
    }
    command->status_code = response->status_code;
    if (!gmv_copy_view(
            command->call_id,
            sizeof(command->call_id),
            response->call_id) ||
        !gmv_copy_view(
            command->reason,
            sizeof(command->reason),
            response->reason)) {
        gmv_free_invite_response_command(command);
        return PJ_ETOOSMALL;
    }

    pj_mutex_lock(runtime->command_mutex);
    if (runtime->invite_response_tail) {
        runtime->invite_response_tail->next = command;
    } else {
        runtime->invite_response_head = command;
    }
    runtime->invite_response_tail = command;
    pj_mutex_unlock(runtime->command_mutex);
    return PJ_SUCCESS;
}

int32_t gmv_sip_runtime_send_subscribe(
    gmv_sip_runtime_t *runtime,
    const gmv_sip_outbound_subscribe_t *subscribe) {
    if (!runtime || !subscribe ||
        subscribe->size < sizeof(*subscribe) ||
        subscribe->version != GMV_SIP_ABI_VERSION ||
        subscribe->operation_id == 0 ||
        (subscribe->transport != GMV_SIP_TRANSPORT_UDP &&
         subscribe->transport != GMV_SIP_TRANSPORT_TCP) ||
        (subscribe->transport == GMV_SIP_TRANSPORT_TCP &&
         subscribe->association_id == 0) ||
        !subscribe->event.ptr || subscribe->event.len == 0 ||
        (subscribe->call_id.len == 0 &&
         (!subscribe->target_uri.ptr ||
          subscribe->target_uri.len == 0 ||
          !subscribe->from_uri.ptr ||
          subscribe->from_uri.len == 0 ||
          !subscribe->contact_uri.ptr ||
          subscribe->contact_uri.len == 0 ||
          subscribe->expires == 0)) ||
        (subscribe->body.len > 0 &&
         (!subscribe->body.ptr ||
          !subscribe->content_type.ptr ||
          subscribe->content_type.len == 0)) ||
        subscribe->body.len > PJSIP_MAX_PKT_LEN ||
        !runtime->started || !runtime->command_mutex) {
        return PJ_EINVAL;
    }

    gmv_subscribe_command_t *command =
        (gmv_subscribe_command_t *)calloc(1, sizeof(*command));
    if (!command) {
        return PJ_ENOMEM;
    }
    command->operation_id = subscribe->operation_id;
    command->association_id = subscribe->association_id;
    command->transport = subscribe->transport;
    command->expires = subscribe->expires;
    if (!gmv_copy_view(
            command->target_uri,
            sizeof(command->target_uri),
            subscribe->target_uri) ||
        !gmv_copy_view(
            command->from_uri,
            sizeof(command->from_uri),
            subscribe->from_uri) ||
        !gmv_copy_view(
            command->contact_uri,
            sizeof(command->contact_uri),
            subscribe->contact_uri) ||
        !gmv_copy_view(
            command->call_id,
            sizeof(command->call_id),
            subscribe->call_id) ||
        !gmv_copy_view(
            command->event,
            sizeof(command->event),
            subscribe->event) ||
        !gmv_copy_view(
            command->content_type,
            sizeof(command->content_type),
            subscribe->content_type)) {
        gmv_free_subscribe_command(command);
        return PJ_ETOOSMALL;
    }
    if (subscribe->body.len > 0) {
        command->body =
            (unsigned char *)malloc(subscribe->body.len);
        if (!command->body) {
            gmv_free_subscribe_command(command);
            return PJ_ENOMEM;
        }
        memcpy(
            command->body,
            subscribe->body.ptr,
            subscribe->body.len);
        command->body_len = subscribe->body.len;
    }

    pj_mutex_lock(runtime->command_mutex);
    if (runtime->subscribe_tail) {
        runtime->subscribe_tail->next = command;
    } else {
        runtime->subscribe_head = command;
    }
    runtime->subscribe_tail = command;
    pj_mutex_unlock(runtime->command_mutex);
    return PJ_SUCCESS;
}

int32_t gmv_sip_runtime_receive_packet(
    gmv_sip_runtime_t *runtime,
    const gmv_sip_received_packet_t *packet) {
    if (!runtime || !packet ||
        packet->size < sizeof(*packet) ||
        packet->version != GMV_SIP_ABI_VERSION ||
        !runtime->started ||
        !runtime->command_mutex ||
        !packet->data.ptr ||
        packet->data.len == 0 ||
        packet->data.len > PJSIP_MAX_PKT_LEN ||
        (packet->transport != GMV_SIP_TRANSPORT_UDP &&
         packet->transport != GMV_SIP_TRANSPORT_TCP) ||
        (packet->transport == GMV_SIP_TRANSPORT_TCP &&
         packet->association_id == 0)) {
        return PJ_EINVAL;
    }

    gmv_receive_command_t *command =
        (gmv_receive_command_t *)calloc(1, sizeof(*command));
    if (!command) {
        return PJ_ENOMEM;
    }
    command->association_id = packet->association_id;
    command->transport = packet->transport;
    command->local_port = packet->local_port;
    command->remote_port = packet->remote_port;
    if (!gmv_copy_view(
            command->local_address,
            sizeof(command->local_address),
            packet->local_address) ||
        !gmv_copy_view(
            command->remote_address,
            sizeof(command->remote_address),
            packet->remote_address) ||
        !command->local_address[0] ||
        !command->remote_address[0]) {
        free(command);
        return PJ_EINVAL;
    }
    command->data = (unsigned char *)malloc(packet->data.len);
    if (!command->data) {
        free(command);
        return PJ_ENOMEM;
    }
    memcpy(command->data, packet->data.ptr, packet->data.len);
    command->data_len = packet->data.len;

    pj_mutex_lock(runtime->command_mutex);
    if (runtime->receive_tail) {
        runtime->receive_tail->next = command;
    } else {
        runtime->receive_head = command;
    }
    runtime->receive_tail = command;
    pj_mutex_unlock(runtime->command_mutex);
    return PJ_SUCCESS;
}

int32_t gmv_sip_runtime_complete_send(
    gmv_sip_runtime_t *runtime,
    const gmv_sip_send_completion_t *completion) {
    if (!runtime || !completion ||
        completion->size < sizeof(*completion) ||
        completion->version != GMV_SIP_ABI_VERSION ||
        completion->send_id == 0 ||
        !runtime->started ||
        !runtime->command_mutex) {
        return PJ_EINVAL;
    }

    gmv_send_completion_command_t *command =
        (gmv_send_completion_command_t *)calloc(1, sizeof(*command));
    if (!command) {
        return PJ_ENOMEM;
    }
    command->send_id = completion->send_id;
    command->sent_bytes = completion->sent_bytes;

    pj_mutex_lock(runtime->command_mutex);
    if (runtime->completion_tail) {
        runtime->completion_tail->next = command;
    } else {
        runtime->completion_head = command;
    }
    runtime->completion_tail = command;
    pj_mutex_unlock(runtime->command_mutex);
    return PJ_SUCCESS;
}

int32_t gmv_sip_runtime_close_transport(
    gmv_sip_runtime_t *runtime,
    uint64_t association_id,
    int32_t transport,
    int32_t status) {
    if (!runtime ||
        !runtime->started ||
        !runtime->command_mutex ||
        association_id == 0 ||
        transport != GMV_SIP_TRANSPORT_TCP) {
        return PJ_EINVAL;
    }
    gmv_close_command_t *command =
        (gmv_close_command_t *)calloc(1, sizeof(*command));
    if (!command) {
        return PJ_ENOMEM;
    }
    command->association_id = association_id;
    command->transport = transport;
    command->status =
        status == PJ_SUCCESS ? PJSIP_ESHUTDOWN : status;

    pj_mutex_lock(runtime->command_mutex);
    if (runtime->close_tail) {
        runtime->close_tail->next = command;
    } else {
        runtime->close_head = command;
    }
    runtime->close_tail = command;
    pj_mutex_unlock(runtime->command_mutex);
    return PJ_SUCCESS;
}

void gmv_sip_runtime_destroy(gmv_sip_runtime_t *runtime) {
    if (!runtime) {
        return;
    }
    gmv_runtime_release(runtime);
    free(runtime);
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
