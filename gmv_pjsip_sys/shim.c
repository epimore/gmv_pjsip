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
#define GMV_SIP_DEFAULT_USER_AGENT "GMV-PJSIP/0.1"
#define GMV_SIP_DEFAULT_POLL_TIMEOUT_MS 10u
#define GMV_SIP_DEFAULT_AUTH_LOOKUP_TIMEOUT_MS 3000u
#define GMV_SIP_DEFAULT_MAX_PENDING_AUTH 20000u
#define GMV_SIP_NONCE_TTL_MS 300000u
#define GMV_SIP_BIND_ADDRESS_CAPACITY 64u
#define GMV_SIP_ADDRESS_CAPACITY (PJ_INET6_ADDRSTRLEN + 16u)
#define GMV_SIP_CONTENT_TYPE_CAPACITY 128u
#define GMV_SIP_CONTACT_CAPACITY 512u
#define GMV_SIP_AUTH_REALM_CAPACITY 128u
#define GMV_SIP_USER_AGENT_CAPACITY 256u
#define GMV_SIP_DEVICE_ID_CAPACITY 128u
#define GMV_SIP_AUTH_SECRET_CAPACITY 512u
#define GMV_SIP_NONCE_CAPACITY 33u
#define GMV_SIP_CALL_ID_CAPACITY 256u
#define GMV_SIP_REASON_CAPACITY 128u
#define GMV_SIP_SUBJECT_CAPACITY 512u
#define GMV_SIP_URI_CAPACITY 1024u
#define GMV_SIP_TAG_CAPACITY 256u
#define GMV_SIP_ROUTE_SET_CAPACITY 4096u
#define GMV_SIP_CONFIG_HAS(config, field) \
    ((config)->size >= \
     offsetof(gmv_sip_runtime_config_t, field) + sizeof((config)->field))
#define GMV_SIP_DUPLICATE_REQUEST_TTL_MS 5000u
#define GMV_SIP_DUPLICATE_REQUEST_MAX 512u
#define GMV_SIP_DUPLICATE_KEY_CAPACITY 768u

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

typedef struct gmv_recent_request {
    char key[GMV_SIP_DUPLICATE_KEY_CAPACITY];
    uint64_t expires_at_ms;
    struct gmv_recent_request *next;
} gmv_recent_request_t;

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

typedef struct gmv_registered_source {
    int32_t transport;
    char device_id[GMV_SIP_DEVICE_ID_CAPACITY];
    char remote_address[GMV_SIP_BIND_ADDRESS_CAPACITY];
    uint64_t generation;
    uint64_t recovery_expires_at_ms;
    struct gmv_registered_source *next;
} gmv_registered_source_t;

typedef struct gmv_register_order {
    char device_id[GMV_SIP_DEVICE_ID_CAPACITY];
    char call_id[GMV_SIP_CALL_ID_CAPACITY];
    uint32_t cseq;
    struct gmv_register_order *next;
} gmv_register_order_t;

typedef struct gmv_incoming_invite_allow {
    int32_t transport;
    char target_id[GMV_SIP_DEVICE_ID_CAPACITY];
    char source_id[GMV_SIP_DEVICE_ID_CAPACITY];
    char remote_address[GMV_SIP_BIND_ADDRESS_CAPACITY];
    uint64_t expires_at_ms;
    struct gmv_incoming_invite_allow *next;
} gmv_incoming_invite_allow_t;

typedef struct gmv_outbound_operation {
    gmv_sip_runtime_t *runtime;
    uint64_t operation_id;
    int final_response_emitted;
} gmv_outbound_operation_t;

typedef struct gmv_dialog_operation {
    gmv_sip_runtime_t *runtime;
    uint64_t operation_id;
    pjsip_dialog *restored_dialog;
    int restored_session_held;
    struct gmv_invite_call *restored_call;
    unsigned active_calls;
    int cleanup_pending;
} gmv_dialog_operation_t;

#include "shim_commands.inc"

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
    int has_dialog_route;
    pj_sockaddr dialog_route_addr;
    unsigned active_calls;
    int cleanup_pending;
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
    unsigned active_calls;
    int cleanup_pending;
    struct gmv_subscription_call *next;
};

struct gmv_sip_runtime {
    char advertised_address[GMV_SIP_BIND_ADDRESS_CAPACITY];
    char auth_realm[GMV_SIP_AUTH_REALM_CAPACITY];
    char user_agent[GMV_SIP_USER_AGENT_CAPACITY];
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
    gmv_recent_request_t *recent_requests;
    uint32_t recent_request_count;
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
    gmv_registered_source_t *registered_sources;
    gmv_register_order_t *register_orders;
    gmv_incoming_invite_allow_t *incoming_invite_allows;
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
static int32_t gmv_transport_type(const pjsip_transport *transport);
static gmv_invite_call_t *gmv_find_invite_call(
    gmv_sip_runtime_t *runtime,
    const char *call_id);
static void gmv_invite_call_save_dialog_route(
    gmv_invite_call_t *call,
    const pjsip_rx_data *rdata);

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

static uint64_t gmv_monotonic_ms(void) {
    pj_time_val now;
    if (pj_gettickcount(&now) != PJ_SUCCESS) {
        return gmv_now_ms();
    }
    return ((uint64_t)now.sec * 1000u) + (uint64_t)now.msec;
}

static pj_str_t gmv_empty_pj_str(void) {
    return pj_str("");
}

static pj_str_t gmv_sip_uri_user(pjsip_uri *uri) {
    if (!uri) {
        return gmv_empty_pj_str();
    }
    uri = pjsip_uri_get_uri(uri);
    if (!uri || !PJSIP_URI_SCHEME_IS_SIP(uri)) {
        return gmv_empty_pj_str();
    }
    return ((pjsip_sip_uri *)uri)->user;
}

static pj_str_t gmv_from_user(const pjsip_rx_data *rdata) {
    if (!rdata || !rdata->msg_info.from || !rdata->msg_info.from->uri) {
        return gmv_empty_pj_str();
    }
    return gmv_sip_uri_user(rdata->msg_info.from->uri);
}

static pj_str_t gmv_to_user(const pjsip_rx_data *rdata) {
    if (!rdata || !rdata->msg_info.to || !rdata->msg_info.to->uri) {
        return gmv_empty_pj_str();
    }
    return gmv_sip_uri_user(rdata->msg_info.to->uri);
}

static int gmv_pj_str_equals_c(const pj_str_t *value, const char *expected) {
    size_t expected_len = expected ? strlen(expected) : 0;
    return value && value->ptr && value->slen >= 0 &&
        (size_t)value->slen == expected_len &&
        memcmp(value->ptr, expected, expected_len) == 0;
}

static int gmv_subject_contains_target(
    const pjsip_rx_data *rdata,
    const char *target_id) {
    if (!rdata || !rdata->msg_info.msg || !target_id || !*target_id) {
        return 0;
    }
    pj_str_t subject_name = pj_str("Subject");
    pjsip_generic_string_hdr *subject =
        (pjsip_generic_string_hdr *)pjsip_msg_find_hdr_by_name(
            rdata->msg_info.msg,
            &subject_name,
            NULL);
    if (!subject || !subject->hvalue.ptr || subject->hvalue.slen <= 0) {
        return 0;
    }
    size_t target_len = strlen(target_id);
    if ((size_t)subject->hvalue.slen < target_len) {
        return 0;
    }
    for (pj_ssize_t offset = 0;
         offset <= subject->hvalue.slen - (pj_ssize_t)target_len;
         ++offset) {
        if (memcmp(subject->hvalue.ptr + offset, target_id, target_len) == 0) {
            return 1;
        }
    }
    return 0;
}

static int gmv_transport_and_source_match(
    int32_t expected_transport,
    const char *expected_address,
    int32_t actual_transport,
    const char *actual_address) {
    return expected_transport == actual_transport &&
        expected_address && actual_address &&
        strcmp(expected_address, actual_address) == 0;
}

static void gmv_remove_register_order(
    gmv_sip_runtime_t *runtime,
    const char *device_id) {
    if (!runtime || !device_id) {
        return;
    }
    gmv_register_order_t **cursor = &runtime->register_orders;
    while (*cursor) {
        gmv_register_order_t *order = *cursor;
        if (strcmp(order->device_id, device_id) == 0) {
            *cursor = order->next;
            free(order);
            return;
        }
        cursor = &order->next;
    }
}

static void gmv_sync_register_order(
    gmv_sip_runtime_t *runtime,
    const char *device_id,
    gmv_sip_string_view_t call_id,
    uint32_t cseq) {
    if (!runtime || !device_id || !call_id.ptr || call_id.len == 0 || cseq == 0) {
        return;
    }
    gmv_register_order_t *order = runtime->register_orders;
    while (order && strcmp(order->device_id, device_id) != 0) {
        order = order->next;
    }
    if (!order) {
        order = (gmv_register_order_t *)calloc(1, sizeof(*order));
        if (!order) {
            return;
        }
        pj_ansi_strxcpy(order->device_id, device_id, sizeof(order->device_id));
        order->next = runtime->register_orders;
        runtime->register_orders = order;
    }
    if (!gmv_copy_view(order->call_id, sizeof(order->call_id), call_id)) {
        return;
    }
    order->cseq = cseq;
}

static void gmv_cleanup_recovery_sources(
    gmv_sip_runtime_t *runtime,
    uint64_t now) {
    if (!runtime) {
        return;
    }
    gmv_registered_source_t **cursor = &runtime->registered_sources;
    while (*cursor) {
        gmv_registered_source_t *source = *cursor;
        if (source->recovery_expires_at_ms > 0 &&
            source->recovery_expires_at_ms <= now) {
            *cursor = source->next;
            gmv_remove_register_order(runtime, source->device_id);
            free(source);
            continue;
        }
        cursor = &source->next;
    }
}

static int gmv_registered_source_allowed(
    gmv_sip_runtime_t *runtime,
    int32_t transport,
    const char *remote_address,
    const pj_str_t *device_id,
    int allow_recovery) {
    if (!device_id || !device_id->ptr || device_id->slen <= 0) {
        return 0;
    }
    gmv_cleanup_recovery_sources(runtime, gmv_monotonic_ms());
    gmv_registered_source_t *source =
        runtime ? runtime->registered_sources : NULL;
    while (source) {
        if (gmv_pj_str_equals_c(device_id, source->device_id) &&
            (source->recovery_expires_at_ms == 0 || allow_recovery) &&
            gmv_transport_and_source_match(
                source->transport,
                source->remote_address,
                transport,
                remote_address)) {
            return 1;
        }
        source = source->next;
    }
    return 0;
}

static void gmv_cleanup_incoming_invite_allows(
    gmv_sip_runtime_t *runtime,
    uint64_t now) {
    if (!runtime) {
        return;
    }
    gmv_incoming_invite_allow_t **cursor = &runtime->incoming_invite_allows;
    while (*cursor) {
        gmv_incoming_invite_allow_t *allow = *cursor;
        if (allow->expires_at_ms <= now) {
            *cursor = allow->next;
            free(allow);
            continue;
        }
        cursor = &allow->next;
    }
}

static int gmv_consume_incoming_invite_allow(
    gmv_sip_runtime_t *runtime,
    pjsip_rx_data *rdata) {
    if (!runtime || !rdata) {
        return 0;
    }
    uint64_t now = gmv_now_ms();
    gmv_cleanup_incoming_invite_allows(runtime, now);
    int32_t transport = gmv_transport_type(rdata->tp_info.transport);
    pj_str_t from_user = gmv_from_user(rdata);
    pj_str_t to_user = gmv_to_user(rdata);

    gmv_incoming_invite_allow_t **cursor = &runtime->incoming_invite_allows;
    while (*cursor) {
        gmv_incoming_invite_allow_t *allow = *cursor;
        int source_matches = gmv_pj_str_equals_c(&to_user, allow->source_id);
        int target_matches =
            gmv_pj_str_equals_c(&from_user, allow->target_id) ||
            gmv_subject_contains_target(rdata, allow->target_id);
        if (source_matches && target_matches &&
            gmv_transport_and_source_match(
                allow->transport,
                allow->remote_address,
                transport,
                rdata->pkt_info.src_name)) {
            *cursor = allow->next;
            free(allow);
            return 1;
        }
        cursor = &allow->next;
    }
    return 0;
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

#include "shim_transport.inc"

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

static pj_status_t gmv_set_user_agent(pjsip_tx_data *tdata) {
    gmv_sip_runtime_t *runtime = g_active_runtime;
    if (!runtime || !tdata || !tdata->msg) {
        return PJ_SUCCESS;
    }

    pj_str_t name = pj_str("User-Agent");
    pjsip_hdr *header = NULL;
    while ((header = pjsip_msg_find_hdr_by_name(tdata->msg, &name, NULL)) != NULL) {
        pj_list_erase(header);
    }
    gmv_add_string_header(tdata, "User-Agent", runtime->user_agent);
    return PJ_SUCCESS;
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
    uint64_t operation_id,
    const pjsip_dialog *dialog) {
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
    char dialog_local_uri[GMV_SIP_URI_CAPACITY];
    char dialog_remote_uri[GMV_SIP_URI_CAPACITY];
    char dialog_remote_target[GMV_SIP_URI_CAPACITY];
    char dialog_route_set[GMV_SIP_ROUTE_SET_CAPACITY];
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
    memset(dialog_local_uri, 0, sizeof(dialog_local_uri));
    memset(dialog_remote_uri, 0, sizeof(dialog_remote_uri));
    memset(dialog_remote_target, 0, sizeof(dialog_remote_target));
    memset(dialog_route_set, 0, sizeof(dialog_route_set));
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

    if (dialog && dialog->call_id && dialog->local.info &&
        dialog->remote.info && dialog->target &&
        dialog->local.cseq > 0 &&
        dialog->local.info->tag.slen > 0 &&
        dialog->remote.info->tag.slen > 0) {
        int local_len = pjsip_uri_print(
            PJSIP_URI_IN_FROMTO_HDR,
            dialog->local.info->uri,
            dialog_local_uri,
            sizeof(dialog_local_uri));
        int remote_len = pjsip_uri_print(
            PJSIP_URI_IN_FROMTO_HDR,
            dialog->remote.info->uri,
            dialog_remote_uri,
            sizeof(dialog_remote_uri));
        int target_len = pjsip_uri_print(
            PJSIP_URI_IN_REQ_URI,
            dialog->target,
            dialog_remote_target,
            sizeof(dialog_remote_target));
        if (local_len > 0 && remote_len > 0 && target_len > 0) {
            event.dialog_local_cseq = (uint32_t)(dialog->local.cseq - 1);
            event.dialog_local_uri = gmv_bytes_view(dialog_local_uri, (size_t)local_len);
            event.dialog_remote_uri = gmv_bytes_view(dialog_remote_uri, (size_t)remote_len);
            event.dialog_local_tag = gmv_string_view(&dialog->local.info->tag);
            event.dialog_remote_tag = gmv_string_view(&dialog->remote.info->tag);
            event.dialog_remote_target =
                gmv_bytes_view(dialog_remote_target, (size_t)target_len);
            size_t route_len = 0;
            const pjsip_route_hdr *route = dialog->route_set.next;
            while (route != &dialog->route_set) {
                if (route_len > 0) {
                    dialog_route_set[route_len++] = '\n';
                }
                int written = pjsip_uri_print(
                    PJSIP_URI_IN_ROUTING_HDR,
                    route->name_addr.uri,
                    dialog_route_set + route_len,
                    sizeof(dialog_route_set) - route_len);
                if (written <= 0 ||
                    route_len + (size_t)written >= sizeof(dialog_route_set)) {
                    route_len = 0;
                    break;
                }
                route_len += (size_t)written;
                route = route->next;
            }
            if (route_len > 0) {
                event.dialog_route_set =
                    gmv_bytes_view(dialog_route_set, route_len);
            }
        }
    }

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
        0,
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
    if (!transaction || transaction->status_code < 200 ||
        operation->final_response_emitted) {
        return;
    }
    operation->final_response_emitted = 1;

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
        operation->operation_id,
        NULL);
}

static pjsip_rx_data *gmv_event_rdata(pjsip_event *event) {
    if (!event ||
        event->type != PJSIP_EVENT_TSX_STATE ||
        event->body.tsx_state.type != PJSIP_EVENT_RX_MSG) {
        return NULL;
    }
    return event->body.tsx_state.src.rdata;
}

static void gmv_invite_call_save_dialog_route(
    gmv_invite_call_t *call,
    const pjsip_rx_data *rdata) {
    if (!call || !rdata ||
        !pj_sockaddr_has_addr(&rdata->pkt_info.src_addr)) {
        return;
    }
    memcpy(
        &call->dialog_route_addr,
        &rdata->pkt_info.src_addr,
        sizeof(call->dialog_route_addr));
    call->has_dialog_route = 1;
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
        operation_id,
        pjsip_tsx_get_dlg(transaction));
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

static void gmv_hold_invite_call(gmv_invite_call_t *call) {
    if (call) {
        ++call->active_calls;
    }
}

static void gmv_release_invite_call(gmv_invite_call_t *call) {
    if (!call || call->active_calls == 0) {
        return;
    }
    --call->active_calls;
    if (call->active_calls == 0 && call->cleanup_pending) {
        free(call);
    }
}

static void gmv_remove_invite_call(
    gmv_sip_runtime_t *runtime,
    gmv_invite_call_t *call) {
    if (!runtime || !call || call->cleanup_pending) {
        return;
    }
    gmv_invite_call_t **cursor = &runtime->invite_calls;
    while (*cursor) {
        if (*cursor == call) {
            *cursor = call->next;
            call->cleanup_pending = 1;
            if (call->active_calls == 0) {
                free(call);
            }
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
        pjsip_rx_data *rdata = gmv_event_rdata(event);
        if (transaction->status_code >= 200 &&
            transaction->status_code < 300) {
            gmv_invite_call_save_dialog_route(call, rdata);
        }
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

static void gmv_hold_subscription(gmv_subscription_call_t *call) {
    if (call) {
        ++call->active_calls;
    }
}

static void gmv_release_subscription(gmv_subscription_call_t *call) {
    if (!call || call->active_calls == 0) {
        return;
    }
    --call->active_calls;
    if (call->active_calls == 0 && call->cleanup_pending) {
        free(call->body);
        free(call);
    }
}

static void gmv_remove_subscription(
    gmv_sip_runtime_t *runtime,
    gmv_subscription_call_t *call) {
    if (!runtime || !call || call->cleanup_pending) {
        return;
    }
    gmv_subscription_call_t **cursor = &runtime->subscriptions;
    while (*cursor) {
        if (*cursor == call) {
            *cursor = call->next;
            call->cleanup_pending = 1;
            if (call->active_calls == 0) {
                free(call->body);
                free(call);
            }
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
    gmv_sip_runtime_t *runtime = call->runtime;
    int32_t transport = call->transport;
    uint32_t expires = call->expires;
    gmv_hold_subscription(call);
    pj_status_t status =
        gmv_start_subscription_request(call, expires);
    gmv_release_subscription(call);
    if (status != PJ_SUCCESS) {
        runtime->last_status = status;
        gmv_emit_event(
            runtime,
            GMV_SIP_EVENT_RUNTIME_FAULT,
            transport,
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

static void gmv_close_association_calls(
    gmv_sip_runtime_t *runtime,
    int32_t transport,
    uint64_t association_id) {
    gmv_invite_call_t *invite_call = runtime->invite_calls;
    while (invite_call) {
        gmv_invite_call_t *next = invite_call->next;
        if (invite_call->transport == transport &&
            invite_call->association_id == association_id) {
            pjsip_inv_session *invite = invite_call->invite;
            if (invite) {
                invite->mod_data[runtime->module.id] = NULL;
                invite_call->invite = NULL;
                pjsip_inv_terminate(
                    invite,
                    PJSIP_SC_SERVICE_UNAVAILABLE,
                    PJ_FALSE);
            }
            gmv_remove_invite_call(runtime, invite_call);
        }
        invite_call = next;
    }

    gmv_subscription_call_t *subscription_call =
        runtime->subscriptions;
    while (subscription_call) {
        gmv_subscription_call_t *next = subscription_call->next;
        if (subscription_call->transport == transport &&
            subscription_call->association_id == association_id) {
            pjsip_evsub *subscription =
                subscription_call->subscription;
            if (subscription) {
                pjsip_evsub_set_mod_data(
                    subscription,
                    (unsigned)runtime->module.id,
                    NULL);
                subscription_call->subscription = NULL;
                pjsip_evsub_terminate(subscription, PJ_FALSE);
            }
            gmv_remove_subscription(runtime, subscription_call);
        }
        subscription_call = next;
    }
}

static void gmv_hold_dialog_operation(
    gmv_dialog_operation_t *operation) {
    if (operation) {
        ++operation->active_calls;
    }
}

static void gmv_complete_dialog_operation(
    gmv_dialog_operation_t *operation) {
    if (!operation || operation->cleanup_pending) {
        return;
    }
    operation->cleanup_pending = 1;
    if (operation->restored_dialog &&
        operation->restored_session_held) {
        operation->restored_session_held = 0;
        pjsip_dlg_dec_session(
            operation->restored_dialog,
            &operation->runtime->module);
        operation->restored_dialog = NULL;
    }
    if (operation->restored_call) {
        gmv_remove_invite_call(
            operation->runtime,
            operation->restored_call);
        operation->restored_call = NULL;
    }
    if (operation->active_calls == 0) {
        free(operation);
    }
}

static void gmv_release_dialog_operation(
    gmv_dialog_operation_t *operation) {
    if (!operation || operation->active_calls == 0) {
        return;
    }
    --operation->active_calls;
    if (operation->active_calls == 0 &&
        operation->cleanup_pending) {
        free(operation);
    }
}

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
        gmv_complete_dialog_operation(operation);
    }
}

#include "shim_auth.inc"

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
        0,
        dialog);
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
                runtime->advertised_address,
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
            gmv_close_association_calls(
                runtime,
                command->transport,
                command->association_id);
        }
        free(command);
    }
}

#include "shim_command_dispatch.inc"

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
    gmv_process_receive_commands(runtime, receive_commands);
    gmv_process_close_commands(runtime, close_commands);
    gmv_process_message_commands(runtime, message_commands);
    gmv_process_invite_commands(runtime, invite_commands);
    gmv_process_dialog_commands(runtime, dialog_commands);
    gmv_process_invite_response_commands(
        runtime,
        invite_response_commands);
    gmv_process_subscribe_commands(runtime, subscribe_commands);
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
    while (runtime->recent_requests) {
        gmv_recent_request_t *request = runtime->recent_requests;
        runtime->recent_requests = request->next;
        free(request);
    }
    runtime->recent_request_count = 0;
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
    while (runtime->registered_sources) {
        gmv_registered_source_t *source = runtime->registered_sources;
        runtime->registered_sources = source->next;
        free(source);
    }
    while (runtime->register_orders) {
        gmv_register_order_t *order = runtime->register_orders;
        runtime->register_orders = order->next;
        free(order);
    }
    while (runtime->incoming_invite_allows) {
        gmv_incoming_invite_allow_t *allow =
            runtime->incoming_invite_allows;
        runtime->incoming_invite_allows = allow->next;
        free(allow);
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
    static const char default_user_agent[] = GMV_SIP_DEFAULT_USER_AGENT;
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
    config->user_agent.ptr = default_user_agent;
    config->user_agent.len = sizeof(default_user_agent) - 1u;
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
        !GMV_SIP_CONFIG_HAS(config, user_agent) ||
        !config->send_callback ||
        config->log_level > PJ_LOG_MAX_LEVEL ||
        (config->bind_address.len > 0 && !config->bind_address.ptr) ||
        config->bind_address.len >= GMV_SIP_BIND_ADDRESS_CAPACITY ||
        !config->user_agent.ptr ||
        config->user_agent.len == 0 ||
        config->user_agent.len >= GMV_SIP_USER_AGENT_CAPACITY ||
        memchr(config->user_agent.ptr, '\0', config->user_agent.len) ||
        memchr(config->user_agent.ptr, '\r', config->user_agent.len) ||
        memchr(config->user_agent.ptr, '\n', config->user_agent.len)) {
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
    memcpy(runtime->advertised_address, address, address_len);
    runtime->advertised_address[address_len] = '\0';
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
    memcpy(
        runtime->user_agent,
        config->user_agent.ptr,
        config->user_agent.len);
    runtime->user_agent[config->user_agent.len] = '\0';

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
    runtime->module.on_tx_request = &gmv_set_user_agent;
    runtime->module.on_tx_response = &gmv_set_user_agent;
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
            runtime->advertised_address,
            runtime->advertised_address,
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
    gmv_cleanup_recovery_sources(runtime, gmv_monotonic_ms());

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

int32_t gmv_sip_runtime_allow_registered_source(
    gmv_sip_runtime_t *runtime,
    const gmv_sip_registered_source_t *source) {
    if (!runtime || !source ||
        source->size < sizeof(*source) ||
        source->version != GMV_SIP_ABI_VERSION ||
        (source->transport != GMV_SIP_TRANSPORT_UDP &&
         source->transport != GMV_SIP_TRANSPORT_TCP) ||
        !source->device_id.ptr || source->device_id.len == 0 ||
        !source->remote_address.ptr || source->remote_address.len == 0 ||
        !runtime->started || !runtime->command_mutex) {
        return PJ_EINVAL;
    }

    char device_id[GMV_SIP_DEVICE_ID_CAPACITY];
    char remote_address[GMV_SIP_BIND_ADDRESS_CAPACITY];
    if (!gmv_copy_view(device_id, sizeof(device_id), source->device_id) ||
        !gmv_copy_view(
            remote_address,
            sizeof(remote_address),
            source->remote_address)) {
        return PJ_ETOOSMALL;
    }

    pj_mutex_lock(runtime->command_mutex);
    gmv_registered_source_t *item = runtime->registered_sources;
    while (item) {
        if (strcmp(item->device_id, device_id) == 0) {
            gmv_sync_register_order(
                runtime,
                device_id,
                source->registration_call_id,
                source->registration_cseq);
            item->transport = source->transport;
            item->generation += 1;
            item->recovery_expires_at_ms = 0;
            pj_ansi_strxcpy(
                item->remote_address,
                remote_address,
                sizeof(item->remote_address));
            pj_mutex_unlock(runtime->command_mutex);
            return PJ_SUCCESS;
        }
        item = item->next;
    }

    item = (gmv_registered_source_t *)calloc(1, sizeof(*item));
    if (!item) {
        pj_mutex_unlock(runtime->command_mutex);
        return PJ_ENOMEM;
    }
    gmv_sync_register_order(
        runtime,
        device_id,
        source->registration_call_id,
        source->registration_cseq);
    item->transport = source->transport;
    item->generation = 1;
    pj_ansi_strxcpy(item->device_id, device_id, sizeof(item->device_id));
    pj_ansi_strxcpy(
        item->remote_address,
        remote_address,
        sizeof(item->remote_address));
    item->next = runtime->registered_sources;
    runtime->registered_sources = item;
    pj_mutex_unlock(runtime->command_mutex);
    return PJ_SUCCESS;
}

int32_t gmv_sip_runtime_allow_recovery_source(
    gmv_sip_runtime_t *runtime,
    const gmv_sip_recovery_source_t *source) {
    if (!runtime || !source ||
        source->size < sizeof(*source) ||
        source->version != GMV_SIP_ABI_VERSION ||
        (source->transport != GMV_SIP_TRANSPORT_UDP &&
         source->transport != GMV_SIP_TRANSPORT_TCP) ||
        !source->device_id.ptr || source->device_id.len == 0 ||
        !source->remote_address.ptr || source->remote_address.len == 0 ||
        source->ttl_ms == 0 ||
        !runtime->started || !runtime->command_mutex) {
        return PJ_EINVAL;
    }

    char device_id[GMV_SIP_DEVICE_ID_CAPACITY];
    char remote_address[GMV_SIP_BIND_ADDRESS_CAPACITY];
    if (!gmv_copy_view(device_id, sizeof(device_id), source->device_id) ||
        !gmv_copy_view(
            remote_address,
            sizeof(remote_address),
            source->remote_address)) {
        return PJ_ETOOSMALL;
    }

    pj_mutex_lock(runtime->command_mutex);
    gmv_cleanup_recovery_sources(runtime, gmv_monotonic_ms());
    gmv_registered_source_t *item = runtime->registered_sources;
    while (item) {
        if (strcmp(item->device_id, device_id) == 0) {
            if (item->recovery_expires_at_ms == 0) {
                pj_mutex_unlock(runtime->command_mutex);
                return PJ_SUCCESS;
            }
            gmv_sync_register_order(
                runtime,
                device_id,
                source->registration_call_id,
                source->registration_cseq);
            item->transport = source->transport;
            item->generation += 1;
            item->recovery_expires_at_ms =
                gmv_monotonic_ms() + source->ttl_ms;
            pj_ansi_strxcpy(
                item->remote_address,
                remote_address,
                sizeof(item->remote_address));
            pj_mutex_unlock(runtime->command_mutex);
            return PJ_SUCCESS;
        }
        item = item->next;
    }

    gmv_sync_register_order(
        runtime,
        device_id,
        source->registration_call_id,
        source->registration_cseq);
    item = (gmv_registered_source_t *)calloc(1, sizeof(*item));
    if (!item) {
        pj_mutex_unlock(runtime->command_mutex);
        return PJ_ENOMEM;
    }
    item->transport = source->transport;
    item->generation = 1;
    item->recovery_expires_at_ms = gmv_monotonic_ms() + source->ttl_ms;
    pj_ansi_strxcpy(item->device_id, device_id, sizeof(item->device_id));
    pj_ansi_strxcpy(
        item->remote_address,
        remote_address,
        sizeof(item->remote_address));
    item->next = runtime->registered_sources;
    runtime->registered_sources = item;
    pj_mutex_unlock(runtime->command_mutex);
    return PJ_SUCCESS;
}

int32_t gmv_sip_runtime_remove_registered_source(
    gmv_sip_runtime_t *runtime,
    gmv_sip_string_view_t device_id) {
    if (!runtime ||
        !device_id.ptr ||
        device_id.len == 0 ||
        !runtime->command_mutex) {
        return PJ_EINVAL;
    }
    char device_id_buffer[GMV_SIP_DEVICE_ID_CAPACITY];
    if (!gmv_copy_view(
            device_id_buffer,
            sizeof(device_id_buffer),
            device_id)) {
        return PJ_ETOOSMALL;
    }

    pj_mutex_lock(runtime->command_mutex);
    gmv_remove_register_order(runtime, device_id_buffer);
    gmv_registered_source_t **cursor = &runtime->registered_sources;
    while (*cursor) {
        gmv_registered_source_t *item = *cursor;
        if (strcmp(item->device_id, device_id_buffer) == 0) {
            *cursor = item->next;
            free(item);
            continue;
        }
        cursor = &item->next;
    }
    pj_mutex_unlock(runtime->command_mutex);
    return PJ_SUCCESS;
}

int32_t gmv_sip_runtime_allow_incoming_invite(
    gmv_sip_runtime_t *runtime,
    const gmv_sip_incoming_invite_allow_t *allow) {
    if (!runtime || !allow ||
        allow->size < sizeof(*allow) ||
        allow->version != GMV_SIP_ABI_VERSION ||
        (allow->transport != GMV_SIP_TRANSPORT_UDP &&
         allow->transport != GMV_SIP_TRANSPORT_TCP) ||
        !allow->target_id.ptr || allow->target_id.len == 0 ||
        !allow->source_id.ptr || allow->source_id.len == 0 ||
        !allow->remote_address.ptr || allow->remote_address.len == 0 ||
        allow->ttl_ms == 0 ||
        !runtime->started || !runtime->command_mutex) {
        return PJ_EINVAL;
    }

    gmv_incoming_invite_allow_t *item =
        (gmv_incoming_invite_allow_t *)calloc(1, sizeof(*item));
    if (!item) {
        return PJ_ENOMEM;
    }
    item->transport = allow->transport;
    item->expires_at_ms = gmv_now_ms() + allow->ttl_ms;
    if (!gmv_copy_view(
            item->target_id,
            sizeof(item->target_id),
            allow->target_id) ||
        !gmv_copy_view(
            item->source_id,
            sizeof(item->source_id),
            allow->source_id) ||
        !gmv_copy_view(
            item->remote_address,
            sizeof(item->remote_address),
            allow->remote_address)) {
        free(item);
        return PJ_ETOOSMALL;
    }

    pj_mutex_lock(runtime->command_mutex);
    gmv_cleanup_incoming_invite_allows(runtime, gmv_now_ms());
    item->next = runtime->incoming_invite_allows;
    runtime->incoming_invite_allows = item;
    pj_mutex_unlock(runtime->command_mutex);
    return PJ_SUCCESS;
}

#include "shim_message.inc"

#include "shim_invite.inc"

#include "shim_dialog.inc"

#include "shim_subscription.inc"

int32_t gmv_sip_runtime_send_message(
    gmv_sip_runtime_t *runtime,
    const gmv_sip_outbound_message_t *message) {
    if (!runtime || !message ||
        message->size < sizeof(*message) ||
        message->version != GMV_SIP_ABI_VERSION ||
        message->operation_id == 0 ||
        message->cseq == 0 ||
        message->cseq > INT32_MAX ||
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
    command->cseq = message->cseq;
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
        invite->local_cseq == 0 ||
        invite->local_cseq > INT32_MAX ||
        !invite->call_id.ptr || invite->call_id.len == 0 ||
        !invite->local_tag.ptr || invite->local_tag.len == 0 ||
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
    command->local_cseq = invite->local_cseq;
    if (!gmv_copy_view(
            command->call_id,
            sizeof(command->call_id),
            invite->call_id) ||
        !gmv_copy_view(
            command->local_tag,
            sizeof(command->local_tag),
            invite->local_tag) ||
        !gmv_copy_view(
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

int32_t gmv_sip_runtime_send_restored_dialog_request(
    gmv_sip_runtime_t *runtime,
    const gmv_sip_restored_dialog_request_t *request) {
    if (!runtime || !request ||
        request->size < sizeof(*request) ||
        request->version != GMV_SIP_ABI_VERSION ||
        request->operation_id == 0 ||
        (request->method != GMV_SIP_DIALOG_BYE &&
         request->method != GMV_SIP_DIALOG_INFO) ||
        request->local_cseq == 0 ||
        !request->call_id.ptr || request->call_id.len == 0 ||
        !request->local_uri.ptr || request->local_uri.len == 0 ||
        !request->remote_uri.ptr || request->remote_uri.len == 0 ||
        !request->local_tag.ptr || request->local_tag.len == 0 ||
        !request->remote_tag.ptr || request->remote_tag.len == 0 ||
        !request->remote_target.ptr || request->remote_target.len == 0 ||
        !request->remote_address.ptr || request->remote_address.len == 0 ||
        request->remote_port == 0 ||
        (request->transport != GMV_SIP_TRANSPORT_UDP &&
         request->transport != GMV_SIP_TRANSPORT_TCP) ||
        (request->transport == GMV_SIP_TRANSPORT_TCP &&
         request->association_id == 0) ||
        (request->method == GMV_SIP_DIALOG_INFO &&
         (!request->content_type.ptr || request->content_type.len == 0 ||
          !request->body.ptr || request->body.len == 0)) ||
        request->body.len > PJSIP_MAX_PKT_LEN ||
        !runtime->started || !runtime->command_mutex) {
        return PJ_EINVAL;
    }

    gmv_dialog_command_t *command =
        (gmv_dialog_command_t *)calloc(1, sizeof(*command));
    if (!command) {
        return PJ_ENOMEM;
    }
    command->restored = 1;
    command->operation_id = request->operation_id;
    command->method = request->method;
    command->association_id = request->association_id;
    command->transport = request->transport;
    command->local_cseq = request->local_cseq;
    command->remote_port = request->remote_port;
    if (!gmv_copy_view(command->call_id, sizeof(command->call_id), request->call_id) ||
        !gmv_copy_view(command->local_uri, sizeof(command->local_uri), request->local_uri) ||
        !gmv_copy_view(command->remote_uri, sizeof(command->remote_uri), request->remote_uri) ||
        !gmv_copy_view(command->local_tag, sizeof(command->local_tag), request->local_tag) ||
        !gmv_copy_view(command->remote_tag, sizeof(command->remote_tag), request->remote_tag) ||
        !gmv_copy_view(command->remote_target, sizeof(command->remote_target), request->remote_target) ||
        !gmv_copy_view(command->route_set, sizeof(command->route_set), request->route_set) ||
        !gmv_copy_view(command->remote_address, sizeof(command->remote_address), request->remote_address) ||
        !gmv_copy_view(command->content_type, sizeof(command->content_type), request->content_type)) {
        gmv_free_dialog_command(command);
        return PJ_ETOOSMALL;
    }
    if (request->body.len > 0) {
        command->body = (unsigned char *)malloc(request->body.len);
        if (!command->body) {
            gmv_free_dialog_command(command);
            return PJ_ENOMEM;
        }
        memcpy(command->body, request->body.ptr, request->body.len);
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
        response->status_code < 200 ||
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
            response->reason) ||
        !gmv_copy_view(
            command->content_type,
            sizeof(command->content_type),
            response->content_type)) {
        gmv_free_invite_response_command(command);
        return PJ_ETOOSMALL;
    }
    if (response->body.len > 0) {
        command->body = (unsigned char *)malloc(response->body.len);
        if (!command->body) {
            gmv_free_invite_response_command(command);
            return PJ_ENOMEM;
        }
        memcpy(command->body, response->body.ptr, response->body.len);
        command->body_len = response->body.len;
    }
    if (response->status_code < 300 &&
        (!command->content_type[0] || command->body_len == 0)) {
        gmv_free_invite_response_command(command);
        return PJ_EINVAL;
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
        (subscribe->call_id.len == 0 &&
         (subscribe->local_cseq == 0 || subscribe->local_cseq > INT32_MAX)) ||
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
    command->local_cseq = subscribe->local_cseq;
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
