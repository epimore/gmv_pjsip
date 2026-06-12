#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GMV_SIP_ABI_VERSION 1u

typedef struct gmv_sip_runtime gmv_sip_runtime_t;

typedef struct gmv_sip_string_view {
    const char *ptr;
    size_t len;
} gmv_sip_string_view_t;

typedef enum gmv_sip_transport {
    GMV_SIP_TRANSPORT_UNKNOWN = 0,
    GMV_SIP_TRANSPORT_UDP = 1,
    GMV_SIP_TRANSPORT_TCP = 2
} gmv_sip_transport_t;

typedef enum gmv_sip_event_type {
    GMV_SIP_EVENT_REQUEST_RECEIVED = 1,
    GMV_SIP_EVENT_RESPONSE_SENT = 2,
    GMV_SIP_EVENT_RUNTIME_FAULT = 3,
    GMV_SIP_EVENT_AUTH_LOOKUP_REQUIRED = 4,
    GMV_SIP_EVENT_REGISTERED = 5,
    GMV_SIP_EVENT_AUTH_REJECTED = 6,
    GMV_SIP_EVENT_UNREGISTERED = 7,
    GMV_SIP_EVENT_OUTBOUND_RESPONSE = 8
} gmv_sip_event_type_t;

typedef enum gmv_sip_auth_lookup_result {
    GMV_SIP_AUTH_CREDENTIAL = 1,
    GMV_SIP_AUTH_BYPASS = 2,
    GMV_SIP_AUTH_REJECT = 3,
    GMV_SIP_AUTH_NOT_FOUND = 4
} gmv_sip_auth_lookup_result_t;

typedef struct gmv_sip_event {
    uint32_t size;
    uint32_t version;
    int32_t event_type;
    int32_t transport;
    int32_t status_code;
    int32_t pj_status;
    gmv_sip_string_view_t method;
    uint64_t event_id;
    uint32_t cseq;
    gmv_sip_string_view_t call_id;
    gmv_sip_string_view_t content_type;
    gmv_sip_string_view_t body;
    gmv_sip_string_view_t local_address;
    gmv_sip_string_view_t remote_address;
    uint64_t lookup_id;
    gmv_sip_string_view_t device_id;
    gmv_sip_string_view_t realm;
    int32_t expires_seconds;
    gmv_sip_string_view_t contact;
    gmv_sip_string_view_t user_agent;
    gmv_sip_string_view_t gb_version;
    uint64_t operation_id;
} gmv_sip_event_t;

typedef void (*gmv_sip_event_callback)(
    const gmv_sip_event_t *event,
    void *user_data);

typedef struct gmv_sip_runtime_config {
    uint32_t size;
    uint32_t version;
    gmv_sip_string_view_t bind_address;
    uint16_t port;
    uint8_t enable_udp;
    uint8_t enable_tcp;
    uint32_t async_count;
    uint32_t poll_timeout_ms;
    gmv_sip_event_callback event_callback;
    void *event_user_data;
    gmv_sip_string_view_t auth_realm;
    int32_t auth_algorithm_type;
    uint32_t max_pending_auth;
    uint32_t auth_lookup_timeout_ms;
} gmv_sip_runtime_config_t;

typedef struct gmv_sip_auth_lookup_completion {
    uint32_t size;
    uint32_t version;
    uint64_t lookup_id;
    int32_t result;
    int32_t credential_type;
    int32_t algorithm_type;
    gmv_sip_string_view_t username;
    gmv_sip_string_view_t realm;
    gmv_sip_string_view_t secret;
} gmv_sip_auth_lookup_completion_t;

typedef struct gmv_sip_outbound_message {
    uint32_t size;
    uint32_t version;
    uint64_t operation_id;
    gmv_sip_string_view_t target_uri;
    gmv_sip_string_view_t from_uri;
    gmv_sip_string_view_t content_type;
    gmv_sip_string_view_t body;
} gmv_sip_outbound_message_t;

uint32_t gmv_sip_abi_version(void);
void gmv_sip_runtime_config_init(gmv_sip_runtime_config_t *config);
int32_t gmv_sip_runtime_create(
    const gmv_sip_runtime_config_t *config,
    gmv_sip_runtime_t **out_runtime);
int32_t gmv_sip_runtime_start(gmv_sip_runtime_t *runtime);
int32_t gmv_sip_runtime_stop(gmv_sip_runtime_t *runtime);
int32_t gmv_sip_runtime_complete_auth_lookup(
    gmv_sip_runtime_t *runtime,
    const gmv_sip_auth_lookup_completion_t *completion);
int32_t gmv_sip_runtime_send_message(
    gmv_sip_runtime_t *runtime,
    const gmv_sip_outbound_message_t *message);
void gmv_sip_runtime_destroy(gmv_sip_runtime_t *runtime);
uint16_t gmv_sip_runtime_udp_port(const gmv_sip_runtime_t *runtime);
uint16_t gmv_sip_runtime_tcp_port(const gmv_sip_runtime_t *runtime);
int32_t gmv_sip_runtime_last_status(const gmv_sip_runtime_t *runtime);
int32_t gmv_sip_error_message(
    int32_t status,
    char *buffer,
    size_t buffer_len);

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
