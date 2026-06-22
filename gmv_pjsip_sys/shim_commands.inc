/* Internal command payloads shared by the owner-thread queues. */
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
    uint32_t cseq;
    char target_uri[GMV_SIP_URI_CAPACITY];
    char from_uri[GMV_SIP_URI_CAPACITY];
    char content_type[GMV_SIP_CONTENT_TYPE_CAPACITY];
    unsigned char *body;
    size_t body_len;
    struct gmv_message_command *next;
} gmv_message_command_t;

typedef struct gmv_invite_command {
    uint64_t operation_id;
    uint64_t association_id;
    int32_t transport;
    uint32_t local_cseq;
    char call_id[GMV_SIP_CALL_ID_CAPACITY];
    char local_tag[GMV_SIP_TAG_CAPACITY];
    char target_uri[GMV_SIP_URI_CAPACITY];
    char to_uri[GMV_SIP_URI_CAPACITY];
    char from_uri[GMV_SIP_URI_CAPACITY];
    char contact_uri[GMV_SIP_URI_CAPACITY];
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
    int restored;
    uint64_t association_id;
    int32_t transport;
    uint32_t local_cseq;
    uint16_t remote_port;
    char local_uri[GMV_SIP_URI_CAPACITY];
    char remote_uri[GMV_SIP_URI_CAPACITY];
    char local_tag[GMV_SIP_TAG_CAPACITY];
    char remote_tag[GMV_SIP_TAG_CAPACITY];
    char remote_target[GMV_SIP_URI_CAPACITY];
    char route_set[GMV_SIP_ROUTE_SET_CAPACITY];
    char remote_address[GMV_SIP_BIND_ADDRESS_CAPACITY];
    struct gmv_dialog_command *next;
} gmv_dialog_command_t;

typedef struct gmv_invite_response_command {
    uint16_t status_code;
    char call_id[GMV_SIP_CALL_ID_CAPACITY];
    char reason[GMV_SIP_REASON_CAPACITY];
    char content_type[GMV_SIP_CONTENT_TYPE_CAPACITY];
    unsigned char *body;
    size_t body_len;
    struct gmv_invite_response_command *next;
} gmv_invite_response_command_t;

typedef struct gmv_subscribe_command {
    uint64_t operation_id;
    uint64_t association_id;
    int32_t transport;
    uint32_t local_cseq;
    char target_uri[GMV_SIP_URI_CAPACITY];
    char from_uri[GMV_SIP_URI_CAPACITY];
    char contact_uri[GMV_SIP_URI_CAPACITY];
    char call_id[GMV_SIP_CALL_ID_CAPACITY];
    char event[GMV_SIP_CONTENT_TYPE_CAPACITY];
    uint32_t expires;
    char content_type[GMV_SIP_CONTENT_TYPE_CAPACITY];
    unsigned char *body;
    size_t body_len;
    struct gmv_subscribe_command *next;
} gmv_subscribe_command_t;
