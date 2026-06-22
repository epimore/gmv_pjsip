/* Internal implementation; included by shim.c to preserve one translation unit. */
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

static int gmv_sockaddr_is_private_or_unusable_ipv4(
    const pj_sockaddr *address) {
    if (!address || address->addr.sa_family != pj_AF_INET()) {
        return 0;
    }
    pj_uint32_t ip = pj_ntohl(address->ipv4.sin_addr.s_addr);
    unsigned a = (ip >> 24) & 0xffu;
    unsigned b = (ip >> 16) & 0xffu;
    if (a == 0 || a == 10 || a == 127) {
        return 1;
    }
    if (a == 100 && b >= 64 && b <= 127) {
        return 1;
    }
    if (a == 169 && b == 254) {
        return 1;
    }
    if (a == 172 && b >= 16 && b <= 31) {
        return 1;
    }
    if (a == 192 && b == 168) {
        return 1;
    }
    return 0;
}

static gmv_invite_call_t *gmv_invite_call_from_tx_data(
    gmv_sip_runtime_t *runtime,
    const pjsip_tx_data *tdata) {
    if (!runtime || !tdata || !tdata->msg) {
        return NULL;
    }
    pjsip_cid_hdr *call_id =
        (pjsip_cid_hdr *)pjsip_msg_find_hdr(
            tdata->msg,
            PJSIP_H_CALL_ID,
            NULL);
    if (!call_id || call_id->id.slen <= 0) {
        return NULL;
    }
    char call_id_value[GMV_SIP_CALL_ID_CAPACITY];
    if (!gmv_copy_view(
            call_id_value,
            sizeof(call_id_value),
            gmv_string_view(&call_id->id))) {
        return NULL;
    }
    return gmv_find_invite_call(runtime, call_id_value);
}

static const pj_sockaddr_t *gmv_dialog_route_destination(
    gmv_sip_runtime_t *runtime,
    const pjsip_tx_data *tdata,
    const pj_sockaddr_t *destination) {
    gmv_invite_call_t *call =
        gmv_invite_call_from_tx_data(runtime, tdata);
    if (!call || !call->has_dialog_route ||
        !pj_sockaddr_has_addr(&call->dialog_route_addr)) {
        return destination;
    }
    if (!destination || !pj_sockaddr_has_addr(destination) ||
        gmv_sockaddr_is_private_or_unusable_ipv4(
            (const pj_sockaddr *)destination)) {
        return &call->dialog_route_addr;
    }
    return destination;
}

static int gmv_packet_header_copy(
    const char *packet,
    size_t packet_len,
    const char *name,
    char *out,
    size_t out_len) {
    if (!packet || packet_len == 0 || !name || !out || out_len == 0) {
        return 0;
    }
    size_t name_len = strlen(name);
    const char *cursor = packet;
    const char *end = packet + packet_len;
    while (cursor < end) {
        const char *line_end = memchr(cursor, '\n', (size_t)(end - cursor));
        if (!line_end) {
            line_end = end;
        }
        size_t line_len = (size_t)(line_end - cursor);
        if (line_len > 0 && cursor[line_len - 1] == '\r') {
            line_len--;
        }
        if (line_len > name_len && cursor[name_len] == ':' &&
            pj_ansi_strnicmp(cursor, name, name_len) == 0) {
            const char *value = cursor + name_len + 1;
            size_t value_len = line_len - name_len - 1;
            while (value_len > 0 &&
                   (*value == ' ' || *value == '\t')) {
                value++;
                value_len--;
            }
            while (value_len > 0 &&
                   (value[value_len - 1] == ' ' ||
                    value[value_len - 1] == '\t')) {
                value_len--;
            }
            if (value_len >= out_len) {
                return 0;
            }
            memcpy(out, value, value_len);
            out[value_len] = '\0';
            return 1;
        }
        cursor = line_end == end ? end : line_end + 1;
    }
    return 0;
}

static int gmv_packet_is_2xx_invite_response(
    const char *packet,
    size_t packet_len) {
    if (!packet || packet_len < 9 ||
        memcmp(packet, "SIP/2.0 ", 8) != 0 ||
        packet[8] != '2') {
        return 0;
    }
    char cseq[128];
    if (!gmv_packet_header_copy(
            packet,
            packet_len,
            "CSeq",
            cseq,
            sizeof(cseq))) {
        return 0;
    }
    return strstr(cseq, "INVITE") != NULL;
}

static void gmv_capture_invite_dialog_route_from_packet(
    gmv_sip_runtime_t *runtime,
    const pjsip_rx_data *rdata) {
    if (!runtime || !rdata ||
        !gmv_packet_is_2xx_invite_response(
            rdata->pkt_info.packet,
            (size_t)rdata->pkt_info.len)) {
        return;
    }
    char call_id[GMV_SIP_CALL_ID_CAPACITY];
    if (!gmv_packet_header_copy(
            rdata->pkt_info.packet,
            (size_t)rdata->pkt_info.len,
            "Call-ID",
            call_id,
            sizeof(call_id))) {
        return;
    }
    gmv_invite_call_save_dialog_route(
        gmv_find_invite_call(runtime, call_id),
        rdata);
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
    const pj_sockaddr_t *destination =
        gmv_dialog_route_destination(runtime, tdata, remote_address);
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
    const char *advertised_address,
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
    pj_strdup2(pool, &base->local_name.host, advertised_address);
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

static size_t gmv_sip_header_end(
    const char *packet,
    size_t packet_len,
    size_t *delimiter_len) {
    if (!packet || packet_len == 0 || !delimiter_len) {
        return 0;
    }
    for (size_t i = 0; i + 3 < packet_len; ++i) {
        if (packet[i] == '\r' && packet[i + 1] == '\n' &&
            packet[i + 2] == '\r' && packet[i + 3] == '\n') {
            *delimiter_len = 4;
            return i;
        }
    }
    for (size_t i = 0; i + 1 < packet_len; ++i) {
        if (packet[i] == '\n' && packet[i + 1] == '\n') {
            *delimiter_len = 2;
            return i;
        }
    }
    return 0;
}

static size_t gmv_sip_content_length(
    const char *headers,
    size_t headers_len) {
    char value[32];
    if (!gmv_packet_header_copy(
            headers,
            headers_len,
            "Content-Length",
            value,
            sizeof(value))) {
        return 0;
    }
    char *end = NULL;
    unsigned long length = strtoul(value, &end, 10);
    if (end == value) {
        return 0;
    }
    return (size_t)length;
}

static size_t gmv_complete_sip_message_len(
    const char *packet,
    size_t packet_len) {
    size_t delimiter_len = 0;
    size_t headers_len =
        gmv_sip_header_end(packet, packet_len, &delimiter_len);
    if (headers_len == 0 && delimiter_len == 0) {
        return 0;
    }
    size_t body_len = gmv_sip_content_length(packet, headers_len);
    size_t message_len = headers_len + delimiter_len + body_len;
    return message_len <= packet_len ? message_len : 0;
}

static void gmv_log_complete_sip_packet_payload(
    gmv_sip_runtime_t *runtime,
    const gmv_custom_transport_t *transport,
    const pjsip_rx_data *rdata,
    const char *packet,
    size_t packet_len) {
    if (!runtime || !transport || !rdata || !packet || packet_len == 0 ||
        !runtime->log_callback || runtime->log_level < 4) {
        return;
    }
    char local[GMV_SIP_ADDRESS_CAPACITY];
    char remote[GMV_SIP_ADDRESS_CAPACITY];
    memset(local, 0, sizeof(local));
    memset(remote, 0, sizeof(remote));
    pj_sockaddr_print(&transport->base.local_addr, local, sizeof(local), 1);
    pj_sockaddr_print(&rdata->pkt_info.src_addr, remote, sizeof(remote), 1);

    char prefix[256];
    int prefix_len = pj_ansi_snprintf(
        prefix,
        sizeof(prefix),
        "complete SIP packet: protocol=%s association=%llu local=%s remote=%s bytes=%zu payload=",
        transport->protocol == GMV_SIP_TRANSPORT_TCP ? "TCP" : "UDP",
        (unsigned long long)transport->association_id,
        local,
        remote,
        packet_len);
    if (prefix_len <= 0) {
        return;
    }
    if ((size_t)prefix_len >= sizeof(prefix)) {
        prefix_len = (int)sizeof(prefix) - 1;
    }

    size_t escaped_len = 0;
    for (size_t i = 0; i < packet_len; ++i) {
        escaped_len +=
            packet[i] == '\r' || packet[i] == '\n' ? 2u : 1u;
    }

    size_t message_len = (size_t)prefix_len + escaped_len;
    char *message = (char *)malloc(message_len);
    if (!message) {
        return;
    }
    memcpy(message, prefix, (size_t)prefix_len);
    size_t cursor = (size_t)prefix_len;
    for (size_t i = 0; i < packet_len; ++i) {
        if (packet[i] == '\r') {
            message[cursor++] = '\\';
            message[cursor++] = 'r';
        } else if (packet[i] == '\n') {
            message[cursor++] = '\\';
            message[cursor++] = 'n';
        } else {
            message[cursor++] = packet[i];
        }
    }

    gmv_sip_string_view_t view;
    view.ptr = message;
    view.len = message_len;
    runtime->log_callback(4, view, runtime->log_user_data);
    free(message);
}

static void gmv_log_complete_sip_packets(
    gmv_sip_runtime_t *runtime,
    const gmv_custom_transport_t *transport,
    const pjsip_rx_data *rdata,
    size_t data_len) {
    if (!rdata || data_len == 0) {
        return;
    }
    const char *packet = rdata->pkt_info.packet;
    size_t offset = 0;
    while (offset < data_len) {
        size_t message_len =
            gmv_complete_sip_message_len(packet + offset, data_len - offset);
        if (message_len == 0) {
            break;
        }
        gmv_log_complete_sip_packet_payload(
            runtime,
            transport,
            rdata,
            packet + offset,
            message_len);
        offset += message_len;
    }
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
    gmv_capture_invite_dialog_route_from_packet(runtime, rdata);

    pj_ssize_t processed = pjsip_tpmgr_receive_packet(
        transport->base.tpmgr,
        rdata);
    if (processed < 0 || (size_t)processed > data_len) {
        status = PJ_EINVALIDOP;
    } else {
        *consumed = (size_t)processed;
        gmv_log_complete_sip_packets(runtime, transport, rdata, *consumed);
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
    for (;;) {
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
        size_t copy_len = offset < data_len ? data_len - offset : 0;
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
        if (offset >= data_len &&
            (consumed == 0 || transport->remainder_len == 0)) {
            break;
        }
    }

    return PJ_SUCCESS;
}

