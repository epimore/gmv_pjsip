/* Internal implementation; included by shim.c to preserve one translation unit. */
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
    gmv_sip_runtime_t *runtime,
    pjsip_rx_data *rdata,
    const pjsip_authorization_hdr *auth) {
    if (!runtime || !rdata || !rdata->msg_info.msg || !auth ||
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
    pjsip_uri *request_uri = rdata->msg_info.msg->line.req.uri;
    if (!authorization_uri || !request_uri) {
        return 0;
    }
    if (pjsip_uri_cmp(
            PJSIP_URI_IN_REQ_URI,
            authorization_uri,
            request_uri) == PJ_SUCCESS) {
        return 1;
    }

    authorization_uri = pjsip_uri_get_uri(authorization_uri);
    request_uri = pjsip_uri_get_uri(request_uri);
    if (!PJSIP_URI_SCHEME_IS_SIP(authorization_uri) ||
        !PJSIP_URI_SCHEME_IS_SIP(request_uri)) {
        return 0;
    }
    pjsip_sip_uri *authorization_sip =
        (pjsip_sip_uri *)authorization_uri;
    pjsip_sip_uri *request_sip = (pjsip_sip_uri *)request_uri;
    int authorization_port = authorization_sip->port
        ? authorization_sip->port
        : 5060;
    int request_port = request_sip->port ? request_sip->port : 5060;
    if (pj_stricmp2(
            &authorization_sip->host,
            runtime->advertised_address) != 0 ||
        authorization_port != request_port ||
        authorization_port != runtime->requested_port) {
        return 0;
    }

    pjsip_sip_uri *normalized = (pjsip_sip_uri *)pjsip_uri_clone(
        rdata->tp_info.pool,
        authorization_sip);
    if (!normalized) {
        return 0;
    }
    normalized->host = request_sip->host;
    return pjsip_uri_cmp(
        PJSIP_URI_IN_REQ_URI,
        normalized,
        request_uri) == PJ_SUCCESS;
}

static int gmv_authorization_shape_valid(
    gmv_sip_runtime_t *runtime,
    pjsip_rx_data *rdata,
    const pjsip_authorization_hdr *auth) {
    if (!gmv_authorization_uri_matches(runtime, rdata, auth)) {
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

static void gmv_preserve_response_to_uri(
    pjsip_rx_data *rdata,
    pjsip_tx_data *tdata) {
    if (!rdata || !tdata || !rdata->msg_info.to || !tdata->msg) {
        return;
    }
    pjsip_to_hdr *response_to =
        (pjsip_to_hdr *)pjsip_msg_find_hdr(
            tdata->msg,
            PJSIP_H_TO,
            NULL);
    if (!response_to) {
        return;
    }
    pjsip_to_hdr *request_to =
        (pjsip_to_hdr *)pjsip_hdr_clone(
            tdata->pool,
            (const pjsip_hdr *)rdata->msg_info.to);
    if (!request_to || !request_to->uri) {
        return;
    }
    response_to->uri = request_to->uri;
}

static void gmv_fix_response_top_via(
    pjsip_rx_data *rdata,
    pjsip_tx_data *tdata) {
    if (!rdata || !tdata || !tdata->msg) {
        return;
    }
    pjsip_via_hdr *via =
        (pjsip_via_hdr *)pjsip_msg_find_hdr(
            tdata->msg,
            PJSIP_H_VIA,
            NULL);
    if (!via) {
        return;
    }
    if (via->rport_param >= 0 && rdata->pkt_info.src_port > 0) {
        via->rport_param = rdata->pkt_info.src_port;
    }
    if (rdata->pkt_info.src_name[0] != '\0' &&
        via->recvd_param.slen == 0) {
        pj_strdup2(
            tdata->pool,
            &via->recvd_param,
            rdata->pkt_info.src_name);
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
    gmv_preserve_response_to_uri(rdata, tdata);
    gmv_fix_response_top_via(rdata, tdata);
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
        0,
        NULL);
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
        if (!gmv_authorization_shape_valid(runtime, rdata, auth)) {
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

static void gmv_cleanup_recent_requests(
    gmv_sip_runtime_t *runtime,
    uint64_t now) {
    gmv_recent_request_t **cursor = &runtime->recent_requests;
    while (*cursor) {
        gmv_recent_request_t *request = *cursor;
        if (request->expires_at_ms > now) {
            cursor = &request->next;
            continue;
        }
        *cursor = request->next;
        free(request);
        --runtime->recent_request_count;
    }
}

static void gmv_trim_recent_requests(gmv_sip_runtime_t *runtime) {
    while (runtime->recent_request_count > GMV_SIP_DUPLICATE_REQUEST_MAX &&
           runtime->recent_requests) {
        gmv_recent_request_t **cursor = &runtime->recent_requests;
        while ((*cursor)->next) {
            cursor = &(*cursor)->next;
        }
        gmv_recent_request_t *request = *cursor;
        *cursor = NULL;
        free(request);
        --runtime->recent_request_count;
    }
}

static int gmv_build_request_dedupe_key(
    pjsip_rx_data *rdata,
    char *out,
    size_t out_len) {
    if (!rdata || !out || out_len == 0 || !rdata->msg_info.msg ||
        !rdata->msg_info.cid || !rdata->msg_info.cseq ||
        !rdata->msg_info.via ||
        rdata->msg_info.cid->id.slen <= 0 ||
        rdata->msg_info.cseq->method.name.slen <= 0 ||
        rdata->msg_info.via->branch_param.slen <= 0) {
        return 0;
    }
    uint64_t association_id = 0;
    if (rdata->tp_info.transport) {
        gmv_custom_transport_t *transport =
            (gmv_custom_transport_t *)rdata->tp_info.transport;
        association_id = transport->association_id;
    }
    int written = pj_ansi_snprintf(
        out,
        out_len,
        "%d|%llu|%.*s|%d|%.*s|%.*s",
        gmv_transport_type(rdata->tp_info.transport),
        (unsigned long long)association_id,
        (int)rdata->msg_info.cid->id.slen,
        rdata->msg_info.cid->id.ptr,
        (int)rdata->msg_info.cseq->cseq,
        (int)rdata->msg_info.cseq->method.name.slen,
        rdata->msg_info.cseq->method.name.ptr,
        (int)rdata->msg_info.via->branch_param.slen,
        rdata->msg_info.via->branch_param.ptr);
    return written > 0 && (size_t)written < out_len;
}

static pj_bool_t gmv_recent_request_seen(
    gmv_sip_runtime_t *runtime,
    pjsip_rx_data *rdata) {
    char key[GMV_SIP_DUPLICATE_KEY_CAPACITY];
    if (!runtime ||
        !gmv_build_request_dedupe_key(rdata, key, sizeof(key))) {
        return PJ_FALSE;
    }
    uint64_t now = gmv_now_ms();
    gmv_cleanup_recent_requests(runtime, now);
    gmv_recent_request_t *request = runtime->recent_requests;
    while (request) {
        if (strcmp(request->key, key) == 0) {
            request->expires_at_ms =
                now + GMV_SIP_DUPLICATE_REQUEST_TTL_MS;
            return PJ_TRUE;
        }
        request = request->next;
    }
    request = (gmv_recent_request_t *)calloc(1, sizeof(*request));
    if (!request) {
        return PJ_FALSE;
    }
    pj_ansi_strxcpy(request->key, key, sizeof(request->key));
    request->expires_at_ms = now + GMV_SIP_DUPLICATE_REQUEST_TTL_MS;
    request->next = runtime->recent_requests;
    runtime->recent_requests = request;
    ++runtime->recent_request_count;
    gmv_trim_recent_requests(runtime);
    return PJ_FALSE;
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
    pj_str_t request_device_id = gmv_from_user(rdata);
    if ((is_options || is_message) &&
        !gmv_registered_source_allowed(
            runtime,
            transport,
            rdata->pkt_info.src_name,
            &request_device_id)) {
        runtime->last_status = PJ_SUCCESS;
        return PJ_TRUE;
    }
    if (is_invite) {
        if (!gmv_consume_incoming_invite_allow(runtime, rdata)) {
            runtime->last_status = PJ_SUCCESS;
            return PJ_TRUE;
        }
        return gmv_handle_incoming_invite(runtime, rdata);
    }
    if (!is_register && gmv_recent_request_seen(runtime, rdata)) {
        if (is_ack || is_bye || is_cancel) {
            return PJ_FALSE;
        }
        pj_status_t duplicate_status = gmv_send_response(
            runtime,
            rdata,
            NULL,
            PJSIP_SC_OK,
            0,
            PJ_FALSE);
        runtime->last_status = duplicate_status;
        return PJ_TRUE;
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
