/* Internal implementation; included by shim.c to preserve one translation unit. */
static pj_status_t gmv_send_message_on_owner(
    gmv_sip_runtime_t *runtime,
    const gmv_message_command_t *message) {
    if (!runtime || !message ||
        message->operation_id == 0 ||
        message->cseq == 0 ||
        message->cseq > INT32_MAX ||
        !message->target_uri[0] ||
        !message->from_uri[0] ||
        !message->content_type[0] ||
        !runtime->started || !runtime->endpoint) {
        return PJ_EINVAL;
    }

    pj_str_t target = pj_str((char *)message->target_uri);
    pj_str_t to = pj_str((char *)message->to_uri);
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
        &to,
        NULL,
        NULL,
        (int)message->cseq,
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
