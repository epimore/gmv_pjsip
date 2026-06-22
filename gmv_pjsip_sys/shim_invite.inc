/* Internal implementation; included by shim.c to preserve one translation unit. */
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
        !command->call_id[0] ||
        !command->local_tag[0] ||
        command->local_cseq == 0 ||
        command->local_cseq > INT32_MAX ||
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

    status = pjsip_ua_unregister_dlg(pjsip_ua_instance(), dialog);
    if (status != PJ_SUCCESS) {
        pjsip_dlg_terminate(dialog);
        return status;
    }
    pj_str_t call_id = pj_str((char *)command->call_id);
    pj_str_t local_tag = pj_str((char *)command->local_tag);
    pj_strdup(dialog->pool, &dialog->call_id->id, &call_id);
    pj_strdup(dialog->pool, &dialog->local.info->tag, &local_tag);
    dialog->local.tag_hval = pj_hash_calc_tolower(
        0,
        NULL,
        &dialog->local.info->tag);
    dialog->local.first_cseq = (pj_int32_t)command->local_cseq;
    dialog->local.cseq = dialog->local.first_cseq;
    status = pjsip_ua_register_dlg(pjsip_ua_instance(), dialog);
    if (status != PJ_SUCCESS) {
        pjsip_dlg_terminate(dialog);
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
    gmv_hold_invite_call(call);
    if (status == PJ_SUCCESS) {
        status = pjsip_inv_send_msg(invite, tdata);
    }
    if (status != PJ_SUCCESS && !call->cleanup_pending) {
        invite->mod_data[runtime->module.id] = NULL;
        call->invite = NULL;
        gmv_remove_invite_call(runtime, call);
        pjsip_inv_terminate(
            invite,
            PJSIP_SC_INTERNAL_SERVER_ERROR,
            PJ_FALSE);
    }
    gmv_release_invite_call(call);
    return status;
}

