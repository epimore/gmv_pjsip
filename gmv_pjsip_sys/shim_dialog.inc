/* Internal implementation; included by shim.c to preserve one translation unit. */
static pj_status_t gmv_send_dialog_on_owner(
    gmv_sip_runtime_t *runtime,
    const gmv_dialog_command_t *command) {
    if (!runtime || !command ||
        command->operation_id == 0 ||
        !command->call_id[0] ||
        !runtime->started) {
        return PJ_EINVAL;
    }
    if (command->restored) {
        gmv_custom_transport_t *transport = gmv_find_transport(
            runtime,
            command->transport,
            command->association_id);
        if (!transport) {
            return PJSIP_EUNSUPTRANSPORT;
        }

        pj_str_t local_uri = pj_str((char *)command->local_uri);
        pj_str_t remote_uri = pj_str((char *)command->remote_uri);
        pj_str_t remote_target = pj_str((char *)command->remote_target);
        pjsip_dialog *dialog = NULL;
        pj_status_t status = pjsip_dlg_create_uac(
            pjsip_ua_instance(),
            &local_uri,
            &local_uri,
            &remote_uri,
            &remote_target,
            &dialog);
        if (status != PJ_SUCCESS) {
            return status;
        }
        status = pjsip_dlg_inc_session(dialog, &runtime->module);
        if (status != PJ_SUCCESS) {
            pjsip_dlg_terminate(dialog);
            return status;
        }

        pjsip_route_hdr route_set;
        pj_list_init(&route_set);
        const char *cursor = command->route_set;
        while (*cursor) {
            const char *end = strchr(cursor, '\n');
            size_t len = end ? (size_t)(end - cursor) : strlen(cursor);
            if (len > 0) {
                char *route_value = (char *)pj_pool_alloc(dialog->pool, len + 1u);
                memcpy(route_value, cursor, len);
                route_value[len] = '\0';
                pj_str_t route_name = pj_str("Route");
                pjsip_route_hdr *route = (pjsip_route_hdr *)pjsip_parse_hdr(
                    dialog->pool,
                    &route_name,
                    route_value,
                    len,
                    NULL);
                if (!route) {
                    pjsip_dlg_dec_session(dialog, &runtime->module);
                    return PJSIP_EINVALIDURI;
                }
                pj_list_push_back(&route_set, route);
            }
            if (!end) {
                break;
            }
            cursor = end + 1;
        }
        if (!pj_list_empty(&route_set)) {
            status = pjsip_dlg_set_route_set(dialog, &route_set);
            if (status != PJ_SUCCESS) {
                pjsip_dlg_dec_session(dialog, &runtime->module);
                return status;
            }
        }

        status = pjsip_ua_unregister_dlg(pjsip_ua_instance(), dialog);
        if (status != PJ_SUCCESS) {
            pjsip_dlg_dec_session(dialog, &runtime->module);
            return status;
        }
        pj_str_t call_id = pj_str((char *)command->call_id);
        pj_str_t local_tag = pj_str((char *)command->local_tag);
        pj_str_t remote_tag = pj_str((char *)command->remote_tag);
        pj_strdup(dialog->pool, &dialog->call_id->id, &call_id);
        pj_strdup(dialog->pool, &dialog->local.info->tag, &local_tag);
        dialog->local.tag_hval = pj_hash_calc_tolower(
            0,
            NULL,
            &dialog->local.info->tag);
        pj_strdup(dialog->pool, &dialog->remote.info->tag, &remote_tag);
        dialog->remote.tag_hval = pj_hash_calc_tolower(
            0,
            NULL,
            &dialog->remote.info->tag);
        dialog->local.first_cseq = (pj_int32_t)command->local_cseq;
        dialog->local.cseq = dialog->local.first_cseq;
        dialog->state = PJSIP_DIALOG_STATE_ESTABLISHED;
        dialog->uac_has_2xx = PJ_TRUE;
        status = pjsip_ua_register_dlg(pjsip_ua_instance(), dialog);
        if (status != PJ_SUCCESS) {
            pjsip_dlg_dec_session(dialog, &runtime->module);
            return status;
        }

        status = pjsip_dlg_add_usage(dialog, &runtime->module, NULL);
        pjsip_tpselector selector;
        memset(&selector, 0, sizeof(selector));
        selector.type = PJSIP_TPSELECTOR_TRANSPORT;
        selector.u.transport = &transport->base;
        if (status == PJ_SUCCESS) {
            status = pjsip_dlg_set_transport(dialog, &selector);
        }
        if (status != PJ_SUCCESS) {
            pjsip_dlg_dec_session(dialog, &runtime->module);
            return status;
        }

        pjsip_method method;
        pj_str_t method_name = pj_str(
            command->method == GMV_SIP_DIALOG_BYE ? "BYE" : "INFO");
        pjsip_method_init_np(&method, &method_name);
        pjsip_tx_data *tdata = NULL;
        status = pjsip_dlg_create_request(dialog, &method, -1, &tdata);
        if (status == PJ_SUCCESS && command->method == GMV_SIP_DIALOG_INFO) {
            status = gmv_set_subscription_body(
                tdata,
                command->content_type,
                command->body,
                command->body_len);
        }
        if (status != PJ_SUCCESS) {
            if (tdata) {
                pjsip_tx_data_dec_ref(tdata);
            }
            pjsip_dlg_dec_session(dialog, &runtime->module);
            return status;
        }

        gmv_dialog_operation_t *operation =
            (gmv_dialog_operation_t *)calloc(1, sizeof(*operation));
        if (!operation) {
            pjsip_tx_data_dec_ref(tdata);
            pjsip_dlg_dec_session(dialog, &runtime->module);
            return PJ_ENOMEM;
        }
        operation->runtime = runtime;
        operation->operation_id = command->operation_id;
        operation->restored_dialog = dialog;
        operation->restored_session_held = 1;
        gmv_invite_call_t *restored_call =
            (gmv_invite_call_t *)calloc(1, sizeof(*restored_call));
        if (!restored_call) {
            pjsip_tx_data_dec_ref(tdata);
            pjsip_dlg_dec_session(dialog, &runtime->module);
            free(operation);
            return PJ_ENOMEM;
        }
        restored_call->runtime = runtime;
        restored_call->transport = command->transport;
        restored_call->association_id = command->association_id;
        strcpy(restored_call->call_id, command->call_id);
        status = gmv_init_address(
            &restored_call->dialog_route_addr,
            command->remote_address,
            command->remote_port);
        if (status != PJ_SUCCESS) {
            free(restored_call);
            pjsip_tx_data_dec_ref(tdata);
            pjsip_dlg_dec_session(dialog, &runtime->module);
            free(operation);
            return status;
        }
        restored_call->has_dialog_route = 1;
        restored_call->next = runtime->invite_calls;
        runtime->invite_calls = restored_call;
        operation->restored_call = restored_call;
        gmv_hold_dialog_operation(operation);
        status = pjsip_dlg_send_request(
            dialog,
            tdata,
            runtime->module.id,
            operation);
        if (status != PJ_SUCCESS) {
            gmv_complete_dialog_operation(operation);
        }
        gmv_release_dialog_operation(operation);
        return status;
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
        gmv_hold_invite_call(call);
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
        gmv_release_invite_call(call);
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
    gmv_hold_dialog_operation(operation);
    status = pjsip_dlg_send_request(
        call->invite->dlg,
        tdata,
        runtime->module.id,
        operation);
    if (status != PJ_SUCCESS) {
        gmv_complete_dialog_operation(operation);
    }
    gmv_release_dialog_operation(operation);
    return status;
}

static pj_status_t gmv_respond_invite_on_owner(
    gmv_sip_runtime_t *runtime,
    const gmv_invite_response_command_t *command) {
    if (!runtime || !command ||
        command->status_code < 200 ||
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

    pjmedia_sdp_session *local_sdp = NULL;
    if (command->status_code < 300) {
        if (!command->content_type[0] || !command->body ||
            command->body_len == 0 ||
            pj_ansi_stricmp(command->content_type, "application/sdp") != 0) {
            return PJ_EINVAL;
        }
        char *sdp_buffer = (char *)pj_pool_alloc(
            call->invite->dlg->pool,
            command->body_len + 1u);
        if (!sdp_buffer) {
            return PJ_ENOMEM;
        }
        memcpy(sdp_buffer, command->body, command->body_len);
        sdp_buffer[command->body_len] = '\0';
        pj_status_t parse_status = pjmedia_sdp_parse(
            call->invite->dlg->pool,
            sdp_buffer,
            command->body_len,
            &local_sdp);
        if (parse_status != PJ_SUCCESS) {
            return parse_status;
        }
    }

    pj_str_t reason = pj_str((char *)command->reason);
    pjsip_tx_data *tdata = NULL;
    gmv_hold_invite_call(call);
    pj_status_t status = pjsip_inv_answer(
        call->invite,
        command->status_code,
        command->reason[0] ? &reason : NULL,
        local_sdp,
        &tdata);
    if (status == PJ_SUCCESS) {
        status = pjsip_inv_send_msg(call->invite, tdata);
    }
    gmv_release_invite_call(call);
    return status;
}

