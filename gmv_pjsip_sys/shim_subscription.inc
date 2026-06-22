/* Internal implementation; included by shim.c to preserve one translation unit. */
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
        gmv_hold_subscription(call);
        status = gmv_start_subscription_request(
            call,
            command->expires);
        if (status != PJ_SUCCESS) {
            call->operation_id = 0;
        }
        gmv_release_subscription(call);
        return status;
    }

    if (!command->target_uri[0] ||
        !command->from_uri[0] ||
        !command->contact_uri[0] ||
        command->local_cseq == 0 ||
        command->local_cseq > INT32_MAX ||
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
    dialog->local.first_cseq = (pj_int32_t)command->local_cseq;
    dialog->local.cseq = dialog->local.first_cseq - 1;

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
    gmv_hold_subscription(call);
    status = gmv_start_subscription_request(
        call,
        command->expires);
    if (status != PJ_SUCCESS && !call->cleanup_pending) {
        pjsip_evsub_set_mod_data(
            subscription,
            (unsigned)runtime->module.id,
            NULL);
        call->subscription = NULL;
        gmv_remove_subscription(runtime, call);
        pjsip_evsub_terminate(subscription, PJ_FALSE);
    }
    gmv_release_subscription(call);
    return status;
}

