/* Owner-thread dispatch and cleanup for outbound business commands. */
static void gmv_free_owned_command(void *payload, void *command) {
    free(payload);
    free(command);
}

static void gmv_free_message_command(gmv_message_command_t *command) {
    if (command) {
        gmv_free_owned_command(command->body, command);
    }
}

static void gmv_free_invite_command(gmv_invite_command_t *command) {
    if (command) {
        gmv_free_owned_command(command->sdp, command);
    }
}

static void gmv_free_dialog_command(gmv_dialog_command_t *command) {
    if (command) {
        gmv_free_owned_command(command->body, command);
    }
}

static void gmv_free_invite_response_command(
    gmv_invite_response_command_t *command) {
    if (command) {
        gmv_free_owned_command(command->body, command);
    }
}

static void gmv_free_subscribe_command(
    gmv_subscribe_command_t *command) {
    if (command) {
        gmv_free_owned_command(command->body, command);
    }
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

