use base::exception::{GlobalError, GlobalResult};

pub(crate) type Result<T> = GlobalResult<T>;

pub(crate) fn system_error(message: impl Into<String>) -> GlobalError {
    let message = message.into();
    GlobalError::new_sys_error(&message, |msg| base::log::error!("{msg}"))
}

pub(crate) fn invalid_config(message: String) -> GlobalError {
    system_error(format!("invalid SIP runtime configuration: {}", message))
}

pub(crate) fn auth_failed(message: String) -> GlobalError {
    system_error(format!("authentication failed: {message}"))
}

pub(crate) fn internal_error(message: String) -> GlobalError {
    system_error(format!("internal SIP error: {message}"))
}

pub(crate) fn runtime_active() -> GlobalError {
    system_error("a PJSIP runtime is already active in this process")
}
