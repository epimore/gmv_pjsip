use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};

use crate::auth::{AuthAlgorithm, AuthCredential, CredentialKind};
use crate::error::{Result, SipError};

fn alg_id(algorithm: AuthAlgorithm) -> c_int {
    unsafe {
        match algorithm {
            AuthAlgorithm::Md5 => gmv_pjsip_sys::gmv_pjsip_auth_alg_md5(),
            AuthAlgorithm::Sha256 => gmv_pjsip_sys::gmv_pjsip_auth_alg_sha256(),
            AuthAlgorithm::Sha512_256 => gmv_pjsip_sys::gmv_pjsip_auth_alg_sha512_256(),
        }
    }
}

pub fn is_algorithm_supported(algorithm: AuthAlgorithm) -> bool {
    unsafe { gmv_pjsip_sys::gmv_pjsip_auth_is_algorithm_supported(alg_id(algorithm)) != 0 }
}

fn cstring(name: &str, value: &str) -> Result<CString> {
    CString::new(value).map_err(|_| SipError::AuthFailed(format!("{name} contains NUL byte")))
}

pub fn create_digest_response(
    credential: &AuthCredential,
    method: &str,
    uri: &str,
    nonce: &str,
    nc: Option<&str>,
    cnonce: Option<&str>,
    qop: Option<&str>,
    algorithm: AuthAlgorithm,
) -> Result<String> {
    if !is_algorithm_supported(algorithm) {
        return Err(SipError::AuthFailed(format!("PJSIP does not support digest algorithm {}", algorithm.iana_name())));
    }

    let username = cstring("username", &credential.username)?;
    let realm = cstring("realm", &credential.realm)?;
    let secret = cstring("secret", &credential.secret)?;
    let method = cstring("method", method)?;
    let uri = cstring("uri", uri)?;
    let nonce = cstring("nonce", nonce)?;
    let nc = cstring("nc", nc.unwrap_or_default())?;
    let cnonce = cstring("cnonce", cnonce.unwrap_or_default())?;
    let qop = cstring("qop", qop.unwrap_or_default())?;

    let data_type = unsafe {
        match credential.kind {
            CredentialKind::PlainPassword => gmv_pjsip_sys::gmv_pjsip_auth_plain_password_type(),
            CredentialKind::DigestHa1 => gmv_pjsip_sys::gmv_pjsip_auth_digest_type(),
        }
    };

    let mut out = vec![0 as c_char; 161];
    let status = unsafe {
        gmv_pjsip_sys::gmv_pjsip_auth_create_digest2(
            out.as_mut_ptr(),
            out.len() as u32,
            username.as_ptr(),
            realm.as_ptr(),
            secret.as_ptr(),
            data_type,
            method.as_ptr(),
            uri.as_ptr(),
            nonce.as_ptr(),
            nc.as_ptr(),
            cnonce.as_ptr(),
            qop.as_ptr(),
            alg_id(algorithm),
        )
    };

    if status != 0 {
        return Err(SipError::AuthFailed(format!("pjsip_auth_create_digest2 failed: pj_status={status}")));
    }

    let digest = unsafe { CStr::from_ptr(out.as_ptr()) }
        .to_string_lossy()
        .to_string();
    Ok(digest)
}
