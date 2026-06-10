use crate::auth::{AuthAlgorithm, AuthCredential, CredentialKind};
use crate::error::{Result, SipError};

#[allow(dead_code)]
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
    if algorithm != AuthAlgorithm::Md5 {
        return Err(SipError::AuthFailed(format!(
            "fallback digest only supports MD5; enable feature `pjsip-sys` for {}",
            algorithm.iana_name()
        )));
    }

    let ha1 = match credential.kind {
        CredentialKind::PlainPassword => format!("{:x}", md5::compute(format!("{}:{}:{}", credential.username, credential.realm, credential.secret))),
        CredentialKind::DigestHa1 => credential.secret.clone(),
    };
    let ha2 = format!("{:x}", md5::compute(format!("{}:{}", method, uri)));

    if let Some(qop) = qop.filter(|q| !q.is_empty()) {
        let nc = nc.ok_or_else(|| SipError::AuthFailed("qop auth requires nc".into()))?;
        let cnonce = cnonce.ok_or_else(|| SipError::AuthFailed("qop auth requires cnonce".into()))?;
        Ok(format!("{:x}", md5::compute(format!("{}:{}:{}:{}:{}:{}", ha1, nonce, nc, cnonce, qop, ha2))))
    } else {
        Ok(format!("{:x}", md5::compute(format!("{}:{}:{}", ha1, nonce, ha2))))
    }
}
