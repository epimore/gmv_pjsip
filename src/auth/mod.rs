//! SIP Digest authentication integration.
//!
//! Main path:
//! - With feature `pjsip-sys`, digest calculation and algorithm support checks
//!   are delegated to PJPROJECT/PJSIP through `gmv_pjsip_sys` shim functions.
//! - Without `pjsip-sys`, a small MD5-only fallback remains for unit tests and
//!   local skeleton builds; production GB28181 auth should enable `pjsip-sys`.
//!
//! Full `pjsip_auth_srv_verify()` requires a live `pjsip_rx_data` produced by
//! the PJSIP parser/transport pipeline. The current GMV adapter still parses
//! packets into Rust `SipMessage`, so this module uses PJSIP's
//! `pjsip_auth_create_digest2()` for standards-compliant digest calculation.
//! The `pjsip_server` submodule contains the FFI-ready server-auth boundary for
//! the next step where `PjRxDataHandle` is retained through parsing.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use rand::{distributions::Alphanumeric, Rng};

use crate::error::{Result, SipError};

mod fallback;
#[cfg(feature = "pjsip-sys")]
mod pjsip_digest;
#[cfg(feature = "pjsip-sys")]
pub mod pjsip_server;

pub trait PasswordProvider: Send + Sync + 'static {
    fn password_for(&self, username: &str, realm: &str) -> Option<String>;

    /// Override this when the storage already contains HA1 instead of a plain
    /// password. HA1 must match the selected digest algorithm.
    fn credential_for(&self, username: &str, realm: &str, algorithm: AuthAlgorithm) -> Option<AuthCredential> {
        self.password_for(username, realm).map(|password| AuthCredential {
            username: username.to_owned(),
            realm: realm.to_owned(),
            secret: password,
            kind: CredentialKind::PlainPassword,
            algorithm,
        })
    }
}

#[derive(Clone, Debug)]
pub struct StaticPasswordProvider {
    pub username: String,
    pub password: String,
}

impl PasswordProvider for StaticPasswordProvider {
    fn password_for(&self, username: &str, _realm: &str) -> Option<String> {
        if username == self.username { Some(self.password.clone()) } else { None }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialKind {
    PlainPassword,
    DigestHa1,
}

#[derive(Clone, Debug)]
pub struct AuthCredential {
    pub username: String,
    pub realm: String,
    /// Plain password when `kind == PlainPassword`, HA1 when `kind == DigestHa1`.
    pub secret: String,
    pub kind: CredentialKind,
    pub algorithm: AuthAlgorithm,
}

#[derive(Clone)]
pub struct AuthConfig {
    pub enabled: bool,
    pub realm: String,
    pub nonce_ttl: Duration,
    pub algorithm: AuthAlgorithm,
    pub provider: Option<Arc<dyn PasswordProvider>>,
}

impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthConfig")
            .field("enabled", &self.enabled)
            .field("realm", &self.realm)
            .field("nonce_ttl", &self.nonce_ttl)
            .field("algorithm", &self.algorithm)
            .field("provider", &self.provider.as_ref().map(|_| "<provider>"))
            .finish()
    }
}

impl AuthConfig {
    pub fn disabled(realm: impl Into<String>) -> Self {
        Self {
            enabled: false,
            realm: realm.into(),
            nonce_ttl: Duration::from_secs(300),
            algorithm: AuthAlgorithm::Md5,
            provider: None,
        }
    }

    pub fn digest(
        realm: impl Into<String>,
        provider: Arc<dyn PasswordProvider>,
        algorithm: AuthAlgorithm,
    ) -> Self {
        Self {
            enabled: true,
            realm: realm.into(),
            nonce_ttl: Duration::from_secs(300),
            algorithm,
            provider: Some(provider),
        }
    }
}

#[derive(Clone, Debug)]
pub enum AuthDecision {
    Disabled,
    Challenge { nonce: String, header_value: String },
    Authorized { username: String },
    Forbidden(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthAlgorithm {
    Md5,
    Sha256,
    Sha512_256,
}

impl AuthAlgorithm {
    pub fn iana_name(self) -> &'static str {
        match self {
            Self::Md5 => "MD5",
            Self::Sha256 => "SHA-256",
            Self::Sha512_256 => "SHA-512-256",
        }
    }

    pub fn from_header(value: Option<&str>, default: Self) -> Self {
        let Some(value) = value else { return default; };
        match value.trim_matches('"').to_ascii_uppercase().as_str() {
            "SHA-256" | "SHA256" => Self::Sha256,
            "SHA-512-256" | "SHA512-256" | "SHA512_256" => Self::Sha512_256,
            "MD5" => Self::Md5,
            _ => default,
        }
    }

    pub fn is_supported(self) -> bool {
        #[cfg(feature = "pjsip-sys")]
        {
            return pjsip_digest::is_algorithm_supported(self);
        }
        #[cfg(not(feature = "pjsip-sys"))]
        {
            matches!(self, Self::Md5)
        }
    }
}

#[derive(Debug)]
pub struct NonceStore {
    items: DashMap<String, Instant>,
    ttl: Duration,
}

impl NonceStore {
    pub fn new(ttl: Duration) -> Self { Self { items: DashMap::new(), ttl } }

    pub fn issue(&self) -> String {
        let nonce: String = rand::thread_rng().sample_iter(&Alphanumeric).take(32).map(char::from).collect();
        self.items.insert(nonce.clone(), Instant::now() + self.ttl);
        nonce
    }

    pub fn valid(&self, nonce: &str) -> bool {
        self.items.get(nonce).map(|v| Instant::now() <= *v).unwrap_or(false)
    }

    pub fn cleanup(&self) -> usize {
        let now = Instant::now();
        let before = self.items.len();
        self.items.retain(|_, expires| *expires > now);
        before.saturating_sub(self.items.len())
    }
}

pub fn build_www_authenticate(realm: &str, nonce: &str, algorithm: AuthAlgorithm) -> String {
    format!(
        "Digest realm=\"{}\", nonce=\"{}\", algorithm={}, qop=\"auth\"",
        realm,
        nonce,
        algorithm.iana_name()
    )
}

pub fn parse_digest_authorization(value: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let s = value.trim().strip_prefix("Digest").unwrap_or(value).trim();
    for part in s.split(',') {
        let Some((k, v)) = part.trim().split_once('=') else { continue; };
        out.insert(k.trim().to_ascii_lowercase(), v.trim().trim_matches('"').to_string());
    }
    out
}

#[derive(Clone)]
pub struct VerifyDigestRequest<'a> {
    pub method: &'a str,
    pub uri: &'a str,
    pub authorization: &'a str,
    pub realm: &'a str,
    pub default_algorithm: AuthAlgorithm,
    pub nonce_store: &'a NonceStore,
    pub provider: &'a dyn PasswordProvider,
}
impl std::fmt::Debug for VerifyDigestRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifyDigestRequest")
            .field("method", &self.method)
            .field("uri", &self.uri)
            .field("authorization", &"<redacted>")
            .field("realm", &self.realm)
            .field("nonce", &"<redacted>")
            .field("provider", &"<PasswordProvider>")
            .finish()
    }
}

pub fn verify_digest_response(req: VerifyDigestRequest<'_>) -> Result<String> {
    let parts = parse_digest_authorization(req.authorization);
    let username = parts.get("username").ok_or_else(|| SipError::AuthFailed("missing username".into()))?;
    let nonce = parts.get("nonce").ok_or_else(|| SipError::AuthFailed("missing nonce".into()))?;
    let response = parts.get("response").ok_or_else(|| SipError::AuthFailed("missing response".into()))?;
    let req_uri = parts.get("uri").map(String::as_str).unwrap_or(req.uri);
    let algorithm = AuthAlgorithm::from_header(parts.get("algorithm").map(String::as_str), req.default_algorithm);

    if !algorithm.is_supported() {
        return Err(SipError::AuthFailed(format!("digest algorithm {} is not supported", algorithm.iana_name())));
    }

    if !req.nonce_store.valid(nonce) {
        return Err(SipError::AuthFailed("nonce expired or unknown".into()));
    }

    let credential = req.provider
        .credential_for(username, req.realm, algorithm)
        .ok_or_else(|| SipError::AuthFailed("credential not found".into()))?;

    let nc = parts.get("nc").map(String::as_str);
    let cnonce = parts.get("cnonce").map(String::as_str);
    let qop = parts.get("qop").map(String::as_str);

    let expected = create_digest_response(
        &credential,
        req.method,
        req_uri,
        nonce,
        nc,
        cnonce,
        qop,
        algorithm,
    )?;

    if expected.eq_ignore_ascii_case(response) { Ok(username.clone()) } else { Err(SipError::AuthFailed("digest response mismatch".into())) }
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
    #[cfg(feature = "pjsip-sys")]
    {
        return pjsip_digest::create_digest_response(credential, method, uri, nonce, nc, cnonce, qop, algorithm);
    }
    #[cfg(not(feature = "pjsip-sys"))]
    {
        fallback::create_digest_response(credential, method, uri, nonce, nc, cnonce, qop, algorithm)
    }
}
