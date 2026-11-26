//! Domain identity, `SignalR` framing, fanout decoding, and batch validation
//! for live notification hubs.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use worker::{D1Database, Env, WebSocketIncomingMessage};

use super::{
    FanoutRequest, FanoutSelector, HANDSHAKE_RESPONSE, LogoutScope, PING, is_signalr_handshake,
    verify_fanout_token,
};
use crate::{
    errors::{AppError, JwtError},
    infra::{db, jwt},
    models::identity::{
        auth_request::AuthRequestRow,
        notification::{ConnectionCheck, validate_connections},
        user::UserRow,
    },
    service::{
        identity::{
            auth_request::is_auth_request_active,
            jwt_keys,
            session::{Claims, TokenUse},
        },
        rate_limit,
    },
    utils::{constant_time_eq, parse_bearer, time},
};

const CLIENT_IDLE_TIMEOUT_SECONDS: i64 = 120;
const MAX_USER_CONNECTIONS: usize = 40;
const MAX_ANONYMOUS_CONNECTIONS_PER_IP: usize = 25;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HubError {
    Unauthorized,
    BearerRequired,
    InvalidBearerToken,
    TooManyConnections,
    Unavailable,
    Forbidden,
    InvalidNotification,
}

pub(crate) type HubResult<T> = Result<T, HubError>;

pub(crate) fn unavailable(operation: &'static str) -> HubError {
    log::warn!("Notification identity validation failed to {operation}");
    HubError::Unavailable
}

fn identity_database(env: &Env) -> HubResult<D1Database> {
    db::binding(env).map_err(|_error| unavailable("resolve D1 binding DB"))
}

fn session_rejection(error: &AppError) -> HubError {
    match error {
        AppError::Auth(_) | AppError::Unauthorized { .. } => HubError::InvalidBearerToken,
        _ => unavailable("validate device session in D1"),
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum HubIdentity {
    User {
        claims: Box<Claims>,
        #[serde(default)]
        account_revision: Option<String>,
    },
    Anonymous {
        request_id: String,
        ip: String,
    },
}

pub(crate) struct TagPolicy {
    pub routing_tags: Vec<String>,
    pub capacity_tag: String,
    pub max_connections: usize,
}

impl HubIdentity {
    pub(crate) async fn authenticate(
        env: &Env,
        anonymous: bool,
        access_token: Option<String>,
        anonymous_token: Option<String>,
        authorization_header: Option<&str>,
        client_ip: Option<&str>,
    ) -> HubResult<Self> {
        if anonymous {
            let id = anonymous_token
                .filter(|id| !id.is_empty() && id.len() <= 128)
                .ok_or(HubError::Unauthorized)?;
            let ip = client_ip.unwrap_or("unknown").to_owned();
            let identity = Self::Anonymous { request_id: id, ip };
            identity.validate(env).await?;
            Ok(identity)
        } else {
            let token = access_token
                .as_deref()
                .or_else(|| authorization_header.and_then(parse_bearer))
                .ok_or(HubError::BearerRequired)?;
            let db = identity_database(env)?;
            let secret = jwt_keys::load(env, &db)
                .await
                .map_err(|_error| unavailable("load JWT signing keys"))?
                .access_secret;
            let options = jwt::ValidationOptions {
                leeway_seconds: 0,
                ..Default::default()
            };
            let claims =
                jwt::decode::<Claims>(token, secret.as_bytes(), &options).map_err(|error| {
                    match error {
                        JwtError::CryptoError(_) => unavailable("verify access token signature"),
                        _ => HubError::InvalidBearerToken,
                    }
                })?;
            let session = claims
                .session_snapshot()
                .map_err(|error| session_rejection(&error))?;
            let account_revision = session
                .revision(&db)
                .await
                .map_err(|error| session_rejection(&error))?;
            Ok(Self::User {
                claims: Box::new(claims),
                account_revision: Some(account_revision),
            })
        }
    }

    pub(crate) async fn validate(&self, env: &Env) -> HubResult<()> {
        let db = identity_database(env)?;
        match self {
            Self::User { claims, .. } => {
                if claims.exp <= time::now_seconds() {
                    return Err(HubError::InvalidBearerToken);
                }
                claims
                    .validate_session(&db, TokenUse::Access)
                    .await
                    .map_err(|error| session_rejection(&error))
            }
            Self::Anonymous { request_id, ip } => {
                let request = AuthRequestRow::find_by_id(&db, request_id)
                    .await
                    .map_err(|_error| unavailable("read authentication request from D1"))?
                    .filter(|request| is_auth_request_active(request) && request.request_ip == *ip)
                    .ok_or(HubError::Unauthorized)?;
                let user = UserRow::fetch_by_id_with(
                    &db,
                    &request.user_id,
                    "Failed to validate notification owner",
                    || AppError::not_found("User"),
                )
                .await
                .map_err(|error| match error {
                    AppError::NotFound { .. } => HubError::Unauthorized,
                    _ => unavailable("read authentication request owner from D1"),
                })?;
                if constant_time_eq(
                    user.security_stamp.as_bytes(),
                    request.security_stamp.as_bytes(),
                ) {
                    Ok(())
                } else {
                    Err(HubError::Unauthorized)
                }
            }
        }
    }

    pub(crate) fn tag_policy(&self) -> TagPolicy {
        match self {
            Self::User { claims, .. } => TagPolicy {
                routing_tags: Vec::new(),
                capacity_tag: super::user_tag(&claims.sub),
                max_connections: MAX_USER_CONNECTIONS,
            },
            Self::Anonymous { request_id, ip } => TagPolicy {
                routing_tags: vec![super::anonymous_tag(request_id)],
                capacity_tag: format!("ip:{}", hex::encode(Sha256::digest(ip.as_bytes()))),
                max_connections: MAX_ANONYMOUS_CONNECTIONS_PER_IP,
            },
        }
    }

    fn matches(&self, selector: &FanoutSelector) -> bool {
        match (self, selector) {
            (Self::User { claims, .. }, FanoutSelector::User { user_id, .. }) => {
                claims.sub == *user_id
            }
            (Self::Anonymous { request_id: id, .. }, FanoutSelector::Anonymous { request_id }) => {
                id == request_id
            }
            _ => false,
        }
    }

    fn matches_logout_scope(&self, selector: &FanoutSelector) -> bool {
        let (
            Self::User {
                claims,
                account_revision,
            },
            FanoutSelector::User {
                logout_scope: Some(scope),
                ..
            },
        ) = (self, selector)
        else {
            return true;
        };
        match scope {
            LogoutScope::Stamp { value } => claims.sstamp == *value,
            LogoutScope::BeforeRevision { value, stamp } => {
                // Sockets created before revision tracking only predate the
                // first rotation that can send a revision-scoped logout.
                claims.sstamp == *stamp
                    && account_revision.as_deref().is_none_or(|revision| {
                        match (time::parse(revision), time::parse(value)) {
                            (Ok(revision), Ok(cutoff)) => revision < cutoff,
                            _ => false,
                        }
                    })
            }
        }
    }

    fn check(&self, now_seconds: i64) -> Option<ConnectionCheck<'_>> {
        match self {
            Self::User { claims, .. } => {
                if claims.exp <= now_seconds {
                    return None;
                }
                let session = claims.session_snapshot().ok()?;
                Some(ConnectionCheck::User {
                    user_id: session.user_id,
                    device_id: session.device_id,
                    stamp: session.security_stamp,
                    nonce: session.session_token,
                })
            }
            Self::Anonymous { request_id, ip } => {
                Some(ConnectionCheck::Anonymous { request_id, ip })
            }
        }
    }
}

pub(crate) async fn check_connect_rate_limit(env: &Env, client_ip: Option<&str>) -> HubResult<()> {
    let ip = client_ip.unwrap_or_default();
    rate_limit::check_auth_attempt(env, format!("notification-connect:{ip}"))
        .await
        .map_err(|error| match error {
            AppError::TooManyRequests { .. } => HubError::TooManyConnections,
            _ => HubError::Unavailable,
        })
}

pub(crate) struct VerifiedFanout {
    pub selector: FanoutSelector,
    pub payload: Vec<u8>,
    pub logout: bool,
}

pub(crate) async fn verify_and_decode_fanout(
    env: &Env,
    body: &str,
    token: &str,
) -> HubResult<VerifiedFanout> {
    verify_fanout_token(env, body, token).await?;
    let request: FanoutRequest =
        serde_json::from_str(body).map_err(|_error| HubError::InvalidNotification)?;
    let payload = STANDARD
        .decode(&request.message)
        .map_err(|_error| HubError::InvalidNotification)?;
    Ok(VerifiedFanout {
        selector: request.selector,
        payload,
        logout: request.logout,
    })
}

#[derive(Clone, Copy)]
pub(crate) enum FrameDecision {
    Reply(&'static [u8]),
    Close { code: u16, reason: &'static str },
}

#[derive(Clone, Copy)]
pub(crate) enum FilterOutcome {
    Include,
    Skip,
    Close { code: u16, reason: &'static str },
}

#[derive(Serialize, Deserialize)]
pub(crate) struct HubSession {
    identity: HubIdentity,
    #[serde(rename = "initialized")]
    is_initialized: bool,
    #[serde(rename = "last_received")]
    last_received_at_seconds: i64,
}

impl HubSession {
    pub(crate) fn new(identity: HubIdentity) -> Self {
        Self {
            identity,
            is_initialized: false,
            last_received_at_seconds: time::now_seconds(),
        }
    }

    pub(crate) const fn is_initialized(&self) -> bool {
        self.is_initialized
    }

    pub(crate) const fn evaluate_keepalive(&self, now_seconds: i64) -> FilterOutcome {
        if now_seconds - self.last_received_at_seconds > CLIENT_IDLE_TIMEOUT_SECONDS {
            FilterOutcome::Close {
                code: 1008,
                reason: "Session expired or inactive",
            }
        } else {
            FilterOutcome::Include
        }
    }

    pub(crate) fn evaluate_fanout(&self, selector: &FanoutSelector, logout: bool) -> FilterOutcome {
        if !self.identity.matches(selector) {
            return FilterOutcome::Close {
                code: 1008,
                reason: "Session expired",
            };
        }
        if !logout || self.identity.matches_logout_scope(selector) {
            FilterOutcome::Include
        } else {
            FilterOutcome::Skip
        }
    }

    pub(crate) async fn handle_frame(
        &mut self,
        env: &Env,
        frame: &WebSocketIncomingMessage,
    ) -> FrameDecision {
        if let Err(error) = self.identity.validate(env).await {
            let (code, reason) = close_for_rejection(error, "Session expired");
            return FrameDecision::Close { code, reason };
        }
        self.last_received_at_seconds = time::now_seconds();
        match frame {
            WebSocketIncomingMessage::String(text)
                if !self.is_initialized && is_signalr_handshake(text) =>
            {
                self.is_initialized = true;
                FrameDecision::Reply(&HANDSHAKE_RESPONSE)
            }
            WebSocketIncomingMessage::Binary(bytes) if self.is_initialized && bytes == &PING => {
                FrameDecision::Reply(&PING)
            }
            _ => FrameDecision::Close {
                code: 1003,
                reason: "Unsupported SignalR message",
            },
        }
    }
}

pub(crate) const fn close_for_rejection(
    error: HubError,
    invalid_reason: &'static str,
) -> (u16, &'static str) {
    match error {
        HubError::Unavailable => (1011, "Service temporarily unavailable"),
        _ => (1008, invalid_reason),
    }
}

pub(crate) async fn validate_sessions<'a>(
    env: &Env,
    sessions: impl Iterator<Item = &'a HubSession>,
) -> Vec<HubResult<()>> {
    let now = time::now();
    let checks = sessions
        .map(|session| session.identity.check(now.as_second()))
        .collect::<Vec<_>>();
    if checks.iter().all(Option::is_none) {
        return vec![Err(HubError::InvalidBearerToken); checks.len()];
    }

    let result = async {
        let db = identity_database(env)?;
        validate_connections(&db, &checks, &time::format_millis(now))
            .await
            .map_err(|_error| unavailable("batch validate WebSocket identities in D1"))
    }
    .await;
    match result {
        Ok(valid) => valid
            .into_iter()
            .map(|valid| valid.then_some(()).ok_or(HubError::InvalidBearerToken))
            .collect(),
        Err(_) => checks
            .iter()
            .map(|check| {
                Err(if check.is_some() {
                    HubError::Unavailable
                } else {
                    HubError::InvalidBearerToken
                })
            })
            .collect(),
    }
}
