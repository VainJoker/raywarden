use base64::{
    Engine as _,
    engine::general_purpose::STANDARD,
};
use serde::{
    Deserialize,
    Serialize,
};
use sha2::{
    Digest as _,
    Sha256,
};
use worker::{
    DurableObject,
    Env,
    Method,
    Request,
    Response,
    Result,
    State,
    WebSocket,
    WebSocketIncomingMessage,
    WebSocketPair,
    durable_object,
};

use crate::{
    errors::{
        AppError,
        AppResult,
        protocol::NotificationError,
    },
    infra::{
        db,
        jwt,
    },
    models::identity::{
        auth_request::AuthRequestRow,
        user::UserRow,
    },
    service::{
        identity::session::Claims,
        notifications,
        notifications::{
            FanoutRequest,
            FanoutSelector,
        },
    },
    utils::constant_time_eq,
};

const KEEPALIVE_INTERVAL_MS: i64 = 25_000;
const CLIENT_IDLE_TIMEOUT_SECONDS: i64 = 120;
const MAX_USER_CONNECTIONS: usize = 40;
const MAX_ANONYMOUS_CONNECTIONS_PER_IP: usize = 25;

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum WebSocketIdentity {
    User {
        claims: Claims,
    },
    Anonymous {
        request_id: String,
        ip:         String,
    },
}

impl WebSocketIdentity {
    async fn is_valid(&self, env: &Env) -> bool {
        let Ok(db) = db::binding(env) else {
            return false;
        };
        match self {
            Self::User { claims } => {
                claims.exp > crate::utils::time::now_seconds() &&
                    claims
                        .validate_session(&db, "access")
                        .await
                        .inspect_err(log_identity_database_failure)
                        .is_ok()
            }
            Self::Anonymous { request_id, ip } => {
                let Ok(Some(request)) =
                    AuthRequestRow::find_by_id(&db, request_id)
                        .await
                        .inspect_err(log_identity_database_failure)
                else {
                    return false;
                };
                if !crate::service::identity::auth_request::is_auth_request_active(
                    &request,
                ) || request.request_ip != *ip
                {
                    return false;
                }
                match UserRow::fetch_by_id_with(
                    &db,
                    &request.user_id,
                    "Failed to validate notification owner",
                    || AppError::not_found("User"),
                )
                .await
                .inspect_err(log_identity_database_failure)
                {
                    Ok(user) => constant_time_eq(
                        user.security_stamp.as_bytes(),
                        request.security_stamp.as_bytes(),
                    ),
                    Err(_) => false,
                }
            }
        }
    }

    fn matches(&self, selector: &FanoutSelector) -> bool {
        match (self, selector) {
            (Self::User { claims }, FanoutSelector::User { user_id }) => {
                claims.sub == *user_id
            }
            (
                Self::Anonymous { request_id: id, .. },
                FanoutSelector::Anonymous { request_id },
            ) => id == request_id,
            _ => false,
        }
    }

    fn connection_tags(&self, state: &State) -> Option<Vec<String>> {
        let (mut tags, limit_tag, limit) = match self {
            Self::User { claims } => (
                Vec::new(),
                format!("u:{}", claims.sub),
                MAX_USER_CONNECTIONS,
            ),
            Self::Anonymous { request_id, ip } => (
                vec![format!("a:{request_id}")],
                format!("ip:{}", hex::encode(Sha256::digest(ip.as_bytes()))),
                MAX_ANONYMOUS_CONNECTIONS_PER_IP,
            ),
        };
        if state.get_websockets_with_tag(&limit_tag).len() >= limit {
            return None;
        }
        tags.push(limit_tag);
        Some(tags)
    }
}

fn log_identity_database_failure(error: &AppError) {
    if matches!(error, AppError::Database(_) | AppError::InternalFailure(_)) {
        log::warn!("Notification identity lookup failed: {error}");
    }
}

#[derive(Serialize, Deserialize)]
struct WebSocketConnection {
    identity:                 WebSocketIdentity,
    #[serde(rename = "initialized")]
    is_initialized:           bool,
    #[serde(rename = "last_received")]
    last_received_at_seconds: i64,
}

impl WebSocketConnection {
    fn new(identity: WebSocketIdentity) -> Self {
        Self {
            identity,
            is_initialized: false,
            last_received_at_seconds: crate::utils::time::now_seconds(),
        }
    }

    fn restore(ws: &WebSocket) -> Option<Self> {
        let connection = ws.deserialize_attachment().ok().flatten();
        if connection.is_none() {
            close(ws, 1008, "Missing connection state");
        }
        connection
    }

    async fn receive(
        &mut self,
        env: &Env,
        ws: &WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        if !self.identity.is_valid(env).await {
            close(ws, 1008, "Session expired");
            return Ok(());
        }
        self.last_received_at_seconds = crate::utils::time::now_seconds();
        match message {
            WebSocketIncomingMessage::String(text)
                if !self.is_initialized &&
                    notifications::is_signalr_handshake(&text) =>
            {
                self.is_initialized = true;
                ws.send_with_bytes(notifications::HANDSHAKE_RESPONSE)?;
            }
            WebSocketIncomingMessage::Binary(bytes)
                if self.is_initialized && bytes == notifications::PING =>
            {
                ws.send_with_bytes(notifications::PING)?;
            }
            _ => {
                close(ws, 1003, "Unsupported SignalR message");
                return Ok(());
            }
        }
        ws.serialize_attachment(self)
    }

    async fn keep_alive(&self, env: &Env, ws: &WebSocket, now: i64) -> bool {
        if now - self.last_received_at_seconds > CLIENT_IDLE_TIMEOUT_SECONDS ||
            !self.identity.is_valid(env).await
        {
            close(ws, 1008, "Session expired or inactive");
            return false;
        }
        if self.is_initialized &&
            ws.send_with_bytes(notifications::PING).is_err()
        {
            close(ws, 1011, "Ping failed");
        }
        true
    }

    async fn deliver(
        &self,
        env: &Env,
        ws: &WebSocket,
        selector: &FanoutSelector,
        bytes: &[u8],
        logout: bool,
    ) -> bool {
        // A signed internal logout is addressed to sockets authenticated
        // before a credential change; deliver it before closing them.
        if !self.identity.matches(selector) ||
            (!logout && !self.identity.is_valid(env).await)
        {
            close(ws, 1008, "Session expired");
            return false;
        }
        let sent = self.is_initialized && {
            let sent = ws.send_with_bytes(bytes).is_ok();
            if !sent {
                close(ws, 1011, "Notification delivery failed");
            }
            sent
        };
        if logout {
            close(ws, 1000, "Notification channel complete");
        }
        sent
    }
}

#[derive(Deserialize, Default)]
struct HubQuery {
    access_token: Option<String>,
    #[serde(alias = "Token")]
    token:        Option<String>,
}

#[durable_object]
pub struct NotifyDo {
    state: State,
    env:   Env,
}

impl DurableObject for NotifyDo {
    fn new(state: State, env: Env) -> Self {
        crate::infra::init(&env);
        Self { state, env }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let path = req.path();
        let path = path.trim_end_matches('/');
        match (req.method(), path) {
            (
                Method::Get,
                "/notifications/hub" | "/notifications/anonymous-hub",
            ) => {
                self.accept_websocket(&req, path.ends_with("anonymous-hub"))
                    .await
            }
            (
                Method::Post,
                "/notifications/hub/negotiate" |
                "/notifications/anonymous-hub/negotiate",
            ) => self.negotiate(&req, path.contains("anonymous-hub")).await,
            (Method::Post, notifications::FANOUT_PATH) => {
                self.fanout(&mut req).await
            }
            _ => NotificationError::NotFound.into_worker_response(),
        }
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        let Some(mut connection) = WebSocketConnection::restore(&ws) else {
            return Ok(());
        };
        connection.receive(&self.env, &ws, message).await
    }

    async fn websocket_close(
        &self,
        ws: WebSocket,
        code: usize,
        reason: String,
        _was_clean: bool,
    ) -> Result<()> {
        let code = match code {
            1000..=4999 if !matches!(code, 1004 | 1005 | 1006 | 1015) => {
                Some(code as u16)
            }
            _ => None,
        };
        let _ = ws.close(code, code.map(|_| reason.as_str()));
        if self.state.get_websockets().is_empty() {
            self.state.storage().delete_alarm().await?;
        }
        Ok(())
    }

    #[allow(
        clippy::unused_async_trait_impl,
        reason = "Keep the Worker SDK callback signature consistent with \
                  other WebSocket events."
    )]
    async fn websocket_error(
        &self,
        ws: WebSocket,
        _error: worker::Error,
    ) -> Result<()> {
        close(&ws, 1011, "WebSocket error");
        Ok(())
    }

    async fn alarm(&self) -> Result<Response> {
        let now = crate::utils::time::now_seconds();
        let mut retained = false;
        for ws in self.state.get_websockets() {
            let Some(connection) = WebSocketConnection::restore(&ws) else {
                continue;
            };
            if connection.keep_alive(&self.env, &ws, now).await {
                retained = true;
            }
        }
        if retained {
            self.state
                .storage()
                .set_alarm(KEEPALIVE_INTERVAL_MS)
                .await?;
        } else {
            self.state.storage().delete_alarm().await?;
        }
        Response::empty()
    }
}

impl NotifyDo {
    async fn identity(
        &self,
        req: &Request,
        anonymous: bool,
    ) -> AppResult<WebSocketIdentity> {
        let query = req.query::<HubQuery>().unwrap_or_default();
        if anonymous {
            let id = query
                .token
                .filter(|id| !id.is_empty() && id.len() <= 128)
                .ok_or_else(|| {
                    AppError::bad_request(
                        "Missing authentication request token",
                    )
                })?;
            let ip = req
                .headers()
                .get("cf-connecting-ip")?
                .unwrap_or_else(|| "unknown".to_string());
            let identity = WebSocketIdentity::Anonymous { request_id: id, ip };
            if !identity.is_valid(&self.env).await {
                return Err(AppError::auth_request_unavailable());
            }
            Ok(identity)
        } else {
            let token = query
                .access_token
                .or_else(|| {
                    req.headers().get("authorization").ok().flatten().and_then(
                        |value| {
                            value.strip_prefix("Bearer ").map(str::to_owned)
                        },
                    )
                })
                .ok_or_else(|| AppError::bad_request("Missing access token"))?;
            let db = db::binding(&self.env)?;
            let secret =
                crate::service::identity::jwt_keys::load(&self.env, &db)
                    .await?
                    .access_secret;
            let options = jwt::ValidationOptions {
                leeway_seconds: 0,
                ..Default::default()
            };
            let claims =
                jwt::decode::<Claims>(&token, secret.as_bytes(), &options)?;
            claims.validate_session(&db, "access").await?;
            Ok(WebSocketIdentity::User { claims })
        }
    }

    async fn negotiate(
        &self,
        req: &Request,
        anonymous: bool,
    ) -> Result<Response> {
        if self
            .identity(req, anonymous)
            .await
            .inspect_err(log_identity_database_failure)
            .is_err()
        {
            return NotificationError::Unauthorized.into_worker_response();
        }
        let id = uuid::Uuid::new_v4().to_string();
        Response::from_json(&serde_json::json!({
            "negotiateVersion":1,"connectionId":id,"connectionToken":id,
            "availableTransports":[{"transport":"WebSockets","transferFormats":["Binary"]}]
        }))
    }

    async fn accept_websocket(
        &self,
        req: &Request,
        anonymous: bool,
    ) -> Result<Response> {
        if !req
            .headers()
            .get("upgrade")?
            .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
        {
            return NotificationError::UpgradeRequired.into_worker_response();
        }
        let Ok(identity) = self
            .identity(req, anonymous)
            .await
            .inspect_err(log_identity_database_failure)
        else {
            return NotificationError::Unauthorized.into_worker_response();
        };
        let ip = req.headers().get("cf-connecting-ip")?.unwrap_or_default();
        if let Err(error) = crate::service::rate_limit::check_login_rate_limit(
            &self.env,
            format!("notification-connect:{ip}"),
        )
        .await
        {
            let rejection = match error {
                AppError::TooManyRequests { .. } => {
                    NotificationError::TooManyConnections
                }
                _ => NotificationError::Unavailable,
            };
            return rejection.into_worker_response();
        }
        let Some(tags) = identity.connection_tags(&self.state) else {
            return NotificationError::TooManyConnections
                .into_worker_response();
        };
        let pair = WebSocketPair::new()?;
        pair.server
            .serialize_attachment(WebSocketConnection::new(identity))?;
        let refs: Vec<&str> = tags.iter().map(String::as_str).collect();
        self.state.accept_websocket_with_tags(&pair.server, &refs);
        self.state
            .storage()
            .set_alarm(KEEPALIVE_INTERVAL_MS)
            .await?;
        Response::from_websocket(pair.client)
    }

    async fn fanout(&self, req: &mut Request) -> Result<Response> {
        let token = req
            .headers()
            .get(notifications::FANOUT_TOKEN_HEADER)?
            .unwrap_or_default();
        if token.is_empty() {
            return NotificationError::Forbidden.into_worker_response();
        }
        let body = req.text().await?;
        if body.len() > 65_536 ||
            notifications::verify_fanout_token(&self.env, &body, &token)
                .await
                .is_err()
        {
            return NotificationError::Forbidden.into_worker_response();
        }
        let request: FanoutRequest = match serde_json::from_str(&body) {
            Ok(request) => request,
            Err(_) => {
                return NotificationError::InvalidNotification
                    .into_worker_response();
            }
        };
        let Ok(bytes) = STANDARD.decode(&request.message) else {
            return NotificationError::InvalidNotification
                .into_worker_response();
        };
        let sent = self
            .deliver(&request.selector, &bytes, request.logout)
            .await;
        Response::from_json(&serde_json::json!({ "sent": sent }))
    }

    async fn deliver(
        &self,
        selector: &FanoutSelector,
        bytes: &[u8],
        logout: bool,
    ) -> usize {
        let mut sent = 0;
        for ws in self.state.get_websockets_with_tag(&selector.tag()) {
            let Some(connection) = WebSocketConnection::restore(&ws) else {
                continue;
            };
            if connection
                .deliver(&self.env, &ws, selector, bytes, logout)
                .await
            {
                sent += 1;
            }
        }
        sent
    }
}

fn close(ws: &WebSocket, code: u16, reason: &str) {
    let _ = ws.close(Some(code), Some(reason));
}
