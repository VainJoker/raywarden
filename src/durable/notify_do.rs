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
    api::service::{
        claims::Claims,
        notifications::{
            self,
            FanoutRequest,
            PublishSelector,
        },
    },
    errors::{
        AppError,
        AppResult,
    },
    infra::{
        crypto::ct_eq,
        jwt,
    },
    models::{
        auth_request::AuthRequestDB,
        user::UserDB,
    },
};

const KEEPALIVE_MS: i64 = 25_000;
const CLIENT_TIMEOUT_SECONDS: i64 = 120;
const MAX_USER_CONNECTIONS: usize = 40;
const MAX_ANONYMOUS_CONNECTIONS_PER_IP: usize = 25;

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ConnectionIdentity {
    User {
        claims: Claims,
    },
    Anonymous {
        request_id: String,
        ip:         String,
    },
}

#[derive(Serialize, Deserialize)]
struct Connection {
    identity:      ConnectionIdentity,
    initialized:   bool,
    last_received: i64,
}

#[derive(Deserialize, Default)]
struct HubQuery {
    access_token: Option<String>,
    #[serde(alias = "Token")]
    token:        Option<String>,
}

#[derive(Deserialize)]
struct FileSyncRequest {
    user_id:    String,
    date:       String,
    context_id: Option<String>,
}

#[durable_object]
pub struct NotifyDo {
    state: State,
    env:   Env,
}

impl DurableObject for NotifyDo {
    fn new(state: State, env: Env) -> Self {
        crate::init(&env);
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
            (Method::Post, notifications::INTERNAL_SYNC_PATH) => {
                self.file_sync(&mut req).await
            }
            (Method::Post, notifications::INTERNAL_PATH) => {
                self.fanout(&mut req).await
            }
            _ => Response::error("Not found", 404),
        }
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        let Some(mut connection) = attachment(&ws) else {
            close(&ws, 1008, "Missing connection state");
            return Ok(());
        };
        if !self.connection_valid(&connection).await {
            close(&ws, 1008, "Session expired");
            return Ok(());
        }
        connection.last_received = crate::infra::time::now_seconds();
        match message {
            WebSocketIncomingMessage::String(text)
                if !connection.initialized &&
                    notifications::is_initial_message(&text) =>
            {
                connection.initialized = true;
                ws.send_with_bytes(notifications::HANDSHAKE_RESPONSE)?;
            }
            WebSocketIncomingMessage::Binary(bytes)
                if connection.initialized && bytes == notifications::PING =>
            {
                ws.send_with_bytes(notifications::PING)?;
            }
            _ => {
                close(&ws, 1003, "Unsupported SignalR message");
                return Ok(());
            }
        }
        ws.serialize_attachment(&connection)?;
        Ok(())
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

    async fn websocket_error(
        &self,
        ws: WebSocket,
        _error: worker::Error,
    ) -> Result<()> {
        close(&ws, 1011, "WebSocket error");
        Ok(())
    }

    async fn alarm(&self) -> Result<Response> {
        let now = crate::infra::time::now_seconds();
        let mut retained = false;
        for ws in self.state.get_websockets() {
            let Some(connection) = attachment(&ws) else {
                close(&ws, 1008, "Missing connection state");
                continue;
            };
            if now - connection.last_received > CLIENT_TIMEOUT_SECONDS ||
                !self.connection_valid(&connection).await
            {
                close(&ws, 1008, "Session expired or inactive");
                continue;
            }
            retained = true;
            if connection.initialized &&
                ws.send_with_bytes(notifications::PING).is_err()
            {
                close(&ws, 1011, "Ping failed");
            }
        }
        if retained {
            self.state.storage().set_alarm(KEEPALIVE_MS).await?;
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
    ) -> AppResult<ConnectionIdentity> {
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
            let identity = ConnectionIdentity::Anonymous { request_id: id, ip };
            if !self.identity_valid(&identity).await {
                return Err(AppError::bad_request(
                    "Authentication request is unavailable",
                ));
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
            let secret =
                crate::infra::jwt_keys::load(&self.env).await?.access_secret;
            let options = jwt::ValidationOptions {
                leeway: 0,
                ..Default::default()
            };
            let claims =
                jwt::decode::<Claims>(&token, secret.as_bytes(), &options)?
                    .claims;
            let db = self.env.d1("warden-db")?;
            claims.validate_session(&db, "access").await?;
            Ok(ConnectionIdentity::User { claims })
        }
    }

    async fn identity_valid(&self, identity: &ConnectionIdentity) -> bool {
        let Ok(db) = self.env.d1("warden-db") else {
            return false;
        };
        match identity {
            ConnectionIdentity::User { claims } => {
                claims.exp > crate::infra::time::now_seconds() &&
                    claims.validate_session(&db, "access").await.is_ok()
            }
            ConnectionIdentity::Anonymous { request_id, ip } => {
                let Ok(Some(request)) =
                    AuthRequestDB::find_by_id(&db, request_id).await
                else {
                    return false;
                };
                if !request.is_active() || request.request_ip != *ip {
                    return false;
                }
                match UserDB::fetch_by_id_with(
                    &db,
                    &request.user_id,
                    "Failed to validate notification owner",
                    || AppError::not_found("User"),
                )
                .await
                {
                    Ok(user) => {
                        ct_eq(&user.security_stamp, &request.security_stamp)
                    }
                    Err(_) => false,
                }
            }
        }
    }

    async fn connection_valid(&self, connection: &Connection) -> bool {
        self.identity_valid(&connection.identity).await
    }

    async fn negotiate(
        &self,
        req: &Request,
        anonymous: bool,
    ) -> Result<Response> {
        if self.identity(req, anonymous).await.is_err() {
            return Response::error("Unauthorized", 401);
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
            return Response::error("WebSocket upgrade required", 426);
        }
        let identity = match self.identity(req, anonymous).await {
            Ok(identity) => identity,
            Err(_) => return Response::error("Unauthorized", 401),
        };
        if let Ok(limiter) = self.env.rate_limiter("LOGIN_RATE_LIMITER") {
            let ip = req.headers().get("cf-connecting-ip")?.unwrap_or_default();
            if let Ok(outcome) =
                limiter.limit(format!("notification-connect:{ip}")).await &&
                !outcome.success
            {
                return Response::error("Too many connections", 429);
            }
        }
        let tag = match &identity {
            ConnectionIdentity::User { claims } => format!("u:{}", claims.sub),
            ConnectionIdentity::Anonymous { request_id, .. } => {
                format!("a:{request_id}")
            }
        };
        let mut tags = vec![tag];
        match &identity {
            ConnectionIdentity::User { .. } => {
                if self.state.get_websockets_with_tag(&tags[0]).len() >=
                    MAX_USER_CONNECTIONS
                {
                    return Response::error("Too many connections", 429);
                }
            }
            ConnectionIdentity::Anonymous { ip, .. } => {
                let ip_tag = format!(
                    "ip:{}",
                    hex::encode(Sha256::digest(ip.as_bytes()))
                );
                if self.state.get_websockets_with_tag(&ip_tag).len() >=
                    MAX_ANONYMOUS_CONNECTIONS_PER_IP
                {
                    return Response::error("Too many connections", 429);
                }
                tags.push(ip_tag);
            }
        }
        let pair = WebSocketPair::new()?;
        pair.server.serialize_attachment(&Connection {
            identity,
            initialized: false,
            last_received: crate::infra::time::now_seconds(),
        })?;
        let refs: Vec<&str> = tags.iter().map(String::as_str).collect();
        self.state.accept_websocket_with_tags(&pair.server, &refs);
        self.state.storage().set_alarm(KEEPALIVE_MS).await?;
        Response::from_websocket(pair.client)
    }

    async fn fanout(&self, req: &mut Request) -> Result<Response> {
        let token = req
            .headers()
            .get(notifications::INTERNAL_HEADER)?
            .unwrap_or_default();
        if token.is_empty() {
            return Response::error("Forbidden", 403);
        }
        let body = req.text().await?;
        if body.len() > 65536 ||
            notifications::verify_internal(&self.env, &body, &token)
                .await
                .is_err()
        {
            return Response::error("Forbidden", 403);
        }
        let request: FanoutRequest = match serde_json::from_str(&body) {
            Ok(request) => request,
            Err(_) => return Response::error("Invalid notification", 400),
        };
        let bytes = match STANDARD.decode(&request.message) {
            Ok(bytes) => bytes,
            Err(_) => return Response::error("Invalid notification", 400),
        };
        let sent = self
            .deliver(&request.selector, &bytes, request.logout)
            .await;
        Response::from_json(&serde_json::json!({ "sent": sent }))
    }

    async fn file_sync(&self, req: &mut Request) -> Result<Response> {
        let token = req
            .headers()
            .get(notifications::INTERNAL_HEADER)?
            .unwrap_or_default();
        if token.is_empty() {
            return Response::error("Forbidden", 403);
        }
        let body = req.text().await?;
        if body.len() > 4096 ||
            notifications::verify_internal(&self.env, &body, &token)
                .await
                .is_err()
        {
            return Response::error("Forbidden", 403);
        }
        let request: FileSyncRequest = match serde_json::from_str(&body) {
            Ok(request) => request,
            Err(_) => return Response::error("Invalid notification", 400),
        };
        if request.user_id.is_empty() ||
            request.user_id.len() > 256 ||
            crate::infra::time::parse(&request.date).is_err() ||
            request.context_id.as_ref().is_some_and(|id| id.len() > 256)
        {
            return Response::error("Invalid notification", 400);
        }
        let bytes = notifications::user_update_message(
            &request.user_id,
            notifications::UpdateType::SyncVault,
            &request.date,
            request.context_id.as_deref(),
        )?;
        // Deliver directly; invoking our own DO stub here would deadlock.
        let sent = self
            .deliver(
                &PublishSelector::User {
                    user_id: request.user_id.clone(),
                },
                &bytes,
                false,
            )
            .await;
        if let Err(error) = crate::api::service::push::send_update(
            &self.env, &request.user_id, notifications::UpdateType::SyncVault as i32,
            &serde_json::json!({ "userId": request.user_id, "date": request.date }),
            request.context_id.as_deref(),
        ).await { log::warn!("File completion mobile push failed: {error}"); }
        Response::from_json(&serde_json::json!({ "sent": sent }))
    }

    async fn deliver(
        &self,
        selector: &PublishSelector,
        bytes: &[u8],
        logout: bool,
    ) -> usize {
        let mut sent = 0;
        for ws in self.state.get_websockets_with_tag(&selector.tag()) {
            let Some(connection) = attachment(&ws) else {
                close(&ws, 1008, "Missing connection state");
                continue;
            };
            let matches = match (&connection.identity, selector) {
                (
                    ConnectionIdentity::User { claims },
                    PublishSelector::User { user_id },
                ) => claims.sub == *user_id,
                (
                    ConnectionIdentity::Anonymous { request_id: id, .. },
                    PublishSelector::Anonymous { request_id },
                ) => id == request_id,
                _ => false,
            };
            // A signed internal logout is addressed to sockets authenticated
            // before a credential change; deliver it before closing them.
            if !matches ||
                (!logout && !self.connection_valid(&connection).await)
            {
                close(&ws, 1008, "Session expired");
                continue;
            }
            if connection.initialized {
                if ws.send_with_bytes(bytes).is_ok() {
                    sent += 1;
                } else {
                    close(&ws, 1011, "Notification delivery failed");
                }
            }
            if logout {
                close(&ws, 1000, "Notification channel complete");
            }
        }
        sent
    }
}

fn attachment(ws: &WebSocket) -> Option<Connection> {
    ws.deserialize_attachment().ok().flatten()
}
fn close(ws: &WebSocket, code: u16, reason: &str) {
    let _ = ws.close(Some(code), Some(reason));
}
