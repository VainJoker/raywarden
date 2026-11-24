//! Thin Cloudflare Durable Object adapter over `service::notifications::hub`.
use std::future::ready;

use futures_util::StreamExt;
use serde::Deserialize;
use worker::{
    DurableObject, Env, Method, Request, Response, Result, State, WebSocket,
    WebSocketIncomingMessage, WebSocketPair, durable_object,
};

use super::{NotificationError, PublicNotificationEndpoint};
use crate::{
    service::notifications::{
        self, FanoutSelector, PING,
        hub::{
            self, FilterOutcome, FrameDecision, HubError, HubIdentity, HubResult, HubSession,
            IncomingFrame,
        },
    },
    utils::time,
};

const KEEPALIVE_INTERVAL_MS: i64 = 25_000;
const FANOUT_MAX_BYTES: usize = 65_536;

enum NotifyRoute {
    Public(PublicNotificationEndpoint),
    Fanout,
}

impl NotifyRoute {
    fn classify(method: &Method, path: &str) -> Option<Self> {
        let trimmed = path.trim_end_matches('/');
        if let Some(endpoint) = PublicNotificationEndpoint::parse(trimmed) {
            let (expected, _) = endpoint.expected_method();
            return (*method == expected).then_some(Self::Public(endpoint));
        }
        (*method == Method::Post && trimmed == notifications::FANOUT_PATH).then_some(Self::Fanout)
    }
}

#[derive(Deserialize, Default)]
struct HubQuery {
    access_token: Option<String>,
    #[serde(alias = "Token")]
    token: Option<String>,
}

// The adapter name is also the lowercase Cloudflare class export.
#[allow(non_camel_case_types)]
#[durable_object]
pub struct notifydo {
    state: State,
    env: Env,
}

impl DurableObject for notifydo {
    fn new(state: State, env: Env) -> Self {
        crate::infra::init(&env);
        Self { state, env }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        match NotifyRoute::classify(&req.method(), &req.path()) {
            Some(NotifyRoute::Public(PublicNotificationEndpoint::Upgrade { anonymous })) => {
                self.accept_websocket(&req, anonymous).await
            }
            Some(NotifyRoute::Public(PublicNotificationEndpoint::Negotiate { anonymous })) => {
                self.negotiate(&req, anonymous).await
            }
            Some(NotifyRoute::Fanout) => self.fanout(&mut req).await,
            None => NotificationError::NotFound.into_worker_response(),
        }
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        let Some(mut session) = restore_session(&ws) else {
            return Ok(());
        };
        let frame = match &message {
            WebSocketIncomingMessage::String(text) => IncomingFrame::Text(text),
            WebSocketIncomingMessage::Binary(bytes) => IncomingFrame::Binary(bytes),
        };
        match session.handle_frame(&self.env, frame).await {
            FrameDecision::Reply(bytes) => {
                ws.send_with_bytes(bytes)?;
                ws.serialize_attachment(&session)
            }
            FrameDecision::Close { code, reason } => {
                close_socket(&ws, code, reason);
                Ok(())
            }
        }
    }

    fn websocket_close(
        &self,
        ws: WebSocket,
        code: usize,
        reason: String,
        _was_clean: bool,
    ) -> impl Future<Output = Result<()>> {
        let code = match code {
            1000..=4999 if !matches!(code, 1004 | 1005 | 1006 | 1015) => Some(code as u16),
            _ => None,
        };
        let _ = ws.close(code, code.map(|_| reason.as_str()));
        ready(Ok(()))
    }

    fn websocket_error(
        &self,
        ws: WebSocket,
        _error: worker::Error,
    ) -> impl Future<Output = Result<()>> {
        close_socket(&ws, 1011, "WebSocket error");
        ready(Ok(()))
    }

    async fn alarm(&self) -> Result<Response> {
        let now = time::now_seconds();
        let active = open_sessions(self.state.get_websockets())
            .filter(|(ws, session)| apply_filter(ws, session.evaluate_keepalive(now)))
            .collect::<Vec<_>>();
        let results =
            hub::validate_sessions(&self.env, active.iter().map(|(_, session)| session)).await;
        for ((ws, session), result) in active.into_iter().zip(results) {
            if !confirm_socket(&ws, result, "Session expired or inactive") {
                continue;
            }
            if session.is_initialized() && ws.send_with_bytes(PING).is_err() {
                close_socket(&ws, 1011, "Ping failed");
            }
        }
        // New sockets can arrive while D1 validates the original connections.
        // An idle alarm can expire naturally without canceling a newer alarm.
        if self
            .state
            .get_websockets()
            .iter()
            .any(|ws| ws.as_ref().ready_state() == web_sys::WebSocket::OPEN)
        {
            self.ensure_keepalive_alarm().await?;
        }
        Response::empty()
    }
}

impl notifydo {
    async fn ensure_keepalive_alarm(&self) -> Result<()> {
        let storage = self.state.storage();
        if storage.get_alarm().await?.is_none() {
            storage.set_alarm(KEEPALIVE_INTERVAL_MS).await?;
        }
        Ok(())
    }

    async fn authenticate(
        &self,
        req: &Request,
        anonymous: bool,
        client_ip: Option<&str>,
    ) -> HubResult<HubIdentity> {
        let query = req.query::<HubQuery>().unwrap_or_default();
        let auth_header = if !anonymous && query.access_token.is_none() {
            req.headers()
                .get("authorization")
                .map_err(|_error| hub::unavailable("read Authorization header"))?
        } else {
            None
        };
        HubIdentity::authenticate(
            &self.env,
            anonymous,
            query.access_token,
            query.token,
            auth_header.as_deref(),
            client_ip,
        )
        .await
    }

    fn connection_tags(&self, identity: &HubIdentity) -> Option<Vec<String>> {
        let (mut tags, limit_tag, limit) = identity.tag_policy();
        if self.state.get_websockets_with_tag(&limit_tag).len() >= limit {
            return None;
        }
        tags.push(limit_tag);
        Some(tags)
    }

    async fn negotiate(&self, req: &Request, anonymous: bool) -> Result<Response> {
        let Ok(ip) = req.headers().get("cf-connecting-ip") else {
            return NotificationError::from(hub::unavailable("read client IP header"))
                .into_worker_response();
        };
        if let Err(error) = self.authenticate(req, anonymous, ip.as_deref()).await {
            return NotificationError::from(error).into_worker_response();
        }
        let id = uuid::Uuid::new_v4().to_string();
        Response::from_json(&serde_json::json!({
            "negotiateVersion":1,"connectionId":id,"connectionToken":id,
            "availableTransports":[{"transport":"WebSockets","transferFormats":["Binary"]}]
        }))
    }

    async fn accept_websocket(&self, req: &Request, anonymous: bool) -> Result<Response> {
        if !req
            .headers()
            .get("upgrade")?
            .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
        {
            return NotificationError::UpgradeRequired.into_worker_response();
        }
        let Ok(ip) = req.headers().get("cf-connecting-ip") else {
            return NotificationError::from(hub::unavailable("read client IP header"))
                .into_worker_response();
        };
        let identity = match self.authenticate(req, anonymous, ip.as_deref()).await {
            Ok(identity) => identity,
            Err(error) => return NotificationError::from(error).into_worker_response(),
        };
        if let Err(error) = hub::check_connect_rate_limit(&self.env, ip.as_deref()).await {
            return NotificationError::from(error).into_worker_response();
        }
        if self.connection_tags(&identity).is_none() {
            return NotificationError::from(HubError::TooManyConnections).into_worker_response();
        }
        if self.ensure_keepalive_alarm().await.is_err() {
            log::warn!("Notification upgrade could not schedule keepalive");
            return NotificationError::from(HubError::Unavailable).into_worker_response();
        }
        // Recheck capacity after the await. Checking and accepting the socket
        // must stay synchronous so another upgrade cannot race the limit.
        let Some(tags) = self.connection_tags(&identity) else {
            return NotificationError::from(HubError::TooManyConnections).into_worker_response();
        };
        let pair = WebSocketPair::new()?;
        pair.server
            .serialize_attachment(HubSession::new(identity))?;
        let refs: Vec<&str> = tags.iter().map(String::as_str).collect();
        self.state.accept_websocket_with_tags(&pair.server, &refs);
        Response::from_websocket(pair.client)
    }

    async fn fanout(&self, req: &mut Request) -> Result<Response> {
        let token = req
            .headers()
            .get(notifications::FANOUT_TOKEN_HEADER)?
            .unwrap_or_default();
        if token.is_empty() {
            return NotificationError::from(HubError::Forbidden).into_worker_response();
        }
        let Some(body) = read_bounded_fanout_body(req).await? else {
            return NotificationError::from(HubError::Forbidden).into_worker_response();
        };
        let fanout = match hub::verify_and_decode_fanout(&self.env, &body, &token).await {
            Ok(fanout) => fanout,
            Err(error) => return NotificationError::from(error).into_worker_response(),
        };
        let sent = self
            .deliver(&fanout.selector, &fanout.payload, fanout.logout)
            .await;
        Response::from_json(&serde_json::json!({ "sent": sent }))
    }

    async fn deliver(&self, selector: &FanoutSelector, bytes: &[u8], logout: bool) -> usize {
        let active = open_sessions(self.state.get_websockets_with_tag(&selector.tag()))
            .filter(|(ws, session)| apply_filter(ws, session.evaluate_fanout(selector, logout)))
            .collect::<Vec<_>>();
        if logout {
            return active
                .iter()
                .filter(|(ws, session)| send_frame(ws, session, bytes, true, Ok(())))
                .count();
        }
        let results =
            hub::validate_sessions(&self.env, active.iter().map(|(_, session)| session)).await;
        active
            .into_iter()
            .zip(results)
            .filter(|((ws, session), result)| send_frame(ws, session, bytes, false, *result))
            .count()
    }
}

fn restore_session(ws: &WebSocket) -> Option<HubSession> {
    let session = ws.deserialize_attachment().ok().flatten();
    if session.is_none() {
        close_socket(ws, 1008, "Missing connection state");
    }
    session
}

fn open_sessions(sockets: Vec<WebSocket>) -> impl Iterator<Item = (WebSocket, HubSession)> {
    sockets
        .into_iter()
        .filter(|ws| ws.as_ref().ready_state() == web_sys::WebSocket::OPEN)
        .filter_map(|ws| restore_session(&ws).map(|session| (ws, session)))
}

fn apply_filter(ws: &WebSocket, outcome: FilterOutcome) -> bool {
    match outcome {
        FilterOutcome::Include => true,
        FilterOutcome::Skip => false,
        FilterOutcome::Close { code, reason } => {
            close_socket(ws, code, reason);
            false
        }
    }
}

fn confirm_socket(ws: &WebSocket, result: HubResult<()>, invalid_reason: &'static str) -> bool {
    match result {
        Ok(()) => true,
        Err(error) => {
            let (code, reason) = hub::close_for_rejection(error, invalid_reason);
            close_socket(ws, code, reason);
            false
        }
    }
}

fn send_frame(
    ws: &WebSocket,
    session: &HubSession,
    bytes: &[u8],
    logout: bool,
    validation: HubResult<()>,
) -> bool {
    // A signed internal logout is addressed to sockets authenticated before a
    // credential change; deliver it before closing them.
    if !logout && !confirm_socket(ws, validation, "Session expired") {
        return false;
    }
    let sent = session.is_initialized() && {
        let ok = ws.send_with_bytes(bytes).is_ok();
        if !ok {
            close_socket(ws, 1011, "Notification delivery failed");
        }
        ok
    };
    if logout {
        close_socket(ws, 1000, "Notification channel complete");
    }
    sent
}

fn close_socket(ws: &WebSocket, code: u16, reason: &str) {
    let _ = ws.close(Some(code), Some(reason));
}

async fn read_bounded_fanout_body(req: &mut Request) -> Result<Option<String>> {
    if let Some(length) = req
        .headers()
        .get("content-length")?
        .filter(|value| !value.is_empty())
        && (!length.bytes().all(|byte| byte.is_ascii_digit())
            || !length
                .parse::<usize>()
                .is_ok_and(|size| size <= FANOUT_MAX_BYTES))
    {
        return Ok(None);
    }
    if req.inner().body().is_none() {
        return Ok(Some(String::new()));
    }
    let mut stream = req.stream()?;
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if chunk.len() > FANOUT_MAX_BYTES - bytes.len() {
            return Ok(None);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8(bytes).ok())
}
