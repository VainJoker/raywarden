//! Thin Cloudflare Durable Object adapter over `service::notifications::hub`.
use std::future::ready;

use serde::Deserialize;
use worker::{
    DurableObject, Env, Method, Request, Response, ResponseBuilder, Result, State, WebSocket,
    WebSocketIncomingMessage, WebSocketPair, durable_object,
};

use super::PublicNotificationEndpoint;
use crate::{
    service::notifications::{
        self, FanoutSelector, PING,
        hub::{self, FilterOutcome, FrameDecision, HubError, HubIdentity, HubResult, HubSession},
    },
    utils::{bounded_content_length, collect_bounded, time},
};

const KEEPALIVE_INTERVAL_MS: i64 = 25_000;
const FANOUT_MAX_BYTES: usize = 65_536;

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
        let path = req.path();
        let path = path.trim_end_matches('/');
        let method = req.method();
        if method == Method::Post && path == notifications::FANOUT_PATH {
            return self.fanout(&mut req).await;
        }
        if let Some(endpoint) = PublicNotificationEndpoint::parse(path)
            && method == endpoint.expected_method().0
        {
            return self.handle_public(&req, endpoint).await;
        }
        Response::error("Not found", 404)
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        let Some(mut session) = restore_session(&ws) else {
            return Ok(());
        };
        match session.handle_frame(&self.env, &message).await {
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
        let mut policy = identity.tag_policy();
        if self
            .state
            .get_websockets_with_tag(&policy.capacity_tag)
            .len()
            >= policy.max_connections
        {
            return None;
        }
        policy.routing_tags.push(policy.capacity_tag);
        Some(policy.routing_tags)
    }

    async fn handle_public(
        &self,
        req: &Request,
        endpoint: PublicNotificationEndpoint,
    ) -> Result<Response> {
        let (anonymous, upgrade) = match endpoint {
            PublicNotificationEndpoint::Upgrade { anonymous } => (anonymous, true),
            PublicNotificationEndpoint::Negotiate { anonymous } => (anonymous, false),
        };
        if upgrade
            && !req
                .headers()
                .get("upgrade")?
                .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
        {
            return ResponseBuilder::new()
                .with_header("Upgrade", "websocket")?
                .with_header("Connection", "upgrade")?
                .error("WebSocket upgrade required", 426);
        }
        let Ok(ip) = req.headers().get("cf-connecting-ip") else {
            return hub::unavailable("read client IP header").response();
        };
        let identity = match self.authenticate(req, anonymous, ip.as_deref()).await {
            Ok(identity) => identity,
            Err(error) => return error.response(),
        };
        if upgrade {
            self.accept_websocket(identity, ip.as_deref()).await
        } else {
            let id = uuid::Uuid::new_v4().to_string();
            Response::from_json(&serde_json::json!({
                "negotiateVersion":1,"connectionId":id,"connectionToken":id,
                "availableTransports":[{"transport":"WebSockets","transferFormats":["Binary"]}]
            }))
        }
    }

    async fn accept_websocket(&self, identity: HubIdentity, ip: Option<&str>) -> Result<Response> {
        if let Err(error) = hub::check_connect_rate_limit(&self.env, ip).await {
            return error.response();
        }
        if self.connection_tags(&identity).is_none() {
            return HubError::TooManyConnections.response();
        }
        if self.ensure_keepalive_alarm().await.is_err() {
            log::warn!("Notification upgrade could not schedule keepalive");
            return HubError::Unavailable.response();
        }
        // Recheck capacity after the await. Checking and accepting the socket
        // must stay synchronous so another upgrade cannot race the limit.
        let Some(tags) = self.connection_tags(&identity) else {
            return HubError::TooManyConnections.response();
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
            return HubError::Forbidden.response();
        }
        let Some(body) = read_bounded_fanout_body(req).await? else {
            return HubError::Forbidden.response();
        };
        let fanout = match hub::verify_and_decode_fanout(&self.env, &body, &token).await {
            Ok(fanout) => fanout,
            Err(error) => return error.response(),
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
    if !bounded_content_length(
        req.headers().get("content-length")?.as_deref(),
        FANOUT_MAX_BYTES,
    ) {
        return Ok(None);
    }
    if req.inner().body().is_none() {
        return Ok(Some(String::new()));
    }
    Ok(collect_bounded(req.stream()?, FANOUT_MAX_BYTES)
        .await?
        .and_then(|bytes| String::from_utf8(bytes).ok()))
}
