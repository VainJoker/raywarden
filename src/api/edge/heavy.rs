//! Forward CPU- and upload-heavy requests to the `heavydo` Durable Object.
use worker::{
    DurableObject, Env, HttpRequest, Method, Request, Response, Result as WorkerResult, State,
    Stub, durable_object,
};

use crate::{
    api::{
        bootstrap::{handle_request, worker_error_response},
        common::response::into_worker_response,
        middleware::cors::CorsContext,
    },
    errors::{AppResult, extract_ray_id},
    infra::config::env_bool,
};

/// CPU offload shares the exact application stack, including authentication,
/// body limits, post-commit notifications and CORS.
#[allow(non_camel_case_types)]
#[durable_object]
pub struct heavydo {
    env: Env,
}

impl DurableObject for heavydo {
    fn new(_state: State, env: Env) -> Self {
        crate::infra::init(&env);
        Self { env }
    }

    async fn fetch(&self, req: Request) -> WorkerResult<Response> {
        let head = req.method() == Method::Head;
        let ray_id = extract_ray_id(req.headers().get("cf-ray").ok().flatten().as_deref());
        let cors = CorsContext::new(&req, &self.env);
        let http_req: HttpRequest = req.try_into()?;
        match handle_request(http_req, self.env.clone(), cors.policy()).await {
            Ok(response) => into_worker_response(response),
            Err(error) => worker_error_response(error, &cors, ray_id.as_deref(), head),
        }
    }
}

pub(super) fn select_stub(path: &str, method: &Method, env: &Env) -> AppResult<Option<Stub>> {
    if !is_heavy_route(path, method) || !env_bool(env, "HEAVY_DO_ENABLED", true) {
        return Ok(None);
    }
    let Ok(namespace) = env.durable_object("heavydo") else {
        return Ok(None);
    };
    Ok(Some(namespace.id_from_name("global")?.get_stub()?))
}

pub(super) fn is_heavy_route(path: &str, method: &Method) -> bool {
    if is_file_upload(path, method) {
        return true;
    }
    matches!(
        (path, method),
        ("/api/accounts", Method::Delete)
            | (
                "/api/two-factor/authenticator",
                Method::Post | Method::Put | Method::Delete
            )
            | ("/api/two-factor/disable", Method::Post | Method::Put)
            | (
                "/identity/connect/token"
                    | "/api/accounts/register"
                    | "/identity/accounts/register"
                    | "/identity/accounts/register/finish"
                    | "/api/ciphers/import"
                    | "/api/accounts/password"
                    | "/api/accounts/kdf"
                    | "/api/accounts/delete"
                    | "/api/ciphers/purge"
                    | "/api/accounts/security-stamp"
                    | "/api/accounts/key-management/rotate-user-keys"
                    | "/api/accounts/key-management/rotate-user-account-keys"
                    | "/api/accounts/verify-password"
                    | "/accounts/verify-password"
                    | "/api/accounts/api-key"
                    | "/api/accounts/rotate-api-key"
                    | "/api/two-factor/get-authenticator"
                    | "/api/two-factor/get-recover"
                    | "/api/two-factor/recover",
                Method::Post,
            )
    )
}

fn is_file_upload(path: &str, method: &Method) -> bool {
    if !matches!(method, Method::Post | Method::Put) {
        return false;
    }
    let Some(rest) = path
        .strip_prefix("/api/")
        .or_else(|| path.strip_prefix('/'))
        .map(|subpath| subpath.trim_end_matches('/'))
    else {
        return false;
    };
    let mut s = rest.split('/');
    match (
        method,
        s.next(),
        s.next(),
        s.next(),
        s.next(),
        s.next(),
        s.next(),
    ) {
        (Method::Post, Some("ciphers"), Some(_), Some("attachment"), Some(id), None, None) => {
            id != "v2"
        }
        (Method::Post, Some("sends"), Some(_), Some("file"), Some(_), None, None)
        | (
            Method::Put,
            Some("ciphers"),
            Some(_),
            Some("attachment"),
            Some(_),
            Some("azure-upload"),
            None,
        )
        | (
            Method::Post | Method::Put,
            Some("sends"),
            Some(_),
            Some("file"),
            Some(_),
            Some("azure-upload"),
            None,
        ) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_uploads_and_heavy_mutations_without_capturing_reads() {
        for (path, method) in [
            ("/identity/connect/token", Method::Post),
            ("/api/accounts/register", Method::Post),
            ("/api/ciphers/import", Method::Post),
            ("/api/accounts", Method::Delete),
            ("/api/ciphers/c/attachment/a", Method::Post),
            ("/api/ciphers/c/attachment/a/azure-upload", Method::Put),
            ("/api/sends/s/file/f", Method::Post),
            ("/api/sends/s/file/f/azure-upload", Method::Put),
        ] {
            assert!(is_heavy_route(path, &method), "{method} {path}");
        }
        for (path, method) in [
            ("/api/sync", Method::Get),
            ("/identity/connect/token", Method::Get),
            ("/api/ciphers/c/attachment/v2", Method::Post),
            ("/api/ciphers/c/attachment/a/download", Method::Get),
            ("/api/sends/s/f", Method::Get),
        ] {
            assert!(!is_heavy_route(path, &method), "{method} {path}");
        }
    }
}
