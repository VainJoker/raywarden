use worker::{
    DurableObject,
    Env,
    HttpRequest,
    Request,
    Response,
    Result,
    State,
    durable_object,
};

use crate::api::{
    bootstrap::handle_request,
    middleware::cors::CorsPolicy,
};

/// CPU offload shares the exact application stack, including authentication,
/// body limits, post-commit notifications and CORS.
#[durable_object]
pub struct HeavyDo {
    env: Env,
}

impl DurableObject for HeavyDo {
    fn new(_state: State, env: Env) -> Self {
        crate::infra::init(&env);
        Self { env }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        let http_req: HttpRequest = req.try_into()?;
        let cors = CorsPolicy::from_env(&self.env);
        let response =
            handle_request(http_req, self.env.clone(), &cors).await?;
        crate::infra::worker_response::into_worker_response(response)
    }
}
