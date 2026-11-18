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

use crate::api::handle_request;

/// CPU offload shares the exact application stack, including authentication,
/// body limits, notification hooks and CORS.
#[durable_object]
pub struct HeavyDo {
    env: Env,
}

impl DurableObject for HeavyDo {
    fn new(_state: State, env: Env) -> Self {
        crate::init(&env);
        Self { env }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        let http_req: HttpRequest = req.try_into()?;
        let response = handle_request(http_req, self.env.clone()).await?;
        crate::infra::storage::into_worker_response(response)
    }
}
