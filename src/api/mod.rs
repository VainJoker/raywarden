pub(crate) mod bootstrap;
mod common;
mod controller;
mod dispatch;
pub(crate) mod durable;
pub(crate) mod middleware;
mod routers;

use std::sync::Arc;

pub(crate) use dispatch::handle_fetch;

use crate::app::AppContext;

type AppState = Arc<AppContext>;
