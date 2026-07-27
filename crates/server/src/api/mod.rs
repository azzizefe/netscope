pub mod auth_routes;
pub mod sensors;
pub mod events;
pub mod alerts;
pub mod rules;
pub mod dashboard;
pub mod health;
pub mod upgrade;

use axum::Router;
use std::sync::Arc;
use sqlx::PgPool;

use crate::auth::{JwtState, RbacState};
use crate::cache::CacheLayer;
use crate::api::sensors::CommandStore;

pub fn build_router(
    pool: PgPool,
    jwt: Arc<JwtState>,
    rbac: Arc<RbacState>,
    cache: Option<Arc<CacheLayer>>,
) -> Router {
    let commands = CommandStore::new();
    let api_state = Arc::new(ApiState {
        pool,
        cache,
        commands,
    });

    let public = Router::new()
        .nest("/api/v1", auth_routes::routes(api_state.clone(), jwt.clone()))
        .nest("/api/v1", upgrade::routes(api_state.clone()));

    let protected = Router::new()
        .nest("/api/v1/sensors", sensors::routes(api_state.clone()))
        .nest("/api/v1/events", events::routes(api_state.clone()))
        .nest("/api/v1/alerts", alerts::routes(api_state.clone()))
        .nest("/api/v1/rules", rules::routes(api_state.clone()))
        .nest("/api/v1/dashboard", dashboard::routes(api_state.clone()))
        .nest("/api/v1", health::routes())
        .layer(axum::middleware::from_fn(crate::auth::auth_middleware));

    Router::new()
        .merge(public)
        .merge(protected)
        .layer(axum::extract::Extension(jwt))
        .layer(axum::extract::Extension(rbac))
}

pub struct ApiState {
    pub pool: PgPool,
    pub cache: Option<Arc<CacheLayer>>,
    pub commands: Arc<CommandStore>,
}
