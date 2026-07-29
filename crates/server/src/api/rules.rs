use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::middleware::from_fn;
use axum::response::IntoResponse;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde_json::json;
use uuid::Uuid;

use crate::api::ApiState;
use crate::auth::{require, Claims};
use crate::db::models::CreateRule;
use crate::db::queries;

/// Listing rules needs `rules:read`; authoring them needs `rules:write`.
///
/// Gating the whole group at `rules:write` was the other half of the same
/// mistake: it locked an `operator` — who holds `rules:read` — out of even
/// listing the rules.
pub fn routes(state: Arc<ApiState>) -> Router {
    let write = || from_fn(require("rules:write"));

    Router::new()
        .route(
            "/",
            get(list_rules)
                .route_layer(from_fn(require("rules:read")))
                .merge(post(create_rule).route_layer(write())),
        )
        .route(
            "/{id}",
            get(get_rule_route)
                .route_layer(from_fn(require("rules:read")))
                .merge(put(update_rule).delete(delete_rule).route_layer(write())),
        )
        .with_state(state)
}

async fn list_rules(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    match queries::list_rules(&state.pool).await {
        Ok(rules) => (StatusCode::OK, Json(json!(rules))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn create_rule(
    State(state): State<Arc<ApiState>>,
    claims: Option<axum::extract::Extension<Claims>>,
    Json(rule): Json<CreateRule>,
) -> impl IntoResponse {
    let user_id = claims.map(|c| c.0.sub);
    match queries::create_rule(&state.pool, &rule, user_id).await {
        Ok(r) => (StatusCode::CREATED, Json(json!(r))).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn update_rule(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<Uuid>,
    Json(rule): Json<CreateRule>,
) -> impl IntoResponse {
    match queries::update_rule(&state.pool, id, &rule).await {
        Ok(Some(r)) => (StatusCode::OK, Json(json!(r))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "rule not found"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn delete_rule(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match queries::delete_rule(&state.pool, id).await {
        Ok(true) => (StatusCode::NO_CONTENT, ()).into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "rule not found"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn get_rule_route(
    State(state): State<Arc<ApiState>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match queries::get_rule(&state.pool, id).await {
        Ok(Some(rule)) => (StatusCode::OK, Json(json!(rule))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "rule not found"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}
