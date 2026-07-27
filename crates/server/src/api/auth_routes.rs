use std::sync::Arc;

use axum::{Json, Router};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use serde_json::json;
use uuid::Uuid;

use crate::api::ApiState;
use crate::auth::{self, AuthResponse, JwtState, LoginRequest};
use crate::db::models::CreateUser;
use crate::db::queries;

pub fn routes(api_state: Arc<ApiState>, jwt: Arc<JwtState>) -> Router {
    Router::new()
        .route("/auth/login", post(login))
        .route("/auth/register", post(register))
        .with_state(api_state)
        .layer(axum::extract::Extension(jwt))
}

async fn login(
    State(state): State<Arc<ApiState>>,
    axum::extract::Extension(jwt): axum::extract::Extension<Arc<JwtState>>,
    Json(creds): Json<LoginRequest>,
) -> impl IntoResponse {
    let user = match queries::get_user_by_username(&state.pool, &creds.username).await {
        Ok(Some(u)) => u,
        Ok(None) => return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid credentials"}))).into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    };

    if !user.is_active {
        return (StatusCode::FORBIDDEN, Json(json!({"error": "account disabled"}))).into_response();
    }

    match auth::verify_password(&creds.password, &user.password_hash) {
        Ok(true) => {}
        Ok(false) => return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid credentials"}))).into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }

    let token = match jwt.create_token(user.id, &user.username, &user.role) {
        Ok(t) => t,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    };

    (StatusCode::OK, Json(json!(AuthResponse {
        token,
        user_id: user.id,
        username: user.username,
        role: user.role,
    }))).into_response()
}

async fn register(
    State(state): State<Arc<ApiState>>,
    axum::extract::Extension(jwt): axum::extract::Extension<Arc<JwtState>>,
    Json(create): Json<CreateUser>,
) -> impl IntoResponse {
    let hash = match auth::hash_password(&create.password) {
        Ok(h) => h,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    };

    let role = if create.role.is_empty() { "viewer".into() } else { create.role.clone() };
    if !["admin", "operator", "analyst", "viewer"].contains(&role.as_str()) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid role"}))).into_response();
    }

    let user = match queries::create_user(&state.pool, &CreateUser {
        username: create.username.clone(),
        email: create.email.clone(),
        password: create.password,
        role: role.clone(),
    }, &hash).await {
        Ok(u) => u,
        Err(e) => {
            if e.to_string().contains("unique") || e.to_string().contains("duplicate") {
                return (StatusCode::CONFLICT, Json(json!({"error": "user already exists"}))).into_response();
            }
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response();
        }
    };

    let token = match jwt.create_token(user.id, &user.username, &user.role) {
        Ok(t) => t,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    };

    (StatusCode::CREATED, Json(json!(AuthResponse {
        token,
        user_id: user.id,
        username: user.username,
        role: user.role,
    }))).into_response()
}
