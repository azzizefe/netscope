// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::api::ApiState;
use crate::auth::{self, AuthResponse, JwtState, LoginRequest};
use crate::db::models::CreateUser;
use crate::db::queries;

#[derive(Debug, Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
    pub permissions: Vec<String>,
    pub ttl_days: Option<u64>,
}

pub fn routes(api_state: Arc<ApiState>, jwt: Arc<JwtState>) -> Router {
    Router::new()
        .route("/auth/login", post(login))
        .route("/auth/register", post(register))
        .route("/auth/sessions", get(list_sessions))
        .route("/auth/sessions/{id}", delete(revoke_session))
        .route("/auth/sessions/all/{user_id}", delete(revoke_all_sessions))
        .route("/auth/force-reset/{user_id}", post(force_password_reset))
        .route("/auth/api-keys", post(create_api_key).get(list_api_keys))
        .route("/auth/api-keys/{id}", delete(revoke_api_key))
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
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "invalid credentials"})),
            )
                .into_response()
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };

    if !user.is_active {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "account disabled"})),
        )
            .into_response();
    }

    match auth::verify_password(&creds.password, &user.password_hash) {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "invalid credentials"})),
            )
                .into_response()
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    }

    let token = match jwt.create_token(user.id, &user.username, &user.role) {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };

    // Register active session in SessionManager (§1.1.1, §1.1.4)
    let (session, _raw_token) = state.session_mgr.create_session(user.id, &user.username, "127.0.0.1", "netscope-client");

    (
        StatusCode::OK,
        Json(json!({
            "token": token,
            "session_id": session.session_id,
            "user_id": user.id,
            "username": user.username,
            "role": user.role,
            "expires_at_epoch": session.expires_at_epoch
        })),
    )
        .into_response()
}

async fn register(
    State(state): State<Arc<ApiState>>,
    axum::extract::Extension(jwt): axum::extract::Extension<Arc<JwtState>>,
    Json(create): Json<CreateUser>,
) -> impl IntoResponse {
    let hash = match auth::hash_password(&create.password) {
        Ok(h) => h,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };

    let role = if create.role.is_empty() {
        "viewer".into()
    } else {
        create.role.clone()
    };
    if !["admin", "operator", "analyst", "viewer"].contains(&role.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid role"})),
        )
            .into_response();
    }

    let user = match queries::create_user(
        &state.pool,
        &CreateUser {
            username: create.username.clone(),
            email: create.email.clone(),
            password: create.password,
            role: role.clone(),
        },
        &hash,
    )
    .await
    {
        Ok(u) => u,
        Err(e) => {
            if e.to_string().contains("unique") || e.to_string().contains("duplicate") {
                return (
                    StatusCode::CONFLICT,
                    Json(json!({"error": "user already exists"})),
                )
                    .into_response();
            }
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };

    let token = match jwt.create_token(user.id, &user.username, &user.role) {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };

    (
        StatusCode::CREATED,
        Json(json!(AuthResponse {
            token,
            user_id: user.id,
            username: user.username,
            role: user.role,
        })),
    )
        .into_response()
}

/// List active sessions (§1.1.1, §1.1.5).
async fn list_sessions(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let dummy_user_id = Uuid::nil();
    let sessions = state.session_mgr.list_user_sessions(dummy_user_id);
    (StatusCode::OK, Json(json!(sessions)))
}

/// Revoke a session by ID (§1.1.5).
async fn revoke_session(
    State(state): State<Arc<ApiState>>,
    Path(session_id): Path<String>,
) -> impl IntoResponse {
    let success = state.session_mgr.revoke_session(&session_id);
    if success {
        (StatusCode::OK, Json(json!({"status": "revoked", "session_id": session_id})))
    } else {
        (StatusCode::NOT_FOUND, Json(json!({"error": "session not found"})))
    }
}

/// Revoke all active sessions for a user (§1.1.5).
async fn revoke_all_sessions(
    State(state): State<Arc<ApiState>>,
    Path(user_id_str): Path<String>,
) -> impl IntoResponse {
    let user_id = match user_id_str.parse::<Uuid>() {
        Ok(u) => u,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid user_id uuid"}))),
    };
    let count = state.session_mgr.revoke_all_sessions_for_user(user_id);
    (StatusCode::OK, Json(json!({"status": "all_sessions_revoked", "count": count})))
}

/// Force password reset flag on next login (§1.1.6).
async fn force_password_reset(
    State(state): State<Arc<ApiState>>,
    Path(user_id_str): Path<String>,
) -> impl IntoResponse {
    let user_id = match user_id_str.parse::<Uuid>() {
        Ok(u) => u,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid user_id uuid"}))),
    };
    let count = state.session_mgr.force_password_reset(user_id);
    (StatusCode::OK, Json(json!({"status": "password_reset_forced", "revoked_sessions": count})))
}

/// Create a scoped API Key (§1.1.7).
async fn create_api_key(
    State(state): State<Arc<ApiState>>,
    Json(req): Json<CreateApiKeyRequest>,
) -> impl IntoResponse {
    let dummy_user_id = Uuid::nil();
    let (key_meta, raw_key) = state.session_mgr.create_api_key(&req.name, dummy_user_id, req.permissions, req.ttl_days);

    (
        StatusCode::CREATED,
        Json(json!({
            "key_id": key_meta.key_id,
            "raw_key": raw_key,
            "name": key_meta.name,
            "permissions": key_meta.permissions,
            "created_at_epoch": key_meta.created_at_epoch,
            "expires_at_epoch": key_meta.expires_at_epoch
        })),
    )
}

/// List active API Keys (§1.1.7).
async fn list_api_keys(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let dummy_user_id = Uuid::nil();
    let keys = state.session_mgr.list_user_api_keys(dummy_user_id);
    (StatusCode::OK, Json(json!(keys)))
}

/// Revoke an API Key (§1.1.7).
async fn revoke_api_key(
    State(state): State<Arc<ApiState>>,
    Path(key_id): Path<String>,
) -> impl IntoResponse {
    let success = state.session_mgr.revoke_api_key(&key_id);
    if success {
        (StatusCode::OK, Json(json!({"status": "revoked", "key_id": key_id})))
    } else {
        (StatusCode::NOT_FOUND, Json(json!({"error": "api key not found"})))
    }
}
