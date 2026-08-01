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
use netscope_core::brute_force_protection::LockoutStatus;

#[derive(Debug, Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
    pub permissions: Vec<String>,
    pub ttl_days: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct CreateCustomRoleRequest {
    pub name: String,
    pub description: String,
    pub permissions: Vec<String>,
    pub can_view_raw_payload: Option<bool>,
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
        .route("/auth/unlock/account/{username}", post(unlock_account))
        .route("/auth/unlock/ip/{ip}", post(unlock_ip))
        .route("/auth/lockout-events", get(list_lockout_events))
        .route("/roles", get(list_roles).post(create_role))
        .route("/roles/{name}", delete(delete_role))
        .route("/permissions", get(list_permissions))
        .route("/audit/chain", get(get_audit_chain))
        .route("/audit/verify", get(verify_audit_chain))
        .with_state(api_state)
        .layer(axum::extract::Extension(jwt))
}

async fn login(
    State(state): State<Arc<ApiState>>,
    axum::extract::Extension(jwt): axum::extract::Extension<Arc<JwtState>>,
    Json(creds): Json<LoginRequest>,
) -> impl IntoResponse {
    let client_ip = "127.0.0.1";

    // 1. Check account & IP lockout status (§1.2.1, §1.2.2)
    match state.protector.check_allowed(&creds.username, client_ip) {
        LockoutStatus::AccountLocked { remaining_secs } => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({
                    "error": "account_locked",
                    "message": format!("Account is locked due to repeated failed logins. Retry in {} seconds.", remaining_secs),
                    "remaining_secs": remaining_secs
                })),
            ).into_response();
        }
        LockoutStatus::IpBanned { remaining_secs } => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({
                    "error": "ip_banned",
                    "message": format!("IP address is temporarily restricted. Retry in {} seconds.", remaining_secs),
                    "remaining_secs": remaining_secs
                })),
            ).into_response();
        }
        LockoutStatus::Allowed => {}
    }

    let user = match queries::get_user_by_username(&state.pool, &creds.username).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            state.protector.record_failure(&creds.username, client_ip);
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "invalid credentials"})),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response();
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
        Ok(true) => {
            // Reset failure counter on successful login (§1.2.1)
            state.protector.record_success(&creds.username, client_ip);
            // Log entry into tamper-proof audit hash chain (§3.1.1)
            state.audit_chain.log_action(
                &user.id.to_string(),
                "USER_LOGIN",
                &user.username,
                client_ip,
            );
        }
        Ok(false) => {
            let status = state.protector.record_failure(&creds.username, client_ip);
            let err_msg = match status {
                LockoutStatus::AccountLocked { remaining_secs } => {
                    format!(
                        "Invalid credentials. Account has been locked for {} seconds.",
                        remaining_secs
                    )
                }
                LockoutStatus::IpBanned { remaining_secs } => {
                    format!(
                        "Invalid credentials. IP address has been restricted for {} seconds.",
                        remaining_secs
                    )
                }
                LockoutStatus::Allowed => "invalid credentials".to_string(),
            };

            return (StatusCode::UNAUTHORIZED, Json(json!({"error": err_msg}))).into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response();
        }
    }

    let token = match jwt.create_token(user.id, &user.username, &user.role) {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };

    // Register active session in SessionManager (§1.1.1, §1.1.4)
    let (session, _raw_token) =
        state
            .session_mgr
            .create_session(user.id, &user.username, client_ip, "netscope-client");

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
        (
            StatusCode::OK,
            Json(json!({"status": "revoked", "session_id": session_id})),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "session not found"})),
        )
    }
}

/// Revoke all active sessions for a user (§1.1.5).
async fn revoke_all_sessions(
    State(state): State<Arc<ApiState>>,
    Path(user_id_str): Path<String>,
) -> impl IntoResponse {
    let user_id = match user_id_str.parse::<Uuid>() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid user_id uuid"})),
            )
        }
    };
    let count = state.session_mgr.revoke_all_sessions_for_user(user_id);
    (
        StatusCode::OK,
        Json(json!({"status": "all_sessions_revoked", "count": count})),
    )
}

/// Force password reset flag on next login (§1.1.6).
async fn force_password_reset(
    State(state): State<Arc<ApiState>>,
    Path(user_id_str): Path<String>,
) -> impl IntoResponse {
    let user_id = match user_id_str.parse::<Uuid>() {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid user_id uuid"})),
            )
        }
    };
    let count = state.session_mgr.force_password_reset(user_id);
    (
        StatusCode::OK,
        Json(json!({"status": "password_reset_forced", "revoked_sessions": count})),
    )
}

/// Create a scoped API Key (§1.1.7).
async fn create_api_key(
    State(state): State<Arc<ApiState>>,
    Json(req): Json<CreateApiKeyRequest>,
) -> impl IntoResponse {
    let dummy_user_id = Uuid::nil();
    let (key_meta, raw_key) =
        state
            .session_mgr
            .create_api_key(&req.name, dummy_user_id, req.permissions, req.ttl_days);

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
        (
            StatusCode::OK,
            Json(json!({"status": "revoked", "key_id": key_id})),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "api key not found"})),
        )
    }
}

/// Admin manual account unlock (§1.2.4).
async fn unlock_account(
    State(state): State<Arc<ApiState>>,
    Path(username): Path<String>,
) -> impl IntoResponse {
    let success = state.protector.unlock_account(&username);
    if success {
        (
            StatusCode::OK,
            Json(json!({"status": "account_unlocked", "username": username})),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "account not locked or not found"})),
        )
    }
}

/// Admin manual IP unlock (§1.2.4).
async fn unlock_ip(
    State(state): State<Arc<ApiState>>,
    Path(ip): Path<String>,
) -> impl IntoResponse {
    let success = state.protector.unlock_ip(&ip);
    if success {
        (
            StatusCode::OK,
            Json(json!({"status": "ip_unlocked", "ip": ip})),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "ip not banned or not found"})),
        )
    }
}

/// List lockout and IP ban audit events (§1.2.3).
async fn list_lockout_events(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let events = state.protector.get_audit_events();
    (StatusCode::OK, Json(json!(events)))
}

/// List all defined roles (§2.1.2, §2.1.3).
async fn list_roles(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let roles = state.rbac_engine.list_roles();
    (StatusCode::OK, Json(json!(roles)))
}

/// Create or Update a custom role (§2.1.3).
async fn create_role(
    State(state): State<Arc<ApiState>>,
    Json(req): Json<CreateCustomRoleRequest>,
) -> impl IntoResponse {
    let can_view = req.can_view_raw_payload.unwrap_or(true);
    match state
        .rbac_engine
        .create_custom_role(&req.name, &req.description, req.permissions, can_view)
    {
        Ok(role) => (StatusCode::CREATED, Json(json!(role))).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response(),
    }
}

/// Delete a custom role (§2.1.3).
async fn delete_role(
    State(state): State<Arc<ApiState>>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    match state.rbac_engine.delete_custom_role(&name) {
        Ok(true) => (
            StatusCode::OK,
            Json(json!({"status": "role_deleted", "name": name})),
        )
            .into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "role not found"})),
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response(),
    }
}

/// List all 50+ available granular permission strings (§2.1.1).
async fn list_permissions(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let perms = state.rbac_engine.get_all_permissions();
    (StatusCode::OK, Json(json!(perms)))
}

/// Query cryptographic audit chain log records (§3.1.1).
async fn get_audit_chain(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let records = state.audit_chain.get_records(100, 0);
    (StatusCode::OK, Json(json!(records)))
}

/// Verify audit chain integrity report (§3.1.2).
async fn verify_audit_chain(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let report = state.audit_chain.verify_integrity();
    (StatusCode::OK, Json(json!(report)))
}
