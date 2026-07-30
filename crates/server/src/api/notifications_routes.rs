// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 azzizefe. All rights reserved.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use crate::api::ApiState;
use netscope_core::notifications::{NotificationConfig, NotificationEngine};

#[derive(Debug, Deserialize)]
pub struct TelegramTestPayload {
    pub token: Option<String>,
    pub chat_id: Option<String>,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct DiscordTestPayload {
    pub webhook_url: Option<String>,
    pub message: String,
    pub details: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SlackTestPayload {
    pub webhook_url: Option<String>,
    pub message: String,
    pub details: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CustomWebhookTestPayload {
    pub target_url: Option<String>,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct EmailTestPayload {
    pub smtp_host: String,
    pub smtp_port: Option<u16>,
    pub from: String,
    pub to: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub subject: String,
    pub body: String,
}

pub fn routes(api_state: Arc<ApiState>) -> Router {
    Router::new()
        .route(
            "/notifications/telegram/send",
            post(send_telegram_notification),
        )
        .route(
            "/notifications/discord/send",
            post(send_discord_notification),
        )
        .route("/notifications/slack/send", post(send_slack_notification))
        .route(
            "/notifications/webhook/send",
            post(send_custom_webhook_notification),
        )
        .route("/notifications/email/send", post(send_email_notification))
        .with_state(api_state)
}

/// Send Telegram Bot Notification (§4.1.1).
async fn send_telegram_notification(
    State(_state): State<Arc<ApiState>>,
    Json(payload): Json<TelegramTestPayload>,
) -> impl IntoResponse {
    let cfg = NotificationConfig {
        email_smtp_host: None,
        email_smtp_port: None,
        email_from: None,
        email_to: None,
        email_username: None,
        email_password: None,
        email_tls: None,
        slack_webhook_url: None,
        discord_webhook_url: None,
        custom_webhook_url: None,
        telegram_token: payload.token,
        telegram_chat_id: payload.chat_id,
        syslog_host: None,
        syslog_port: None,
    };

    let engine = NotificationEngine::new(cfg);
    match engine.send_telegram(&payload.message) {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({"status": "sent", "channel": "telegram"})),
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response(),
    }
}

/// Send Discord Webhook Notification (§4.1.2).
async fn send_discord_notification(
    State(_state): State<Arc<ApiState>>,
    Json(payload): Json<DiscordTestPayload>,
) -> impl IntoResponse {
    let cfg = NotificationConfig {
        email_smtp_host: None,
        email_smtp_port: None,
        email_from: None,
        email_to: None,
        email_username: None,
        email_password: None,
        email_tls: None,
        slack_webhook_url: None,
        discord_webhook_url: payload.webhook_url,
        custom_webhook_url: None,
        telegram_token: None,
        telegram_chat_id: None,
        syslog_host: None,
        syslog_port: None,
    };

    let details = payload
        .details
        .unwrap_or_else(|| "No additional details".to_string());
    let engine = NotificationEngine::new(cfg);
    match engine.send_discord(&payload.message, &details) {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({"status": "sent", "channel": "discord"})),
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response(),
    }
}

/// Send Slack Webhook Notification (§4.1.2).
async fn send_slack_notification(
    State(_state): State<Arc<ApiState>>,
    Json(payload): Json<SlackTestPayload>,
) -> impl IntoResponse {
    let cfg = NotificationConfig {
        email_smtp_host: None,
        email_smtp_port: None,
        email_from: None,
        email_to: None,
        email_username: None,
        email_password: None,
        email_tls: None,
        slack_webhook_url: payload.webhook_url,
        discord_webhook_url: None,
        custom_webhook_url: None,
        telegram_token: None,
        telegram_chat_id: None,
        syslog_host: None,
        syslog_port: None,
    };

    let details = payload
        .details
        .unwrap_or_else(|| "No additional details".to_string());
    let engine = NotificationEngine::new(cfg);
    match engine.send_slack(&payload.message, &details) {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({"status": "sent", "channel": "slack"})),
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response(),
    }
}

/// Send Custom HTTP POST JSON Webhook (§4.1.3).
async fn send_custom_webhook_notification(
    State(_state): State<Arc<ApiState>>,
    Json(payload): Json<CustomWebhookTestPayload>,
) -> impl IntoResponse {
    let cfg = NotificationConfig {
        email_smtp_host: None,
        email_smtp_port: None,
        email_from: None,
        email_to: None,
        email_username: None,
        email_password: None,
        email_tls: None,
        slack_webhook_url: None,
        discord_webhook_url: None,
        custom_webhook_url: payload.target_url.clone(),
        telegram_token: None,
        telegram_chat_id: None,
        syslog_host: None,
        syslog_port: None,
    };

    let engine = NotificationEngine::new(cfg);
    match engine.send_custom_webhook(&payload.message, payload.target_url.as_deref()) {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({"status": "sent", "channel": "custom_webhook"})),
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response(),
    }
}

/// Send SMTP Email Notification (§4.1.4).
async fn send_email_notification(
    State(_state): State<Arc<ApiState>>,
    Json(payload): Json<EmailTestPayload>,
) -> impl IntoResponse {
    let cfg = NotificationConfig {
        email_smtp_host: Some(payload.smtp_host),
        email_smtp_port: payload.smtp_port,
        email_from: Some(payload.from),
        email_to: Some(payload.to),
        email_username: payload.username,
        email_password: payload.password,
        email_tls: Some("starttls".to_string()),
        slack_webhook_url: None,
        discord_webhook_url: None,
        custom_webhook_url: None,
        telegram_token: None,
        telegram_chat_id: None,
        syslog_host: None,
        syslog_port: None,
    };

    let engine = NotificationEngine::new(cfg);
    match engine.send_email(&payload.subject, &payload.body) {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({"status": "sent", "channel": "email"})),
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": e}))).into_response(),
    }
}
