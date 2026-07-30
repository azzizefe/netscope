// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::middleware::from_fn;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use std::net::IpAddr;
use std::sync::Arc;

use crate::api::ApiState;
use crate::auth::require;
use netscope_core::business_impact::{
    global_asset_registry, AssetItem,
};

/// Asset Inventory & CMDB Sync API routes (§1.1.6).
pub fn routes(state: Arc<ApiState>) -> Router {
    Router::new()
        .route(
            "/",
            get(list_assets)
                .post(create_or_update_asset)
                .route_layer(from_fn(require("events:read"))),
        )
        .route(
            "/batch",
            post(batch_sync_cmdb_assets).route_layer(from_fn(require("events:write"))),
        )
        .route(
            "/:ip",
            get(get_asset_by_ip)
                .delete(delete_asset)
                .route_layer(from_fn(require("events:read"))),
        )
        .with_state(state)
}

async fn list_assets() -> impl IntoResponse {
    let registry = global_asset_registry().lock().unwrap();
    let assets = registry.list_assets();
    (StatusCode::OK, Json(json!(assets)))
}

async fn get_asset_by_ip(Path(ip_str): Path<String>) -> impl IntoResponse {
    if let Ok(ip) = ip_str.parse::<IpAddr>() {
        let registry = global_asset_registry().lock().unwrap();
        if let Some(asset) = registry.get_by_ip(ip) {
            return (StatusCode::OK, Json(json!(asset))).into_response();
        }
    }
    (StatusCode::NOT_FOUND, Json(json!({"error": "Asset not found"}))).into_response()
}

async fn create_or_update_asset(Json(asset): Json<AssetItem>) -> impl IntoResponse {
    let mut registry = global_asset_registry().lock().unwrap();
    registry.register_asset(asset.clone());
    (StatusCode::CREATED, Json(json!(asset))).into_response()
}

#[derive(Debug, Deserialize)]
struct CmdbBatchSyncRequest {
    assets: Vec<AssetItem>,
}

async fn batch_sync_cmdb_assets(Json(payload): Json<CmdbBatchSyncRequest>) -> impl IntoResponse {
    let mut registry = global_asset_registry().lock().unwrap();
    let count = payload.assets.len();
    for asset in payload.assets {
        registry.register_asset(asset);
    }
    (
        StatusCode::OK,
        Json(json!({"status": "success", "synced_assets_count": count})),
    )
        .into_response()
}

async fn delete_asset(Path(ip_str): Path<String>) -> impl IntoResponse {
    if let Ok(ip) = ip_str.parse::<IpAddr>() {
        let mut registry = global_asset_registry().lock().unwrap();
        if let Some(removed) = registry.remove_asset(ip) {
            return (StatusCode::OK, Json(json!(removed))).into_response();
        }
    }
    (StatusCode::NOT_FOUND, Json(json!({"error": "Asset not found"}))).into_response()
}
