// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

//! SIEM Comparison, Formats & Connectors REST API Router (§3, §4).

use axum::{
    extract::Query,
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use std::sync::Arc;
use netscope_core::siem_comparison::SiemComparisonEngine;
use netscope_core::siem_connectors::SiemConnectorManager;
use crate::api::ApiState;

#[derive(Debug, Deserialize)]
pub struct StixQuery {
    pub ioc_type: Option<String>,
    pub ioc_value: Option<String>,
}

pub fn routes(_state: Arc<ApiState>) -> Router {
    Router::new()
        .route("/matrix", get(get_capability_matrix))
        .route("/usps", get(get_usps))
        .route("/benchmarks", get(get_benchmarks))
        .route("/connectors", get(get_connectors))
        .route("/stix", get(export_stix))
        .route("/sigma", get(export_sigma))
        .route("/asyncapi", get(export_asyncapi))
}

async fn get_capability_matrix() -> Json<serde_json::Value> {
    let matrix = SiemComparisonEngine::get_matrix();
    Json(serde_json::json!({ "matrix": matrix }))
}

async fn get_usps() -> Json<serde_json::Value> {
    let usps = SiemComparisonEngine::get_usps();
    Json(serde_json::json!({ "usps": usps }))
}

async fn get_benchmarks() -> Json<serde_json::Value> {
    let benchmarks = SiemComparisonEngine::get_benchmarks();
    Json(serde_json::json!({ "benchmarks": benchmarks }))
}

async fn get_connectors() -> Json<serde_json::Value> {
    let connectors = SiemConnectorManager::get_available_connectors();
    Json(serde_json::json!({ "connectors": connectors }))
}

async fn export_stix(Query(q): Query<StixQuery>) -> Json<serde_json::Value> {
    let ioc_type = q.ioc_type.as_deref().unwrap_or("ip");
    let ioc_value = q.ioc_value.as_deref().unwrap_or("10.0.1.47");
    let bundle = SiemConnectorManager::export_stix21_bundle(ioc_type, ioc_value, "netscope detected IOC");
    Json(serde_json::to_value(&bundle).unwrap_or_default())
}

async fn export_sigma() -> Json<serde_json::Value> {
    let sigma = SiemConnectorManager::export_sigma_rule("SMB Unsigned Access", "SMB", "signing=false");
    Json(serde_json::to_value(&sigma).unwrap_or_default())
}

async fn export_asyncapi() -> Json<serde_json::Value> {
    let asyncapi = SiemConnectorManager::export_asyncapi_spec();
    Json(asyncapi)
}
