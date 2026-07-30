// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

//! SIEM Comparison, Formats & Connectors REST API Router (§3, §4).

use crate::api::ApiState;
use axum::{extract::Query, routing::get, Json, Router};
use netscope_core::siem_comparison::SiemComparisonEngine;
use netscope_core::siem_connectors::SiemConnectorManager;
use serde::Deserialize;
use std::sync::Arc;

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
        .route("/presets", get(get_presets))
        .route("/autocomplete", get(get_autocomplete))
        .route("/explain", get(get_explain))
        .route("/pivot", get(get_pivot))
        .route("/education", get(get_education))
        .route("/gamification", get(get_gamification))
        .route("/metrics", get(get_quality_metrics))
        .route("/exclusive", get(get_exclusive_features))
}

#[derive(Debug, Deserialize)]
pub struct QueryParams {
    pub q: Option<String>,
    pub field: Option<String>,
    pub val: Option<String>,
    pub pivot_type: Option<String>,
    pub proto: Option<String>,
    pub analyst: Option<String>,
}

async fn get_presets() -> Json<serde_json::Value> {
    let presets = netscope_core::analyst_command_center::AnalystCommandCenterEngine::get_saved_filter_templates();
    Json(serde_json::json!({ "presets": presets }))
}

async fn get_autocomplete(Query(qp): Query<QueryParams>) -> Json<serde_json::Value> {
    let prefix = qp.q.as_deref().unwrap_or("");
    let suggestions = netscope_core::analyst_command_center::AnalystCommandCenterEngine::get_autocomplete_suggestions(prefix);
    Json(serde_json::to_value(&suggestions).unwrap_or_default())
}

async fn get_explain(Query(qp): Query<QueryParams>) -> Json<serde_json::Value> {
    let filter_q = qp.q.as_deref().unwrap_or("smb");
    let field = qp.field.as_deref().unwrap_or("protocol");
    let val = qp.val.as_deref().unwrap_or("SMB");
    let explanation =
        netscope_core::analyst_command_center::AnalystCommandCenterEngine::explain_search_match(
            filter_q, field, val,
        );
    Json(serde_json::to_value(&explanation).unwrap_or_default())
}

async fn get_pivot(Query(qp): Query<QueryParams>) -> Json<serde_json::Value> {
    let ptype = qp.pivot_type.as_deref().unwrap_or("IP");
    let pval = qp.val.as_deref().unwrap_or("10.0.1.47");
    let pivot = netscope_core::analyst_command_center::AnalystCommandCenterEngine::generate_pivot(
        ptype, pval,
    );
    Json(serde_json::to_value(&pivot).unwrap_or_default())
}

async fn get_education(Query(qp): Query<QueryParams>) -> Json<serde_json::Value> {
    let proto = qp.proto.as_deref().unwrap_or("SMB");
    let edu =
        netscope_core::analyst_command_center::AnalystCommandCenterEngine::get_alert_education(
            proto,
        );
    Json(serde_json::to_value(&edu).unwrap_or_default())
}

async fn get_gamification(Query(qp): Query<QueryParams>) -> Json<serde_json::Value> {
    let analyst = qp.analyst.as_deref().unwrap_or("efe.akkaya");
    let gami =
        netscope_core::analyst_command_center::AnalystCommandCenterEngine::get_analyst_gamification(
            analyst,
        );
    Json(serde_json::to_value(&gami).unwrap_or_default())
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
    let bundle =
        SiemConnectorManager::export_stix21_bundle(ioc_type, ioc_value, "netscope detected IOC");
    Json(serde_json::to_value(&bundle).unwrap_or_default())
}

async fn export_sigma() -> Json<serde_json::Value> {
    let sigma =
        SiemConnectorManager::export_sigma_rule("SMB Unsigned Access", "SMB", "signing=false");
    Json(serde_json::to_value(&sigma).unwrap_or_default())
}

async fn export_asyncapi() -> Json<serde_json::Value> {
    let asyncapi = SiemConnectorManager::export_asyncapi_spec();
    Json(asyncapi)
}

async fn get_quality_metrics() -> Json<serde_json::Value> {
    let metrics =
        netscope_core::siem_quality_metrics::SiemQualityMetricsEngine::get_quality_metrics();
    Json(serde_json::to_value(&metrics).unwrap_or_default())
}

async fn get_exclusive_features() -> Json<serde_json::Value> {
    let report =
        netscope_core::netscope_exclusive_features::NetscopeExclusiveEngine::get_exclusive_report();
    Json(serde_json::to_value(&report).unwrap_or_default())
}
