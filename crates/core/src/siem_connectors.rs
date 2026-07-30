// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 azzizefe. All rights reserved.

//! SIEM Formats & Output Connectors Explosion Engine (§4.1, §4.2).

use serde::{Deserialize, Serialize};

/// Supported Connector Type (§4.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectorType {
    Kafka,
    AmazonS3,
    GoogleCloudStorage,
    AzureDataLakeGen2,
    GrafanaLoki,
    OpenTelemetryOtlp,
    Fluentd,
    Vector,
    TimescaleDB,
    ClickHouse,
}

/// Connector Config & Health Status (§4.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorConfig {
    pub id: String,
    pub name: String,
    pub connector_type: ConnectorType,
    pub endpoint: String,
    pub format: String, // "OCSF", "JSON", "Parquet", "AVRO", "Protobuf", "STIX"
    pub enabled: bool,
    pub health_status: String, // "CONNECTED", "HEALTHY", "STANDBY"
}

/// STIX 2.1 Indicator Bundle (§4.1.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixBundle {
    pub r#type: String, // "bundle"
    pub id: String,
    pub spec_version: String, // "2.1"
    pub objects: Vec<serde_json::Value>,
}

/// Sigma Rule Conversion Structure (§4.1.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaRule {
    pub title: String,
    pub id: String,
    pub status: String,
    pub description: String,
    pub logsource: serde_json::Value,
    pub detection: serde_json::Value,
    pub level: String,
}

pub struct SiemConnectorManager;

impl SiemConnectorManager {
    /// Return active §4.2 Connectors catalog.
    pub fn get_available_connectors() -> Vec<ConnectorConfig> {
        vec![
            ConnectorConfig {
                id: "conn_kafka".to_string(),
                name: "Kafka (Confluent Schema Registry AVRO/Protobuf)".to_string(),
                connector_type: ConnectorType::Kafka,
                endpoint: "kafka.internal.corp:9092".to_string(),
                format: "AVRO".to_string(),
                enabled: true,
                health_status: "HEALTHY".to_string(),
            },
            ConnectorConfig {
                id: "conn_s3".to_string(),
                name: "Amazon S3 (Parquet Format for Athena/Redshift)".to_string(),
                connector_type: ConnectorType::AmazonS3,
                endpoint: "s3://netscope-logs-bucket/parquet/".to_string(),
                format: "Parquet".to_string(),
                enabled: true,
                health_status: "CONNECTED".to_string(),
            },
            ConnectorConfig {
                id: "conn_gcs".to_string(),
                name: "Google Cloud Storage (Parquet + BigQuery External Table)".to_string(),
                connector_type: ConnectorType::GoogleCloudStorage,
                endpoint: "gs://netscope-siem-datalake/".to_string(),
                format: "Parquet".to_string(),
                enabled: true,
                health_status: "CONNECTED".to_string(),
            },
            ConnectorConfig {
                id: "conn_adls".to_string(),
                name: "Azure Data Lake Storage Gen2 (Parquet)".to_string(),
                connector_type: ConnectorType::AzureDataLakeGen2,
                endpoint: "https://netscopedatalake.dfs.core.windows.net/logs/".to_string(),
                format: "Parquet".to_string(),
                enabled: true,
                health_status: "CONNECTED".to_string(),
            },
            ConnectorConfig {
                id: "conn_loki".to_string(),
                name: "Grafana Loki Push API (Label-indexed)".to_string(),
                connector_type: ConnectorType::GrafanaLoki,
                endpoint: "http://loki:3100/loki/api/v1/push".to_string(),
                format: "JSON".to_string(),
                enabled: true,
                health_status: "HEALTHY".to_string(),
            },
            ConnectorConfig {
                id: "conn_otlp".to_string(),
                name: "OpenTelemetry (OTLP Logs + Metrics + Traces)".to_string(),
                connector_type: ConnectorType::OpenTelemetryOtlp,
                endpoint: "grpc://otel-collector:4317".to_string(),
                format: "OTLP".to_string(),
                enabled: true,
                health_status: "HEALTHY".to_string(),
            },
            ConnectorConfig {
                id: "conn_fluentd".to_string(),
                name: "Fluentd / Fluent Bit Output Plugin".to_string(),
                connector_type: ConnectorType::Fluentd,
                endpoint: "tcp://fluentbit:24224".to_string(),
                format: "JSON".to_string(),
                enabled: true,
                health_status: "CONNECTED".to_string(),
            },
            ConnectorConfig {
                id: "conn_vector".to_string(),
                name: "Vector Sink Collector".to_string(),
                connector_type: ConnectorType::Vector,
                endpoint: "http://vector:9000".to_string(),
                format: "JSON".to_string(),
                enabled: true,
                health_status: "CONNECTED".to_string(),
            },
            ConnectorConfig {
                id: "conn_timescaledb".to_string(),
                name: "TimescaleDB Hypertable Series Storage".to_string(),
                connector_type: ConnectorType::TimescaleDB,
                endpoint: "postgres://postgres:5432/netscope_tsdb".to_string(),
                format: "SQL".to_string(),
                enabled: true,
                health_status: "HEALTHY".to_string(),
            },
            ConnectorConfig {
                id: "conn_clickhouse".to_string(),
                name: "ClickHouse Columnar Storage Engine".to_string(),
                connector_type: ConnectorType::ClickHouse,
                endpoint: "http://clickhouse:8123".to_string(),
                format: "Native".to_string(),
                enabled: true,
                health_status: "HEALTHY".to_string(),
            },
        ]
    }

    /// Export STIX 2.1 Bundle (§4.1.2).
    pub fn export_stix21_bundle(ioc_type: &str, ioc_value: &str, description: &str) -> StixBundle {
        let pattern_str = match ioc_type.to_lowercase().as_str() {
            "ip" | "ipv4" => format!("[ipv4-addr:value = '{}']", ioc_value),
            "domain" => format!("[domain-name:value = '{}']", ioc_value),
            _ => format!("[file:name = '{}']", ioc_value),
        };

        let indicator = serde_json::json!({
            "type": "indicator",
            "spec_version": "2.1",
            "id": format!("indicator--{:x}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)),
            "created": chrono::Utc::now().to_rfc3339(),
            "modified": chrono::Utc::now().to_rfc3339(),
            "name": format!("netscope detected IOC: {}", ioc_value),
            "description": description,
            "pattern": pattern_str,
            "pattern_type": "stix",
            "valid_from": chrono::Utc::now().to_rfc3339()
        });

        StixBundle {
            r#type: "bundle".to_string(),
            id: format!(
                "bundle--{:x}",
                chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
            ),
            spec_version: "2.1".to_string(),
            objects: vec![indicator],
        }
    }

    /// Export Sigma Rule (§4.1.3).
    pub fn export_sigma_rule(title: &str, protocol: &str, condition: &str) -> SigmaRule {
        SigmaRule {
            title: title.to_string(),
            id: format!(
                "sigma-{:x}",
                chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
            ),
            status: "experimental".to_string(),
            description: format!(
                "netscope auto-exported Sigma detection rule for {}",
                protocol
            ),
            logsource: serde_json::json!({
                "category": "network_traffic",
                "product": "netscope"
            }),
            detection: serde_json::json!({
                "selection": {
                    "Protocol": protocol,
                    "Condition": condition
                },
                "condition": "selection"
            }),
            level: "high".to_string(),
        }
    }

    /// Export AsyncAPI 3.0 Spec (§4.1.4).
    pub fn export_asyncapi_spec() -> serde_json::Value {
        serde_json::json!({
            "asyncapi": "3.0.0",
            "info": {
                "title": "netscope SIEM Event Stream API",
                "version": "2.0.0",
                "description": "Event-driven AsyncAPI spec for real-time netscope enriched events & security findings."
            },
            "channels": {
                "netscope/events/enriched": {
                    "address": "netscope/events/enriched",
                    "messages": {
                        "enrichedEvent": {
                            "name": "EnrichedEvent",
                            "title": "7-Layer Enriched OCSF Event",
                            "summary": "Full OCSF 1.3.0 compliant security event stream"
                        }
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_siem_connectors_and_formats() {
        let connectors = SiemConnectorManager::get_available_connectors();
        assert_eq!(connectors.len(), 10);

        let stix = SiemConnectorManager::export_stix21_bundle(
            "ip",
            "10.0.1.47",
            "Malicious insider workstation",
        );
        assert_eq!(stix.spec_version, "2.1");
        assert_eq!(stix.objects.len(), 1);

        let sigma =
            SiemConnectorManager::export_sigma_rule("SMB Unsigned Access", "SMB", "signing=false");
        assert_eq!(sigma.level, "high");

        let asyncapi = SiemConnectorManager::export_asyncapi_spec();
        assert_eq!(asyncapi["asyncapi"], "3.0.0");
    }
}
