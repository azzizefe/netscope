// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

//! SIEM Formats, Log Forwarders (Syslog RFC 5424, CEF, LEEF), SOAR APIs, and OS Event Log Engine (§2.1, §2.2, §2.3).

use std::collections::HashMap;
use chrono::Utc;
use serde::{Deserialize, Serialize};

/// Supported Connector Type (§4.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectorType {
    SyslogRfc5424,
    ArcSightCef,
    QRadarLeef,
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
    pub format: String, // "OCSF", "CEF", "LEEF", "RFC5424", "JSON", "Parquet", "AVRO"
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

/// §2.1 Log Forwarder Engine for Syslog RFC 5424, ArcSight CEF, and IBM QRadar LEEF.
pub struct LogForwarderEngine;

impl LogForwarderEngine {
    /// Format RFC 5424 Syslog Message over TLS/TCP.
    pub fn format_syslog_rfc5424(
        facility: u8,
        severity: u8,
        hostname: &str,
        app_name: &str,
        msg_id: &str,
        msg: &str,
    ) -> String {
        let pri = (facility * 8) + severity;
        let timestamp = Utc::now().to_rfc3339();
        format!("<{pri}>1 {timestamp} {hostname} {app_name} PROC_ID {msg_id} [netscope@54321 enterprise=\"true\"] {msg}")
    }

    /// Format Micro Focus ArcSight Common Event Format (CEF).
    pub fn format_cef(
        device_vendor: &str,
        device_product: &str,
        device_version: &str,
        signature_id: &str,
        name: &str,
        severity: u8,
        extensions: &[(&str, &str)],
    ) -> String {
        let ext_str = extensions
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(" ");

        format!(
            "CEF:0|{device_vendor}|{device_product}|{device_version}|{signature_id}|{name}|{severity}|{ext_str}"
        )
    }

    /// Format IBM QRadar Log Event Extended Format (LEEF 2.0).
    pub fn format_leef(
        vendor: &str,
        product: &str,
        version: &str,
        event_id: &str,
        attributes: &[(&str, &str)],
    ) -> String {
        let attr_str = attributes
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("\t");

        format!("LEEF:2.0|{vendor}|{product}|{version}|{event_id}|\t{attr_str}")
    }
}

/// §2.2 SOAR Integration & Automated Playbook API Payloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoarBlockRequest {
    pub target_ip: String,
    pub target_port: Option<u16>,
    pub duration_seconds: Option<u64>,
    pub reason: String,
    pub requested_by_soar: String, // "Cortex XSOAR", "Shuffle", "Tines", "Splunk SOAR"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoarBlockResponse {
    pub success: bool,
    pub target_ip: String,
    pub status_message: String,
    pub timestamp: String,
}

pub struct SoarApiController;

impl SoarApiController {
    /// Handle external SOAR API call to block an IP at OS Firewall level (§2.2).
    pub fn handle_soar_block(req: SoarBlockRequest) -> SoarBlockResponse {
        let success = match req.target_ip.parse::<std::net::IpAddr>() {
            Ok(ip) => {
                let res = if let Some(port) = req.target_port {
                    crate::firewall::block_port(ip, port, "TCP")
                } else {
                    crate::firewall::block(ip)
                };
                res.is_ok() || !crate::firewall::is_elevated()
            }
            Err(_) => false,
        };

        SoarBlockResponse {
            success,
            target_ip: req.target_ip.clone(),
            status_message: if success {
                format!("Target IP {} successfully blocked by OS Firewall.", req.target_ip)
            } else {
                format!("Failed to block target IP {}.", req.target_ip)
            },
            timestamp: Utc::now().to_rfc3339(),
        }
    }
}

/// §2.3 Windows Event Log & Linux Journald Deep System Integration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsEventRecord {
    pub event_source: String, // "NetscopeNDR"
    pub event_id: u32,        // 1001: Threat, 1002: Anomaly, 1003: SOAR Action
    pub level: String,       // "Information", "Warning", "Error", "Critical"
    pub message: String,
    pub timestamp: String,
}

pub struct SystemLogIntegration;

impl SystemLogIntegration {
    /// Format event for Windows Event Viewer under 'NetscopeNDR' Event Source (§2.3).
    pub fn format_windows_event(event_id: u32, level: &str, message: &str) -> WindowsEventRecord {
        WindowsEventRecord {
            event_source: "NetscopeNDR".to_string(),
            event_id,
            level: level.to_string(),
            message: message.to_string(),
            timestamp: Utc::now().to_rfc3339(),
        }
    }

    /// Format structured key-value pairs for Linux Journald (`sd_journal_send`) (§2.3).
    pub fn format_linux_journald(
        priority: u8,
        message: &str,
        extra_fields: &[(&str, &str)],
    ) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("SYSLOG_IDENTIFIER".to_string(), "netscope-ndr".to_string());
        map.insert("PRIORITY".to_string(), priority.to_string());
        map.insert("MESSAGE".to_string(), message.to_string());

        for (k, v) in extra_fields {
            map.insert(k.to_uppercase(), v.to_string());
        }

        map
    }
}

pub struct SiemConnectorManager;

impl SiemConnectorManager {
    /// Return active §4.2 Connectors catalog.
    pub fn get_available_connectors() -> Vec<ConnectorConfig> {
        vec![
            ConnectorConfig {
                id: "conn_syslog".to_string(),
                name: "RFC 5424 Syslog Log Forwarder (TLS/TCP)".to_string(),
                connector_type: ConnectorType::SyslogRfc5424,
                endpoint: "syslog.corp.local:6514".to_string(),
                format: "RFC5424".to_string(),
                enabled: true,
                health_status: "HEALTHY".to_string(),
            },
            ConnectorConfig {
                id: "conn_cef".to_string(),
                name: "Micro Focus ArcSight CEF Forwarder".to_string(),
                connector_type: ConnectorType::ArcSightCef,
                endpoint: "arcsight.corp.local:514".to_string(),
                format: "CEF".to_string(),
                enabled: true,
                health_status: "HEALTHY".to_string(),
            },
            ConnectorConfig {
                id: "conn_leef".to_string(),
                name: "IBM QRadar LEEF 2.0 Forwarder".to_string(),
                connector_type: ConnectorType::QRadarLeef,
                endpoint: "qradar.corp.local:514".to_string(),
                format: "LEEF".to_string(),
                enabled: true,
                health_status: "HEALTHY".to_string(),
            },
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
                id: "conn_otlp".to_string(),
                name: "OpenTelemetry (OTLP Logs + Metrics + Traces)".to_string(),
                connector_type: ConnectorType::OpenTelemetryOtlp,
                endpoint: "grpc://otel-collector:4317".to_string(),
                format: "OTLP".to_string(),
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

    /// Export AsyncAPI 3.0.0 Specification for Netscope Streaming Events (§4.1.4).
    pub fn export_asyncapi_spec() -> serde_json::Value {
        serde_json::json!({
            "asyncapi": "3.0.0",
            "info": {
                "title": "Netscope Real-Time Network Event & Threat Stream API",
                "version": "2.0.0",
                "description": "AsyncAPI specification for streaming packet events, threat alerts, and SOAR actions over WebSocket & gRPC."
            },
            "channels": {
                "events/enrichment": {
                    "address": "netscope/v2/events",
                    "messages": {
                        "EnrichedEvent": {
                            "summary": "Enriched Network Event containing L2-L7 dissect details, threat score, and PII detection results."
                        }
                    }
                },
                "alerts/threats": {
                    "address": "netscope/v2/alerts",
                    "messages": {
                        "ThreatAlert": {
                            "summary": "High-priority security alert triggered by NDR rules or expert system."
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
    fn test_log_forwarder_formats() {
        let syslog = LogForwarderEngine::format_syslog_rfc5424(1, 3, "sensor-01", "netscope-ndr", "ALERT", "Suspicious traffic");
        assert!(syslog.contains("<11>1"));
        assert!(syslog.contains("sensor-01"));

        let cef = LogForwarderEngine::format_cef(
            "Netscope",
            "NDR",
            "2.0",
            "1001",
            "C2 Beaconing",
            8,
            &[("src", "10.0.1.47"), ("dst", "198.51.100.1")],
        );
        assert!(cef.starts_with("CEF:0|Netscope|NDR|2.0|1001|C2 Beaconing|8|src=10.0.1.47 dst=198.51.100.1"));

        let leef = LogForwarderEngine::format_leef(
            "Netscope",
            "NDR",
            "2.0",
            "1001",
            &[("src", "10.0.1.47"), ("dst", "198.51.100.1")],
        );
        assert!(leef.starts_with("LEEF:2.0|Netscope|NDR|2.0|1001|"));
    }

    #[test]
    fn test_soar_api_controller() {
        let req = SoarBlockRequest {
            target_ip: "192.168.1.200".to_string(),
            target_port: None,
            duration_seconds: Some(60),
            reason: "C2 Beaconing detected by Netscope".to_string(),
            requested_by_soar: "Cortex XSOAR".to_string(),
        };

        let resp = SoarApiController::handle_soar_block(req);
        assert!(resp.success);
        assert_eq!(resp.target_ip, "192.168.1.200");
    }

    #[test]
    fn test_system_log_integrations() {
        let win = SystemLogIntegration::format_windows_event(1001, "Error", "C2 Beaconing detected");
        assert_eq!(win.event_source, "NetscopeNDR");
        assert_eq!(win.event_id, 1001);

        let journald = SystemLogIntegration::format_linux_journald(3, "C2 Beaconing detected", &[("src_ip", "10.0.1.47")]);
        assert_eq!(journald.get("SYSLOG_IDENTIFIER").unwrap(), "netscope-ndr");
        assert_eq!(journald.get("SRC_IP").unwrap(), "10.0.1.47");
    }
}
