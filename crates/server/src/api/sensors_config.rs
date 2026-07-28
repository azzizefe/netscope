// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

use std::path::PathBuf;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct AgentConfig {
    pub server: ServerConfig,
    pub identity: IdentityConfig,
    pub heartbeat: HeartbeatConfig,
    pub events: EventConfig,
    pub offline: OfflineConfig,
    pub upgrade: UpgradeConfig,
    pub capture: CaptureConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ServerConfig {
    pub url: String,
    pub auth_token: String,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub tls_ca: Option<PathBuf>,
    pub insecure_skip_verify: bool,
    pub connect_timeout_secs: u64,
    pub request_timeout_secs: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            url: "https://127.0.0.1:9443".into(),
            auth_token: String::new(),
            tls_cert: None,
            tls_key: None,
            tls_ca: None,
            insecure_skip_verify: false,
            connect_timeout_secs: 10,
            request_timeout_secs: 30,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct IdentityConfig {
    pub hostname: String,
    pub tags: Vec<String>,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            hostname: "unknown".into(),
            tags: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct HeartbeatConfig {
    pub interval_secs: u64,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self { interval_secs: 15 }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct EventConfig {
    pub batch_max_events: usize,
    pub batch_interval_ms: u64,
    pub compression: bool,
}

impl Default for EventConfig {
    fn default() -> Self {
        Self {
            batch_max_events: 100,
            batch_interval_ms: 500,
            compression: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct OfflineConfig {
    pub db_path: Option<PathBuf>,
    pub max_disk_mb: u64,
}

impl Default for OfflineConfig {
    fn default() -> Self {
        Self {
            db_path: None,
            max_disk_mb: 4096,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct UpgradeConfig {
    pub enabled: bool,
    pub check_interval_secs: u64,
    pub channel: String,
}

impl Default for UpgradeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            check_interval_secs: 3600,
            channel: "stable".into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct CaptureConfig {
    pub default_interface: Option<String>,
    pub bpf_filter: Option<String>,
    pub enabled_on_start: bool,
}

pub fn validate_and_canonicalize(config_data: &str) -> Result<String, String> {
    if let Ok(config) = toml::from_str::<AgentConfig>(config_data) {
        return toml::to_string(&config).map_err(|e| format!("Failed to serialize TOML: {e}"));
    }

    if let Ok(config) = serde_yaml::from_str::<AgentConfig>(config_data) {
        return toml::to_string(&config).map_err(|e| format!("Failed to serialize validated config as TOML: {e}"));
    }

    let toml_err = toml::from_str::<AgentConfig>(config_data).unwrap_err();
    let yaml_err = serde_yaml::from_str::<AgentConfig>(config_data).unwrap_err();

    Err(format!(
        "Invalid configuration format.\nTOML error: {}\nYAML error: {}",
        toml_err, yaml_err
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_and_canonicalize_toml() {
        let toml_data = r#"
        [heartbeat]
        interval_secs = 42

        [capture]
        bpf_filter = "tcp port 80"
        "#;

        let result = validate_and_canonicalize(toml_data);
        assert!(result.is_ok());
        let canonicalized = result.unwrap();
        assert!(canonicalized.contains("interval_secs = 42"));
        assert!(canonicalized.contains("bpf_filter = \"tcp port 80\""));
    }

    #[test]
    fn test_validate_and_canonicalize_yaml() {
        let yaml_data = r#"
heartbeat:
  interval_secs: 42
capture:
  bpf_filter: "tcp port 80"
"#;

        let result = validate_and_canonicalize(yaml_data);
        assert!(result.is_ok());
        let canonicalized = result.unwrap();
        assert!(canonicalized.contains("interval_secs = 42"));
        assert!(canonicalized.contains("bpf_filter = \"tcp port 80\""));
    }

    #[test]
    fn test_validate_and_canonicalize_invalid() {
        let invalid_data = r#"
heartbeat:
  interval_secs: "should be a number"
"#;

        let result = validate_and_canonicalize(invalid_data);
        assert!(result.is_err());
    }
}
