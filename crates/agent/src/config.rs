use clap::Parser;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(name = "netscope-agent", about = "Netscope Sensor Agent")]
pub struct CliArgs {
    #[arg(short = 'c', long, default_value = "/etc/netscope/agent.toml")]
    pub config: PathBuf,

    #[arg(long)]
    pub server_url: Option<String>,

    #[arg(long)]
    pub auth_token: Option<String>,

    #[arg(long)]
    pub sensor_id: Option<String>,

    #[arg(long)]
    pub register: bool,

    #[arg(long)]
    pub service: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct AgentConfig {
    pub server: ServerConfig,
    pub identity: IdentityConfig,
    pub heartbeat: HeartbeatConfig,
    pub events: EventConfig,
    pub offline: OfflineConfig,
    pub upgrade: UpgradeConfig,
    pub capture: CaptureConfig,
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct IdentityConfig {
    pub hostname: String,
    pub tags: Vec<String>,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            hostname: hostname(),
            tags: Vec::new(),
        }
    }
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown".into())
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct HeartbeatConfig {
    pub interval_secs: u64,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self { interval_secs: 15 }
    }
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct CaptureConfig {
    pub default_interface: Option<String>,
    pub bpf_filter: Option<String>,
    pub enabled_on_start: bool,
}

impl AgentConfig {
    pub fn load(args: &CliArgs) -> anyhow::Result<Self> {
        let mut config: Self = if args.config.exists() {
            let text = std::fs::read_to_string(&args.config)?;
            toml::from_str(&text)?
        } else {
            Self::default()
        };

        if let Some(url) = &args.server_url {
            config.server.url = url.clone();
        }
        if let Some(token) = &args.auth_token {
            config.server.auth_token = token.clone();
        }

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every section carries `#[serde(default)]`, so a config file naming one
    /// setting must keep the defaults for everything it does not mention. A
    /// missing default turns an unrelated omission into a zero — a heartbeat
    /// interval of 0 seconds would hammer the server.
    #[test]
    fn a_partial_config_keeps_the_defaults_around_it() {
        let config: AgentConfig = toml::from_str(
            r#"
            [heartbeat]
            interval_secs = 60
            "#,
        )
        .expect("parse");

        assert_eq!(config.heartbeat.interval_secs, 60);
        assert_eq!(config.server.url, "https://127.0.0.1:9443");
        assert_eq!(config.server.connect_timeout_secs, 10);
        assert_eq!(config.events.batch_max_events, 100);
        assert!(config.events.compression);
        assert_eq!(config.offline.max_disk_mb, 4096);
        assert_eq!(config.upgrade.channel, "stable");
    }

    /// An empty file is a valid config: it means "all defaults".
    #[test]
    fn an_empty_config_is_all_defaults() {
        let from_file: AgentConfig = toml::from_str("").expect("parse");
        let built_in = AgentConfig::default();

        assert_eq!(from_file.server.url, built_in.server.url);
        assert_eq!(
            from_file.heartbeat.interval_secs,
            built_in.heartbeat.interval_secs,
        );
        assert_eq!(from_file.upgrade.enabled, built_in.upgrade.enabled);
    }

    /// TLS paths are optional and stay unset unless the file names them —
    /// `insecure_skip_verify` in particular must never default to true.
    #[test]
    fn tls_is_verified_unless_the_file_says_otherwise() {
        let config = AgentConfig::default();
        assert!(!config.server.insecure_skip_verify);
        assert!(config.server.tls_cert.is_none());
        assert!(config.server.tls_key.is_none());
    }

    /// The flag wins over the file, which is the whole point of having both:
    /// pointing one agent at a different server must not need an edit to a
    /// config file shared by the fleet.
    #[test]
    fn a_cli_flag_overrides_the_config_file() {
        let mut config: AgentConfig = toml::from_str(
            r#"
            [server]
            url = "https://from-the-file:9443"
            auth_token = "file-token"
            "#,
        )
        .expect("parse");

        // The same two assignments `load` makes once the file has been read.
        let args = CliArgs {
            config: PathBuf::from("unused"),
            server_url: Some("https://from-the-flag:9443".into()),
            auth_token: None,
            sensor_id: None,
            register: false,
            service: None,
        };
        if let Some(url) = &args.server_url {
            config.server.url = url.clone();
        }
        if let Some(token) = &args.auth_token {
            config.server.auth_token = token.clone();
        }

        assert_eq!(config.server.url, "https://from-the-flag:9443");
        // Not overridden, so the file's value stands rather than being blanked.
        assert_eq!(config.server.auth_token, "file-token");
    }
}
