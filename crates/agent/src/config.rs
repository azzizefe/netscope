use std::path::PathBuf;
use clap::Parser;
use serde::Deserialize;

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
pub struct AgentConfig {
    pub server: ServerConfig,
    pub identity: IdentityConfig,
    pub heartbeat: HeartbeatConfig,
    pub events: EventConfig,
    pub offline: OfflineConfig,
    pub upgrade: UpgradeConfig,
    pub capture: CaptureConfig,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            identity: IdentityConfig::default(),
            heartbeat: HeartbeatConfig::default(),
            events: EventConfig::default(),
            offline: OfflineConfig::default(),
            upgrade: UpgradeConfig::default(),
            capture: CaptureConfig::default(),
        }
    }
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
pub struct CaptureConfig {
    pub default_interface: Option<String>,
    pub bpf_filter: Option<String>,
    pub enabled_on_start: bool,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            default_interface: None,
            bpf_filter: None,
            enabled_on_start: false,
        }
    }
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
