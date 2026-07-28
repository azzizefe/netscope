use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(name = "netscope-server", about = "Netscope Central Management Server")]
pub struct CliArgs {
    #[arg(short = 'c', long, default_value = "/etc/netscope/server.toml")]
    pub config: PathBuf,

    #[arg(short = 'H', long)]
    pub db_url: Option<String>,

    #[arg(long)]
    pub redis_url: Option<String>,

    // No clap defaults on the three below: a default is indistinguishable from
    // an explicit flag, so main.rs could never tell "the operator asked for
    // 9443" from "the operator said nothing", and the config file's `[server]`
    // block lost every time. `Option` plus the fallback chain in main.rs makes
    // the precedence flag > config file > built-in default, which is how
    // `--db-url` and `--jwt-secret` already behave.
    #[arg(short = 'l', long)]
    pub listen: Option<String>,

    #[arg(short = 'p', long)]
    pub port: Option<u16>,

    #[arg(long)]
    pub tls_cert: Option<PathBuf>,

    #[arg(long)]
    pub tls_key: Option<PathBuf>,

    #[arg(long)]
    pub tls_ca: Option<PathBuf>,

    #[arg(long)]
    pub jwt_secret: Option<String>,

    /// Sign tokens with a per-process secret when none is configured.
    ///
    /// Local development only: sessions do not survive a restart and a second
    /// instance will not accept the first one's tokens. Without this the server
    /// refuses to start unconfigured rather than doing it silently.
    #[arg(long, default_value_t = false)]
    pub dev_insecure_jwt: bool,

    #[arg(long, default_value_t = false)]
    pub grpc_enabled: bool,

    #[arg(long)]
    pub grpc_port: Option<u16>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ServerConfig {
    pub listen: String,
    pub port: u16,
    pub tls: Option<TlsConfig>,
    pub jwt: Option<JwtConfig>,
    pub grpc: Option<GrpcConfig>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct TlsConfig {
    pub cert: PathBuf,
    pub key: PathBuf,
    pub ca: Option<PathBuf>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct JwtConfig {
    pub secret: String,
    pub issuer: Option<String>,
    pub expiry_hours: Option<i64>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct GrpcConfig {
    pub enabled: bool,
    pub port: u16,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: Option<u32>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RedisConfig {
    pub url: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct AppConfig {
    pub server: Option<ServerConfig>,
    pub database: Option<DatabaseConfig>,
    pub redis: Option<RedisConfig>,
}
