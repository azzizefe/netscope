use std::path::PathBuf;
use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "netscope-server", about = "Netscope Central Management Server")]
pub struct CliArgs {
    #[arg(short = 'c', long, default_value = "/etc/netscope/server.toml")]
    pub config: PathBuf,

    #[arg(short = 'H', long)]
    pub db_url: Option<String>,

    #[arg(long)]
    pub redis_url: Option<String>,

    #[arg(short = 'l', long, default_value = "0.0.0.0")]
    pub listen: String,

    #[arg(short = 'p', long, default_value_t = 9443)]
    pub port: u16,

    #[arg(long)]
    pub tls_cert: Option<PathBuf>,

    #[arg(long)]
    pub tls_key: Option<PathBuf>,

    #[arg(long)]
    pub tls_ca: Option<PathBuf>,

    #[arg(long)]
    pub jwt_secret: Option<String>,

    #[arg(long, default_value_t = false)]
    pub grpc_enabled: bool,

    #[arg(long, default_value_t = 9444)]
    pub grpc_port: u16,
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
