use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::AgentState;

#[derive(Debug, Serialize)]
pub struct RegisterRequest {
    pub hostname: String,
    pub ip_address: String,
    pub os: String,
    pub version: String,
    pub interfaces: Vec<InterfaceInfo>,
    pub cpu_cores: i32,
    pub ram_mb: i32,
}

#[derive(Debug, Serialize)]
pub struct InterfaceInfo {
    pub name: String,
    pub mac: Option<String>,
    pub ips: Vec<String>,
    pub mtu: Option<u16>,
}

#[derive(Debug, Deserialize)]
pub struct RegisterResponse {
    pub id: Uuid,
    pub hostname: String,
    pub status: String,
}

pub async fn register(state: &AgentState) -> anyhow::Result<Uuid> {
    let info = system_info();

    let resp: RegisterResponse = state
        .http_post("/api/v1/sensors/register", &info)
        .await?;

    tracing::info!("Registered with server as sensor {}", resp.id);
    Ok(resp.id)
}

fn system_info() -> RegisterRequest {
    let os = if cfg!(windows) {
        "windows".into()
    } else if cfg!(target_os = "linux") {
        "linux".into()
    } else if cfg!(target_os = "macos") {
        "macos".into()
    } else {
        "unknown".into()
    };

    RegisterRequest {
        hostname: state::config.identity.hostname.clone(),
        ip_address: local_ip().unwrap_or_else(|| "127.0.0.1".into()),
        os,
        version: env!("CARGO_PKG_VERSION").into(),
        interfaces: Vec::new(),
        cpu_cores: num_cpus::get() as i32,
        ram_mb: total_ram_mb(),
    }
}

fn local_ip() -> Option<String> {
    for iface in pcap::Device::list().ok()? {
        for addr in iface.addrs {
            if addr.addr.is_ipv4() && !addr.addr.is_loopback() {
                return Some(addr.addr.to_string());
            }
        }
    }
    None
}

fn total_ram_mb() -> i32 {
    use sysinfo::System;
    let mut sys = System::new();
    sys.refresh_memory();
    (sys.total_memory() / (1024 * 1024)) as i32
}
