use serde::{Deserialize, Serialize};
use sysinfo::Networks;
use uuid::Uuid;

use crate::state::AgentState;

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
    let info = system_info(state);

    let resp: RegisterResponse = state
        .http_post("/api/v1/sensors/register", &info)
        .await?;

    tracing::info!("Registered with server as sensor {}", resp.id);
    Ok(resp.id)
}

fn system_info(state: &AgentState) -> RegisterRequest {
    let os = if cfg!(windows) {
        "windows".into()
    } else if cfg!(target_os = "linux") {
        "linux".into()
    } else if cfg!(target_os = "macos") {
        "macos".into()
    } else {
        "unknown".into()
    };

    let mut sys = sysinfo::System::new();
    sys.refresh_memory();

    RegisterRequest {
        hostname: state.config.identity.hostname.clone(),
        ip_address: local_ip().unwrap_or_else(|| "127.0.0.1".into()),
        os,
        version: env!("CARGO_PKG_VERSION").into(),
        interfaces: list_interfaces(),
        cpu_cores: num_cpus::get() as i32,
        ram_mb: (sys.total_memory() / (1024 * 1024)) as i32,
    }
}

fn local_ip() -> Option<String> {
    for iface in get_ifaces() {
        for ip in iface.ips {
            if let Ok(std::net::IpAddr::V4(v4)) = ip.parse() {
                if !v4.is_loopback() && !v4.is_link_local() {
                    return Some(v4.to_string());
                }
            }
        }
    }
    None
}

fn get_ifaces() -> Vec<InterfaceInfo> {
    let networks = Networks::new_with_refreshed_list();
    let mut result = Vec::new();

    for (name, data) in networks.iter() {
        let ips: Vec<String> = data.ip_networks()
            .iter()
            .map(|n| n.addr.to_string())
            .collect();
        let mac_str = {
            let m = data.mac_address();
            format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                m.0[0], m.0[1], m.0[2], m.0[3], m.0[4], m.0[5])
        };
        result.push(InterfaceInfo {
            name: name.clone(),
            mac: Some(mac_str),
            ips,
            mtu: None,
        });
    }
    result
}

fn list_interfaces() -> Vec<InterfaceInfo> {
    get_ifaces()
}
