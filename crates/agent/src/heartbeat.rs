use std::time::Instant;

use serde::Serialize;
use sysinfo::{Disks, Networks, System};

use crate::state::AgentState;

#[derive(Debug, Serialize)]
pub struct HeartbeatPayload {
    pub cpu_load_pct: f32,
    pub ram_used_mb: i32,
    pub capture_throughput_bps: i64,
    pub disk_free_mb: i64,
    pub uptime_secs: i64,
}

pub async fn heartbeat_loop(state: AgentState, started_at: Instant) {
    let interval = std::time::Duration::from_secs(state.config.heartbeat.interval_secs);
    let mut sys = System::new();
    let mut disks = Disks::new();
    let mut networks = Networks::new();

    loop {
        if state.shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }

        tokio::time::sleep(interval).await;
        if let Err(e) = send_heartbeat(&state, &mut sys, &mut disks, &mut networks, started_at).await {
            tracing::warn!("Heartbeat failed: {}", e);
        }
    }
}

async fn send_heartbeat(
    state: &AgentState,
    sys: &mut System,
    disks: &mut Disks,
    _networks: &mut Networks,
    started_at: Instant,
) -> anyhow::Result<()> {
    sys.refresh_cpu();
    sys.refresh_memory();
    disks.refresh();

    let sensor_id = match state.get_sensor_id() {
        Some(id) => id,
        None => return Err(anyhow::anyhow!("Not registered yet")),
    };

    let disk_free_mb: i64 = disks
        .iter()
        .filter(|d| {
            cfg!(windows) && d.mount_point().to_string_lossy().contains("C:")
                || d.mount_point() == std::path::Path::new("/")
                || d.mount_point() == std::path::Path::new("/var")
        })
        .next()
        .map(|d| (d.available_bytes() / (1024 * 1024)) as i64)
        .unwrap_or(0);

    let hb = HeartbeatPayload {
        cpu_load_pct: sys.global_cpu_usage(),
        ram_used_mb: (sys.used_memory() / (1024 * 1024)) as i32,
        capture_throughput_bps: 0,
        disk_free_mb,
        uptime_secs: started_at.elapsed().as_secs() as i64,
    };

    let path = format!("/api/v1/sensors/{}/heartbeat", sensor_id);
    let resp: serde_json::Value = state.http_put(&path, &hb).await?;
    tracing::debug!("Heartbeat sent: CPU={}% RAM={}MB Disk={}MB",
        hb.cpu_load_pct, hb.ram_used_mb, hb.disk_free_mb);
    Ok(())
}
