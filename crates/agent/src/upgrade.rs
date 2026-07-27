use std::path::Path;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::state::AgentState;

#[derive(Debug, Deserialize)]
pub struct UpgradeInfo {
    pub version: String,
    pub url: String,
    pub sha256: String,
}

pub async fn upgrade_loop(state: AgentState) {
    if !state.config.upgrade.enabled {
        return;
    }

    let interval = std::time::Duration::from_secs(state.config.upgrade.check_interval_secs);

    loop {
        if state.shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }

        tokio::time::sleep(interval).await;

        match check_upgrade(&state).await {
            Ok(Some(info)) => {
                tracing::info!("Upgrade available: {} -> {}", env!("CARGO_PKG_VERSION"), info.version);
                if let Err(e) = upgrade_binary(&state, &info).await {
                    tracing::error!("Upgrade failed: {}", e);
                }
            }
            Ok(None) => {
                tracing::debug!("No upgrade available");
            }
            Err(e) => {
                tracing::warn!("Upgrade check failed: {}", e);
            }
        }
    }
}

async fn check_upgrade(state: &AgentState) -> anyhow::Result<Option<UpgradeInfo>> {
    let current = env!("CARGO_PKG_VERSION");
    let channel = &state.config.upgrade.channel;

    let info: UpgradeInfo = state
        .http_get(&format!("/api/v1/upgrade/check?version={}&channel={}", current, channel))
        .await?;

    if info.version.as_str() > current {
        Ok(Some(info))
    } else {
        Ok(None)
    }
}

pub async fn do_upgrade(state: &AgentState) -> anyhow::Result<()> {
    let current = env!("CARGO_PKG_VERSION");
    let channel = &state.config.upgrade.channel;

    let info: UpgradeInfo = state
        .http_get(&format!("/api/v1/upgrade/check?version={}&channel={}", current, channel))
        .await?;

    if info.version.as_str() <= current {
        anyhow::bail!("No newer version available (current: {}, latest: {})", current, info.version);
    }

    upgrade_binary(state, &info).await
}

async fn upgrade_binary(state: &AgentState, info: &UpgradeInfo) -> anyhow::Result<()> {
    let tmp_dir = std::env::temp_dir().join("netscope-upgrade");
    std::fs::create_dir_all(&tmp_dir)?;

    let bin_name = current_binary_name();
    let download_path = tmp_dir.join(format!("{}.new", bin_name));
    let backup_path = tmp_dir.join(format!("{}.bak", bin_name));

    let url = if info.url.starts_with("http") {
        info.url.clone()
    } else {
        format!("{}{}", state.config.server.url, info.url)
    };

    tracing::info!("Downloading new binary from {}", url);
    let response = state.http_client.get(&url).send().await?;
    let bytes = response.bytes().await?;

    let hash = Sha256::digest(&bytes);
    let hash_hex = format!("{:x}", hash);
    if hash_hex != info.sha256 {
        anyhow::bail!("SHA256 mismatch: expected {}, got {}", info.sha256, hash_hex);
    }
    tracing::info!("Checksum verified");

    std::fs::write(&download_path, &bytes)?;
    set_executable(&download_path);

    let current_path = std::env::current_exe()?;

    if backup_path.exists() {
        std::fs::remove_file(&backup_path)?;
    }

    std::fs::rename(&current_path, &backup_path)?;
    if let Err(e) = std::fs::rename(&download_path, &current_path) {
        let _ = std::fs::rename(&backup_path, &current_path);
        anyhow::bail!("Swap failed, rollback applied: {}", e);
    }

    tracing::info!("Upgrade to {} complete. Restarting...", info.version);

    restart_process(&current_path);
    Ok(())
}

fn current_binary_name() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_else(|| "netscope-agent".into())
}

fn set_executable(_path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(_path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o755);
            let _ = std::fs::set_permissions(_path, perms);
        }
    }
}

fn restart_process(new_binary: &Path) {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let _ = std::process::Command::new(new_binary)
        .args(&args)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn();

    std::process::exit(0);
}
