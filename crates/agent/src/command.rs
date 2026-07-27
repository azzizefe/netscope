use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::state::AgentState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerCommand {
    pub id: String,
    pub command: String,
    pub parameters: Value,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct CommandResult {
    pub command_id: String,
    pub status: String,
    pub output: Option<String>,
}

pub async fn command_loop(state: AgentState) {
    let interval = std::time::Duration::from_secs(5);

    loop {
        if state.shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }

        let sensor_id = match state.get_sensor_id() {
            Some(id) => id,
            None => {
                tokio::time::sleep(interval).await;
                continue;
            }
        };

        match poll_commands(&state, sensor_id).await {
            Ok(commands) => {
                for cmd in commands {
                    tracing::info!("Executing command: {} ({})", cmd.command, cmd.id);
                    let result = execute_command(&state, &cmd).await;
                    if let Err(e) = report_result(&state, sensor_id, &cmd.id, &result).await {
                        tracing::warn!("Failed to report command result: {}", e);
                    }
                }
            }
            Err(e) => {
                tracing::debug!("Command poll failed: {}", e);
            }
        }

        tokio::time::sleep(interval).await;
    }
}

async fn poll_commands(state: &AgentState, sensor_id: uuid::Uuid) -> anyhow::Result<Vec<ServerCommand>> {
    let path = format!("/api/v1/sensors/{}/commands", sensor_id);
    state.http_get(&path).await
}

async fn execute_command(state: &AgentState, cmd: &ServerCommand) -> CommandResult {
    let status = match cmd.command.as_str() {
        "ping" => "success".into(),
        "capture_start" => {
            state.capture_active.store(true, std::sync::atomic::Ordering::Relaxed);
            "success".into()
        }
        "capture_stop" => {
            state.capture_active.store(false, std::sync::atomic::Ordering::Relaxed);
            "success".into()
        }
        "set_filter" => {
            if let Some(filter) = cmd.parameters.get("bpf_filter").and_then(|v| v.as_str()) {
                tracing::info!("Setting BPF filter: {}", filter);
            }
            "success".into()
        }
        "upgrade" => {
            match crate::upgrade::do_upgrade(state).await {
                Ok(_) => "success".into(),
                Err(e) => {
                    tracing::error!("Upgrade failed: {}", e);
                    format!("failed: {}", e)
                }
            }
        }
        "restart" => {
            tracing::info!("Restart command received, initiating shutdown...");
            state.shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
            "success".into()
        }
        other => format!("unknown_command: {}", other),
    };

    CommandResult {
        command_id: cmd.id.clone(),
        status,
        output: None,
    }
}

async fn report_result(
    state: &AgentState,
    sensor_id: uuid::Uuid,
    cmd_id: &str,
    result: &CommandResult,
) -> anyhow::Result<()> {
    let path = format!("/api/v1/sensors/{}/commands/{}/result", sensor_id, cmd_id);
    let _: Value = state.http_put(&path, result).await?;
    Ok(())
}
