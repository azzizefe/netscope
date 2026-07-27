use std::time::Instant;

use tracing_subscriber::EnvFilter;

use crate::command;
use crate::config::{AgentConfig, CliArgs};
use crate::events;
use crate::heartbeat;
use crate::register;
use crate::state::AgentState;
use crate::upgrade;

pub async fn run_agent(args: CliArgs) -> anyhow::Result<()> {
    let config = AgentConfig::load(&args)?;

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info,netscope_agent=debug")))
        .init();

    tracing::info!("Starting netscope-agent v{}", env!("CARGO_PKG_VERSION"));

    let state = AgentState::new(config.clone()).await?;

    if args.register || state.get_sensor_id().is_none() {
        match register::register(&state).await {
            Ok(id) => {
                state.save_sensor_id(id);
                tracing::info!("Registered as sensor {}", id);
            }
            Err(e) => {
                if state.get_sensor_id().is_none() {
                    tracing::warn!("Registration failed (will retry): {}", e);
                } else {
                    tracing::warn!("Re-registration failed: {}", e);
                }
            }
        }
    }

    let started_at = Instant::now();
    let (event_tx, event_rx) = events::create_event_channel();

    let mut handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    if state.get_sensor_id().is_some() {
        handles.push(tokio::spawn(heartbeat::heartbeat_loop(
            state.clone(),
            started_at,
        )));
        handles.push(tokio::spawn(command::command_loop(state.clone())));
        handles.push(tokio::spawn(events::event_loop(
            state.clone(),
            event_rx,
        )));
        handles.push(tokio::spawn(upgrade::upgrade_loop(state.clone())));
    }

    if state.get_sensor_id().is_some() {
        let _ = event_tx.send(events::RawEvent {
            event_type: "agent.startup".into(),
            severity: "info".into(),
            title: "Agent started".into(),
            description: Some(format!("Version {}", env!("CARGO_PKG_VERSION"))),
            source_ip: None,
            dest_ip: None,
            protocol: None,
            port: None,
            raw_data: None,
        }).await;
    }

    let flush_state = state.clone();
    handles.push(tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            events::flush_offline_buffer(&flush_state).await;

            if flush_state.shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
        }
    }));

    wait_for_shutdown().await;

    tracing::info!("Shutting down...");
    state.shutdown.store(true, std::sync::atomic::Ordering::Relaxed);

    for handle in handles {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
    }

    Ok(())
}

async fn wait_for_shutdown() {
    tokio::signal::ctrl_c().await.ok();
    tracing::info!("Received Ctrl+C, shutting down...");
}
