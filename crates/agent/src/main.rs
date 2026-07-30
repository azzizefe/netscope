mod command;
mod config;
mod events;
mod heartbeat;
mod offline;
mod register;
mod service;
mod state;
mod upgrade;
mod ws_client;

use clap::Parser;
use config::CliArgs;

fn main() -> anyhow::Result<()> {
    let args = CliArgs::parse();

    #[cfg(windows)]
    if let Some(ref action) = args.service {
        return handle_windows_service(action);
    }

    // `--service` is a Windows SCM wrapper, but clap accepts the flag on every
    // platform. Without this branch, `--service install` on Linux or macOS fell
    // through to the line below and started a foreground agent: the command
    // appeared to succeed, no service was installed, and the operator only
    // found out when the host rebooted and nothing came back.
    #[cfg(not(windows))]
    if args.service.is_some() {
        anyhow::bail!(
            "--service is Windows-only (it drives the Windows Service Manager).\n  \
             On Linux use the systemd unit and on macOS a launchd plist — see \
             docs/ENTERPRISE_DEPLOYMENT.md."
        );
    }

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(service::run_agent(args))
}

#[cfg(windows)]
fn handle_windows_service(action: &str) -> anyhow::Result<()> {
    let service_name = "netscope-agent";

    match action {
        "install" => {
            let binary_path = std::env::current_exe()?;
            let status = std::process::Command::new("sc")
                .args([
                    "create",
                    service_name,
                    "binPath=",
                    &binary_path.to_string_lossy(),
                    "start=",
                    "auto",
                    "DisplayName=",
                    "Netscope Sensor Agent",
                    "description=",
                    "Netscope remote capture sensor agent",
                ])
                .status()?;
            if status.success() {
                println!("Service '{}' installed", service_name);
            } else {
                anyhow::bail!("Failed to install service (try running as Administrator)");
            }
        }
        "uninstall" => {
            let status = std::process::Command::new("sc")
                .args(["delete", service_name])
                .status()?;
            if status.success() {
                println!("Service '{}' removed", service_name);
            } else {
                anyhow::bail!("Failed to remove service (try running as Administrator)");
            }
        }
        "start" => {
            let status = std::process::Command::new("net")
                .args(["start", service_name])
                .status()?;
            if status.success() {
                println!("Service '{}' started", service_name);
            } else {
                anyhow::bail!("Failed to start service (try running as Administrator)");
            }
        }
        "stop" => {
            let status = std::process::Command::new("net")
                .args(["stop", service_name])
                .status()?;
            if status.success() {
                println!("Service '{}' stopped", service_name);
            } else {
                anyhow::bail!("Failed to stop service (try running as Administrator)");
            }
        }
        "run" => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(service::run_agent(CliArgs::parse()))?;
        }
        _ => {
            eprintln!(
                "Usage: netscope-agent --service [install|uninstall|start|stop|run]\n\
                       For first install, run as Administrator:\n  \
                       netscope-agent --service install\n  \
                       netscope-agent --service start"
            );
        }
    }

    Ok(())
}
