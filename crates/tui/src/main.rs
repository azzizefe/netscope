mod app;
mod colors;
mod headless;
mod ui;
mod views;

use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
#[command(name = "netscope", about = "Terminal network packet analyzer")]
struct Cli {
    /// Interface to capture on
    #[arg(short = 'i', long)]
    interface: Option<String>,

    /// Read packets from a pcap file
    #[arg(short = 'r', long = "read")]
    read: Option<String>,

    /// Save captured packets to a pcap file
    #[arg(short = 'w', long)]
    write: Option<String>,

    /// BPF filter expression (e.g. "tcp port 443")
    #[arg(short = 'f', long)]
    filter: Option<String>,

    /// Capture in monitor (rfmon) mode for raw 802.11 Wi-Fi frames
    /// (requires a monitor-capable adapter/driver)
    #[arg(long)]
    monitor: bool,

    /// List available network interfaces
    #[arg(short = 'D', long = "list-interfaces")]
    list_interfaces: bool,

    /// List IPs currently blocked by netscope firewall rules
    #[arg(long = "list-blocked")]
    list_blocked: bool,

    /// Remove all netscope firewall block rules and exit
    #[arg(long = "unblock-all")]
    unblock_all: bool,

    /// Headless mode: output packets as plain text to stdout
    #[arg(long)]
    headless: bool,

    /// JSON output mode (implies --headless, one JSON object per line)
    #[arg(long)]
    json: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.list_interfaces {
        return list_interfaces();
    }

    if cli.list_blocked {
        return list_blocked();
    }

    if cli.unblock_all {
        return unblock_all();
    }

    let headless = cli.headless || cli.json;
    if headless {
        return headless::run(cli);
    }

    // TUI mode — ratatui::init() handles raw mode + alternate screen itself;
    // doubling those calls leaves conhost on a blank buffer.
    let terminal = ratatui::init();
    let result = run_tui(cli, terminal);
    ratatui::restore();
    result
}

fn run_tui(cli: Cli, terminal: ratatui::DefaultTerminal) -> Result<()> {
    let app = app::App::new(
        cli.interface.as_deref(),
        cli.read.as_deref(),
        cli.filter.as_deref(),
        cli.write.as_deref(),
        cli.monitor,
    )?;
    app.run(terminal)
}

fn list_blocked() -> Result<()> {
    let blocked = netscope_core::firewall::blocked_ips();
    if blocked.is_empty() {
        println!("No IPs are currently blocked by netscope.");
    } else {
        println!("Blocked by netscope ({}):", blocked.len());
        for ip in &blocked {
            println!("  {ip}");
        }
    }
    Ok(())
}

fn unblock_all() -> Result<()> {
    if !netscope_core::firewall::is_elevated() {
        eprintln!("⚠ Not running as Administrator — removing rules may fail.");
    }
    let count = netscope_core::firewall::unblock_all()?;
    println!("Removed {count} netscope block rule(s).");
    Ok(())
}

fn list_interfaces() -> Result<()> {
    let devices = netscope_core::capture::list_interfaces()?;
    for dev in &devices {
        println!("{}", dev.name);
        if let Some(ref desc) = dev.desc {
            println!("  {desc}");
        }
        for addr in &dev.addresses {
            println!("  {}", addr.addr);
        }
        println!();
    }
    Ok(())
}
