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

    /// List available network interfaces
    #[arg(short = 'D', long = "list-interfaces")]
    list_interfaces: bool,

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

    let headless = cli.headless || cli.json;
    if headless {
        return headless::run(cli);
    }

    // TUI mode
    use ratatui::crossterm::terminal::{
        disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
    };
    use ratatui::crossterm::ExecutableCommand;
    use std::io::stdout;

    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let terminal = ratatui::init();

    let result = run_tui(cli, terminal);

    ratatui::restore();
    stdout().execute(LeaveAlternateScreen)?;
    disable_raw_mode()?;
    result
}

fn run_tui(cli: Cli, terminal: ratatui::DefaultTerminal) -> Result<()> {
    let app = app::App::new(
        cli.interface.as_deref(),
        cli.read.as_deref(),
        cli.filter.as_deref(),
        cli.write.as_deref(),
    )?;
    app.run(terminal)
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
