mod app;
mod colors;
mod columns;
mod detail;
mod headless;
mod insights;
mod setup;
mod stream;
mod theme;
mod ui;
mod views;

use anyhow::Result;
use clap::Parser;
use netscope_core::editcap::{MergeOptions, SplitOptions, SplitMode, WriteFormat};

#[derive(Parser)]
#[command(name = "netscope", about = "Terminal network packet analyzer")]
struct Cli {
    /// Interface(s) to capture on — comma-separated for several at once
    /// (e.g. "Wi-Fi,Ethernet"), Wireshark-style. "-" reads a pcap/pcapng
    /// stream from stdin; "\\.\USBPcap1" captures USB via USBPcap (Windows)
    #[arg(short = 'i', long)]
    interface: Option<String>,

    /// Read packets from a pcap file
    #[arg(short = 'r', long = "read")]
    read: Option<String>,

    /// Passphrase to decrypt an encrypted capture file (.pcap.enc)
    #[arg(long = "passphrase", value_name = "PASSPHRASE")]
    passphrase: Option<String>,

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

    /// Stop the capture automatically (repeatable, Wireshark's -a):
    /// duration:SECONDS, packets:COUNT or filesize:kB
    #[arg(short = 'a', long = "autostop", value_name = "COND")]
    autostop: Vec<String>,

    /// Ring-buffer rotation for the -w file (repeatable, Wireshark's -b):
    /// filesize:kB, duration:SECONDS, files:COUNT
    #[arg(short = 'b', long = "ring", value_name = "COND")]
    ring: Vec<String>,

    /// Capture on a remote host over SSH, sshdump-style (runs tcpdump
    /// there and streams the pcap back; needs key/agent authentication)
    #[arg(long, value_name = "HOST")]
    remote_host: Option<String>,

    /// SSH user for --remote-host
    #[arg(long, value_name = "USER")]
    remote_user: Option<String>,

    /// SSH port for --remote-host
    #[arg(long, value_name = "PORT")]
    remote_port: Option<u16>,

    /// SSH identity (private-key) file for --remote-host
    #[arg(long, value_name = "FILE")]
    remote_identity: Option<String>,

    /// Interface to capture on the remote host (default: any)
    #[arg(long, value_name = "IFACE")]
    remote_interface: Option<String>,

    /// Full remote command override — must write pcap/pcapng to stdout
    /// (e.g. "dumpcap -w -" or a vendor CLI); replaces the tcpdump default
    #[arg(long, value_name = "CMD")]
    remote_command: Option<String>,

    /// Run the remote capture command with sudo (passwordless sudo on the
    /// remote side)
    #[arg(long)]
    remote_sudo: bool,

    /// Coloring rules file: one "<hex-color> <display filter>" per line,
    /// first match tints the packet row (default:
    /// ~/.config/netscope/colors or %APPDATA%\netscope\colors)
    #[arg(long)]
    colors: Option<String>,

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

    /// Spawn a lightweight REST API server on the specified port (implies --headless)
    #[arg(long = "serve", value_name = "PORT")]
    serve: Option<u16>,

    #[command(subcommand)]
    subcommand: Option<SubCommand>,
}

#[derive(clap::Subcommand)]
enum SubCommand {
    /// Merge multiple capture files into one (mergecap equivalent)
    Merge {
        /// Input capture files to merge
        #[arg(required = true)]
        inputs: Vec<String>,
        /// Output file path
        #[arg(short = 'w', long = "write", required = true)]
        output: String,
        /// Write in pcapng format instead of classic pcap
        #[arg(long = "pcapng")]
        pcapng: bool,
        /// Do not interleave packets chronologically (concatenate instead)
        #[arg(long = "no-sort")]
        no_sort: bool,
    },
    /// Split a capture file into smaller chunks (editcap split equivalent)
    Split {
        /// Input capture file to split
        #[arg(required = true)]
        input: String,
        /// Output prefix for split files (e.g., "prefix")
        #[arg(short = 'w', long = "write", required = true)]
        output_prefix: String,
        /// Split by packet count per file
        #[arg(long = "packets", value_name = "COUNT")]
        packets: Option<usize>,
        /// Split by time interval (seconds) per file
        #[arg(long = "seconds", value_name = "SECONDS")]
        seconds: Option<u64>,
        /// Split by byte size per file
        #[arg(long = "bytes", value_name = "BYTES")]
        bytes: Option<u64>,
        /// Write in pcapng format instead of classic pcap
        #[arg(long = "pcapng")]
        pcapng: bool,
    },
    /// Show summary information about a capture file (capinfos equivalent)
    Info {
        /// Capture file to inspect
        #[arg(required = true)]
        input: String,
    },
}

fn handle_subcommand(sub: SubCommand) -> Result<()> {
    match sub {
        SubCommand::Merge { inputs, output, pcapng, no_sort } => {
            let format = if pcapng { WriteFormat::PcapNg } else { WriteFormat::Pcap };
            let opts = MergeOptions {
                format,
                chronological: !no_sort,
                comment: Some("Merged with netscope".to_string()),
            };
            let input_paths: Vec<std::path::PathBuf> = inputs.iter().map(std::path::PathBuf::from).collect();
            let output_path = std::path::PathBuf::from(output);
            
            println!("Merging {} file(s) into {}...", input_paths.len(), output_path.display());
            let stats = netscope_core::editcap::merge(&input_paths, &output_path, &opts)?;
            println!("Merge complete!");
            println!("  Packets merged: {}", stats.packets);
            println!("  Output size: {} bytes", std::fs::metadata(&output_path)?.len());
        }
        SubCommand::Split { input, output_prefix, packets, seconds, bytes, pcapng } => {
            let format = if pcapng { WriteFormat::PcapNg } else { WriteFormat::Pcap };
            let mode = match (packets, seconds, bytes) {
                (Some(p), None, None) => SplitMode::Packets(p),
                (None, Some(s), None) => SplitMode::Seconds(s),
                (None, None, Some(b)) => SplitMode::Bytes(b),
                _ => anyhow::bail!("Specify exactly one split condition: --packets, --seconds, or --bytes"),
            };
            let opts = SplitOptions { format, mode };
            let input_path = std::path::PathBuf::from(input);
            let prefix_path = std::path::PathBuf::from(output_prefix);

            println!("Splitting {}...", input_path.display());
            let files = netscope_core::editcap::split(&input_path, &prefix_path, &opts)?;
            println!("Split complete! Created {} file(s):", files.len());
            for f in files {
                println!("  {}", f.display());
            }
        }
        SubCommand::Info { input } => {
            let input_path = std::path::PathBuf::from(input);
            let info = netscope_core::editcap::info(&input_path)?;
            println!("File name:    {}", input_path.file_name().unwrap_or_default().to_string_lossy());
            println!("File format:  {}", info.format.label());
            println!("Link type:    {} ({})", info.linktype, match info.linktype {
                1 => "Ethernet",
                127 => "IEEE 802.11 (WLAN)",
                189 | 220 | 249 => "USB",
                _ => "Other",
            });
            println!("Packet count: {}", info.packets);
            println!("Data size:    {} bytes", info.data_bytes);
            if let Some(dur) = info.duration_secs() {
                println!("Duration:     {:.6} seconds", dur);
            } else {
                println!("Duration:     N/A");
            }
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if let Some(sub) = cli.subcommand {
        return handle_subcommand(sub);
    }

    // Layered configuration (~/.netscope, ROADMAP §2.4): load once and
    // install the declarative protocol plugins (§2.3) into the dissector
    // registry — both the TUI and headless modes see them.
    let config = netscope_core::config::Config::load();
    let plugins = netscope_core::plugins::load_from_config(&config);
    for err in &plugins.errors {
        eprintln!("Warning: plugin skipped — {err}");
    }

    if cli.list_interfaces {
        return list_interfaces();
    }

    if cli.list_blocked {
        return list_blocked();
    }

    if cli.unblock_all {
        return unblock_all();
    }

    let headless = cli.headless || cli.json || cli.serve.is_some();
    if headless {
        return headless::run(cli);
    }

    // TUI mode — ratatui::init() handles raw mode + alternate screen itself;
    // doubling those calls leaves conhost on a blank buffer. Mouse capture
    // (ROADMAP §6.1) is opt-in on top: enable it here, disable it on restore.
    let terminal = ratatui::init();
    let _ = ratatui::crossterm::execute!(
        std::io::stdout(),
        ratatui::crossterm::event::EnableMouseCapture
    );
    let result = run_tui(cli, terminal);
    let _ = ratatui::crossterm::execute!(
        std::io::stdout(),
        ratatui::crossterm::event::DisableMouseCapture
    );
    ratatui::restore();
    result
}

fn run_tui(cli: Cli, terminal: ratatui::DefaultTerminal) -> Result<()> {
    let app = app::App::new(&cli)?;
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
        let kind = netscope_core::capture::interface_kind(dev);
        match kind {
            netscope_core::capture::InterfaceKind::Regular => println!("{}", dev.name),
            other => println!("{}  [{}]", dev.name, other.as_str()),
        }
        if let Some(ref desc) = dev.desc {
            println!("  {desc}");
        }
        for addr in &dev.addresses {
            println!("  {}", addr.addr);
        }
        println!();
    }
    // Windows USB capture devices (USBPcap) aren't libpcap interfaces; list
    // them too so `-i \\.\USBPcap1` is discoverable.
    let usb = netscope_core::remote::usbpcap_interfaces();
    for (value, display) in &usb {
        println!("{value}  [usb]");
        println!("  {display}");
        println!();
    }
    Ok(())
}
