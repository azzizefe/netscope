use std::collections::{BTreeSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};

use anyhow::Result;
use crossbeam_channel::Receiver;
use netscope_core::capture::CaptureEngine;
use netscope_core::flows::FlowTable;
use netscope_core::models::Packet;
use netscope_core::names::NameCache;
use netscope_core::stats::StatsEngine;
use ratatui::crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};
use ratatui::DefaultTerminal;

use crate::views::View;

const MAX_PACKETS: usize = 10_000;

pub struct App {
    pub capture: CaptureEngine,
    pub packets: VecDeque<Packet>,
    pub selected: usize,
    pub paused: bool,
    pub view: View,
    pub show_hex: bool,
    pub detail_expanded: bool,
    pub filter_text: String,
    pub stats: StatsEngine,
    pub flows: FlowTable,
    pub names: NameCache,
    pub start_time: DateTime<Utc>,
    pub running: Arc<AtomicBool>,
    pub packet_rx: Receiver<Packet>,
    pub interface_name: String,
    pub show_help: bool,
    /// Row selected in the Connections view.
    pub conn_selected: usize,
    /// IPs blocked via OS firewall rules (mirrors `netscope-block-*` rules).
    pub blocked: BTreeSet<IpAddr>,
    /// Whether this process can install firewall rules.
    pub elevated: bool,
    /// Transient status line message with the time it was set.
    pub status_msg: Option<(String, Instant)>,
}

impl App {
    pub fn new(
        interface: Option<&str>,
        file: Option<&str>,
        bpf_filter: Option<&str>,
        output: Option<&str>,
    ) -> Result<Self> {
        let running = Arc::new(AtomicBool::new(true));
        let (packet_tx, packet_rx) = crossbeam_channel::unbounded();

        let mut capture = CaptureEngine::new();

        let interface_name = if let Some(iface) = interface {
            capture.start_live(iface, bpf_filter, output, packet_tx)?;
            netscope_core::capture::friendly_name_of(iface)
        } else if let Some(path) = file {
            capture.start_offline(path, bpf_filter, output, packet_tx)?;
            path.to_string()
        } else {
            let dev = netscope_core::capture::default_interface()?;
            let label = netscope_core::capture::friendly_name(&dev);
            capture.start_live(&dev.name, bpf_filter, output, packet_tx)?;
            label
        };

        Ok(Self {
            capture,
            packets: VecDeque::with_capacity(MAX_PACKETS),
            selected: 0,
            paused: false,
            view: View::Packets,
            show_hex: false,
            detail_expanded: false,
            filter_text: String::new(),
            stats: StatsEngine::new(),
            flows: FlowTable::new(),
            names: NameCache::new(),
            start_time: Utc::now(),
            running,
            packet_rx,
            interface_name,
            show_help: false,
            conn_selected: 0,
            blocked: netscope_core::firewall::blocked_ips(),
            elevated: netscope_core::firewall::is_elevated(),
            status_msg: None,
        })
    }

    /// Set a transient message shown in the status bar for a few seconds.
    fn notify(&mut self, msg: impl Into<String>) {
        self.status_msg = Some((msg.into(), Instant::now()));
    }

    /// The most recent status message, if still fresh (< 5s old).
    pub fn active_status(&self) -> Option<&str> {
        self.status_msg.as_ref().and_then(|(msg, at)| {
            if at.elapsed() < Duration::from_secs(5) {
                Some(msg.as_str())
            } else {
                None
            }
        })
    }

    /// Block or unblock the remote host of the selected connection.
    fn toggle_block_selected(&mut self) {
        let flows = self.flows.flows();
        let Some(flow) = flows.get(self.conn_selected) else {
            return;
        };
        // The "remote" side is the server (the address the client reached out to).
        let ip = flow.server_addr;
        let label = self
            .names
            .name_for(ip)
            .map(|n| n.to_string())
            .unwrap_or_else(|| ip.to_string());

        if self.blocked.contains(&ip) {
            match netscope_core::firewall::unblock(ip) {
                Ok(()) => {
                    self.blocked.remove(&ip);
                    self.notify(format!("Unblocked {label}"));
                }
                Err(e) => self.notify(format!("Unblock failed: {e}")),
            }
        } else {
            match netscope_core::firewall::block(ip) {
                Ok(()) => {
                    self.blocked.insert(ip);
                    self.notify(format!("Blocked {label} ({ip})"));
                }
                Err(e) => self.notify(format!("Block failed: {e}")),
            }
        }
    }

    pub fn run(mut self, mut terminal: DefaultTerminal) -> Result<()> {
        let tick_rate = Duration::from_millis(50);
        let mut last_tick = Instant::now();

        loop {
            let now = Instant::now();
            if now - last_tick >= tick_rate {
                self.tick();
                last_tick = now;
            }

            terminal.draw(|f| crate::ui::render(f, &mut self))?;

            if !self.running.load(Ordering::Relaxed) {
                break;
            }

            if crossterm::event::poll(Duration::from_millis(10))? {
                if let crossterm::event::Event::Key(key) = crossterm::event::read()? {
                    if key.kind == KeyEventKind::Press && !self.handle_key(key)? {
                        break;
                    }
                }
            }
        }

        self.capture.stop();
        Ok(())
    }

    fn tick(&mut self) {
        if self.paused {
            return;
        }
        // Drain available packets
        while let Ok(pkt) = self.packet_rx.try_recv() {
            self.names.observe(&pkt);
            self.stats.record_packet(&pkt);
            self.flows.record(&pkt);
            if self.packets.len() >= MAX_PACKETS {
                self.packets.pop_front();
                if self.selected > 0 {
                    self.selected -= 1;
                }
            }
            self.packets.push_back(pkt);
        }
    }

    fn handle_key(&mut self, key: crossterm::event::KeyEvent) -> Result<bool> {
        if self.show_help {
            if key.code == KeyCode::Char('?') || key.code == KeyCode::Esc {
                self.show_help = false;
            }
            return Ok(true);
        }

        // The Connections view has its own navigation and block controls;
        // handle those first so letter keys act as commands, not filter text.
        if self.view == View::Connections {
            match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    self.conn_selected = self.conn_selected.saturating_sub(1);
                    return Ok(true);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    let n = self.flows.len();
                    if n > 0 && self.conn_selected + 1 < n {
                        self.conn_selected += 1;
                    }
                    return Ok(true);
                }
                KeyCode::Char('b') | KeyCode::Char('u') => {
                    self.toggle_block_selected();
                    return Ok(true);
                }
                _ => {}
            }
        }

        match key.code {
            KeyCode::Char('q') => {
                self.running.store(false, Ordering::Relaxed);
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if !self.packets.is_empty() {
                    self.selected = self.selected.saturating_sub(1);
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if !self.packets.is_empty() && self.selected + 1 < self.packets.len() {
                    self.selected += 1;
                }
            }
            KeyCode::Enter => {
                self.detail_expanded = !self.detail_expanded;
            }
            KeyCode::Tab => {
                self.view = if key.modifiers.contains(KeyModifiers::SHIFT) {
                    self.view.prev()
                } else {
                    self.view.next()
                };
            }
            KeyCode::Char(' ') => {
                self.paused = !self.paused;
            }
            KeyCode::Char('h') => {
                self.show_hex = !self.show_hex;
            }
            KeyCode::Char('?') => {
                self.show_help = true;
            }
            KeyCode::Esc => {
                if !self.filter_text.is_empty() {
                    self.filter_text.clear();
                }
            }
            KeyCode::Backspace => {
                self.filter_text.pop();
            }
            KeyCode::Char(c) => {
                self.filter_text.push(c);
            }
            _ => {}
        }
        Ok(true)
    }

    pub fn filtered_packets(&self) -> Vec<&Packet> {
        if self.filter_text.is_empty() {
            return self.packets.iter().collect();
        }
        let lower = self.filter_text.to_lowercase();
        self.packets
            .iter()
            .filter(|p| {
                p.summary.to_lowercase().contains(&lower)
                    || p.protocol.to_string().to_lowercase().contains(&lower)
                    || p.src_addr.is_some_and(|a| a.to_string().contains(&lower))
                    || p.dst_addr.is_some_and(|a| a.to_string().contains(&lower))
                    || p.src_addr
                        .and_then(|a| self.names.name_for(a))
                        .is_some_and(|n| n.to_lowercase().contains(&lower))
                    || p.dst_addr
                        .and_then(|a| self.names.name_for(a))
                        .is_some_and(|n| n.to_lowercase().contains(&lower))
            })
            .collect()
    }

    pub fn elapsed_secs(&self) -> i64 {
        (Utc::now() - self.start_time).num_seconds()
    }
}
