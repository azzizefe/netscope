use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};

use anyhow::Result;
use crossbeam_channel::Receiver;
use netscope_core::capture::CaptureEngine;
use netscope_core::flows::FlowTable;
use netscope_core::models::Packet;
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
    pub start_time: DateTime<Utc>,
    pub running: Arc<AtomicBool>,
    pub packet_rx: Receiver<Packet>,
    pub interface_name: String,
    pub show_help: bool,
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
            iface.to_string()
        } else if let Some(path) = file {
            capture.start_offline(path, bpf_filter, output, packet_tx)?;
            path.to_string()
        } else {
            let devices = netscope_core::capture::list_interfaces()?;
            let first = devices
                .first()
                .map(|d| d.name.clone())
                .ok_or_else(|| anyhow::anyhow!("No network interfaces found"))?;
            let name = first.clone();
            capture.start_live(&first, bpf_filter, output, packet_tx)?;
            name
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
            start_time: Utc::now(),
            running,
            packet_rx,
            interface_name,
            show_help: false,
        })
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
            })
            .collect()
    }

    pub fn elapsed_secs(&self) -> i64 {
        (Utc::now() - self.start_time).num_seconds()
    }
}
