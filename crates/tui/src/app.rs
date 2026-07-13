use std::collections::{BTreeSet, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};

use anyhow::Result;
use crossbeam_channel::Receiver;
use netscope_core::capture::CaptureEngine;
use netscope_core::filter::Filter;
use netscope_core::flows::FlowTable;
use netscope_core::models::Packet;
use netscope_core::names::NameCache;
use netscope_core::stats::StatsEngine;
use ratatui::crossterm::event::{
    KeyCode, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::layout::Rect;
use ratatui::DefaultTerminal;

use crate::columns::Columns;
use crate::theme::{Theme, THEMES};
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
    /// Vertical scroll offset in the Learn view.
    pub learn_scroll: u16,
    /// Vertical scroll offset in the Insights view.
    pub insights_scroll: u16,
    /// User-defined coloring rules (first match tints the packet row).
    pub color_rules: crate::colors::ColorRules,
    /// Index into [`THEMES`] of the active chrome theme (cycled with `t`).
    pub theme_idx: usize,
    /// Which packet-list columns are shown (toggled in the Columns overlay).
    pub columns: Columns,
    /// Whether the Columns overlay is open.
    pub show_columns: bool,
    /// Whether the Follow-Stream overlay is open.
    pub show_stream: bool,
    /// Scroll offset within the Follow-Stream overlay.
    pub stream_scroll: u16,
    /// Whether keyboard focus is inside the detail tree (navigating layers)
    /// rather than the packet list.
    pub detail_focus: bool,
    /// Selected layer index within the detail tree, when focused.
    pub detail_sel: usize,
    /// Detail-tree layer indices that are collapsed (hide their fields).
    pub detail_collapsed: HashSet<usize>,
    // ---- Mouse hit-test regions, refreshed each render ----
    /// The terminal row the tab strip is drawn on.
    pub tab_row: u16,
    /// Per-tab `(x_start, x_end, view)` ranges on the tab strip.
    pub tab_hits: Vec<(u16, u16, View)>,
    /// Inner area of the packet-list rows (for click-to-select).
    pub list_inner: Rect,
    /// Index of the first packet row currently drawn (the table's scroll offset).
    pub list_offset: usize,
}

impl App {
    pub fn new(cli: &crate::Cli) -> Result<Self> {
        let color_rules =
            crate::colors::ColorRules::load(cli.colors.as_deref().map(std::path::Path::new))?;
        let running = Arc::new(AtomicBool::new(true));
        let (packet_tx, packet_rx) = crossbeam_channel::unbounded();

        let mut capture = CaptureEngine::new();
        // Local interfaces, `-i -` (stdin stream), USBPcap devices or a
        // remote host over SSH — plus autostop and ring-buffer options.
        let interface_name = crate::setup::start_capture(cli, &mut capture, packet_tx)?;

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
            learn_scroll: 0,
            insights_scroll: 0,
            color_rules,
            // Startup theme: honour $NETSCOPE_THEME (e.g. "dracula"), else dark.
            theme_idx: std::env::var("NETSCOPE_THEME")
                .ok()
                .and_then(|n| Theme::index_by_name(&n))
                .unwrap_or(0),
            columns: Columns::default(),
            show_columns: false,
            show_stream: false,
            stream_scroll: 0,
            detail_focus: false,
            detail_sel: 0,
            detail_collapsed: HashSet::new(),
            tab_row: 0,
            tab_hits: Vec::new(),
            list_inner: Rect::default(),
            list_offset: 0,
        })
    }

    /// The active chrome theme.
    pub fn theme(&self) -> Theme {
        THEMES[self.theme_idx % THEMES.len()]
    }

    /// Advance to the next chrome theme and report its name for the status bar.
    fn cycle_theme(&mut self) {
        self.theme_idx = (self.theme_idx + 1) % THEMES.len();
        let name = self.theme().name;
        self.notify(format!("Theme: {name}"));
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
                match crossterm::event::read()? {
                    crossterm::event::Event::Key(key) => {
                        if key.kind == KeyEventKind::Press && !self.handle_key(key)? {
                            break;
                        }
                    }
                    crossterm::event::Event::Mouse(m) => self.handle_mouse(m),
                    _ => {}
                }
            }
        }

        self.capture.stop();
        Ok(())
    }

    fn tick(&mut self) {
        if self.paused {
            // Drain the channel to prevent memory leak / OOM
            while self.packet_rx.try_recv().is_ok() {}
            return;
        }
        // Advance the bandwidth sampler once per tick (it self-throttles to 1 Hz).
        self.stats.tick();

        // Resolve the current selection to a position in the unfiltered deque
        // so it can be restored after the drain (which may evict old packets).
        // Doing this once per tick keeps the drain loop O(1) per packet.
        let selected_unfiltered = self.selected_unfiltered_index();

        let mut evicted = 0usize;
        let mut received = false;
        while let Ok(pkt) = self.packet_rx.try_recv() {
            received = true;
            self.names.observe(&pkt);
            self.stats.record_packet(&pkt);
            self.flows.record(&pkt);
            if self.packets.len() >= MAX_PACKETS {
                self.packets.pop_front();
                evicted += 1;
            }
            self.packets.push_back(pkt);
        }
        if !received {
            return;
        }

        // Restore the selection: follow the previously selected packet to its
        // new position, clamping to the oldest packet if it was evicted.
        match selected_unfiltered {
            Some(idx) => {
                let target_pkt = &self.packets[idx.saturating_sub(evicted)];
                if let Some(new_idx) = self
                    .filtered_packets()
                    .iter()
                    .position(|&p| std::ptr::eq(p, target_pkt))
                {
                    self.selected = new_idx;
                } else {
                    // The packet fell out of the filtered view; keep the old
                    // slot but clamp to the current filtered length.
                    self.selected = self
                        .selected
                        .min(self.filtered_packets().len().saturating_sub(1));
                }
            }
            None => self.selected = 0,
        }
    }

    /// Move the packet-list selection, resetting the detail tree to the top of
    /// the newly-selected packet.
    fn select_packet(&mut self, next: usize) {
        self.selected = next;
        self.detail_sel = 0;
        self.detail_collapsed.clear();
    }

    /// Collapse/expand the focused detail-tree layer.
    fn toggle_detail_node(&mut self) {
        if !self.detail_collapsed.remove(&self.detail_sel) {
            self.detail_collapsed.insert(self.detail_sel);
        }
    }

    fn handle_key(&mut self, key: crossterm::event::KeyEvent) -> Result<bool> {
        // ---- Overlays consume input first ----
        if self.show_columns {
            match key.code {
                KeyCode::Esc | KeyCode::Char('C') | KeyCode::Char('c') => self.show_columns = false,
                KeyCode::Char(d @ '1'..='6') => {
                    self.columns.toggle_index(d as usize - '0' as usize)
                }
                _ => {}
            }
            return Ok(true);
        }
        if self.show_stream {
            match key.code {
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('F') => {
                    self.show_stream = false;
                    self.stream_scroll = 0;
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.stream_scroll = self.stream_scroll.saturating_sub(1)
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.stream_scroll = self.stream_scroll.saturating_add(1)
                }
                _ => {}
            }
            return Ok(true);
        }
        if self.show_help {
            if key.code == KeyCode::Char('?') || key.code == KeyCode::Esc {
                self.show_help = false;
            }
            return Ok(true);
        }

        // Theme cycling works in every view. Uppercase so it doesn't collide
        // with lowercase filter text typed in the Packets view.
        if key.code == KeyCode::Char('T') {
            self.cycle_theme();
            return Ok(true);
        }

        // The Learn view scrolls with the arrow/vim keys.
        if self.view == View::Learn {
            match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    self.learn_scroll = self.learn_scroll.saturating_sub(1);
                    return Ok(true);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.learn_scroll = self.learn_scroll.saturating_add(1);
                    return Ok(true);
                }
                _ => {}
            }
        }

        // The Insights view scrolls with the arrow/vim keys too.
        if self.view == View::Insights {
            match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    self.insights_scroll = self.insights_scroll.saturating_sub(1);
                    return Ok(true);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.insights_scroll = self.insights_scroll.saturating_add(1);
                    return Ok(true);
                }
                _ => {}
            }
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

        // Detail-tree focus (Packets view): navigation keys drive the tree,
        // not the packet list, until Esc leaves focus.
        if self.view == View::Packets && self.detail_focus {
            match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    self.detail_sel = self.detail_sel.saturating_sub(1);
                    return Ok(true);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.detail_sel = self.detail_sel.saturating_add(1);
                    return Ok(true);
                }
                KeyCode::Left | KeyCode::Char(' ') | KeyCode::Enter => {
                    self.toggle_detail_node();
                    return Ok(true);
                }
                KeyCode::Right => {
                    self.detail_collapsed.remove(&self.detail_sel);
                    return Ok(true);
                }
                KeyCode::Esc => {
                    self.detail_focus = false;
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
                let visible = self.filtered_packets().len();
                if visible > 0 {
                    self.select_packet(self.selected.saturating_sub(1).min(visible - 1));
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let visible = self.filtered_packets().len();
                if visible > 0 && self.selected + 1 < visible {
                    self.select_packet(self.selected + 1);
                }
            }
            KeyCode::Enter => {
                // Enter focuses the detail tree (and reveals it if hex was up).
                if self.view == View::Packets {
                    self.show_hex = false;
                    self.detail_expanded = true;
                    self.detail_focus = true;
                }
            }
            KeyCode::Tab => {
                self.view = if key.modifiers.contains(KeyModifiers::SHIFT) {
                    self.view.prev()
                } else {
                    self.view.next()
                };
                self.detail_focus = false;
            }
            KeyCode::Char(' ') => {
                self.paused = !self.paused;
            }
            KeyCode::Char('h') => {
                self.show_hex = !self.show_hex;
                if self.show_hex {
                    self.detail_focus = false;
                }
            }
            KeyCode::Char('F') => {
                // Follow Stream for the selected conversation (Packets view).
                if self.view == View::Packets && !self.filtered_packets().is_empty() {
                    self.show_stream = true;
                    self.stream_scroll = 0;
                }
            }
            KeyCode::Char('C') => {
                self.show_columns = true;
            }
            KeyCode::Char('?') => {
                self.show_help = true;
            }
            KeyCode::Esc => {
                if self.detail_focus {
                    self.detail_focus = false;
                } else if !self.filter_text.is_empty() {
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

    /// Mouse dispatch (ROADMAP §6.1): wheel scrolls the active list, a left
    /// click on the tab strip switches views, and a click on a packet row
    /// selects it.
    fn handle_mouse(&mut self, m: MouseEvent) {
        match m.kind {
            MouseEventKind::ScrollDown => self.scroll(1),
            MouseEventKind::ScrollUp => self.scroll(-1),
            MouseEventKind::Down(MouseButton::Left) => self.click(m.column, m.row),
            _ => {}
        }
    }

    /// Scroll the focused list by `delta` rows (positive = down).
    fn scroll(&mut self, delta: i32) {
        let down = delta > 0;
        if self.show_stream {
            self.stream_scroll = step(self.stream_scroll, down);
            return;
        }
        if self.view == View::Packets && self.detail_focus {
            self.detail_sel = step_usize(self.detail_sel, down);
            return;
        }
        match self.view {
            View::Packets => {
                let visible = self.filtered_packets().len();
                if visible == 0 {
                    return;
                }
                let next = if down {
                    (self.selected + 1).min(visible - 1)
                } else {
                    self.selected.saturating_sub(1)
                };
                self.select_packet(next);
            }
            View::Connections => {
                let n = self.flows.len();
                if down {
                    if n > 0 && self.conn_selected + 1 < n {
                        self.conn_selected += 1;
                    }
                } else {
                    self.conn_selected = self.conn_selected.saturating_sub(1);
                }
            }
            View::Learn => self.learn_scroll = step(self.learn_scroll, down),
            View::Insights => self.insights_scroll = step(self.insights_scroll, down),
            _ => {}
        }
    }

    /// Handle a left click at terminal cell (`x`, `y`).
    fn click(&mut self, x: u16, y: u16) {
        // Tab strip: switch to the clicked tab.
        if y == self.tab_row {
            if let Some(view) = self
                .tab_hits
                .iter()
                .find(|(start, end, _)| x >= *start && x < *end)
                .map(|(_, _, v)| *v)
            {
                self.view = view;
                self.detail_focus = false;
            }
            return;
        }
        // Packet list: click a row to select it.
        if self.view == View::Packets
            && !self.packets.is_empty()
            && y >= self.list_inner.y
            && y < self.list_inner.y + self.list_inner.height
            && x >= self.list_inner.x
            && x < self.list_inner.x + self.list_inner.width
        {
            let row = (y - self.list_inner.y) as usize;
            let idx = self.list_offset + row;
            let visible = self.filtered_packets().len();
            if idx < visible {
                self.select_packet(idx);
            }
        }
    }

    /// Position of the currently selected (filtered) packet within the
    /// unfiltered deque, if a packet is selected.
    pub fn selected_unfiltered_index(&self) -> Option<usize> {
        let target = *self.filtered_packets().get(self.selected)?;
        self.packets.iter().position(|p| std::ptr::eq(p, target))
    }

    pub fn filtered_packets(&self) -> Vec<&Packet> {
        if self.filter_text.is_empty() {
            return self.packets.iter().collect();
        }
        // Try the structured display-filter language first (ip.addr == x,
        // tcp.port == 443, dns && frame.len > 1000, …). If the text isn't a
        // valid filter expression, fall back to the free-text substring search
        // so partially-typed input and plain keywords still work.
        if let Ok(filter) = Filter::parse(&self.filter_text) {
            return self.packets.iter().filter(|p| filter.matches(p)).collect();
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

/// Nudge a `u16` scroll offset by one row in the given direction.
fn step(v: u16, down: bool) -> u16 {
    if down {
        v.saturating_add(1)
    } else {
        v.saturating_sub(1)
    }
}

/// Nudge a `usize` index by one in the given direction.
fn step_usize(v: usize, down: bool) -> usize {
    if down {
        v.saturating_add(1)
    } else {
        v.saturating_sub(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam_channel::Sender;
    use netscope_core::models::Protocol;
    use ratatui::crossterm::event::{KeyEvent, KeyEventState};

    /// An App wired to a test channel instead of a live capture.
    fn test_app() -> (App, Sender<Packet>) {
        let (packet_tx, packet_rx) = crossbeam_channel::unbounded();
        let app = App {
            capture: CaptureEngine::new(),
            packets: VecDeque::new(),
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
            running: Arc::new(AtomicBool::new(true)),
            packet_rx,
            interface_name: "test0".into(),
            show_help: false,
            conn_selected: 0,
            blocked: BTreeSet::new(),
            elevated: false,
            status_msg: None,
            learn_scroll: 0,
            insights_scroll: 0,
            color_rules: crate::colors::ColorRules::parse(""),
            theme_idx: 0,
            columns: Columns::default(),
            show_columns: false,
            show_stream: false,
            stream_scroll: 0,
            detail_focus: false,
            detail_sel: 0,
            detail_collapsed: HashSet::new(),
            tab_row: 0,
            tab_hits: Vec::new(),
            list_inner: Rect::default(),
            list_offset: 0,
        };
        (app, packet_tx)
    }

    fn pkt(n: usize, protocol: Protocol) -> Packet {
        let port = match protocol {
            Protocol::Udp => 53,
            _ => 443,
        };
        Packet {
            timestamp: Utc::now(),
            src_addr: "10.0.0.1".parse().ok(),
            dst_addr: "10.0.0.2".parse().ok(),
            src_port: Some(50000),
            dst_port: Some(port),
            protocol,
            length: 60,
            summary: format!("packet-{n}"),
            data: bytes::Bytes::from_static(&[0u8; 60]),
        }
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    #[test]
    fn tick_drains_channel_and_evicts_at_cap() {
        let (mut app, tx) = test_app();
        for i in 0..MAX_PACKETS + 5 {
            tx.send(pkt(i, Protocol::Tcp)).unwrap();
        }
        app.tick();
        assert_eq!(app.packets.len(), MAX_PACKETS);
        // The 5 oldest packets were evicted.
        assert_eq!(app.packets.front().unwrap().summary, "packet-5");
        assert_eq!(
            app.packets.back().unwrap().summary,
            format!("packet-{}", MAX_PACKETS + 4)
        );
    }

    #[test]
    fn tick_follows_selected_packet_through_eviction() {
        let (mut app, tx) = test_app();
        for i in 0..MAX_PACKETS {
            tx.send(pkt(i, Protocol::Tcp)).unwrap();
        }
        app.tick();
        app.selected = 100;
        let summary = app.packets[100].summary.clone();

        // 50 more packets arrive at the cap: 50 old ones fall off the front.
        for i in 0..50 {
            tx.send(pkt(MAX_PACKETS + i, Protocol::Tcp)).unwrap();
        }
        app.tick();
        assert_eq!(app.selected, 50);
        assert_eq!(app.packets[app.selected].summary, summary);
    }

    #[test]
    fn tick_keeps_selection_while_buffer_grows() {
        let (mut app, tx) = test_app();
        for i in 0..10 {
            tx.send(pkt(i, Protocol::Tcp)).unwrap();
        }
        app.tick();
        app.selected = 5;
        for i in 10..15 {
            tx.send(pkt(i, Protocol::Tcp)).unwrap();
        }
        app.tick();
        assert_eq!(app.selected, 5);
        assert_eq!(app.packets[5].summary, "packet-5");
    }

    #[test]
    fn tick_while_paused_discards_incoming_packets() {
        let (mut app, tx) = test_app();
        app.paused = true;
        for i in 0..3 {
            tx.send(pkt(i, Protocol::Tcp)).unwrap();
        }
        app.tick();
        assert!(app.packets.is_empty());
        // The channel was drained, not left to grow unbounded.
        assert!(app.packet_rx.try_recv().is_err());
    }

    #[test]
    fn filtered_packets_structured_filter_and_freetext_fallback() {
        let (mut app, _tx) = test_app();
        app.packets.push_back(pkt(0, Protocol::Tcp));
        app.packets.push_back(pkt(1, Protocol::Udp));
        app.packets.push_back(pkt(2, Protocol::Tcp));

        // No filter: everything is visible.
        assert_eq!(app.filtered_packets().len(), 3);

        // Structured protocol filter.
        app.filter_text = "udp".into();
        let udp_only = app.filtered_packets();
        assert_eq!(udp_only.len(), 1);
        assert_eq!(udp_only[0].summary, "packet-1");

        // Free-text fallback on the summary.
        app.filter_text = "packet-2".into();
        let by_summary = app.filtered_packets();
        assert_eq!(by_summary.len(), 1);
        assert_eq!(by_summary[0].summary, "packet-2");

        // No matches.
        app.filter_text = "zzz-no-such-packet".into();
        assert!(app.filtered_packets().is_empty());
    }

    #[test]
    fn selection_is_clamped_to_the_filtered_view() {
        let (mut app, _tx) = test_app();
        for i in 0..5 {
            app.packets.push_back(pkt(i, Protocol::Tcp));
        }
        app.packets.push_back(pkt(5, Protocol::Udp));

        // Only one packet is visible under the filter.
        app.filter_text = "udp".into();
        assert_eq!(app.filtered_packets().len(), 1);

        // Down must not walk past the end of the filtered list.
        app.handle_key(key(KeyCode::Down)).unwrap();
        app.handle_key(key(KeyCode::Down)).unwrap();
        assert_eq!(app.selected, 0);

        // A selection left stale by a filter change is pulled back in range.
        app.selected = 4;
        app.handle_key(key(KeyCode::Up)).unwrap();
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn selected_unfiltered_index_maps_through_the_filter() {
        let (mut app, _tx) = test_app();
        app.packets.push_back(pkt(0, Protocol::Tcp));
        app.packets.push_back(pkt(1, Protocol::Udp));
        app.packets.push_back(pkt(2, Protocol::Tcp));

        app.filter_text = "udp".into();
        app.selected = 0; // first (and only) filtered row = packet-1
        assert_eq!(app.selected_unfiltered_index(), Some(1));

        app.filter_text = "zzz-no-such-packet".into();
        assert_eq!(app.selected_unfiltered_index(), None);
    }

    #[test]
    fn basic_keys_toggle_state() {
        let (mut app, _tx) = test_app();
        app.packets.push_back(pkt(0, Protocol::Tcp));

        app.handle_key(key(KeyCode::Char(' '))).unwrap();
        assert!(app.paused);
        app.handle_key(key(KeyCode::Char(' '))).unwrap();
        assert!(!app.paused);

        app.handle_key(key(KeyCode::Char('h'))).unwrap();
        assert!(app.show_hex);

        app.handle_key(key(KeyCode::Char('?'))).unwrap();
        assert!(app.show_help);
        // While the help overlay is up, other keys are swallowed.
        app.handle_key(key(KeyCode::Char(' '))).unwrap();
        assert!(!app.paused);
        app.handle_key(key(KeyCode::Esc)).unwrap();
        assert!(!app.show_help);

        // Typing builds the filter; Esc clears it.
        app.handle_key(key(KeyCode::Char('d'))).unwrap();
        app.handle_key(key(KeyCode::Char('n'))).unwrap();
        app.handle_key(key(KeyCode::Char('s'))).unwrap();
        assert_eq!(app.filter_text, "dns");
        app.handle_key(key(KeyCode::Backspace)).unwrap();
        assert_eq!(app.filter_text, "dn");
        app.handle_key(key(KeyCode::Esc)).unwrap();
        assert!(app.filter_text.is_empty());

        // Tab cycles the view; 'q' requests shutdown.
        let start = app.view;
        app.handle_key(key(KeyCode::Tab)).unwrap();
        assert_ne!(app.view, start);
        app.handle_key(key(KeyCode::Char('q'))).unwrap();
        assert!(!app.running.load(Ordering::Relaxed));
    }

    #[test]
    fn active_status_expires() {
        let (mut app, _tx) = test_app();
        assert_eq!(app.active_status(), None);
        app.notify("hello");
        assert_eq!(app.active_status(), Some("hello"));
        // Backdate the message beyond the 5 s freshness window.
        app.status_msg = Some(("old".into(), Instant::now() - Duration::from_secs(6)));
        assert_eq!(app.active_status(), None);
    }
}
