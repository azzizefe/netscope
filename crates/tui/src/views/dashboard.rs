use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::colors::{protocol_color, PANEL_BORDER};
use netscope_core::models::Protocol;

pub fn render(frame: &mut Frame, area: Rect, app: &mut App) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6),
            Constraint::Min(4),
            Constraint::Length(3),
            Constraint::Length(6),
        ])
        .split(area);

    render_stats_panel(frame, layout[0], app);
    render_protocol_distribution(frame, layout[1], app);
    render_bandwidth_panel(frame, layout[2], app);
    render_top_talkers(frame, layout[3], app);
}

fn render_stats_panel(frame: &mut Frame, area: Rect, app: &mut App) {
    let snap = app.stats.snapshot();

    let lines = vec![
        Line::from(vec![
            Span::raw(format!(" Total Packets: {}", snap.total_packets)),
            Span::raw("  |  "),
            Span::raw(format!(
                "Total Bytes: {} ({} MB)",
                snap.total_bytes,
                snap.total_bytes / 1_000_000
            )),
        ]),
        Line::from(vec![
            Span::raw(format!(
                " Current Bandwidth: {:.1} KB/s",
                snap.current_bandwidth / 1000.0
            )),
            Span::raw("  |  "),
            Span::raw(format!(
                "Average Bandwidth: {:.1} KB/s",
                snap.average_bandwidth / 1000.0
            )),
        ]),
    ];

    let block = Block::default()
        .title(" Stats ")
        .borders(Borders::ALL)
        .border_style(Style::new().fg(PANEL_BORDER));

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_protocol_distribution(frame: &mut Frame, area: Rect, app: &mut App) {
    let snap = app.stats.snapshot();
    let total = snap.total_packets.max(1) as f64;

    let mut protocols: Vec<(&Protocol, &netscope_core::stats::ProtocolStats)> =
        snap.per_protocol.iter().collect();
    protocols.sort_by_key(|b| std::cmp::Reverse(b.1.total_packets));

    let mut lines = vec![];
    for (proto, stats) in &protocols {
        let pct = (stats.total_packets as f64 / total * 100.0) as u32;
        let bar_len = (stats.total_packets as f64 / total * 30.0) as usize;
        let bar = "█".repeat(bar_len);
        let color = protocol_color(proto);
        lines.push(Line::from(vec![
            Span::styled(
                format!(" {:<8}", proto.to_string()),
                Style::new().fg(color).bold(),
            ),
            Span::raw(format!(" {:>4}% ", pct)),
            Span::styled(bar, Style::new().fg(color)),
            Span::raw(format!(" ({} pkts)", stats.total_packets)),
        ]));
    }

    if lines.is_empty() {
        lines.push(Line::from(" No packets captured yet"));
    }

    let block = Block::default()
        .title(" Protocol Distribution ")
        .borders(Borders::ALL)
        .border_style(Style::new().fg(PANEL_BORDER));

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_bandwidth_panel(frame: &mut Frame, area: Rect, app: &mut App) {
    let snap = app.stats.snapshot();

    let bw_bps = snap.current_bandwidth;
    let bar_len = ((bw_bps / 10_000_000.0).min(1.0) * 50.0) as usize;
    let bar = "━".repeat(bar_len);
    let visual = if bw_bps > 1_000_000.0 {
        format!(" {:.1} Mbps {}", bw_bps / 1_000_000.0, bar)
    } else if bw_bps > 1000.0 {
        format!(" {:.1} Kbps {}", bw_bps / 1000.0, bar)
    } else {
        format!(" {:.0} bps {}", bw_bps, bar)
    };

    let lines = vec![Line::from(visual)];

    let block = Block::default()
        .title(" Bandwidth ")
        .borders(Borders::ALL)
        .border_style(Style::new().fg(PANEL_BORDER));

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_top_talkers(frame: &mut Frame, area: Rect, app: &mut App) {
    let snap = app.stats.snapshot();

    let layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Top senders
    let sent_lines: Vec<Line> = snap
        .top_talkers_sent
        .iter()
        .take(5)
        .map(|(ip, bytes)| {
            let size = if *bytes > 1_000_000 {
                format!("{:.1} MB", *bytes as f64 / 1_000_000.0)
            } else {
                format!("{:.1} KB", *bytes as f64 / 1000.0)
            };
            Line::from(format!(" {}  {}", ip, size))
        })
        .collect();

    let sent_block = Block::default()
        .title(" Top Senders ")
        .borders(Borders::ALL)
        .border_style(Style::new().fg(PANEL_BORDER));
    frame.render_widget(
        Paragraph::new(if sent_lines.is_empty() {
            vec![Line::from(" (no data)")]
        } else {
            sent_lines
        })
        .block(sent_block),
        layout[0],
    );

    // Top receivers
    let recv_lines: Vec<Line> = snap
        .top_talkers_received
        .iter()
        .take(5)
        .map(|(ip, bytes)| {
            let size = if *bytes > 1_000_000 {
                format!("{:.1} MB", *bytes as f64 / 1_000_000.0)
            } else {
                format!("{:.1} KB", *bytes as f64 / 1000.0)
            };
            Line::from(format!(" {}  {}", ip, size))
        })
        .collect();

    let recv_block = Block::default()
        .title(" Top Receivers ")
        .borders(Borders::ALL)
        .border_style(Style::new().fg(PANEL_BORDER));
    frame.render_widget(
        Paragraph::new(if recv_lines.is_empty() {
            vec![Line::from(" (no data)")]
        } else {
            recv_lines
        })
        .block(recv_block),
        layout[1],
    );
}
