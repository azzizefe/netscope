// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::App;
use netscope_core::stats::StatsSnapshot;

pub fn render(frame: &mut Frame, area: Rect, app: &mut App) {
    let border = app.theme().border;
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6),
            Constraint::Min(8),
            Constraint::Length(3),
            Constraint::Length(6),
        ])
        .split(area);

    let snap = app.stats.snapshot();
    render_stats_panel(frame, layout[0], &snap, border);

    // Split layout[1] horizontally for Protocol Hierarchy and Packet Lengths
    let sub_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(layout[1]);

    render_protocol_hierarchy(frame, sub_layout[0], &snap, border);
    render_packet_lengths(frame, sub_layout[1], &snap, border);

    render_bandwidth_panel(frame, layout[2], &snap, border);
    render_top_talkers(frame, layout[3], &snap, border);
}

fn render_stats_panel(frame: &mut Frame, area: Rect, snap: &StatsSnapshot, border: Color) {
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
        .border_style(Style::new().fg(border));

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_protocol_hierarchy(frame: &mut Frame, area: Rect, snap: &StatsSnapshot, border: Color) {
    let mut lines = vec![];
    for (name, packets, bytes) in &snap.protocol_hierarchy {
        let size_str = if *bytes > 1_000_000 {
            format!("{:.1} MB", *bytes as f64 / 1_000_000.0)
        } else {
            format!("{:.1} KB", *bytes as f64 / 1000.0)
        };
        lines.push(Line::from(vec![
            Span::raw(format!("{:<30}", name)),
            Span::styled(
                format!(" {:>6} pkts", packets),
                Style::new().fg(Color::Cyan),
            ),
            Span::raw("  ·  "),
            Span::styled(size_str, Style::new().fg(Color::Green)),
        ]));
    }
    if lines.is_empty() {
        lines.push(Line::from(" No protocols recorded"));
    }
    let block = Block::default()
        .title(" Protocol Hierarchy Tree ")
        .borders(Borders::ALL)
        .border_style(Style::new().fg(border));
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_packet_lengths(frame: &mut Frame, area: Rect, snap: &StatsSnapshot, border: Color) {
    let total = snap.total_packets.max(1) as f64;
    let buckets = &[
        ("0 - 79 B", snap.len_distribution[0]),
        ("80 - 639 B", snap.len_distribution[1]),
        ("640 - 1279 B", snap.len_distribution[2]),
        ("1280 - 1500 B", snap.len_distribution[3]),
        ("> 1500 B", snap.len_distribution[4]),
    ];

    let mut lines = vec![];
    for &(label, count) in buckets {
        let pct = (count as f64 / total * 100.0) as u32;
        let bar_len = (count as f64 / total * 20.0) as usize;
        let bar = "█".repeat(bar_len);
        lines.push(Line::from(vec![
            Span::raw(format!(" {:<12} ", label)),
            Span::styled(
                format!(" {:>6} pkts", count),
                Style::new().fg(Color::White).bold(),
            ),
            Span::raw(format!(" ({:>3}%) ", pct)),
            Span::styled(bar, Style::new().fg(Color::Yellow)),
        ]));
    }

    let block = Block::default()
        .title(" Packet Lengths Distribution ")
        .borders(Borders::ALL)
        .border_style(Style::new().fg(border));
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_bandwidth_panel(frame: &mut Frame, area: Rect, snap: &StatsSnapshot, border: Color) {
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
        .border_style(Style::new().fg(border));

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_top_talkers(frame: &mut Frame, area: Rect, snap: &StatsSnapshot, border: Color) {
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
        .border_style(Style::new().fg(border));
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
        .border_style(Style::new().fg(border));
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
