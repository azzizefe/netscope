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
            Constraint::Min(6),
            Constraint::Length(3),
            Constraint::Length(6),
            Constraint::Length(7),
            Constraint::Length(5),
        ])
        .split(area);

    let snap = app.stats.snapshot();
    render_stats_panel(frame, layout[0], &snap, border);

    let sub_mid = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(layout[1]);

    render_protocol_hierarchy(frame, sub_mid[0], &snap, border);
    render_packet_lengths(frame, sub_mid[1], &snap, border);

    render_bandwidth_panel(frame, layout[2], &snap, border);
    render_top_talkers(frame, layout[3], &snap, border);

    let sub_llm = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(layout[4]);

    render_llm_model_stats(frame, sub_llm[0], &snap, border);
    render_cost_counter(frame, sub_llm[1], &snap, border);

    render_anomaly_alerts(frame, layout[5], &snap, border);
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

fn render_llm_model_stats(frame: &mut Frame, area: Rect, snap: &StatsSnapshot, border: Color) {
    let llm = &snap.llm;
    let mut lines: Vec<Line> = Vec::new();

    if llm.per_model.is_empty() {
        lines.push(Line::from(Span::styled(
            " No AI model data yet.",
            Style::new().dim().italic(),
        )));
    } else {
        let header = format!(
            " {:<12} {:>5} {:>5} {:>5} {:>5} {:>5} {:>6} {:>7}",
            "Model", "Req", "TTFT", "TPOT", "Tok/s", "Hata%", "TopTok", "Maliyet"
        );
        lines.push(Line::from(Span::styled(
            header,
            Style::new().bold().white().underlined(),
        )));

        let mut models: Vec<_> = llm.per_model.iter().collect();
        models.sort_by_key(|(_, ms)| std::cmp::Reverse(ms.requests));

        for (model, ms) in models.iter().take(5) {
            let avg_ttft = if ms.ttft_count > 0 {
                ms.ttft_sum_ms as f64 / ms.ttft_count as f64
            } else {
                0.0
            };
            let avg_tpot = if ms.tpot_count > 0 {
                ms.tpot_sum_us as f64 / ms.tpot_count as f64 / 1000.0
            } else {
                0.0
            };
            let avg_tps = if ms.tokens_per_second_count > 0 {
                ms.tokens_per_second_sum / ms.tokens_per_second_count as f64
            } else {
                0.0
            };
            let error_rate = if ms.requests > 0 {
                (ms.error_4xx + ms.error_5xx) as f64 / ms.requests as f64 * 100.0
            } else {
                0.0
            };

            let model_short = if model.len() > 11 {
                format!("{}…", &model[..10])
            } else {
                model.to_string()
            };

            lines.push(Line::from(vec![
                Span::raw(format!(" {:<12}", model_short)),
                Span::raw(format!(" {:>5}", ms.requests)),
                Span::styled(
                    format!(" {:>4}ms", if avg_ttft > 0.0 { format!("{:.0}", avg_ttft) } else { "-".into() }),
                    if avg_ttft > 500.0 {
                        Style::new().fg(Color::Red).bold()
                    } else if avg_ttft > 200.0 {
                        Style::new().fg(Color::Yellow)
                    } else {
                        Style::new().fg(Color::Green)
                    },
                ),
                Span::styled(
                    format!(" {:>4}ms", if avg_tpot > 0.0 { format!("{:.0}", avg_tpot) } else { "-".into() }),
                    if avg_tpot > 80.0 {
                        Style::new().fg(Color::Red).bold()
                    } else {
                        Style::new().fg(Color::Green)
                    },
                ),
                Span::styled(
                    format!(" {:>4.0}", avg_tps),
                    if avg_tps > 0.0 && avg_tps < 20.0 {
                        Style::new().fg(Color::Red).bold()
                    } else {
                        Style::new().fg(Color::Green)
                    },
                ),
                Span::styled(
                    format!(" {:>4.0}%", error_rate),
                    if error_rate > 5.0 {
                        Style::new().fg(Color::Red).bold()
                    } else {
                        Style::new().fg(Color::Green)
                    },
                ),
                Span::raw(format!(" {:>6}", ms.total_tokens)),
                Span::raw(format!(" ${:.4}", ms.cost)),
            ]));
        }
    }

    let block = Block::default()
        .title(" Model Stats ")
        .borders(Borders::ALL)
        .border_style(Style::new().fg(border));
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_cost_counter(frame: &mut Frame, area: Rect, snap: &StatsSnapshot, border: Color) {
    let llm = &snap.llm;
    let lines = vec![
        Line::from(vec![
            Span::raw(" Session Cost:  "),
            Span::styled(
                format!("${:.4}", llm.session_cost),
                Style::new().fg(Color::Cyan).bold(),
            ),
        ]),
        Line::from(vec![
            Span::raw(" Daily Cost:    "),
            Span::styled(
                format!("${:.4}", llm.daily_cost),
                Style::new().fg(Color::Yellow).bold(),
            ),
        ]),
        Line::from(vec![
            Span::raw(" Total Cost:    "),
            Span::styled(
                format!("${:.4}", llm.total_cost),
                Style::new().fg(Color::White).bold(),
            ),
        ]),
        Line::from(vec![
            Span::raw(" Active Sessions: "),
            Span::styled(
                format!("{}", snap.ai_active_sessions),
                Style::new().fg(Color::Magenta).bold(),
            ),
        ]),
        Line::from(vec![
            Span::raw(" Completed:     "),
            Span::styled(
                format!("{}", snap.ai_records.len()),
                Style::new().fg(Color::Green).bold(),
            ),
        ]),
    ];

    let block = Block::default()
        .title(" Maliyet Sayaci ")
        .borders(Borders::ALL)
        .border_style(Style::new().fg(border));
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_anomaly_alerts(frame: &mut Frame, area: Rect, snap: &StatsSnapshot, border: Color) {
    let llm = &snap.llm;
    let mut lines: Vec<Line> = Vec::new();

    let alerts: Vec<_> = llm.anomalies.iter().rev().take(4).collect();

    if alerts.is_empty() {
        lines.push(Line::from(Span::styled(
            " No anomalies detected.",
            Style::new().dim().italic(),
        )));
    } else {
        for alert in &alerts {
            lines.push(Line::from(vec![
                Span::styled(" ⚠ ", Style::new().fg(Color::Red).bold()),
                Span::styled(
                    format!("{} ", alert.metric),
                    Style::new().fg(Color::Red).bold(),
                ),
                Span::raw(format!(
                    "{} → {} ({}: {}) ",
                    alert.model, alert.value, alert.metric, alert.threshold
                )),
            ]));
        }
    }

    let active_alerts = llm
        .anomalies
        .iter()
        .filter(|a| {
            (chrono::Utc::now() - a.timestamp).num_seconds() < 30
        })
        .count();
    let title = if active_alerts > 0 {
        format!(" Anomali Uyarilari ({} aktif) ", active_alerts)
    } else {
        " Anomali Uyarilari ".to_string()
    };

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::new().fg(if active_alerts > 0 { Color::Red } else { border }));
    frame.render_widget(Paragraph::new(lines).block(block), area);
}
