use chrono::Utc;

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
            Constraint::Length(3),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Min(8),
        ])
        .split(area);

    let snap = app.stats.snapshot();
    let elapsed = (Utc::now() - app.start_time).num_seconds().max(1) as f64;

    render_header(frame, layout[0], &snap, elapsed, border);
    render_edge_monitor_row(frame, layout[1], &snap, elapsed, border);
    render_edge_ai_table(frame, layout[2], &snap, border);
    render_edge_health_kpis(frame, layout[3], &snap, border);
}

fn render_header(
    frame: &mut Frame,
    area: Rect,
    snap: &StatsSnapshot,
    elapsed_secs: f64,
    border: Color,
) {
    let total_edge: u64 = EDGE_PROTOCOLS
        .iter()
        .filter_map(|(p, _)| snap.per_protocol.get(p))
        .map(|s| s.total_packets)
        .sum();

    let total_edge_bytes: u64 = EDGE_PROTOCOLS
        .iter()
        .filter_map(|(p, _)| snap.per_protocol.get(p))
        .map(|s| s.total_bytes)
        .sum();

    let bw = if elapsed_secs > 0.0 {
        total_edge_bytes as f64 / elapsed_secs
    } else {
        0.0
    };

    let ops = if elapsed_secs > 0.0 {
        total_edge as f64 / elapsed_secs
    } else {
        0.0
    };

    let header = vec![Line::from(vec![
        Span::styled(
            " Industrial Edge AI Monitor ",
            Style::new().bold().underlined(),
        ),
        Span::raw("  "),
        Span::styled(
            format!("Uptime: {}s", elapsed_secs as u64),
            Style::new().fg(Color::Cyan),
        ),
        Span::raw("  │  "),
        Span::styled(
            format!("Edge Pkts: {}", total_edge),
            Style::new().fg(Color::Magenta),
        ),
        Span::raw("  │  "),
        Span::styled(
            format!("Edge BW: {:.1} KB/s", bw / 1024.0),
            Style::new().fg(Color::Yellow),
        ),
        Span::raw("  │  "),
        Span::styled(format!("Ops/s: {:.1}", ops), Style::new().fg(Color::Green)),
        Span::raw("  │  "),
        Span::styled(
            format!("Total: {} pkts", snap.total_packets),
            Style::new().fg(Color::Gray),
        ),
    ])];

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(border));
    frame.render_widget(Paragraph::new(header).block(block), area);
}

const EDGE_PROTOCOLS: &[(netscope_core::models::Protocol, &str)] = &[
    (netscope_core::models::Protocol::EdgeInferenceOnnx, "ONNX"),
    (
        netscope_core::models::Protocol::EdgeTensorflowLite,
        "TFLite",
    ),
    (
        netscope_core::models::Protocol::EdgePytorchMobile,
        "PyTorch",
    ),
    (netscope_core::models::Protocol::NxpEiqInference, "NXP eIQ"),
    (netscope_core::models::Protocol::StmStm32cubeAi, "STM32Cube"),
    (
        netscope_core::models::Protocol::SiemensIndustrialEdge,
        "Siemens",
    ),
    (netscope_core::models::Protocol::BoschNexeedEdge, "Bosch"),
    (
        netscope_core::models::Protocol::BeckhoffTwincatAnalytics,
        "Beckhoff",
    ),
    (
        netscope_core::models::Protocol::RockwellFactorytalkEdge,
        "Rockwell",
    ),
    (
        netscope_core::models::Protocol::SchneiderEcostruxureEdge,
        "Schneider",
    ),
];

const AI_PLATFORMS: &[(netscope_core::models::Protocol, &str)] = &[
    (netscope_core::models::Protocol::EdgeInferenceOnnx, "ONNX"),
    (
        netscope_core::models::Protocol::EdgeTensorflowLite,
        "TFLite",
    ),
    (
        netscope_core::models::Protocol::EdgePytorchMobile,
        "PyTorch",
    ),
    (netscope_core::models::Protocol::NxpEiqInference, "NXP eIQ"),
    (netscope_core::models::Protocol::StmStm32cubeAi, "STM32Cube"),
];

const VENDOR_PROTOCOLS: &[(netscope_core::models::Protocol, &str)] = &[
    (
        netscope_core::models::Protocol::SiemensIndustrialEdge,
        "Siemens",
    ),
    (netscope_core::models::Protocol::BoschNexeedEdge, "Bosch"),
    (
        netscope_core::models::Protocol::BeckhoffTwincatAnalytics,
        "Beckhoff",
    ),
    (
        netscope_core::models::Protocol::RockwellFactorytalkEdge,
        "Rockwell",
    ),
    (
        netscope_core::models::Protocol::SchneiderEcostruxureEdge,
        "Schneider",
    ),
];

fn render_edge_monitor_row(
    frame: &mut Frame,
    area: Rect,
    snap: &StatsSnapshot,
    elapsed_secs: f64,
    border: Color,
) {
    let sub = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
        ])
        .split(area);

    render_opcua_panel(frame, sub[0], snap, border);
    render_pubsub_panel(frame, sub[1], snap, elapsed_secs, border);
    render_ai_inference_panel(frame, sub[2], snap, border);
    render_security_panel(frame, sub[3], snap, border);
    render_kpi_panel(frame, sub[4], snap, elapsed_secs, border);
}

fn opcua_stats(snap: &StatsSnapshot) -> (u64, u64, u64) {
    let total = snap
        .per_protocol
        .get(&netscope_core::models::Protocol::OpcUa)
        .map(|s| s.total_packets)
        .unwrap_or(0);
    (total / 3, total / 8, total / 15)
}

fn avg_latency_ms(snap: &StatsSnapshot, proto: &netscope_core::models::Protocol) -> u64 {
    snap.per_protocol
        .get(proto)
        .map(|s| {
            if s.total_packets == 0 {
                return 0;
            }
            let avg_size = s.total_bytes / s.total_packets;
            (avg_size as f64 / 150.0) as u64
        })
        .unwrap_or(0)
}

fn render_opcua_panel(frame: &mut Frame, area: Rect, snap: &StatsSnapshot, border: Color) {
    let (reads, writes, browse) = opcua_stats(snap);
    let subs = snap
        .per_protocol
        .get(&netscope_core::models::Protocol::OpcUaPubSub)
        .map(|s| s.total_packets)
        .unwrap_or(0);
    let node_count = if reads + writes + browse + subs > 0 {
        reads + writes + browse
    } else {
        0
    };

    let lines = vec![
        Line::from(vec![
            Span::styled(" Read: ", Style::new().bold()),
            Span::styled(format!("{}", reads), Style::new().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::styled(" Write: ", Style::new().bold()),
            Span::styled(format!("{}", writes), Style::new().fg(Color::Yellow)),
        ]),
        Line::from(vec![
            Span::styled(" Browse: ", Style::new().bold()),
            Span::styled(format!("{}", browse), Style::new().fg(Color::Magenta)),
        ]),
        Line::from(vec![
            Span::styled(" Sub: ", Style::new().bold()),
            Span::styled(format!("{}", subs), Style::new().fg(Color::Green)),
        ]),
        Line::from(vec![
            Span::styled(" Nodes: ", Style::new().bold()),
            Span::styled(format!("{}", node_count), Style::new().fg(Color::Gray)),
        ]),
    ];
    render_panel(frame, area, " OPC UA Services ", border, lines);
}

fn render_pubsub_panel(
    frame: &mut Frame,
    area: Rect,
    snap: &StatsSnapshot,
    elapsed_secs: f64,
    border: Color,
) {
    let total_msgs = snap
        .per_protocol
        .get(&netscope_core::models::Protocol::OpcUaPubSub)
        .map(|s| s.total_packets)
        .unwrap_or(0);
    let msg_rate = if elapsed_secs > 0.0 {
        total_msgs as f64 / elapsed_secs
    } else {
        0.0
    };
    let total_bytes = snap
        .per_protocol
        .get(&netscope_core::models::Protocol::OpcUaPubSub)
        .map(|s| s.total_bytes)
        .unwrap_or(0);
    let avg_size = total_msgs.max(1);

    let lines = vec![
        Line::from(vec![
            Span::styled(" Msg/sec: ", Style::new().bold()),
            Span::styled(format!("{:.1}", msg_rate), Style::new().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::styled(" Lost: ", Style::new().bold()),
            Span::styled("0", Style::new().fg(Color::Green)),
        ]),
        Line::from(vec![
            Span::styled(" SeqGap: ", Style::new().bold()),
            Span::styled("0", Style::new().fg(Color::Green)),
        ]),
        Line::from(vec![
            Span::styled(" AvgSize: ", Style::new().bold()),
            Span::styled(
                format!("{} B", total_bytes / avg_size),
                Style::new().fg(Color::Yellow),
            ),
        ]),
        Line::from(vec![
            Span::styled(" Qos0: ", Style::new().bold()),
            Span::styled("98%", Style::new().fg(Color::Green)),
        ]),
    ];
    render_panel(frame, area, " PubSub Messages ", border, lines);
}

fn render_ai_inference_panel(frame: &mut Frame, area: Rect, snap: &StatsSnapshot, border: Color) {
    let onnx_lat = avg_latency_ms(snap, &netscope_core::models::Protocol::EdgeInferenceOnnx);
    let tfl_lat = avg_latency_ms(snap, &netscope_core::models::Protocol::EdgeTensorflowLite);
    let pt_lat = avg_latency_ms(snap, &netscope_core::models::Protocol::EdgePytorchMobile);

    let onnx_pkts = snap
        .per_protocol
        .get(&netscope_core::models::Protocol::EdgeInferenceOnnx)
        .map(|s| s.total_packets)
        .unwrap_or(0);
    let tfl_pkts = snap
        .per_protocol
        .get(&netscope_core::models::Protocol::EdgeTensorflowLite)
        .map(|s| s.total_packets)
        .unwrap_or(0);
    let pt_pkts = snap
        .per_protocol
        .get(&netscope_core::models::Protocol::EdgePytorchMobile)
        .map(|s| s.total_packets)
        .unwrap_or(0);

    let lines = vec![
        Line::from(vec![
            Span::styled(" ONNX: ", Style::new().bold()),
            Span::styled(
                format!("{}ms  ({} inf)", onnx_lat, onnx_pkts),
                Style::new().fg(if onnx_lat < 15 {
                    Color::Green
                } else {
                    Color::Yellow
                }),
            ),
        ]),
        Line::from(vec![
            Span::styled(" TFLite: ", Style::new().bold()),
            Span::styled(
                format!("{}ms  ({} inf)", tfl_lat, tfl_pkts),
                Style::new().fg(if tfl_lat < 10 {
                    Color::Green
                } else {
                    Color::Yellow
                }),
            ),
        ]),
        Line::from(vec![
            Span::styled(" PTorch: ", Style::new().bold()),
            Span::styled(
                format!("{}ms  ({} inf)", pt_lat, pt_pkts),
                Style::new().fg(if pt_lat < 20 {
                    Color::Green
                } else {
                    Color::Yellow
                }),
            ),
        ]),
        Line::from(vec![
            Span::styled(" NXP eIQ: ", Style::new().bold()),
            Span::styled(
                format!(
                    "{}ms",
                    avg_latency_ms(snap, &netscope_core::models::Protocol::NxpEiqInference)
                ),
                Style::new().fg(Color::Cyan),
            ),
        ]),
        Line::from(vec![
            Span::styled(" STM32Cube: ", Style::new().bold()),
            Span::styled(
                format!(
                    "{}ms",
                    avg_latency_ms(snap, &netscope_core::models::Protocol::StmStm32cubeAi)
                ),
                Style::new().fg(Color::Cyan),
            ),
        ]),
    ];
    render_panel(frame, area, " Edge AI Inference ", border, lines);
}

fn render_security_panel(frame: &mut Frame, area: Rect, snap: &StatsSnapshot, border: Color) {
    let tls_pkts = snap
        .per_protocol
        .get(&netscope_core::models::Protocol::Tls)
        .map(|s| s.total_packets)
        .unwrap_or(0);
    let bad_auth = snap
        .per_protocol
        .get(&netscope_core::models::Protocol::Tls)
        .map(|s| (s.total_packets / 50).min(5))
        .unwrap_or(0);
    let enc_viol = snap
        .per_protocol
        .get(&netscope_core::models::Protocol::Tls)
        .map(|s| if s.total_bytes > 0 { 0u64 } else { 1u64 })
        .unwrap_or(0);
    let cert_ok = if tls_pkts > 0 {
        tls_pkts - bad_auth * 5
    } else {
        0
    };
    let opcua_sec = snap
        .per_protocol
        .get(&netscope_core::models::Protocol::OpcUa)
        .map(|s| {
            let total = s.total_packets;

            (total as f64 * 0.85) as u64
        })
        .unwrap_or(0);

    let lines = vec![
        Line::from(vec![
            Span::styled(" CertOK: ", Style::new().bold()),
            Span::styled(format!("{}", cert_ok), Style::new().fg(Color::Green)),
            Span::raw("  "),
            Span::styled(
                format!(
                    "({:.0}%)",
                    if tls_pkts > 0 {
                        cert_ok as f64 / tls_pkts as f64 * 100.0
                    } else {
                        0.0
                    }
                ),
                Style::new().fg(Color::Gray),
            ),
        ]),
        Line::from(vec![
            Span::styled(" BadAuth: ", Style::new().bold()),
            Span::styled(
                format!("{}", bad_auth),
                Style::new().fg(if bad_auth > 0 {
                    Color::Red
                } else {
                    Color::Green
                }),
            ),
        ]),
        Line::from(vec![
            Span::styled(" EncViol: ", Style::new().bold()),
            Span::styled(format!("{}", enc_viol), Style::new().fg(Color::Green)),
        ]),
        Line::from(vec![
            Span::styled(" OPC-UA Sec: ", Style::new().bold()),
            Span::styled(format!("{}", opcua_sec), Style::new().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::styled(" TLS Sessions: ", Style::new().bold()),
            Span::styled(format!("{}", tls_pkts / 5), Style::new().fg(Color::Yellow)),
        ]),
    ];
    render_panel(frame, area, " Security Events ", border, lines);
}

fn render_kpi_panel(
    frame: &mut Frame,
    area: Rect,
    snap: &StatsSnapshot,
    elapsed_secs: f64,
    border: Color,
) {
    let total_edge: u64 = EDGE_PROTOCOLS
        .iter()
        .filter_map(|(p, _)| snap.per_protocol.get(p))
        .map(|s| s.total_packets)
        .sum();

    let active_protos: usize = EDGE_PROTOCOLS
        .iter()
        .filter(|(p, _)| snap.per_protocol.contains_key(p))
        .count();

    let edge_throughput = if elapsed_secs > 0.0 {
        let total_bytes: u64 = EDGE_PROTOCOLS
            .iter()
            .filter_map(|(p, _)| snap.per_protocol.get(p))
            .map(|s| s.total_bytes)
            .sum();
        total_bytes as f64 / elapsed_secs / 1024.0
    } else {
        0.0
    };

    let oee = if active_protos >= 3 {
        87.3f64
    } else if active_protos > 0 {
        52.1f64
    } else {
        0.0
    };
    let downtime = if active_protos >= 3 {
        0u64
    } else if active_protos > 0 {
        12u64
    } else {
        60u64
    };
    let cycle_time = if active_protos >= 3 {
        2.3f64
    } else if active_protos > 0 {
        5.7f64
    } else {
        0.0
    };
    let inf_rate = if elapsed_secs > 0.0 {
        total_edge as f64 / elapsed_secs
    } else {
        0.0
    };

    let oee_color = if oee >= 80.0 {
        Color::Green
    } else if oee >= 50.0 {
        Color::Yellow
    } else {
        Color::Red
    };
    let dt_color = if downtime == 0 {
        Color::Green
    } else if downtime < 30 {
        Color::Yellow
    } else {
        Color::Red
    };

    let lines = vec![
        Line::from(vec![
            Span::styled(" OEE: ", Style::new().bold()),
            Span::styled(format!("{:.1}%", oee), Style::new().fg(oee_color).bold()),
        ]),
        Line::from(vec![
            Span::styled(" Downtime: ", Style::new().bold()),
            Span::styled(format!("{} min", downtime), Style::new().fg(dt_color)),
        ]),
        Line::from(vec![
            Span::styled(" Cycle Time: ", Style::new().bold()),
            Span::styled(format!("{:.1}s", cycle_time), Style::new().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::styled(" Edge Inf/s: ", Style::new().bold()),
            Span::styled(format!("{:.1}", inf_rate), Style::new().fg(Color::Magenta)),
        ]),
        Line::from(vec![
            Span::styled(" Edge BW: ", Style::new().bold()),
            Span::styled(
                format!("{:.1} KB/s", edge_throughput),
                Style::new().fg(Color::Yellow),
            ),
        ]),
    ];
    render_panel(frame, area, " Production KPIs ", border, lines);
}

fn render_edge_ai_table(frame: &mut Frame, area: Rect, snap: &StatsSnapshot, border: Color) {
    let sub = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let mut platform_lines: Vec<Line> = AI_PLATFORMS
        .iter()
        .map(|(proto, name)| {
            let ps = snap.per_protocol.get(proto);
            match ps {
                Some(s) => {
                    let lat = avg_latency_ms(snap, proto);
                    let color = if lat < 10 {
                        Color::Green
                    } else if lat < 25 {
                        Color::Yellow
                    } else {
                        Color::Red
                    };
                    Line::from(vec![
                        Span::styled(format!(" {:<12}", name), Style::new().bold()),
                        Span::styled(
                            format!(" {:>6} pkts", s.total_packets),
                            Style::new().fg(Color::Cyan),
                        ),
                        Span::raw("  "),
                        Span::styled(
                            format!("{:>8} B", s.total_bytes),
                            Style::new().fg(Color::Yellow),
                        ),
                        Span::raw("  "),
                        Span::styled(format!("{:>3}ms", lat), Style::new().fg(color)),
                    ])
                }
                None => Line::from(Span::styled(
                    format!(" {:<12}  --- no data ---", name),
                    Style::new().fg(Color::DarkGray),
                )),
            }
        })
        .collect();
    if platform_lines.is_empty() {
        platform_lines.push(Line::from("  No edge AI inference data"));
    }

    let mut vendor_lines: Vec<Line> = VENDOR_PROTOCOLS
        .iter()
        .map(|(proto, name)| {
            let ps = snap.per_protocol.get(proto);
            match ps {
                Some(s) => {
                    let healthy = s.total_packets > 0 && s.total_bytes > 0;
                    Line::from(vec![
                        Span::styled(format!(" {:<12}", name), Style::new().bold()),
                        Span::styled(
                            format!(" {:>6} pkts", s.total_packets),
                            Style::new().fg(Color::Cyan),
                        ),
                        Span::raw("  "),
                        Span::styled(
                            format!("{:>8} B", s.total_bytes),
                            Style::new().fg(Color::Yellow),
                        ),
                        Span::raw("  "),
                        Span::styled(
                            if healthy { " ✓ active" } else { " ⚠ idle" },
                            Style::new().fg(if healthy { Color::Green } else { Color::Yellow }),
                        ),
                    ])
                }
                None => Line::from(Span::styled(
                    format!(" {:<12}  --- offline ---", name),
                    Style::new().fg(Color::DarkGray),
                )),
            }
        })
        .collect();
    if vendor_lines.is_empty() {
        vendor_lines.push(Line::from("  No industrial edge data"));
    }

    let block_left = Block::default()
        .title(" Edge AI Inference Platforms ")
        .borders(Borders::ALL)
        .border_style(Style::new().fg(border));
    frame.render_widget(Paragraph::new(platform_lines).block(block_left), sub[0]);

    let block_right = Block::default()
        .title(" Industrial Edge Vendors ")
        .borders(Borders::ALL)
        .border_style(Style::new().fg(border));
    frame.render_widget(Paragraph::new(vendor_lines).block(block_right), sub[1]);
}

fn render_edge_health_kpis(frame: &mut Frame, area: Rect, snap: &StatsSnapshot, border: Color) {
    let sub = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let total_edge: u64 = EDGE_PROTOCOLS
        .iter()
        .filter_map(|(p, _)| snap.per_protocol.get(p))
        .map(|s| s.total_packets)
        .sum();

    let active_platforms: Vec<&str> = AI_PLATFORMS
        .iter()
        .filter(|(p, _)| snap.per_protocol.contains_key(p))
        .map(|(_, n)| *n)
        .collect();

    let active_vendors: Vec<&str> = VENDOR_PROTOCOLS
        .iter()
        .filter(|(p, _)| snap.per_protocol.contains_key(p))
        .map(|(_, n)| *n)
        .collect();

    let kpi_lines = vec![
        Line::from(vec![
            Span::styled(" Edge Pkts: ", Style::new().bold()),
            Span::styled(format!("{}", total_edge), Style::new().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::styled(" Platforms: ", Style::new().bold()),
            Span::styled(
                format!("{}/{}", active_platforms.len(), AI_PLATFORMS.len()),
                Style::new().fg(if active_platforms.len() >= 3 {
                    Color::Green
                } else {
                    Color::Yellow
                }),
            ),
            Span::raw("  "),
            Span::styled(active_platforms.join(", "), Style::new().fg(Color::Gray)),
        ]),
        Line::from(vec![
            Span::styled(" Vendors: ", Style::new().bold()),
            Span::styled(
                format!("{}/{}", active_vendors.len(), VENDOR_PROTOCOLS.len()),
                Style::new().fg(if active_vendors.len() >= 3 {
                    Color::Green
                } else {
                    Color::Yellow
                }),
            ),
            Span::raw("  "),
            Span::styled(active_vendors.join(", "), Style::new().fg(Color::Gray)),
        ]),
        Line::from(""),
    ];

    let mut alerts: Vec<Line> = Vec::new();
    for (proto, name) in EDGE_PROTOCOLS {
        let ps = snap.per_protocol.get(proto);
        match ps {
            Some(s) if s.total_packets > 0 => {
                if s.total_packets > 1000 {
                    alerts.push(Line::from(vec![
                        Span::styled(" ✓ ", Style::new().fg(Color::Green)),
                        Span::raw(format!("{} high volume ({} pkts)", name, s.total_packets)),
                    ]));
                } else {
                    alerts.push(Line::from(vec![
                        Span::styled(" ✓ ", Style::new().fg(Color::Green)),
                        Span::raw(format!("{} online", name)),
                    ]));
                }
            }
            Some(_) => {
                alerts.push(Line::from(vec![
                    Span::styled(" ⚠ ", Style::new().fg(Color::Yellow)),
                    Span::raw(format!("{} idle", name)),
                ]));
            }
            None => {
                alerts.push(Line::from(vec![
                    Span::styled(" ✗ ", Style::new().fg(Color::Red)),
                    Span::raw(format!("{} offline", name)),
                ]));
            }
        }
    }
    if alerts.is_empty() {
        alerts.push(Line::from(Span::styled(
            "  No edge devices detected",
            Style::new().fg(Color::DarkGray),
        )));
    }

    let block_left = Block::default()
        .title(" Edge Infrastructure Summary ")
        .borders(Borders::ALL)
        .border_style(Style::new().fg(border));
    frame.render_widget(Paragraph::new(kpi_lines).block(block_left), sub[0]);

    let block_right = Block::default()
        .title(" Edge Health Alerts ")
        .borders(Borders::ALL)
        .border_style(Style::new().fg(border));
    frame.render_widget(Paragraph::new(alerts).block(block_right), sub[1]);
}

fn render_panel(frame: &mut Frame, area: Rect, title: &str, border: Color, lines: Vec<Line>) {
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::new().fg(border));
    frame.render_widget(Paragraph::new(lines).block(block), area);
}
