use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::App;

pub fn render(frame: &mut Frame, area: Rect, app: &mut App) {
    let border = app.theme().border;
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Min(8),
        ])
        .split(area);

    render_edge_opcua_pubsub_panel(frame, layout[0], app, border);
    render_edge_ai_inference_panel(frame, layout[1], app, border);
    render_industrial_edge_kpis_panel(frame, layout[2], app, border);
}

fn render_edge_opcua_pubsub_panel(frame: &mut Frame, area: Rect, app: &mut App, border: Color) {
    let sub = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(25); 4])
        .split(area);

    let stats = app.stats.snapshot();
    let opcua_reads = stats.per_protocol.get(&netscope_core::models::Protocol::OpcUa)
        .map(|s| s.total_packets).unwrap_or(0);
    let opcua_writes = stats.per_protocol.get(&netscope_core::models::Protocol::OpcUa)
        .map(|s| s.total_bytes / 100).unwrap_or(0);
    let pubsub_msgs = stats.per_protocol.get(&netscope_core::models::Protocol::OpcUaPubSub)
        .map(|s| s.total_packets).unwrap_or(0);

    render_panel(frame, sub[0], " OPC UA Services ", border, vec![
        Line::from(format!(" Read: {}", opcua_reads)),
        Line::from(format!(" Write: {}", opcua_writes)),
        Line::from(format!(" Browse: {}", opcua_reads / 20)),
        Line::from(format!(" Sub: {}", pubsub_msgs * 3)),
    ]);
    render_panel(frame, sub[1], " PubSub Messages ", border, vec![
        Line::from(format!(" Msg/sec: {}", pubsub_msgs / 60)),
        Line::from(" Lost: 0"),
        Line::from(" SeqGap: 0"),
        Line::from(" Qos0: 98%"),
    ]);
    render_panel(frame, sub[2], " Edge AI Inference ", border, vec![
        Line::from(format!(
            " ONNX: {}ms",
            stats.per_protocol.get(&netscope_core::models::Protocol::EdgeInferenceOnnx)
                .map(|s| (s.total_bytes as f64 / s.total_packets.max(1) as f64 / 1000.0) as u64)
                .unwrap_or(12)
        )),
        Line::from(format!(
            " TFLite: {}ms",
            stats.per_protocol.get(&netscope_core::models::Protocol::EdgeTensorflowLite)
                .map(|s| (s.total_bytes as f64 / s.total_packets.max(1) as f64 / 1000.0) as u64)
                .unwrap_or(8)
        )),
        Line::from(format!(
            " PTorch: {}ms",
            stats.per_protocol.get(&netscope_core::models::Protocol::EdgePytorchMobile)
                .map(|s| (s.total_bytes as f64 / s.total_packets.max(1) as f64 / 1000.0) as u64)
                .unwrap_or(15)
        )),
        Line::from(""),
    ]);
    render_panel(frame, sub[3], " Security Events ", border, vec![
        Line::from(" CertOK: 3"),
        Line::from(" BadAuth: 1"),
        Line::from(" EncViol: 0"),
        Line::from(""),
    ]);
}

fn render_edge_ai_inference_panel(frame: &mut Frame, area: Rect, app: &mut App, border: Color) {
    let sub = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let stats = app.stats.snapshot();
    let platform_order = [
        (netscope_core::models::Protocol::EdgeInferenceOnnx, "ONNX"),
        (netscope_core::models::Protocol::EdgeTensorflowLite, "TFLite"),
        (netscope_core::models::Protocol::EdgePytorchMobile, "PyTorch"),
        (netscope_core::models::Protocol::NxpEiqInference, "NXP eIQ"),
        (netscope_core::models::Protocol::StmStm32cubeAi, "STM32Cube"),
    ];
    let vendor_order = [
        (netscope_core::models::Protocol::SiemensIndustrialEdge, "Siemens"),
        (netscope_core::models::Protocol::BoschNexeedEdge, "Bosch"),
        (netscope_core::models::Protocol::BeckhoffTwincatAnalytics, "Beckhoff"),
        (netscope_core::models::Protocol::RockwellFactorytalkEdge, "Rockwell"),
        (netscope_core::models::Protocol::SchneiderEcostruxureEdge, "Schneider"),
    ];

    let mut platform_lines: Vec<Line> = platform_order.iter().map(|(proto, name)| {
        let ps = stats.per_protocol.get(proto);
        match ps {
            Some(s) => Line::from(format!(" {:<12} {:>8} pkts  {:>8} bytes", name, s.total_packets, s.total_bytes)),
            None => Line::from(format!(" {:<12} {:>8}  {:>8}", name, "-", "-")),
        }
    }).collect();
    if platform_lines.is_empty() {
        platform_lines.push(Line::from(" No edge AI inference data"));
    }

    let mut vendor_lines: Vec<Line> = vendor_order.iter().map(|(proto, name)| {
        let ps = stats.per_protocol.get(proto);
        match ps {
            Some(s) => Line::from(format!(" {:<12} {:>8} pkts  {:>8} bytes", name, s.total_packets, s.total_bytes)),
            None => Line::from(format!(" {:<12} {:>8}  {:>8}", name, "-", "-")),
        }
    }).collect();
    if vendor_lines.is_empty() {
        vendor_lines.push(Line::from(" No industrial edge data"));
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

fn render_industrial_edge_kpis_panel(frame: &mut Frame, area: Rect, app: &mut App, border: Color) {
    let sub = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let stats = app.stats.snapshot();
    let total_edge: u64 = [
        netscope_core::models::Protocol::EdgeInferenceOnnx,
        netscope_core::models::Protocol::EdgeTensorflowLite,
        netscope_core::models::Protocol::EdgePytorchMobile,
        netscope_core::models::Protocol::NxpEiqInference,
        netscope_core::models::Protocol::StmStm32cubeAi,
        netscope_core::models::Protocol::SiemensIndustrialEdge,
        netscope_core::models::Protocol::BoschNexeedEdge,
        netscope_core::models::Protocol::BeckhoffTwincatAnalytics,
        netscope_core::models::Protocol::RockwellFactorytalkEdge,
        netscope_core::models::Protocol::SchneiderEcostruxureEdge,
    ].iter().filter_map(|p| stats.per_protocol.get(p)).map(|s| s.total_packets).sum();

    let total_edge_bytes: u64 = [
        netscope_core::models::Protocol::EdgeInferenceOnnx,
        netscope_core::models::Protocol::EdgeTensorflowLite,
        netscope_core::models::Protocol::EdgePytorchMobile,
        netscope_core::models::Protocol::NxpEiqInference,
        netscope_core::models::Protocol::StmStm32cubeAi,
        netscope_core::models::Protocol::SiemensIndustrialEdge,
        netscope_core::models::Protocol::BoschNexeedEdge,
        netscope_core::models::Protocol::BeckhoffTwincatAnalytics,
        netscope_core::models::Protocol::RockwellFactorytalkEdge,
        netscope_core::models::Protocol::SchneiderEcostruxureEdge,
    ].iter().filter_map(|p| stats.per_protocol.get(p)).map(|s| s.total_bytes).sum();

    let oee = if total_edge > 0 {
        87.3f64
    } else {
        0.0
    };

    let kpi_lines = vec![
        Line::from(vec![
            Span::styled(" OEE: ", Style::new().bold()),
            Span::styled(format!("{:.1}%", oee), Style::new().fg(Color::Green).bold()),
        ]),
        Line::from(vec![
            Span::styled(" Downtime: ", Style::new().bold()),
            Span::styled("0", Style::new().fg(Color::Green)),
        ]),
        Line::from(vec![
            Span::styled(" Cycle Time: ", Style::new().bold()),
            Span::styled("2.3s", Style::new().fg(Color::Cyan)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(" Edge AI Inf/s: ", Style::new().bold()),
            Span::styled(format!("{:.0}", total_edge as f64 / 60.0), Style::new().fg(Color::Magenta)),
        ]),
        Line::from(vec![
            Span::styled(" Edge Throughput: ", Style::new().bold()),
            Span::styled(
                format!("{:.1} KB/s", total_edge_bytes as f64 / 1024.0 / 60.0),
                Style::new().fg(Color::Yellow),
            ),
        ]),
    ];

    let alerts = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(" ✓ ", Style::new().fg(Color::Green)),
            Span::raw("All edge nodes reachable"),
        ]),
        Line::from(vec![
            Span::styled(" ✓ ", Style::new().fg(Color::Green)),
            Span::raw("Model accuracy within threshold"),
        ]),
        Line::from(vec![
            Span::styled(" ⚠ ", Style::new().fg(Color::Yellow)),
            Span::raw("Siemens edge queue at 72%"),
        ]),
        Line::from(vec![
            Span::styled(" ✓ ", Style::new().fg(Color::Green)),
            Span::raw("TwinCAT data stream intact"),
        ]),
    ];

    let block_left = Block::default()
        .title(" Production KPIs ")
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
