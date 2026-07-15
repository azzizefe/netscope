// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Style, Stylize};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState};
use ratatui::Frame;

use crate::app::App;
use crate::colors::protocol_color;
use netscope_core::flows::Flow;

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let theme = app.theme();
    let flows = app.flows.flows();

    let title = format!(
        " Connections ({}){} ",
        flows.len(),
        if app.blocked.is_empty() {
            String::new()
        } else {
            format!(" · {} blocked", app.blocked.len())
        }
    );
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::new().fg(theme.border));

    if flows.is_empty() {
        let inner = block.inner(area);
        frame.render_widget(block, area);
        frame.render_widget(
            Paragraph::new("No connections yet — waiting for traffic...").centered(),
            inner,
        );
        return;
    }

    let header = [
        " # ",
        " ",
        " Client ",
        " Server ",
        " Proto ",
        " Pkts ",
        " ⇄ ",
        " Bytes ",
        " Duration ",
        " Last activity ",
    ];
    let constraints = [
        Constraint::Length(5),
        Constraint::Length(3),
        Constraint::Length(24),
        Constraint::Length(24),
        Constraint::Length(7),
        Constraint::Length(7),
        Constraint::Length(9),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Min(10),
    ];

    let rows: Vec<Row> = flows
        .iter()
        .enumerate()
        .map(|(i, flow)| {
            let color = protocol_color(&flow.app_protocol);
            let is_blocked = app.blocked.contains(&flow.server_addr);
            let mark = if is_blocked { " ⛔" } else { "  " };
            let row = Row::new(vec![
                Cell::from(format!(" {:<3}", i + 1)),
                Cell::from(mark),
                Cell::from(format!(" {} ", endpoint(flow, true, app))),
                Cell::from(format!(" {} ", endpoint(flow, false, app))),
                Cell::from(format!(" {} ", flow.app_protocol)).style(Style::new().fg(color).bold()),
                Cell::from(format!(" {} ", flow.packet_count)),
                Cell::from(format!(
                    " {}↑{}↓ ",
                    flow.packets_to_server, flow.packets_to_client
                )),
                Cell::from(format!(" {} ", format_bytes(flow.byte_count))),
                Cell::from(format!(" {} ", format_duration(flow))),
                Cell::from(format!(" {} ", flow.last_summary)),
            ]);
            if is_blocked {
                row.style(Style::new().fg(ratatui::style::Color::Rgb(0xF8, 0x71, 0x71)))
            } else {
                row
            }
        })
        .collect();

    let header_cells: Vec<Cell> = header
        .iter()
        .map(|h| Cell::from(*h).style(Style::new().bold().white()))
        .collect();
    let table = Table::new(rows, constraints)
        .header(Row::new(header_cells))
        .row_highlight_style(Style::new().bg(theme.selected_bg))
        .block(block);

    let mut state = TableState::new().with_selected(Some(app.conn_selected.min(flows.len() - 1)));
    frame.render_stateful_widget(table, area, &mut state);
}

fn endpoint(flow: &Flow, client: bool, app: &App) -> String {
    let (addr, port) = if client {
        (flow.client_addr, flow.client_port)
    } else {
        (flow.server_addr, flow.server_port)
    };
    app.names.display_endpoint(addr, port)
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_000_000 {
        format!("{:.1} MB", bytes as f64 / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{:.1} KB", bytes as f64 / 1_000.0)
    } else {
        format!("{bytes} B")
    }
}

fn format_duration(flow: &Flow) -> String {
    let ms = flow.duration().num_milliseconds();
    if ms >= 60_000 {
        format!("{}m{}s", ms / 60_000, (ms % 60_000) / 1000)
    } else if ms >= 1000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else {
        format!("{ms}ms")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use netscope_core::flows::Transport;
    use netscope_core::models::Protocol;

    #[test]
    fn bytes_use_the_right_unit() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(999), "999 B");
        assert_eq!(format_bytes(1_000), "1.0 KB");
        assert_eq!(format_bytes(45_600), "45.6 KB");
        assert_eq!(format_bytes(1_000_000), "1.0 MB");
        assert_eq!(format_bytes(2_345_678), "2.3 MB");
    }

    fn flow_lasting(ms: i64) -> Flow {
        let start = chrono::Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap();
        Flow {
            client_addr: "10.0.0.1".parse().unwrap(),
            client_port: Some(50000),
            server_addr: "10.0.0.2".parse().unwrap(),
            server_port: Some(443),
            transport: Transport::Tcp,
            app_protocol: Protocol::Tls,
            packet_count: 1,
            byte_count: 60,
            packets_to_server: 1,
            packets_to_client: 0,
            start_time: start,
            end_time: start + chrono::Duration::milliseconds(ms),
            last_summary: String::new(),
        }
    }

    #[test]
    fn durations_scale_from_ms_to_minutes() {
        assert_eq!(format_duration(&flow_lasting(0)), "0ms");
        assert_eq!(format_duration(&flow_lasting(999)), "999ms");
        assert_eq!(format_duration(&flow_lasting(1_500)), "1.5s");
        assert_eq!(format_duration(&flow_lasting(59_999)), "60.0s");
        assert_eq!(format_duration(&flow_lasting(61_000)), "1m1s");
        assert_eq!(format_duration(&flow_lasting(150_000)), "2m30s");
    }
}
