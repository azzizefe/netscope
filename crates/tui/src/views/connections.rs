use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Style, Stylize};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};
use ratatui::Frame;

use crate::app::App;
use crate::colors::{protocol_color, PANEL_BORDER};
use netscope_core::flows::Flow;

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let flows = app.flows.flows();

    let block = Block::default()
        .title(format!(" Connections ({}) ", flows.len()))
        .borders(Borders::ALL)
        .border_style(Style::new().fg(PANEL_BORDER));

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
        Constraint::Length(22),
        Constraint::Length(22),
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
            Row::new(vec![
                Cell::from(format!(" {:<3}", i + 1)),
                Cell::from(format!(" {} ", endpoint(flow, true))),
                Cell::from(format!(" {} ", endpoint(flow, false))),
                Cell::from(format!(" {} ", flow.app_protocol)).style(Style::new().fg(color).bold()),
                Cell::from(format!(" {} ", flow.packet_count)),
                Cell::from(format!(
                    " {}↑{}↓ ",
                    flow.packets_to_server, flow.packets_to_client
                )),
                Cell::from(format!(" {} ", format_bytes(flow.byte_count))),
                Cell::from(format!(" {} ", format_duration(flow))),
                Cell::from(format!(" {} ", flow.last_summary)),
            ])
        })
        .collect();

    let header_cells: Vec<Cell> = header
        .iter()
        .map(|h| Cell::from(*h).style(Style::new().bold().white()))
        .collect();
    let table = Table::new(rows, constraints)
        .header(Row::new(header_cells))
        .block(block);

    frame.render_widget(table, area);
}

fn endpoint(flow: &Flow, client: bool) -> String {
    let (addr, port) = if client {
        (flow.client_addr, flow.client_port)
    } else {
        (flow.server_addr, flow.server_port)
    };
    netscope_core::models::format_endpoint(addr, port)
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
