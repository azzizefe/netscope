use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Style, Stylize};
use ratatui::widgets::{Block, Borders, Cell, Row, Table};
use ratatui::Frame;

use crate::app::App;
use crate::colors::protocol_color;
use netscope_core::models::Protocol;

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let dns_packets: Vec<&netscope_core::models::Packet> = app
        .packets
        .iter()
        .filter(|p| p.protocol == Protocol::Dns)
        .collect();

    let header = [" # ", " Time ", " Query / Response ", " Details "];
    let constraints = [
        Constraint::Length(5),
        Constraint::Length(10),
        Constraint::Length(12),
        Constraint::Min(10),
    ];

    let rows: Vec<Row> = dns_packets
        .iter()
        .enumerate()
        .map(|(i, pkt)| {
            let kind = if pkt.summary.contains("Query") {
                "Query"
            } else {
                "Response"
            };
            let color = protocol_color(&Protocol::Dns);
            let elapsed = (pkt.timestamp - app.start_time)
                .to_std()
                .unwrap_or_default()
                .as_secs_f64();
            Row::new(vec![
                Cell::from(format!(" {:<3}", i + 1)),
                Cell::from(format!(" {:.3}s", elapsed)),
                Cell::from(format!(" {} ", kind)).style(Style::new().fg(color).bold()),
                Cell::from(format!(" {} ", pkt.summary)),
            ])
        })
        .collect();

    let block = Block::default()
        .title(" DNS Log ")
        .borders(Borders::ALL)
        .border_style(Style::new().fg(app.theme().border));

    let header_cells: Vec<Cell> = header
        .iter()
        .map(|h| Cell::from(*h).style(Style::new().bold().white()))
        .collect();
    let table = Table::new(rows, constraints)
        .header(Row::new(header_cells))
        .block(block);

    frame.render_widget(table, area);
}
