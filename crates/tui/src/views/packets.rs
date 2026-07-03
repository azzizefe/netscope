use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState};
use ratatui::Frame;

use crate::app::App;
use crate::colors::{protocol_color, PANEL_BORDER, SELECTED_BG};

pub fn render(frame: &mut Frame, area: Rect, app: &mut App) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(if app.detail_expanded {
            vec![Constraint::Percentage(50), Constraint::Percentage(50)]
        } else if app.show_hex {
            vec![Constraint::Percentage(60), Constraint::Percentage(40)]
        } else {
            vec![Constraint::Percentage(70), Constraint::Percentage(30)]
        })
        .split(area);

    render_packet_list(frame, layout[0], app);
    let detail_area = layout[1];

    if app.show_hex {
        render_hex_dump(frame, detail_area, app);
    } else {
        render_detail_panel(frame, detail_area, app);
    }
}

fn render_packet_list(frame: &mut Frame, area: Rect, app: &App) {
    let packets = app.filtered_packets();

    let header = [
        " # ",
        " Time ",
        " Source → Destination ",
        " Proto ",
        " Info ",
    ];
    let constraints = [
        Constraint::Length(5),
        Constraint::Length(10),
        Constraint::Length(34),
        Constraint::Length(7),
        Constraint::Min(10),
    ];

    let rows: Vec<Row> = packets
        .iter()
        .enumerate()
        .map(|(i, pkt)| {
            let is_selected = i == app.selected;
            let proto_color = protocol_color(&pkt.protocol);

            let num = Span::raw(format!(" {:>3}", i + 1));
            let elapsed = format!(
                " {:.3}s",
                (pkt.timestamp - app.start_time)
                    .to_std()
                    .unwrap_or_default()
                    .as_secs_f64()
            );
            let src = pkt
                .src_addr
                .map(|a| netscope_core::models::format_endpoint(a, pkt.src_port))
                .unwrap_or_else(|| "?".into());
            let dst = pkt
                .dst_addr
                .map(|a| netscope_core::models::format_endpoint(a, pkt.dst_port))
                .unwrap_or_else(|| "?".into());
            let proto = Span::styled(
                format!(" {} ", pkt.protocol),
                Style::new().fg(proto_color).bold(),
            );
            let summary = Span::raw(format!(" {} ", pkt.summary));

            let src_dst = format!(" {} → {} ", src, dst);

            let cells = vec![
                Cell::from(num),
                Cell::from(elapsed),
                Cell::from(src_dst),
                Cell::from(proto),
                Cell::from(summary),
            ];

            let row = Row::new(cells);
            if is_selected {
                row.style(Style::new().bg(SELECTED_BG))
            } else {
                row
            }
        })
        .collect();

    let block = Block::default()
        .title(" Packets ")
        .borders(Borders::ALL)
        .border_style(Style::new().fg(PANEL_BORDER));

    let mut state = TableState::new()
        .with_offset(app.selected.saturating_sub(if area.height > 5 {
            area.height as usize - 5
        } else {
            0
        }))
        .with_selected(Some(app.selected));

    let table = Table::new(rows, constraints)
        .header(Row::new(header.iter().map(|h| {
            Cell::from(Span::styled(*h, Style::new().bold().white()))
        })))
        .block(block);

    frame.render_stateful_widget(table, area, &mut state);
}

fn render_detail_panel(frame: &mut Frame, area: Rect, app: &App) {
    if app.packets.is_empty() || app.selected >= app.packets.len() {
        let block = Block::default()
            .title(" Details ")
            .borders(Borders::ALL)
            .border_style(Style::new().fg(PANEL_BORDER));
        frame.render_widget(block, area);
        return;
    }

    let pkt = &app.packets[app.selected];
    let proto_color = protocol_color(&pkt.protocol);
    let lines = vec![
        Line::from(vec![
            Span::styled(
                format!(" {} ", pkt.protocol),
                Style::new().fg(proto_color).bold(),
            ),
            Span::raw(" "),
            Span::styled(&pkt.summary, Style::new().bold()),
        ]),
        Line::from(""),
        Line::from(format!(
            " Source: {}",
            pkt.src_addr
                .map(|a| a.to_string())
                .unwrap_or_else(|| "?".into())
        )),
        Line::from(format!(
            " Destination: {}",
            pkt.dst_addr
                .map(|a| a.to_string())
                .unwrap_or_else(|| "?".into())
        )),
        Line::from(format!(
            " Ports: {} → {}",
            pkt.src_port
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".into()),
            pkt.dst_port
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".into())
        )),
        Line::from(format!(" Length: {} bytes", pkt.length)),
        Line::from(format!(
            " Timestamp: {}",
            pkt.timestamp.format("%H:%M:%S%.3f")
        )),
    ];

    let block = Block::default()
        .title(" Details ")
        .borders(Borders::ALL)
        .border_style(Style::new().fg(PANEL_BORDER));

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_hex_dump(frame: &mut Frame, area: Rect, app: &App) {
    if app.packets.is_empty() || app.selected >= app.packets.len() {
        return;
    }

    let pkt = &app.packets[app.selected];
    let data = &pkt.data;
    let hex_lines: Vec<String> = data
        .chunks(16)
        .enumerate()
        .map(|(i, chunk)| {
            let addr = i * 16;
            let hex: String = chunk
                .iter()
                .map(|b| format!("{b:02x} "))
                .collect::<Vec<_>>()
                .join("");
            let ascii: String = chunk
                .iter()
                .map(|&b| {
                    if b.is_ascii_graphic() || b == b' ' {
                        b as char
                    } else {
                        '.'
                    }
                })
                .collect();
            format!("{:04x}  {:48}  {}", addr, hex, ascii)
        })
        .collect();

    let block = Block::default()
        .title(" Hex Dump ")
        .borders(Borders::ALL)
        .border_style(Style::new().fg(PANEL_BORDER));

    frame.render_widget(Paragraph::new(hex_lines.join("\n")).block(block), area);
}
