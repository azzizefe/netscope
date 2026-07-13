use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState};
use ratatui::Frame;

use crate::app::App;
use crate::colors::protocol_color;
use crate::columns::Column;
use crate::detail::build_tree;

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
        render_detail_tree(frame, detail_area, app);
    }
}

/// The dynamic column layout for the packet list, honouring `app.columns`.
/// Info is always last and always present.
fn column_spec(app: &App) -> (Vec<Constraint>, Vec<&'static str>, Vec<Column>) {
    let mut constraints = Vec::new();
    let mut headers = Vec::new();
    let mut cols = Vec::new();
    for col in Column::ALL {
        if !app.columns.is_on(col) {
            continue;
        }
        let (width, header) = match col {
            Column::Num => (Constraint::Length(5), " # "),
            Column::Time => (Constraint::Length(10), " Time "),
            Column::Source => (Constraint::Length(24), " Source "),
            Column::Destination => (Constraint::Length(24), " Destination "),
            Column::Protocol => (Constraint::Length(9), " Proto "),
            Column::Length => (Constraint::Length(8), " Len "),
        };
        constraints.push(width);
        headers.push(header);
        cols.push(col);
    }
    constraints.push(Constraint::Min(10));
    headers.push(" Info ");
    (constraints, headers, cols)
}

fn render_packet_list(frame: &mut Frame, area: Rect, app: &mut App) {
    let theme = app.theme();
    let packets = app.filtered_packets();
    let (constraints, headers, cols) = column_spec(app);

    let rows: Vec<Row> = packets
        .iter()
        .enumerate()
        .map(|(i, pkt)| {
            let is_selected = i == app.selected;
            // Coloring rules: the first matching rule tints the whole row
            // (selection wins); otherwise the protocol keeps its colour.
            let rule_color = app.color_rules.color_for(pkt);
            let proto_color = rule_color.unwrap_or_else(|| protocol_color(&pkt.protocol));

            let mut cells: Vec<Cell> = Vec::with_capacity(cols.len() + 1);
            for col in &cols {
                let cell = match col {
                    Column::Num => Cell::from(format!(" {:>3}", i + 1)),
                    Column::Time => Cell::from(format!(
                        " {:.3}s",
                        (pkt.timestamp - app.start_time)
                            .to_std()
                            .unwrap_or_default()
                            .as_secs_f64()
                    )),
                    Column::Source => Cell::from(format!(
                        " {} ",
                        pkt.src_addr
                            .map(|a| app.names.display_endpoint(a, pkt.src_port))
                            .unwrap_or_else(|| "?".into())
                    )),
                    Column::Destination => Cell::from(format!(
                        " {} ",
                        pkt.dst_addr
                            .map(|a| app.names.display_endpoint(a, pkt.dst_port))
                            .unwrap_or_else(|| "?".into())
                    )),
                    Column::Protocol => Cell::from(Span::styled(
                        format!(" {} ", pkt.protocol),
                        Style::new().fg(proto_color).bold(),
                    )),
                    Column::Length => Cell::from(format!(" {} ", pkt.length)),
                };
                cells.push(cell);
            }
            cells.push(Cell::from(format!(" {} ", pkt.summary)));

            let row = Row::new(cells);
            if is_selected {
                row.style(Style::new().bg(theme.selected_bg))
            } else if let Some(color) = rule_color {
                row.style(Style::new().fg(color))
            } else {
                row
            }
        })
        .collect();

    let block = Block::default()
        .title(" Packets ")
        .borders(Borders::ALL)
        .border_style(Style::new().fg(theme.border));

    // Keep the selected row on screen and remember the scroll offset + row area
    // so a mouse click can map a screen row back to a packet index.
    let visible = area.height.saturating_sub(3) as usize; // borders + header
    let offset = if visible > 0 && app.selected >= visible {
        app.selected - visible + 1
    } else {
        0
    };
    app.list_offset = offset;
    app.list_inner = Rect {
        x: area.x + 1,
        y: area.y + 2,
        width: area.width.saturating_sub(2),
        height: visible as u16,
    };

    let mut state = TableState::new()
        .with_offset(offset)
        .with_selected(Some(app.selected));

    let table = Table::new(rows, constraints)
        .header(Row::new(headers.iter().map(|h| {
            Cell::from(Span::styled(*h, Style::new().bold().white()))
        })))
        .block(block);

    frame.render_stateful_widget(table, area, &mut state);
}

/// Wireshark-style expandable protocol tree (ROADMAP §6.1). Each layer is a
/// collapsible node; `Enter` focuses the tree and the focused layer is
/// highlighted, with `←/→` collapsing/expanding it.
fn render_detail_tree(frame: &mut Frame, area: Rect, app: &mut App) {
    let theme = app.theme();
    let block = Block::default()
        .title(if app.detail_focus {
            " Details · tree focus (Esc to leave) "
        } else {
            " Details (Enter to explore) "
        })
        .borders(Borders::ALL)
        .border_style(Style::new().fg(if app.detail_focus {
            theme.accent
        } else {
            theme.border
        }));

    let packets = app.filtered_packets();
    if packets.is_empty() || app.selected >= packets.len() {
        frame.render_widget(block, area);
        return;
    }

    let pkt = packets[app.selected];
    let nodes = build_tree(pkt, app.selected);
    // Clamp the focused layer to the available nodes.
    app.detail_sel = app.detail_sel.min(nodes.len().saturating_sub(1));

    let mut lines: Vec<Line> = Vec::new();
    for (i, node) in nodes.iter().enumerate() {
        let collapsed = app.detail_collapsed.contains(&i);
        let focused = app.detail_focus && i == app.detail_sel;
        let twist = if collapsed { "▸" } else { "▾" };
        let head_style = if focused {
            Style::new().fg(theme.accent).bold()
        } else {
            Style::new().fg(theme.accent)
        };
        let mut head = vec![
            Span::styled(format!("{twist} "), head_style),
            Span::styled(node.title.clone(), head_style),
        ];
        if !node.subtitle.is_empty() {
            head.push(Span::styled(
                format!("  {}", node.subtitle),
                Style::new().dim(),
            ));
        }
        let head_line = Line::from(head);
        lines.push(if focused {
            head_line.style(Style::new().bg(theme.selected_bg))
        } else {
            head_line
        });
        if !collapsed {
            for (key, value) in &node.fields {
                lines.push(Line::from(vec![
                    Span::styled(format!("    {key}: "), Style::new().dim()),
                    Span::raw(value.clone()),
                ]));
            }
        }
    }

    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(ratatui::widgets::Wrap { trim: false }),
        area,
    );
}

fn render_hex_dump(frame: &mut Frame, area: Rect, app: &App) {
    let theme = app.theme();
    let packets = app.filtered_packets();
    if packets.is_empty() || app.selected >= packets.len() {
        let block = Block::default()
            .title(" Hex Dump ")
            .borders(Borders::ALL)
            .border_style(Style::new().fg(theme.border));
        frame.render_widget(block, area);
        return;
    }

    let pkt = packets[app.selected];
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
        .border_style(Style::new().fg(theme.border));

    frame.render_widget(Paragraph::new(hex_lines.join("\n")).block(block), area);
}
