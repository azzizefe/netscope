use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Style, Stylize};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::colors::{KEYBIND_BG, STATUS_BAR_BG};
use crate::views::{connections, dashboard, dns_log, packets, View};

pub fn render(frame: &mut Frame, app: &mut App) {
    let area = frame.area();
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // status bar
            Constraint::Min(1),    // main content
            Constraint::Length(1), // keybinding bar
        ])
        .split(area);

    render_status_bar(frame, layout[0], app);
    render_main_content(frame, layout[1], app);
    render_keybinding_bar(frame, layout[2], app);

    if app.show_help {
        render_help_overlay(frame, area);
    }
}

fn render_status_bar(frame: &mut Frame, area: Rect, app: &mut App) {
    // A transient action message (block succeeded/failed) takes over the bar.
    if let Some(msg) = app.active_status() {
        let line = Line::from(format!(" {msg} "));
        let block = Block::default().style(Style::new().bg(STATUS_BAR_BG).white());
        frame.render_widget(block, area);
        frame.render_widget(
            Paragraph::new(line).style(Style::new().bg(STATUS_BAR_BG).white().bold()),
            area,
        );
        return;
    }

    let state_icon = if app.paused { "⏸" } else { "●" };
    let state_color = if app.paused { "Paused" } else { "Capturing" };
    let elapsed = app.elapsed_secs();
    let total = app.stats.snapshot().total_packets;

    let mut spans = vec![
        format!(" netscope ▸ {} ", app.interface_name).into(),
        format!(" {} {} ", state_icon, state_color).into(),
        format!(" {} packets ", total).into(),
        format!(" {}s ", elapsed).into(),
    ];
    if !app.blocked.is_empty() {
        spans.push(format!(" ⛔ {} blocked ", app.blocked.len()).into());
    }
    if !app.elevated {
        spans.push(" ⚠ not admin (blocking disabled) ".into());
    }

    let block = Block::default().style(Style::new().bg(STATUS_BAR_BG).white());
    frame.render_widget(block, area);
    frame.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::new().bg(STATUS_BAR_BG).white()),
        area,
    );
}

fn render_keybinding_bar(frame: &mut Frame, area: Rect, app: &App) {
    // In Connections, surface the block controls instead of hex/expand.
    let binds: &[&str] = if app.view == crate::views::View::Connections {
        &[
            " ↑↓/jk select ",
            " b block ",
            " u unblock ",
            " Tab switch ",
            " Space pause ",
            " ? help ",
            " q quit ",
        ]
    } else {
        &[
            " ↑↓/jk navigate ",
            " Enter expand ",
            " Tab switch ",
            " type to filter ",
            " Space pause ",
            " h hex ",
            " ? help ",
            " q quit ",
        ]
    };
    let text = Line::from(
        binds
            .iter()
            .map(|s| s.to_string().into())
            .collect::<Vec<ratatui::text::Span>>(),
    );
    let block = Block::default().style(Style::new().bg(KEYBIND_BG).dark_gray());
    frame.render_widget(block, area);
    frame.render_widget(
        Paragraph::new(text).style(Style::new().bg(KEYBIND_BG).dark_gray()),
        area,
    );
}

fn render_main_content(frame: &mut Frame, area: Rect, app: &mut App) {
    match app.view {
        View::Packets => packets::render(frame, area, app),
        View::Dashboard => dashboard::render(frame, area, app),
        View::Connections => connections::render(frame, area, app),
        View::DnsLog => dns_log::render(frame, area, app),
    }
}

fn render_help_overlay(frame: &mut Frame, area: Rect) {
    let lines = vec![
        Line::from(" Help ").bold().white(),
        Line::from(""),
        Line::from(" j/k  or  ↑/↓     Navigate packet list"),
        Line::from(" Enter              Expand/collapse details"),
        Line::from(" Tab / Shift+Tab    Switch views"),
        Line::from(" /                  Filter packets"),
        Line::from(" Space              Pause/resume capture"),
        Line::from(" h                  Toggle hex dump"),
        Line::from(" q                  Quit"),
        Line::from(" ? or Esc           Close this help"),
        Line::from(""),
        Line::from(" Views:"),
        Line::from("   Packets      Live packet stream"),
        Line::from("   Dashboard    Real-time stats & bandwidth"),
        Line::from("   Connections  Group packets by flow"),
        Line::from("   DNS Log      All DNS queries"),
        Line::from(""),
        Line::from(" In Connections:"),
        Line::from("   j/k or ↑/↓         Select a connection"),
        Line::from("   b                  Block the remote host (firewall)"),
        Line::from("   u                  Unblock the remote host"),
        Line::from(" Blocking needs Administrator. Rules are named"),
        Line::from(" netscope-block-<ip> and persist until unblocked."),
    ];

    let block = Block::default()
        .title(" Help ")
        .borders(Borders::ALL)
        .style(Style::new().white().on_blue());

    let area = centered_rect(58, 80, area);
    frame.render_widget(Clear, area);
    frame.render_widget(block.clone(), area);
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length((r.height * (100 - percent_y)) / 200),
            Constraint::Min(0),
            Constraint::Length((r.height * (100 - percent_y)) / 200),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length((r.width * (100 - percent_x)) / 200),
            Constraint::Min(0),
            Constraint::Length((r.width * (100 - percent_x)) / 200),
        ])
        .split(popup[1])[1]
}
