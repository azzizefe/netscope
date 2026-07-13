use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::App;
use crate::columns::Column;
use crate::theme::Theme;
use crate::views::{connections, dashboard, dns_log, insights, learn, packets, View};

pub fn render(frame: &mut Frame, app: &mut App) {
    let theme = app.theme();
    let area = frame.area();
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // status bar
            Constraint::Length(1), // tab strip
            Constraint::Min(1),    // main content
            Constraint::Length(1), // keybinding bar
        ])
        .split(area);

    render_status_bar(frame, layout[0], app, theme);
    render_tabs(frame, layout[1], app, theme);
    render_main_content(frame, layout[2], app);
    render_keybinding_bar(frame, layout[3], app, theme);

    if app.show_stream {
        render_stream_overlay(frame, area, app, theme);
    }
    if app.show_columns {
        render_columns_overlay(frame, area, app, theme);
    }
    if app.show_bookmarks {
        render_bookmarks_overlay(frame, area, app, theme);
    }
    if app.show_expert {
        render_expert_overlay(frame, area, app, theme);
    }
    if app.show_help {
        render_help_overlay(frame, area, theme);
    }
}

fn render_status_bar(frame: &mut Frame, area: Rect, app: &mut App, theme: Theme) {
    // A transient action message (block succeeded/failed, theme change) takes
    // over the bar.
    if let Some(msg) = app.active_status() {
        let line = Line::from(format!(" {msg} "));
        let block = Block::default().style(Style::new().bg(theme.bar_bg).white());
        frame.render_widget(block, area);
        frame.render_widget(
            Paragraph::new(line).style(Style::new().bg(theme.bar_bg).white().bold()),
            area,
        );
        return;
    }

    let state_icon = if app.paused { "⏸" } else { "●" };
    let state_color = if app.paused { "Paused" } else { "Capturing" };
    let elapsed = app.elapsed_secs();
    let total = app.stats.total_packets();

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

    let block = Block::default().style(Style::new().bg(theme.bar_bg).white());
    frame.render_widget(block, area);
    frame.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::new().bg(theme.bar_bg).white()),
        area,
    );
}

/// Clickable tab strip. Records each tab's x-range in `app.tab_hits` so a
/// mouse click on the strip can switch views (ROADMAP §6.1).
fn render_tabs(frame: &mut Frame, area: Rect, app: &mut App, theme: Theme) {
    let block = Block::default().style(Style::new().bg(theme.bar_bg));
    frame.render_widget(block, area);

    app.tab_row = area.y;
    app.tab_hits.clear();
    let mut spans: Vec<Span> = Vec::new();
    let mut x = area.x;
    for view in View::ORDER {
        let label = format!(" {} ", view.title());
        let width = label.chars().count() as u16;
        app.tab_hits.push((x, x + width, view));
        let style = if view == app.view {
            Style::new()
                .bg(theme.accent)
                .fg(ratatui::style::Color::Black)
                .bold()
        } else {
            Style::new().bg(theme.bar_bg).fg(theme.bar_fg)
        };
        spans.push(Span::styled(label, style));
        spans.push(Span::styled(
            "│",
            Style::new().bg(theme.bar_bg).fg(theme.border),
        ));
        x += width + 1;
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn render_keybinding_bar(frame: &mut Frame, area: Rect, app: &App, theme: Theme) {
    // Surface the controls that matter for the active view/overlay.
    let binds: &[&str] = if app.detail_focus {
        &[
            " ↑↓/jk layer ",
            " ←/Enter collapse ",
            " → expand ",
            " Esc back ",
            " q quit ",
        ]
    } else if app.view == View::Connections {
        &[
            " ↑↓/jk select ",
            " b block ",
            " u unblock ",
            " Tab switch ",
            " T theme ",
            " ? help ",
            " q quit ",
        ]
    } else if app.view == View::Learn || app.view == View::Insights {
        &[
            " ↑↓/jk scroll ",
            " Tab switch ",
            " T theme ",
            " ? help ",
            " q quit ",
        ]
    } else {
        &[
            " ↑↓/jk navigate ",
            " Enter details ",
            " F follow ",
            " C columns ",
            " B filters ",
            " E expert ",
            " R time ref ",
            " h hex ",
            " T theme ",
            " ? help ",
            " q quit ",
        ]
    };
    let text = Line::from(
        binds
            .iter()
            .map(|s| Span::styled(s.to_string(), Style::new().fg(theme.bar_fg)))
            .collect::<Vec<Span>>(),
    );
    let block = Block::default().style(Style::new().bg(theme.bar_bg));
    frame.render_widget(block, area);
    frame.render_widget(
        Paragraph::new(text).style(Style::new().bg(theme.bar_bg)),
        area,
    );
}

fn render_main_content(frame: &mut Frame, area: Rect, app: &mut App) {
    match app.view {
        View::Packets => packets::render(frame, area, app),
        View::Dashboard => dashboard::render(frame, area, app),
        View::Connections => connections::render(frame, area, app),
        View::DnsLog => dns_log::render(frame, area, app),
        View::Insights => insights::render(frame, area, app),
        View::Learn => learn::render(frame, area, app),
    }
}

/// Follow TCP/UDP Stream overlay (ROADMAP §6.1).
fn render_stream_overlay(frame: &mut Frame, area: Rect, app: &App, theme: Theme) {
    // Resolve the filtered-list selection to its unfiltered position: the
    // stream reconstruction scans the full capture for the conversation.
    let stream = app
        .selected_unfiltered_index()
        .and_then(|idx| crate::stream::follow(&app.packets, idx));
    let area = centered_rect(80, 80, area);
    frame.render_widget(Clear, area);

    let (title, mut lines): (String, Vec<Line>) = match &stream {
        Some(s) => {
            let title = format!(" 💬 Follow Stream — {} ⇄ {} ", s.client, s.server);
            let mut lines = vec![Line::from(vec![
                Span::styled(
                    format!("{} sent {} B", s.client, s.client_bytes),
                    Style::new().fg(theme.accent),
                ),
                Span::raw("  ·  "),
                Span::styled(
                    format!("{} sent {} B", s.server, s.server_bytes),
                    Style::new().fg(ratatui::style::Color::Rgb(0x34, 0xD3, 0x99)),
                ),
            ])];
            lines.push(Line::from(""));
            if s.chunks.is_empty() {
                lines.push(Line::from(Span::styled(
                    "Nothing to show — this conversation has no plain-text payload",
                    Style::new().dim().italic(),
                )));
                lines.push(Line::from(Span::styled(
                    "(common for TLS/HTTPS, which is encrypted by design).",
                    Style::new().dim().italic(),
                )));
            }
            for c in &s.chunks {
                let (dir, color) = if c.from_client {
                    ("Client → Server", theme.accent)
                } else {
                    (
                        "Server → Client",
                        ratatui::style::Color::Rgb(0x34, 0xD3, 0x99),
                    )
                };
                lines.push(Line::from(Span::styled(dir, Style::new().fg(color).bold())));
                for raw_line in c.text.split('\n') {
                    lines.push(Line::from(format!("  {}", raw_line.trim_end_matches('\r'))));
                }
            }
            (title, lines)
        }
        None => (
            " 💬 Follow Stream ".into(),
            vec![Line::from(
                "This packet has no addressed conversation to follow.",
            )],
        ),
    };
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        " j/k scroll · Esc close ",
        Style::new().dim(),
    )));

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::new().fg(theme.border))
        .style(Style::new().bg(theme.bar_bg));
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((app.stream_scroll, 0)),
        area,
    );
}

/// Column-picker overlay (ROADMAP §6.1) — number keys toggle each column.
fn render_columns_overlay(frame: &mut Frame, area: Rect, app: &App, theme: Theme) {
    let mut lines = vec![
        Line::from(Span::styled(
            " Toggle packet-list columns ",
            Style::new().bold(),
        )),
        Line::from(""),
    ];
    for (i, col) in Column::ALL.iter().enumerate() {
        let on = app.columns.is_on(*col);
        let mark = if on { "[x]" } else { "[ ]" };
        let style = if on {
            Style::new().fg(theme.accent)
        } else {
            Style::new().dim()
        };
        lines.push(Line::from(vec![
            Span::styled(format!("  {}  {} ", i + 1, mark), style),
            Span::styled(col.label(), style),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        " 1–6 toggle · Info is always shown · C/Esc close ",
        Style::new().dim(),
    )));

    let area = centered_rect(40, 55, area);
    frame.render_widget(Clear, area);
    let block = Block::default()
        .title(" Columns ")
        .borders(Borders::ALL)
        .border_style(Style::new().fg(theme.border))
        .style(Style::new().bg(theme.bar_bg));
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_bookmarks_overlay(frame: &mut Frame, area: Rect, _app: &App, theme: Theme) {
    let mut lines = vec![
        Line::from(Span::styled(
            " Saved Filter Bookmarks ",
            Style::new().bold(),
        )),
        Line::from(""),
    ];
    let bookmarks = &[
        ("tcp.port == 443", "HTTPS (TCP Port 443)"),
        ("dns", "DNS Traffic"),
        ("http2", "HTTP/2 Cleartext"),
        ("grpc", "gRPC Messages"),
        ("rtp || rtcp", "RTP / VoIP Media"),
        ("ntlm", "NTLM Authentication"),
        ("tls.sni contains \"google\"", "Google TLS Connections"),
        ("frame.len > 1000", "Large Frames (> 1000B)"),
    ];
    for (i, (filter, label)) in bookmarks.iter().enumerate() {
        lines.push(Line::from(vec![
            Span::styled(format!("  {}  ", i + 1), Style::new().fg(theme.accent).bold()),
            Span::styled(format!("{:<30} ", filter), Style::new().white()),
            Span::styled(format!("({})", label), Style::new().dim()),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        " 1–8 select & apply · B/Esc close ",
        Style::new().dim(),
    )));

    let area = centered_rect(50, 60, area);
    frame.render_widget(Clear, area);
    let block = Block::default()
        .title(" Filter Library ")
        .borders(Borders::ALL)
        .border_style(Style::new().fg(theme.border))
        .style(Style::new().bg(theme.bar_bg));
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_expert_overlay(frame: &mut Frame, area: Rect, app: &App, theme: Theme) {
    use netscope_core::expert::{classify, ExpertSeverity};

    let mut chat_count = 0;
    let mut note_count = 0;
    let mut warn_count = 0;
    let mut err_count = 0;
    let mut anomalies = Vec::new();

    for (i, pkt) in app.packets.iter().enumerate() {
        let sev = classify(pkt);
        match sev {
            ExpertSeverity::Chat => chat_count += 1,
            ExpertSeverity::Note => note_count += 1,
            ExpertSeverity::Warning => {
                warn_count += 1;
                anomalies.push((i + 1, "Warning", &pkt.summary));
            }
            ExpertSeverity::Error => {
                err_count += 1;
                anomalies.push((i + 1, "Error", &pkt.summary));
            }
        }
    }

    let mut lines = vec![
        Line::from(Span::styled(" 🔬 Expert Info Diagnostics ", Style::new().bold())),
        Line::from(""),
        Line::from(vec![
            Span::styled(format!("  Errors: {}  ", err_count), Style::new().bg(ratatui::style::Color::Red).fg(ratatui::style::Color::White).bold()),
            Span::raw("  "),
            Span::styled(format!("  Warnings: {}  ", warn_count), Style::new().bg(ratatui::style::Color::Yellow).fg(ratatui::style::Color::Black).bold()),
            Span::raw("  "),
            Span::styled(format!("  Notes: {}  ", note_count), Style::new().bg(ratatui::style::Color::Cyan).fg(ratatui::style::Color::Black).bold()),
            Span::raw("  "),
            Span::styled(format!("  Chat: {}  ", chat_count), Style::new().bg(ratatui::style::Color::Green).fg(ratatui::style::Color::Black).bold()),
        ]),
        Line::from(""),
        Line::from(Span::styled(" Recent Warnings & Errors: ", Style::new().underlined().bold())),
        Line::from(""),
    ];

    if anomalies.is_empty() {
        lines.push(Line::from("  No anomalies detected. Network health is excellent!"));
    } else {
        for &(num, sev, summary) in anomalies.iter().rev().take(10) {
            let color = if sev == "Error" {
                ratatui::style::Color::Red
            } else {
                ratatui::style::Color::Yellow
            };
            lines.push(Line::from(vec![
                Span::styled(format!("  Pkt {:>4} ", num), Style::new().dim()),
                Span::styled(format!(" [{:<7}] ", sev), Style::new().fg(color).bold()),
                Span::styled(summary.to_string(), Style::new().white()),
            ]));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(" Esc / E close ", Style::new().dim())));

    let area = centered_rect(65, 70, area);
    frame.render_widget(Clear, area);
    let block = Block::default()
        .title(" Expert Info Analyzer ")
        .borders(Borders::ALL)
        .border_style(Style::new().fg(theme.border))
        .style(Style::new().bg(theme.bar_bg));
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_help_overlay(frame: &mut Frame, area: Rect, theme: Theme) {
    let lines = vec![
        Line::from(" Help ").bold().white(),
        Line::from(""),
        Line::from(" j/k  or  ↑/↓     Navigate packet list"),
        Line::from(" Enter              Focus the protocol detail tree"),
        Line::from("   ↑/↓ layer · ←/Enter collapse · → expand · Esc back"),
        Line::from(" Tab / Shift+Tab    Switch views (or click a tab)"),
        Line::from(" F                  Follow the selected conversation's stream"),
        Line::from(" C                  Choose packet-list columns"),
        Line::from(" B                  Saved filter bookmarks/macros library"),
        Line::from(" E                  Open Expert Info diagnostics"),
        Line::from(" R                  Toggle time reference on selected packet"),
        Line::from(" T                  Cycle colour theme"),
        Line::from(" h                  Toggle hex dump"),
        Line::from(" Space              Pause/resume capture"),
        Line::from(" Mouse              Click rows/tabs, wheel scrolls"),
        Line::from(" q                  Quit"),
        Line::from(" ? or Esc           Close this help"),
        Line::from(""),
        Line::from(" Filter (Wireshark-style, or plain text):"),
        Line::from("   ip.addr == 1.2.3.4   tcp.port == 443   frame.len > 1000"),
        Line::from("   dns   http   !udp   tcp && ip.dst == 8.8.8.8"),
        Line::from(""),
        Line::from(" Views:"),
        Line::from("   Packets      Live packet stream + detail tree"),
        Line::from("   Dashboard    Real-time stats & bandwidth"),
        Line::from("   Connections  Group packets by flow (block hosts here)"),
        Line::from("   DNS Log      All DNS queries"),
        Line::from("   Insights     Automatic security/privacy findings"),
        Line::from("   Learn        Plain-language protocol guide + glossary"),
    ];

    let block = Block::default()
        .title(" Help ")
        .borders(Borders::ALL)
        .border_style(Style::new().fg(theme.border))
        .style(Style::new().white().bg(theme.bar_bg));

    let area = centered_rect(60, 85, area);
    frame.render_widget(Clear, area);
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
