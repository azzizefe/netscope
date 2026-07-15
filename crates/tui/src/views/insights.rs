// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! The Insights view (ROADMAP §6.1) — a scrollable list of the automatic
//! security/privacy findings produced by [`crate::insights::analyze`], the
//! TUI counterpart of the desktop's Insights tab.

use ratatui::layout::Rect;
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::App;
use crate::insights::{analyze, Severity};

fn severity_color(sev: Severity) -> Color {
    match sev {
        Severity::High => Color::Rgb(0xF8, 0x71, 0x71),
        Severity::Warn => Color::Rgb(0xFB, 0xBF, 0x24),
        Severity::Info => Color::Rgb(0x60, 0xA5, 0xFA),
        Severity::Ok => Color::Rgb(0x34, 0xD3, 0x99),
    }
}

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let theme = app.theme();
    let findings = analyze(&app.packets, &app.flows);

    let mut lines: Vec<Line> = vec![
        Line::from(Span::styled(
            "Automatic security & privacy analysis",
            Style::new().bold(),
        )),
        Line::from(Span::styled(
            "Findings below come only from what's actually in this capture — nothing is invented.",
            Style::new().dim(),
        )),
        Line::from(""),
    ];

    if findings.is_empty() {
        lines.push(Line::from(Span::styled(
            "No findings yet — capture some traffic and they'll appear here.",
            Style::new().dim().italic(),
        )));
    }

    for f in &findings {
        let color = severity_color(f.severity);
        lines.push(Line::from(vec![
            Span::styled(
                format!(" {} ", f.severity.label()),
                Style::new().fg(Color::Black).bg(color).bold(),
            ),
            Span::raw("  "),
            Span::styled(f.title.clone(), Style::new().fg(color).bold()),
        ]));
        for chunk in wrap_words(&f.detail, 96) {
            lines.push(Line::from(Span::styled(
                format!("    {chunk}"),
                Style::new().dim(),
            )));
        }
        for ev in &f.evidence {
            lines.push(Line::from(vec![
                Span::styled("    • ", Style::new().fg(color)),
                Span::raw(ev.clone()),
            ]));
        }
        lines.push(Line::from(""));
    }

    let total = lines.len() as u16;
    let visible = area.height.saturating_sub(2);
    let max_scroll = total.saturating_sub(visible);
    let scroll = app.insights_scroll.min(max_scroll);

    let title = if max_scroll > 0 {
        format!(
            " Insights ({} finding{})  ·  j/k scroll ",
            findings.len(),
            if findings.len() == 1 { "" } else { "s" }
        )
    } else {
        format!(" Insights ({} findings) ", findings.len())
    };

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::new().fg(theme.border));

    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0)),
        area,
    );
}

/// Greedy word-wrap to a rough column width (shared shape with the Learn view).
fn wrap_words(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if !current.is_empty() && current.len() + 1 + word.len() > width {
            lines.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}
