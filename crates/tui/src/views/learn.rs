// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! The Learn view — a scrollable, beginner-friendly primer on the protocols
//! netscope shows, plus a glossary. For people who've never opened Wireshark.

use ratatui::layout::Rect;
use ratatui::style::{Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::App;
use crate::colors::protocol_color;
use netscope_core::education::{all_lessons, glossary};

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let mut lines: Vec<Line> = vec![
        Line::from("Welcome — this is what netscope is showing you.".bold()),
        Line::from(Span::styled(
            "Every line in the Packets view is one 'packet' — a small chunk of data your",
            Style::new().dim(),
        )),
        Line::from(Span::styled(
            "computer sent or received. Below is what each protocol means, in plain words.",
            Style::new().dim(),
        )),
        Line::from(""),
    ];

    for (proto, lesson) in &all_lessons() {
        let color = protocol_color(proto);
        lines.push(Line::from(Span::styled(
            format!("▍ {}", lesson.title),
            Style::new().fg(color).bold(),
        )));
        lines.push(Line::from(format!("  {}", lesson.summary)).italic());
        for chunk in wrap_words(lesson.body, 92) {
            lines.push(Line::from(format!("  {chunk}")));
        }
        lines.push(Line::from(vec![
            Span::styled("  In netscope: ", Style::new().dim()),
            Span::styled(lesson.look_for, Style::new().fg(color)),
        ]));
        lines.push(Line::from(""));
    }

    lines.push(Line::from("Glossary".bold().underlined()));
    lines.push(Line::from(""));
    for term in glossary() {
        lines.push(Line::from(vec![
            Span::styled(format!("  {}", term.term), Style::new().cyan().bold()),
            Span::raw("  —  "),
            Span::raw(term.meaning),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Tip: in the Packets view, select a row to see a one-line explanation of it.",
        Style::new().dim(),
    )));

    let total = lines.len() as u16;
    // How many lines fit inside the bordered box.
    let visible = area.height.saturating_sub(2);
    let max_scroll = total.saturating_sub(visible);
    let scroll = app.learn_scroll.min(max_scroll);

    let hint = if max_scroll > 0 {
        format!(
            " Learn  ·  j/k or ↑/↓ to scroll  ({}/{}) ",
            scroll + 1,
            max_scroll + 1
        )
    } else {
        " Learn ".to_string()
    };

    let block = Block::default()
        .title(hint)
        .borders(Borders::ALL)
        .border_style(Style::new().fg(app.theme().border));

    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0));

    frame.render_widget(paragraph, area);
}

/// Greedy word-wrap to a rough column width.
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
