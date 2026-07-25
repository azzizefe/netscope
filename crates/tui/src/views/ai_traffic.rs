use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::App;

pub fn render(frame: &mut Frame, area: Rect, app: &mut App) {
    let border = app.theme().border;
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(6), Constraint::Min(6)])
        .split(area);

    render_summary(frame, layout[0], app, border);
    render_records_table(frame, layout[1], app, border);
}

fn render_summary(frame: &mut Frame, area: Rect, app: &App, border: Color) {
    let snap = app.stats.snapshot();
    let llm = &snap.llm;
    let streaming = llm.streaming_requests;
    let non_streaming = llm.non_streaming_requests;
    let errors = llm.total_errors;

    let lines = vec![
        Line::from(vec![
            Span::raw(format!(" Total LLM Requests: {}", llm.total_requests)),
            Span::raw("  |  "),
            Span::raw(format!("Active Sessions: {}", snap.ai_active_sessions)),
        ]),
        Line::from(vec![
            Span::raw(format!(" Prompt Tokens: {}", llm.total_prompt_tokens)),
            Span::raw("  |  "),
            Span::raw(format!("Completion Tokens: {}", llm.total_completion_tokens)),
            Span::raw("  |  "),
            Span::raw(format!("Total Tokens: {}", llm.total_tokens)),
        ]),
        Line::from(vec![
            Span::raw(format!(" Streaming: {}", streaming)),
            Span::raw("  |  "),
            Span::raw(format!("Non-Streaming: {}", non_streaming)),
            Span::raw("  |  "),
            Span::styled(
                if errors > 0 {
                    format!(" Errors: {} ", errors)
                } else {
                    " Errors: 0 ".into()
                },
                if errors > 0 {
                    Style::new().fg(Color::Red).bold()
                } else {
                    Style::new().fg(Color::Green)
                },
            ),
        ]),
        Line::from(vec![
            Span::raw(format!(" Total Cost: ${:.6}", llm.total_cost)),
            Span::raw("  |  "),
            Span::styled(
                format!("Completed Records: {}", snap.ai_records.len()),
                Style::new().fg(Color::Cyan).bold(),
            ),
        ]),
    ];

    let block = Block::default()
        .title(" AI Traffic Summary ")
        .borders(Borders::ALL)
        .border_style(Style::new().fg(border));

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_records_table(frame: &mut Frame, area: Rect, app: &mut App, border: Color) {
    let snap = app.stats.snapshot();
    let records = &snap.ai_records;
    let scroll = app.ai_scroll as usize;
    let max_visible = (area.height.saturating_sub(2)) as usize;

    let mut lines: Vec<Line> = Vec::new();

    if records.is_empty() {
        lines.push(Line::from(Span::styled(
            " No AI traffic records yet. Capture LLM API traffic to see records here.",
            Style::new().dim().italic(),
        )));
    } else {
        let header = format!(
            " {:<5} {:<12} {:<18} {:<8} {:<8} {:<6} {:<10} {:<8} {}",
            "Sess", "Provider", "Model", "Prompt", "Comp.", "TTFT", "Cost", "Stream", "Status"
        );
        lines.push(Line::from(Span::styled(
            header,
            Style::new().bold().white().underlined(),
        )));

        let visible: Vec<_> = records
            .iter()
            .skip(scroll)
            .take(max_visible)
            .collect();
        for rec in &visible {
            let provider_str = format!("{:?}", rec.provider);
            let model_short = if rec.model_name.len() > 17 {
                format!("{}…", &rec.model_name[..16])
            } else {
                rec.model_name.clone()
            };
            let stream_str = if rec.total_stream_duration_ms > 0 {
                "Y".to_string()
            } else {
                "N".to_string()
            };
            let status_color = if rec.finish_reason == "stop" {
                Color::Green
            } else if rec.finish_reason == "error"
                || rec.error_type.is_some()
            {
                Color::Red
            } else {
                Color::Yellow
            };
            let status_label = if rec.error_type.is_some() {
                "error"
            } else {
                &rec.finish_reason
            };

            lines.push(Line::from(vec![
                Span::raw(format!(" {:<5}", rec.session_id)),
                Span::raw(format!(" {:<12}", &provider_str[..provider_str.len().min(12)])),
                Span::raw(format!(" {:<18}", model_short)),
                Span::raw(format!(" {:<8}", rec.prompt_token_count)),
                Span::raw(format!(" {:<8}", rec.completion_tokens)),
                Span::raw(format!(" {:<6}", rec.first_token_latency_ms)),
                Span::raw(format!(" ${:<8.6}", rec.total_cost_usd)),
                Span::raw(format!(" {:<10}", stream_str)),
                Span::styled(status_label, Style::new().fg(status_color).bold()),
            ]));
        }
    }

    let block = Block::default()
        .title(format!(
            " Completed AI Sessions {}",
            if records.len() > max_visible {
                format!("(scroll: {}/{})", scroll + 1, records.len())
            } else {
                String::new()
            }
        ))
        .borders(Borders::ALL)
        .border_style(Style::new().fg(border));

    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}
