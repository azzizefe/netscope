use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::App;

pub fn render(frame: &mut Frame, area: Rect, app: &mut App) {
    let border = app.theme().border;

    if app.show_ai_detail {
        render_detail_view(frame, area, app, border);
        return;
    }

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6),
            Constraint::Length(8),
            Constraint::Min(6),
            Constraint::Length(6),
        ])
        .split(area);

    render_summary(frame, layout[0], app, border);
    render_per_model_metrics(frame, layout[1], app, border);
    render_records_table(frame, layout[2], app, border);
    render_heatmap(frame, layout[3], app, border);
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
            Span::raw("  |  "),
            Span::styled(" H", Style::new().fg(Color::Yellow).bold()),
            Span::raw(":Heatmap"),
        ]),
    ];

    let block = Block::default()
        .title(" AI Traffic Summary ")
        .borders(Borders::ALL)
        .border_style(Style::new().fg(border));

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_per_model_metrics(frame: &mut Frame, area: Rect, app: &App, border: Color) {
    let snap = app.stats.snapshot();
    let llm = &snap.llm;

    let mut lines: Vec<Line> = Vec::new();

    if llm.per_model.is_empty() {
        lines.push(Line::from(Span::styled(
            " No completed AI sessions yet.",
            Style::new().dim().italic(),
        )));
    } else {
        let header = format!(
            " {:<14} {:>6} {:>8} {:>6} {:>6} {:>6} {:>8} {:>6} {:>6} {:>7}",
            "Model", "Req", "TTFTms", "TPOTms", "Tok/s", "Hata%", "RLimit%", "Kesinti%", "TopTok", "Maliyet"
        );
        lines.push(Line::from(Span::styled(
            header,
            Style::new().bold().white().underlined(),
        )));

        let mut models: Vec<_> = llm.per_model.iter().collect();
        models.sort_by_key(|(_, ms)| std::cmp::Reverse(ms.requests));

        for (model, ms) in models.iter().take(10) {
            let avg_ttft = if ms.ttft_count > 0 { ms.ttft_sum_ms as f64 / ms.ttft_count as f64 } else { 0.0 };
            let avg_tpot = if ms.tpot_count > 0 { ms.tpot_sum_us as f64 / ms.tpot_count as f64 / 1000.0 } else { 0.0 };
            let avg_tps = if ms.tokens_per_second_count > 0 { ms.tokens_per_second_sum / ms.tokens_per_second_count as f64 } else { 0.0 };
            let error_rate = if ms.requests > 0 { (ms.error_4xx + ms.error_5xx) as f64 / ms.requests as f64 * 100.0 } else { 0.0 };
            let rl_rate = if ms.requests > 0 { ms.rate_limited as f64 / ms.requests as f64 * 100.0 } else { 0.0 };
            let kesinti_rate = if ms.total_streams > 0 { ms.incomplete_streams as f64 / ms.total_streams as f64 * 100.0 } else { 0.0 };

            let model_short = if model.len() > 13 { format!("{}…", &model[..12]) } else { model.to_string() };

            let warn_ttft = avg_ttft > 500.0;
            let warn_tpot = avg_tpot > 80.0;
            let warn_tps = avg_tps > 0.0 && avg_tps < 20.0;
            let warn_hata = error_rate > 5.0;
            let warn_rl = rl_rate > 2.0;
            let warn_kesinti = kesinti_rate > 1.0;

            lines.push(Line::from(vec![
                Span::raw(format!(" {:<14}", model_short)),
                Span::raw(format!(" {:>6}", ms.requests)),
                Span::styled(
                    format!(" {:>5}ms", if avg_ttft > 0.0 { format!("{:.0}", avg_ttft) } else { "-".into() }),
                    if warn_ttft { Style::new().fg(Color::Red).bold() } else { Style::new().fg(Color::Green) },
                ),
                Span::styled(
                    format!(" {:>5}ms", if avg_tpot > 0.0 { format!("{:.0}", avg_tpot) } else { "-".into() }),
                    if warn_tpot { Style::new().fg(Color::Red).bold() } else { Style::new().fg(Color::Green) },
                ),
                Span::styled(
                    format!(" {:>5.0}", avg_tps),
                    if warn_tps { Style::new().fg(Color::Red).bold() } else { Style::new().fg(Color::Green) },
                ),
                Span::styled(
                    format!(" {:>5.1}%", error_rate),
                    if warn_hata { Style::new().fg(Color::Red).bold() } else { Style::new().fg(Color::Green) },
                ),
                Span::styled(
                    format!(" {:>5.1}%", rl_rate),
                    if warn_rl { Style::new().fg(Color::Red).bold() } else { Style::new().fg(Color::Green) },
                ),
                Span::styled(
                    format!(" {:>5.1}%", kesinti_rate),
                    if warn_kesinti { Style::new().fg(Color::Red).bold() } else { Style::new().fg(Color::Green) },
                ),
                Span::raw(format!(" {:>6}", ms.total_tokens)),
                Span::raw(format!(" ${:.4}", ms.cost)),
            ]));
        }
    }

    let block = Block::default()
        .title(" Per-Model Metrics ")
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
            " Completed AI Sessions (Enter: detail) {}",
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

fn render_heatmap(frame: &mut Frame, area: Rect, app: &App, border: Color) {
    if !app.show_ai_heatmap {
        let lines = vec![Line::from(Span::styled(
            " Press H to show Gecikme Heatmap (TTFT zaman × model matrisi)",
            Style::new().dim().italic(),
        ))];
        let block = Block::default()
            .title(" Gecikme Heatmap ")
            .borders(Borders::ALL)
            .border_style(Style::new().fg(border));
        frame.render_widget(Paragraph::new(lines).block(block), area);
        return;
    }

    let snap = app.stats.snapshot();
    let heatmap = &snap.llm.latency_heatmap;
    let mut lines: Vec<Line> = Vec::new();

    if heatmap.is_empty() {
        lines.push(Line::from(Span::styled(
            " No latency data yet.",
            Style::new().dim().italic(),
        )));
    } else {
        let mut models: Vec<(String, Vec<u64>)> = Vec::new();
        let mut model_map: std::collections::HashMap<String, Vec<u64>> =
            std::collections::HashMap::new();

        for (_, model, ttft) in heatmap.iter().rev().take(50) {
            model_map
                .entry(model.clone())
                .or_default()
                .push(*ttft);
        }

        for (model, vals) in &model_map {
            let avg = vals.iter().sum::<u64>() as f64 / vals.len() as f64;
            models.push((model.clone(), vals.clone()));
            let bar_len = ((avg / 500.0).min(1.0) * 20.0) as usize;
            let bar = "█".repeat(bar_len);
            let color = if avg > 500.0 {
                Color::Red
            } else if avg > 200.0 {
                Color::Yellow
            } else {
                Color::Green
            };
            let model_short = if model.len() > 12 {
                format!("{}…", &model[..11])
            } else {
                model.clone()
            };
            lines.push(Line::from(vec![
                Span::raw(format!(" {:<12} ", model_short)),
                Span::styled(
                    format!(" {:>5.0}ms ", avg),
                    Style::new().fg(color).bold(),
                ),
                Span::styled(bar, Style::new().fg(color)),
            ]));
        }
    }

    let block = Block::default()
        .title(" Gecikme Heatmap (TTFT) ")
        .borders(Borders::ALL)
        .border_style(Style::new().fg(border));
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_detail_view(frame: &mut Frame, area: Rect, app: &mut App, border: Color) {
    let snap = app.stats.snapshot();
    let records = &snap.ai_records;
    let idx = app.ai_selected.unwrap_or(0);
    let Some(rec) = records.get(idx) else {
        app.show_ai_detail = false;
        return;
    };

    let scroll = app.ai_detail_scroll as usize;

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7),
            Constraint::Min(4),
            Constraint::Length(3),
        ])
        .split(area);

    render_detail_info(frame, layout[0], rec, border);

    if app.show_ai_prompt_response {
        render_prompt_response(frame, layout[1], rec, scroll, border);
    } else {
        render_token_stream(frame, layout[1], rec, scroll, border);
    }

    let help = vec![Line::from(vec![
        Span::styled(" p ", Style::new().fg(Color::Yellow).bold()),
        Span::raw(":Prompt/Response  "),
        Span::styled(" d ", Style::new().fg(Color::Yellow).bold()),
        Span::raw(":Close  "),
        Span::styled(" ↑/↓ ", Style::new().fg(Color::Yellow).bold()),
        Span::raw(":Scroll"),
    ])];
    let block = Block::default()
        .title(" Controls ")
        .borders(Borders::ALL)
        .border_style(Style::new().fg(border));
    frame.render_widget(Paragraph::new(help).block(block), layout[2]);
}

fn render_detail_info(frame: &mut Frame, area: Rect, rec: &netscope_core::ai_traffic::AiTrafficRecord, border: Color) {
    let lines = vec![
        Line::from(vec![
            Span::raw(format!(" Session: {}  |  ", rec.session_id)),
            Span::raw(format!("Provider: {:?}  |  ", rec.provider)),
            Span::raw(format!("Model: {}", rec.model_name)),
        ]),
        Line::from(vec![
            Span::raw(format!(" TTFT: {}ms  |  ", rec.first_token_latency_ms)),
            Span::raw(format!("TPOT: {:.1}ms  |  ", rec.tpot_ms())),
            Span::raw(format!("Tok/s: {:.1}", rec.tokens_per_second)),
        ]),
        Line::from(vec![
            Span::raw(format!(" Prompt Tokens: {}  |  ", rec.prompt_token_count)),
            Span::raw(format!("Completion Tokens: {}  |  ", rec.completion_tokens)),
            Span::raw(format!("Total Tokens: {}", rec.response_total_tokens)),
        ]),
        Line::from(vec![
            Span::raw(format!(" Cost: ${:.6}  |  ", rec.total_cost_usd)),
            Span::raw(format!("Status: {}  |  ", rec.finish_reason)),
            Span::styled(
                if rec.error_type.is_some() {
                    format!("Error: {}", rec.error_type.as_ref().unwrap())
                } else {
                    "No Error".into()
                },
                if rec.error_type.is_some() {
                    Style::new().fg(Color::Red).bold()
                } else {
                    Style::new().fg(Color::Green)
                },
            ),
        ]),
        Line::from(vec![
            Span::raw(format!(" HTTP Status: {}  |  ", rec.http_status)),
            Span::raw(format!("Streaming: {}  |  ", if rec.total_stream_duration_ms > 0 { "Yes" } else { "No" })),
            Span::raw(format!("Duration: {}ms", rec.total_stream_duration_ms)),
        ]),
    ];

    let block = Block::default()
        .title(" Token Akis Canli ")
        .borders(Borders::ALL)
        .border_style(Style::new().fg(border));
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_token_stream(frame: &mut Frame, area: Rect, rec: &netscope_core::ai_traffic::AiTrafficRecord, scroll: usize, border: Color) {
    let text = if rec.response_text_snippet.is_empty() {
        " (No response text captured)".to_string()
    } else {
        rec.response_text_snippet.clone()
    };

    let lines: Vec<Line> = text
        .lines()
        .skip(scroll)
        .take(area.height.saturating_sub(2) as usize)
        .map(|l| {
            Line::from(Span::styled(l.to_string(), Style::new().fg(Color::Cyan)))
        })
        .collect();

    let lines = if lines.is_empty() {
        vec![Line::from(Span::styled(
            " (empty response)",
            Style::new().dim().italic(),
        ))]
    } else {
        lines
    };

    let block = Block::default()
        .title(format!(
            " Token Akisi (gercek zamanli) {}",
            if text.len() > area.height.saturating_sub(2) as usize {
                format!("(scroll: {}/{})", scroll + 1, text.lines().count())
            } else {
                String::new()
            }
        ))
        .borders(Borders::ALL)
        .border_style(Style::new().fg(border));
    frame.render_widget(
        Paragraph::new(lines).block(block).wrap(Wrap { trim: false }),
        area,
    );
}

fn render_prompt_response(frame: &mut Frame, area: Rect, rec: &netscope_core::ai_traffic::AiTrafficRecord, scroll: usize, border: Color) {
    let layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let prompt_text = if rec.prompt_text_snippet.is_empty() {
        " (No prompt text)".to_string()
    } else {
        rec.prompt_text_snippet.clone()
    };
    let response_text = if rec.response_text_snippet.is_empty() {
        " (No response text)".to_string()
    } else {
        rec.response_text_snippet.clone()
    };

    let prompt_lines: Vec<Line> = prompt_text
        .lines()
        .skip(scroll / 2)
        .take(layout[0].height.saturating_sub(2) as usize)
        .map(|l| Line::from(Span::styled(l.to_string(), Style::new().fg(Color::Yellow))))
        .collect();
    let prompt_lines = if prompt_lines.is_empty() {
        vec![Line::from(Span::styled(" (empty)", Style::new().dim().italic()))]
    } else {
        prompt_lines
    };

    let response_lines: Vec<Line> = response_text
        .lines()
        .skip(scroll / 2)
        .take(layout[1].height.saturating_sub(2) as usize)
        .map(|l| Line::from(Span::styled(l.to_string(), Style::new().fg(Color::Cyan))))
        .collect();
    let response_lines = if response_lines.is_empty() {
        vec![Line::from(Span::styled(" (empty)", Style::new().dim().italic()))]
    } else {
        response_lines
    };

    let prompt_block = Block::default()
        .title(" Prompt ")
        .borders(Borders::ALL)
        .border_style(Style::new().fg(border));
    frame.render_widget(Paragraph::new(prompt_lines).block(prompt_block).wrap(Wrap { trim: false }), layout[0]);

    let response_block = Block::default()
        .title(" Response ")
        .borders(Borders::ALL)
        .border_style(Style::new().fg(border));
    frame.render_widget(Paragraph::new(response_lines).block(response_block).wrap(Wrap { trim: false }), layout[1]);
}
