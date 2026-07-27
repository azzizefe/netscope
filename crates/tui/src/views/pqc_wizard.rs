use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::App;
use netscope_core::pqc_wizard::{Priority, RiskScore, Severity, Tls13PqcWizard};
use netscope_core::stats::StatsSnapshot;

pub fn render(frame: &mut Frame, area: Rect, app: &mut App) {
    let border = app.theme().border;
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Length(7),
            Constraint::Min(6),
        ])
        .split(area);

    let snap = app.stats.snapshot();
    let report = Tls13PqcWizard::analyze(&snap.pqc_store);

    render_header(frame, layout[0], &report, border);
    render_algos(frame, layout[1], &report, border);
    render_body(frame, layout[2], &report, app.pqc_wizard_scroll, border);
}

fn render_header(
    frame: &mut Frame,
    area: Rect,
    report: &netscope_core::pqc_wizard::TlsPqcWizardReport,
    border: Color,
) {
    let o = &report.overview;
    let risk_color = risk_color(o.risk_score);
    let lines = vec![
        Line::from(vec![
            Span::styled(" TLS 1.3 PQC Smart Wizard ", Style::new().bold().underlined()),
            Span::raw("  │  "),
            Span::styled(format!("Risk: {}", o.risk_score.label()), Style::new().fg(risk_color).bold()),
            Span::raw("  │  "),
            Span::styled(format!("Adoption: {:.1}%", o.adoption_rate), Style::new().fg(Color::Cyan)),
            Span::raw("  │  "),
            Span::styled(format!("Hybrid: {:.1}%", o.hybrid_ratio), Style::new().fg(Color::Yellow)),
        ]),
        Line::from(vec![
            Span::raw(format!(" PQC handshakes: {}/{}", o.pqc_handshakes, o.total_handshakes)),
            Span::raw("  │  "),
            Span::raw(format!("Failed: {}  ", o.failed_handshakes)),
            Span::raw("  │  "),
            Span::raw(format!("Avg KEM: {:.1}µs  ", o.avg_latency_us)),
            Span::raw("  │  "),
            Span::raw(format!("BW extra: {:.0}B", o.avg_bandwidth_extra_bytes)),
        ]),
        Line::from(vec![
            Span::styled(" PQC sigs: ", Style::new().fg(Color::Green)),
            Span::raw(format!("{:.1}%  ", o.pqc_signature_ratio)),
            Span::styled("Composite certs: ", Style::new().fg(Color::Green)),
            Span::raw(format!("{:.1}%", o.composite_cert_ratio)),
        ]),
    ];
    let block = Block::default().borders(Borders::ALL).border_style(Style::new().fg(border));
    frame.render_widget(Paragraph::new(lines).block(block).wrap(Wrap { trim: false }), area);
}

fn render_algos(
    frame: &mut Frame,
    area: Rect,
    report: &netscope_core::pqc_wizard::TlsPqcWizardReport,
    border: Color,
) {
    let mut lines: Vec<Line> = Vec::new();
    if report.algorithms.is_empty() {
        lines.push(Line::from(Span::raw(" No KEM algorithms detected.")));
    } else {
        lines.push(Line::from(Span::styled(" KEM Distribution", Style::new().bold())));
        for kem in &report.algorithms {
            let hybrid_tag = if kem.is_hybrid_used { " [hybrid]" } else { "" };
            lines.push(Line::from(vec![
                Span::raw(format!("  {:25}", format!("{:?}", kem.algorithm))),
                Span::styled(format!("{}x", kem.count), Style::new().fg(Color::Yellow)),
                Span::raw(format!("  {:>6}µs  {:>4}B extra{}", kem.avg_latency_us as u64, kem.avg_bandwidth_extra, hybrid_tag)),
            ]));
        }
    }
    let block = Block::default().borders(Borders::ALL).border_style(Style::new().fg(border));
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_body(
    frame: &mut Frame,
    area: Rect,
    report: &netscope_core::pqc_wizard::TlsPqcWizardReport,
    scroll: u16,
    border: Color,
) {
    let mut lines: Vec<Line> = Vec::new();

    if report.vulnerabilities.is_empty() {
        lines.push(Line::from(Span::styled(" No vulnerabilities detected.", Style::new().fg(Color::Green))));
    } else {
        lines.push(Line::from(Span::styled(" Vulnerabilities", Style::new().bold().underlined())));
        for v in &report.vulnerabilities {
            let sev_color = severity_color(v.severity);
            lines.push(Line::from(vec![
                Span::styled(format!(" [{}] ", v.severity.label()), Style::new().fg(sev_color).bold()),
                Span::styled(&v.title, Style::new().bold()),
            ]));
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::raw(&v.description),
            ]));
        }
    }

    lines.push(Line::from(""));
    if report.recommendations.is_empty() {
        lines.push(Line::from(Span::raw(" No recommendations.")));
    } else {
        lines.push(Line::from(Span::styled(" Recommendations", Style::new().bold().underlined())));
        for r in &report.recommendations {
            let pri_color = priority_color(r.priority);
            lines.push(Line::from(vec![
                Span::styled(format!(" [{:9}] ", r.priority.label()), Style::new().fg(pri_color).bold()),
                Span::styled(&r.action, Style::new().bold()),
            ]));
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::raw(&r.rationale),
            ]));
        }
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(border))
        .title(format!(" Report (scroll: {})", scroll));

    let paragraph = Paragraph::new(lines).block(block).scroll((scroll, 0));
    frame.render_widget(paragraph, area);
}

fn risk_color(risk: RiskScore) -> Color {
    match risk {
        RiskScore::Safe => Color::Green,
        RiskScore::Low => Color::Cyan,
        RiskScore::Medium => Color::Yellow,
        RiskScore::High => Color::Red,
        RiskScore::Critical => Color::LightRed,
    }
}

fn severity_color(sev: Severity) -> Color {
    match sev {
        Severity::Low => Color::Cyan,
        Severity::Medium => Color::Yellow,
        Severity::High => Color::Red,
        Severity::Critical => Color::LightRed,
    }
}

fn priority_color(p: Priority) -> Color {
    match p {
        Priority::Immediate => Color::LightRed,
        Priority::High => Color::Red,
        Priority::Medium => Color::Yellow,
        Priority::Low => Color::Cyan,
    }
}
