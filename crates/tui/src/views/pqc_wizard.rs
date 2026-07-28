use ratatui::layout::Rect;
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::App;
use netscope_core::pqc_handshake::{KemId, NamedGroup};
use netscope_core::pqc_wizard::{
    ComplianceFramework, Priority, RiskScore, Severity, Tls13PqcWizard, TlsPqcWizardReport,
};

pub fn render(frame: &mut Frame, area: Rect, app: &mut App) {
    let theme = app.theme();
    let report = Tls13PqcWizard::analyze(&app.pqc_store);

    let mut lines: Vec<Line> = Vec::new();

    render_header(&mut lines, &report);
    lines.push(Line::from(""));
    render_security_score(&mut lines, &report);
    lines.push(Line::from(""));
    render_kem_panel(&mut lines, &report);
    lines.push(Line::from(""));
    render_cert_chain(&mut lines, &report);
    lines.push(Line::from(""));
    render_vuln_scan(&mut lines, &report);
    lines.push(Line::from(""));
    render_key_share_prediction(&mut lines, &report);
    lines.push(Line::from(""));
    render_downgrade_detector(&mut lines, &report);
    lines.push(Line::from(""));
    render_cve_feed(&mut lines, &report);
    lines.push(Line::from(""));
    render_middlebox_detector(&mut lines, &report);
    lines.push(Line::from(""));
    render_performance(&mut lines, &report);
    lines.push(Line::from(""));
    render_recommendations(&mut lines, &report);
    lines.push(Line::from(""));
    render_compliance(&mut lines, &report);
    lines.push(Line::from(""));
    render_session_resumption(&mut lines, &report);
    lines.push(Line::from(""));
    render_buttons(&mut lines);

    let total = lines.len() as u16;
    let visible = area.height.saturating_sub(2);
    let max_scroll = total.saturating_sub(visible);
    let scroll = app.pqc_wizard_scroll.min(max_scroll);

    let hint = if max_scroll > 0 {
        format!(
            " PQC Wizard Report  ·  j/k scroll  ({}/{}) ",
            scroll + 1,
            max_scroll + 1
        )
    } else {
        " PQC Wizard Report ".to_string()
    };

    let block = Block::default()
        .title(hint)
        .borders(Borders::ALL)
        .border_style(Style::new().fg(theme.border));

    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0));
    frame.render_widget(paragraph, area);
}

fn render_header(lines: &mut Vec<Line>, report: &netscope_core::pqc_wizard::TlsPqcWizardReport) {
    let target = report
        .session_reports
        .first()
        .map(|s| format!("{} ({})", s.server_name, s.server_ip))
        .unwrap_or_else(|| "N/A".into());

    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC");

    lines.push(Line::from(vec![Span::styled(
        " TLS 1.3 PQC Smart Wizard — Report ",
        Style::new().bold().underlined(),
    )]));
    lines.push(Line::from(vec![Span::raw(format!(
        " Target: {}    Date: {}",
        target, now
    ))]));
}

fn render_security_score(
    lines: &mut Vec<Line>,
    report: &netscope_core::pqc_wizard::TlsPqcWizardReport,
) {
    lines.push(Line::from(Span::styled(
        " Security Score",
        Style::new().bold(),
    )));

    let score = compute_score(report);
    let risk = report.overview.risk_score;
    let risk_color = risk_color(risk);
    let score_color = if score >= 70 {
        Color::Green
    } else if score >= 50 {
        Color::Yellow
    } else {
        Color::Red
    };
    let label = risk.label();

    let bar_len = 40usize;
    let filled = (score as usize * bar_len / 100).min(bar_len);
    let empty = bar_len.saturating_sub(filled);
    let bar = format!("{}{}", "█".repeat(filled), "░".repeat(empty));

    lines.push(Line::from(vec![
        Span::raw("  "),
        Span::styled(
            format!("{} / 100", score),
            Style::new().fg(score_color).bold(),
        ),
        Span::raw(format!("  —  {} ", label)),
        Span::styled(
            format!("({} uyarı)", report.vulnerabilities.len()),
            Style::new().fg(risk_color),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::raw("  "),
        Span::styled(bar, Style::new().fg(score_color)),
    ]));
}

fn render_kem_panel(lines: &mut Vec<Line>, report: &netscope_core::pqc_wizard::TlsPqcWizardReport) {
    lines.push(Line::from(Span::styled(
        " KEM / Key Exchange",
        Style::new().bold(),
    )));

    if let Some(session) = report.session_reports.first() {
        let offered: Vec<String> = session.kem_offered.iter().map(kem_label).collect();
        let offered_str = if offered.is_empty() {
            "ECDH only".into()
        } else {
            offered.join(", ")
        };

        let selected = session
            .kem_selected
            .as_ref()
            .map(kem_label)
            .unwrap_or_else(|| "None".into());
        let hybrid_tag = if session.is_hybrid {
            let classic = session
                .classical_group
                .as_ref()
                .map(named_group_label)
                .unwrap_or("ECDH");
            format!("{} + {} (Hybrid)", selected, classic)
        } else {
            selected
        };
        let success_icon = if session.success { "✅" } else { "❌" };

        lines.push(Line::from(vec![
            Span::raw("  Client Offered:  "),
            Span::styled(offered_str, Style::new().fg(Color::Cyan)),
        ]));
        lines.push(Line::from(vec![
            Span::raw("  Server Selected: "),
            Span::styled(hybrid_tag, Style::new().fg(Color::Green).bold()),
            Span::raw(format!(" {} ", success_icon)),
        ]));
        lines.push(Line::from(vec![Span::raw(format!(
            "  Shared Secret:   {:.0}-bit entropy",
            session.shared_secret_entropy_bits
        ))]));
        lines.push(Line::from(vec![Span::raw(format!(
            "  Est. KEM Time:   ~{:.1}ms",
            session.pqc_kem_time_us as f64 / 1000.0
        ))]));

        let ech_compatible = session.client_hello_size > 0
            && session.server_hello_size > 0
            && session.kem_selected.is_some();
        lines.push(Line::from(vec![
            Span::raw("  ECH+PQC Interop:  "),
            Span::styled(
                if ech_compatible {
                    "compatible ✅"
                } else {
                    "not detected"
                },
                Style::new().fg(if ech_compatible {
                    Color::Green
                } else {
                    Color::DarkGray
                }),
            ),
        ]));
    } else if report.raw_records > 0 {
        lines.push(Line::from(Span::raw("  No PQC session data available.")));
    } else {
        lines.push(Line::from(Span::raw("  No handshake data captured.")));
    }
}

fn render_cert_chain(
    lines: &mut Vec<Line>,
    report: &netscope_core::pqc_wizard::TlsPqcWizardReport,
) {
    lines.push(Line::from(Span::styled(
        " Certificate Chain",
        Style::new().bold(),
    )));

    if let Some(session) = report.session_reports.first() {
        let sig_type = if session.is_pqc_signature {
            "PQC"
        } else {
            "Classic"
        };
        lines.push(Line::from(vec![Span::raw(format!(
            "  Leaf:   CN={}  — {} signature",
            session.server_name, sig_type
        ))]));
        lines.push(Line::from(vec![Span::raw(format!(
            "  Chain depth: {}",
            session.cert_chain_length
        ))]));
        lines.push(Line::from(vec![
            Span::raw(format!(
                "  Root is PQC: {}  ",
                if session.root_is_pqc { "Yes" } else { "No" }
            )),
            Span::styled(
                if session.root_is_pqc { "✅" } else { "⚠️" },
                Style::new().fg(if session.root_is_pqc {
                    Color::Green
                } else {
                    Color::Yellow
                }),
            ),
        ]));
        if session.cert_valid_days_left > 0 {
            lines.push(Line::from(vec![
                Span::raw(format!(
                    "  Cert valid: {} days remaining  ",
                    session.cert_valid_days_left
                )),
                Span::styled("✅", Style::new().fg(Color::Green)),
            ]));
        } else {
            lines.push(Line::from(vec![
                Span::raw("  Cert valid: EXPIRED  "),
                Span::styled("❌", Style::new().fg(Color::Red)),
            ]));
        }
        if session.rsa_key_size > 0 {
            lines.push(Line::from(vec![Span::raw(format!(
                "  RSA key size: {} bits",
                session.rsa_key_size
            ))]));
        }
        if !session.root_is_pqc {
            lines.push(Line::from(vec![Span::styled(
                "  ⚠️  Root certificate not PQC-signed",
                Style::new().fg(Color::Yellow),
            )]));
            lines.push(Line::from(Span::raw(
                "     Risk: Low (trust anchor, replace edilmesi zor)",
            )));
        }
        let ct_status = if session.cert_chain_length > 0 {
            "SCT present"
        } else {
            "no SCT data"
        };
        lines.push(Line::from(vec![
            Span::raw("  CT v3 Status:     "),
            Span::styled(
                ct_status,
                Style::new().fg(if session.cert_chain_length > 0 {
                    Color::Green
                } else {
                    Color::DarkGray
                }),
            ),
        ]));
    } else {
        lines.push(Line::from(Span::raw("  No certificate data.")));
    }
}

fn render_vuln_scan(lines: &mut Vec<Line>, report: &netscope_core::pqc_wizard::TlsPqcWizardReport) {
    lines.push(Line::from(Span::styled(
        " Vulnerability Scan",
        Style::new().bold(),
    )));

    if report.vulnerabilities.is_empty() {
        lines.push(Line::from(vec![Span::styled(
            "  ✅ All checks passed — no vulnerabilities detected",
            Style::new().fg(Color::Green),
        )]));
    } else {
        for v in &report.vulnerabilities {
            let sev_color = severity_color(v.severity);
            let pass_fail = if matches!(v.severity, Severity::Low) {
                "ℹ️"
            } else {
                "⚠️"
            };
            lines.push(Line::from(vec![
                Span::raw(format!("  {} ", pass_fail)),
                Span::styled(
                    format!("{:8}", v.severity.label()),
                    Style::new().fg(sev_color).bold(),
                ),
                Span::raw("  "),
                Span::styled(v.title.clone(), Style::new().bold()),
            ]));
            if !v.description.is_empty() {
                lines.push(Line::from(vec![
                    Span::raw("           "),
                    Span::raw(v.description.clone()),
                ]));
            }
            if let Some(ref cvss) = v.cvss_vector {
                lines.push(Line::from(vec![
                    Span::raw("           CVSS: "),
                    Span::styled(cvss.clone(), Style::new().fg(Color::Cyan)),
                ]));
            }
            if !v.fix.is_empty() {
                lines.push(Line::from(vec![
                    Span::raw("           Fix: "),
                    Span::styled(v.fix.clone(), Style::new().fg(Color::Green)),
                ]));
            }
        }
    }
}

fn render_performance(
    lines: &mut Vec<Line>,
    report: &netscope_core::pqc_wizard::TlsPqcWizardReport,
) {
    lines.push(Line::from(Span::styled(
        " Performance Impact",
        Style::new().bold(),
    )));

    let perf = &report.stages.performance_report;
    lines.push(Line::from(vec![Span::raw(format!(
        "  Classic TLS 1.3:              ~{:.0}ms handshake",
        perf.classic_handshake_time_us / 1000.0
    ))]));
    lines.push(Line::from(vec![Span::raw(format!(
        "  Hybrid TLS 1.3 (PQC + x25519): ~{:.0}ms handshake",
        perf.pqc_handshake_time_us / 1000.0
    ))]));
    lines.push(Line::from(vec![Span::raw(format!(
        "  PQC Overhead:                  +{:.0}ms (+{:.0}%)",
        perf.pqc_overhead_us / 1000.0,
        perf.pqc_overhead_us / perf.classic_handshake_time_us.max(1.0) * 100.0
    ))]));
    lines.push(Line::from(vec![Span::raw(format!(
        "  Bandwidth Overhead:             +{:.0}B (KEM + cert)",
        perf.pqc_clienthello_extra_bytes
    ))]));
    lines.push(Line::from(vec![Span::raw(
        "  Estimated Throughput Loss:      < %1 (ihmal edilebilir)".to_string(),
    )]));
}

fn render_recommendations(
    lines: &mut Vec<Line>,
    report: &netscope_core::pqc_wizard::TlsPqcWizardReport,
) {
    lines.push(Line::from(Span::styled(
        " Recommendations",
        Style::new().bold(),
    )));

    if report.recommendations.is_empty() {
        lines.push(Line::from(Span::raw("  No recommendations.")));
    } else {
        for (i, r) in report.recommendations.iter().enumerate() {
            let pri_color = priority_color(r.priority);
            lines.push(Line::from(vec![
                Span::styled(format!("  {}. ", i + 1), Style::new().fg(pri_color).bold()),
                Span::styled(
                    format!("[{}] ", r.priority.label()),
                    Style::new().fg(pri_color).bold(),
                ),
                Span::styled(r.action.clone(), Style::new().bold()),
            ]));
            lines.push(Line::from(vec![
                Span::raw("     "),
                Span::raw(r.rationale.clone()),
            ]));
        }
    }
}

fn render_compliance(
    lines: &mut Vec<Line>,
    report: &netscope_core::pqc_wizard::TlsPqcWizardReport,
) {
    lines.push(Line::from(Span::styled(
        " Compliance Status",
        Style::new().bold(),
    )));

    if report.compliance.is_empty() {
        lines.push(Line::from(Span::raw("  No compliance data.")));
    } else {
        let mut combined = Line::from(Span::raw("  "));
        for flag in &report.compliance {
            let (emoji, name) = compliance_display(flag);
            let color = if flag.compliant {
                Color::Green
            } else {
                Color::Yellow
            };
            combined.push_span(Span::styled(
                format!(
                    "{} {} {}  ",
                    emoji,
                    name,
                    if flag.compliant { "✅" } else { "⚠️" }
                ),
                Style::new().fg(color),
            ));
        }
        lines.push(combined);
        for flag in &report.compliance {
            lines.push(Line::from(vec![
                Span::raw("    "),
                Span::raw(flag.note.clone()),
            ]));
        }
    }
}

fn render_key_share_prediction(lines: &mut Vec<Line>, report: &TlsPqcWizardReport) {
    lines.push(Line::from(Span::styled(
        " Key Share Prediction",
        Style::new().bold(),
    )));

    let total = report.session_reports.len();
    let failures: Vec<&netscope_core::pqc_wizard::SessionPqcReport> = report
        .session_reports
        .iter()
        .filter(|s| !s.success)
        .collect();
    let fail_rate = if total > 0 {
        failures.len() as f64 / total as f64 * 100.0
    } else {
        0.0
    };

    let kem_mismatches: Vec<String> = failures
        .iter()
        .filter(|s| s.kem_selected.is_some())
        .map(|s| {
            let kem = s.kem_selected.as_ref().map(kem_label).unwrap_or_default();
            format!("{} KEM={}", s.server_name, kem)
        })
        .collect();

    lines.push(Line::from(vec![Span::raw(format!(
        "  Sessions: {}  |  Failures: {} ({:.1}%)",
        total,
        failures.len(),
        fail_rate
    ))]));
    if kem_mismatches.is_empty() {
        lines.push(Line::from(Span::styled(
            "  ✅ No KEM negotiation failures predicted",
            Style::new().fg(Color::Green),
        )));
    } else {
        lines.push(Line::from(vec![
            Span::raw("  ⚠️  KEM failures: "),
            Span::styled(kem_mismatches.join("; "), Style::new().fg(Color::Yellow)),
        ]));
    }
    let risk = if fail_rate > 20.0 {
        "HIGH"
    } else if fail_rate > 5.0 {
        "MEDIUM"
    } else {
        "LOW"
    };
    let risk_color = if fail_rate > 20.0 {
        Color::Red
    } else if fail_rate > 5.0 {
        Color::Yellow
    } else {
        Color::Green
    };
    lines.push(Line::from(vec![
        Span::raw("  Risk: "),
        Span::styled(risk, Style::new().fg(risk_color).bold()),
    ]));
}

fn render_downgrade_detector(lines: &mut Vec<Line>, report: &TlsPqcWizardReport) {
    lines.push(Line::from(Span::styled(
        " Downgrade Detection",
        Style::new().bold(),
    )));

    let mut findings: Vec<String> = Vec::new();
    for s in &report.session_reports {
        if !s.success && s.kem_selected.is_some() {
            findings.push(format!(
                "{}: PQC offered but handshake failed",
                s.server_name
            ));
        }
        if s.is_hybrid && !s.success {
            findings.push(format!("{}: hybrid KEM stripped", s.server_name));
        }
    }

    if findings.is_empty() {
        lines.push(Line::from(Span::styled(
            "  ✅ No downgrade activity detected",
            Style::new().fg(Color::Green),
        )));
    } else {
        for f in &findings {
            lines.push(Line::from(vec![
                Span::styled("  ⚠️  ", Style::new().fg(Color::Yellow)),
                Span::raw(f.clone()),
            ]));
        }
    }
}

fn render_cve_feed(lines: &mut Vec<Line>, report: &TlsPqcWizardReport) {
    lines.push(Line::from(Span::styled(
        " PQC CVE Feed",
        Style::new().bold(),
    )));

    let kem_counts: Vec<String> = report
        .algorithms
        .iter()
        .map(|k| format!("{}: {}", kem_label(&k.algorithm), k.count))
        .collect();

    if kem_counts.is_empty() {
        lines.push(Line::from(Span::raw("  No PQC algorithms detected.")));
    } else {
        lines.push(Line::from(vec![
            Span::raw("  Detected KEMs: "),
            Span::styled(kem_counts.join(", "), Style::new().fg(Color::Cyan)),
        ]));
    }
    let cve_count = report
        .vulnerabilities
        .iter()
        .filter(|v| v.cve_ref.is_some())
        .count();
    if cve_count > 0 {
        lines.push(Line::from(vec![Span::styled(
            format!("  ⚠️  {} CVE-related findings", cve_count),
            Style::new().fg(Color::Yellow),
        )]));
        for v in report
            .vulnerabilities
            .iter()
            .filter(|v| v.cve_ref.is_some())
        {
            lines.push(Line::from(vec![Span::raw(format!(
                "     {}: {}",
                v.cve_ref.as_ref().unwrap(),
                v.title
            ))]));
        }
    } else {
        lines.push(Line::from(Span::styled(
            "  ✅ No known CVEs match detected KEMs",
            Style::new().fg(Color::Green),
        )));
    }
}

fn render_middlebox_detector(lines: &mut Vec<Line>, report: &TlsPqcWizardReport) {
    lines.push(Line::from(Span::styled(
        " Middlebox Interference",
        Style::new().bold(),
    )));

    let mut anomalies: Vec<String> = Vec::new();
    for s in &report.session_reports {
        if s.client_hello_size > 2048 {
            anomalies.push(format!(
                "{}: oversized ClientHello ({}B)",
                s.server_name, s.client_hello_size
            ));
        }
        if s.cert_chain_length > 5 {
            anomalies.push(format!(
                "{}: deep cert chain ({} certs)",
                s.server_name, s.cert_chain_length
            ));
        }
        if s.is_hybrid && !s.success {
            anomalies.push(format!("{}: hybrid KEM rejected", s.server_name));
        }
    }

    if anomalies.is_empty() {
        lines.push(Line::from(Span::styled(
            "  ✅ No middlebox interference detected",
            Style::new().fg(Color::Green),
        )));
    } else {
        for a in &anomalies {
            lines.push(Line::from(vec![
                Span::styled("  ⚠️  ", Style::new().fg(Color::Yellow)),
                Span::raw(a.clone()),
            ]));
        }
    }
}

fn render_session_resumption(lines: &mut Vec<Line>, report: &TlsPqcWizardReport) {
    lines.push(Line::from(Span::styled(
        " Session Resumption (PSK)",
        Style::new().bold(),
    )));

    let total = report.session_reports.len();
    let zero_rtt: Vec<&netscope_core::pqc_wizard::SessionPqcReport> = report
        .session_reports
        .iter()
        .filter(|s| s.is_0rtt)
        .collect();
    let pqc_zero_rtt: Vec<&&netscope_core::pqc_wizard::SessionPqcReport> = zero_rtt
        .iter()
        .filter(|s| s.kem_selected.is_some())
        .collect();
    let psk_ratio = if !zero_rtt.is_empty() {
        pqc_zero_rtt.len() as f64 / zero_rtt.len() as f64 * 100.0
    } else {
        0.0
    };

    lines.push(Line::from(vec![Span::raw(format!(
        "  Sessions: {}  |  0-RTT capable: {}  |  PQC+PSK: {} ({:.1}%)",
        total,
        zero_rtt.len(),
        pqc_zero_rtt.len(),
        psk_ratio
    ))]));
    if pqc_zero_rtt.is_empty() {
        lines.push(Line::from(Span::styled(
            "  ℹ️  No PQC-aware session resumption detected",
            Style::new().fg(Color::DarkGray),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            "  ✅ PQC-aware PSK negotiation active",
            Style::new().fg(Color::Green),
        )));
    }
}

fn render_buttons(lines: &mut Vec<Line>) {
    lines.push(Line::from(Span::styled(
        " [PDF Export]  [JSON Export]  [Share]  [Rescan]",
        Style::new().fg(Color::DarkGray),
    )));
}

fn compute_score(report: &netscope_core::pqc_wizard::TlsPqcWizardReport) -> u8 {
    let mut score: i32 = 50;
    let o = &report.overview;
    if o.adoption_rate > 80.0 {
        score += 20;
    } else if o.adoption_rate > 50.0 {
        score += 10;
    } else if o.adoption_rate > 20.0 {
        score += 5;
    }
    if o.failed_handshakes == 0 {
        score += 10;
    }
    if o.pqc_signature_ratio > 0.0 {
        score += 5;
    }
    if o.composite_cert_ratio > 0.0 {
        score += 5;
    }

    for v in &report.vulnerabilities {
        score -= match v.severity {
            Severity::Critical => 15,
            Severity::High => 10,
            Severity::Medium => 5,
            Severity::Low => 2,
        };
    }
    score.clamp(0, 100) as u8
}

fn kem_label(kem: &KemId) -> String {
    match kem {
        KemId::MlKem512 => "ML-KEM-512".into(),
        KemId::MlKem768 => "ML-KEM-768".into(),
        KemId::MlKem1024 => "ML-KEM-1024".into(),
        KemId::FrodoKem640Aes => "FrodoKEM-640-AES".into(),
        KemId::FrodoKem976Aes => "FrodoKEM-976-AES".into(),
        KemId::FrodoKem1344Aes => "FrodoKEM-1344-AES".into(),
        KemId::ClassicMcEliece348864 => "McEliece-348864".into(),
        KemId::ClassicMcEliece460896 => "McEliece-460896".into(),
        KemId::ClassicMcEliece6688128 => "McEliece-6688128".into(),
        KemId::BikeL1 => "BIKE-L1".into(),
        KemId::BikeL3 => "BIKE-L3".into(),
        KemId::BikeL5 => "BIKE-L5".into(),
        KemId::Hqc128 => "HQC-128".into(),
        KemId::Hqc192 => "HQC-192".into(),
        KemId::Hqc256 => "HQC-256".into(),
        KemId::Sntrup761 => "sntrup761".into(),
        _ => format!("{:?}", kem),
    }
}

fn named_group_label(g: &NamedGroup) -> &'static str {
    match g {
        NamedGroup::Secp256r1 => "secp256r1",
        NamedGroup::Secp384r1 => "secp384r1",
        NamedGroup::Secp521r1 => "secp521r1",
        NamedGroup::X25519 => "x25519",
        NamedGroup::X448 => "x448",
        NamedGroup::Ffdhe2048 => "ffdhe2048",
        NamedGroup::Ffdhe3072 => "ffdhe3072",
        NamedGroup::Ffdhe4096 => "ffdhe4096",
        NamedGroup::Ffdhe6144 => "ffdhe6144",
        NamedGroup::Ffdhe8192 => "ffdhe8192",
        _ => "unknown",
    }
}

fn compliance_display(
    flag: &netscope_core::pqc_wizard::ComplianceFlag,
) -> (&'static str, &'static str) {
    match flag.framework {
        ComplianceFramework::NistSp800131a => ("🇺🇸", "NIST SP 800-131A"),
        ComplianceFramework::BsiTr02102 => ("🇩🇪", "BSI TR-02102"),
        ComplianceFramework::AnssiPqc => ("🇫🇷", "ANSSI PQC"),
        ComplianceFramework::Cnsa2 => ("🇺🇸", "NSA CNSA 2.0"),
        ComplianceFramework::EtsiTs119312 => ("🇪🇺", "ETSI TS 119 312"),
    }
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
