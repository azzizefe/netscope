// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Automatic plain-language security/privacy analysis for the TUI Insights
//! view (ROADMAP §6.1) — a focused port of the desktop's `analyzeCapture`
//! (app.js). It works only from data the TUI already has (the packet ring,
//! the flow table and passive-DNS names) and reports the same honest set of
//! findings: cleartext credentials, unencrypted HTTP, connection problems,
//! port-scan / fan-out shapes, cleartext + unusual DNS, and an
//! encrypted-vs-cleartext headline. No finding is invented — each comes from
//! something actually present in the capture.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::IpAddr;

use netscope_core::flows::FlowTable;
use netscope_core::models::{Packet, Protocol};

/// How serious a finding is. Ordered so `Ord` sorts most-severe first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    High,
    Warn,
    Info,
    Ok,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::High => "HIGH",
            Severity::Warn => "WARN",
            Severity::Info => "INFO",
            Severity::Ok => "OK",
        }
    }
}

/// One analysis result: a severity, a one-line title, an explanation, and up
/// to a handful of supporting evidence strings.
pub struct Finding {
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub evidence: Vec<String>,
}

/// Credential-looking needles searched for in cleartext HTTP payloads.
const CRED_NEEDLES: &[&str] = &[
    "password",
    "passwd",
    "pass=",
    "pwd=",
    "token",
    "authorization:",
    "api_key",
    "apikey",
    "secret",
];

/// Run the analysis over the current capture. Findings come back most-severe
/// first; an empty list means nothing notable was seen.
pub fn analyze(packets: &VecDeque<Packet>, flows: &FlowTable) -> Vec<Finding> {
    let mut findings = Vec::new();

    let threat_engine = netscope_core::threat::ThreatEngine::load();
    let mut threat_alerts = Vec::new();

    let mut tls_bytes = 0u64;
    let mut http_bytes = 0u64;
    let mut http_hosts: BTreeSet<String> = BTreeSet::new();
    let mut creds: Vec<String> = Vec::new();
    let mut dns_domains: BTreeMap<String, u32> = BTreeMap::new();
    let mut suspicious_domains: BTreeSet<String> = BTreeSet::new();
    let mut resets = 0u32;
    let mut malformed = 0u32;
    // (src,dst) -> set of dst ports, for the port-scan heuristic.
    let mut ports_per_target: BTreeMap<(IpAddr, IpAddr), BTreeSet<u16>> = BTreeMap::new();
    // src -> set of distinct dst addrs, for the fan-out heuristic.
    let mut hosts_per_src: BTreeMap<IpAddr, BTreeSet<IpAddr>> = BTreeMap::new();

    for p in packets {
        let alerts = threat_engine.check_packet(p);
        for alert in alerts {
            threat_alerts.push(format!("Packet #{}: {}", p.summary, alert.msg));
        }
        match p.protocol {
            Protocol::Tls => tls_bytes += p.length as u64,
            Protocol::Http => {
                http_bytes += p.length as u64;
                if let Some(d) = p.dst_addr {
                    http_hosts.insert(d.to_string());
                }
                if let Some(text) = payload_text(p) {
                    let lower = text.to_lowercase();
                    if let Some(n) = CRED_NEEDLES.iter().find(|n| lower.contains(**n)) {
                        let host = p
                            .dst_addr
                            .map(|d| d.to_string())
                            .unwrap_or_else(|| "?".into());
                        creds.push(format!("{n} → {host}"));
                    }
                }
            }
            Protocol::Dns | Protocol::Mdns => {
                if let Some(d) = dns_query_name(&p.summary) {
                    *dns_domains.entry(d.clone()).or_insert(0) += 1;
                    let label = d.split('.').next().unwrap_or("");
                    let digits = label.bytes().filter(|b| b.is_ascii_digit()).count();
                    if label.len() > 25 || digits > 8 {
                        suspicious_domains.insert(d);
                    }
                }
            }
            _ => {}
        }

        if p.summary.contains("reset (RST)") {
            resets += 1;
        }
        if p.summary.contains("Malformed") {
            malformed += 1;
        }

        if let (Some(src), Some(dst)) = (p.src_addr, p.dst_addr) {
            if let Some(dport) = p.dst_port {
                ports_per_target
                    .entry((src, dst))
                    .or_default()
                    .insert(dport);
            }
            hosts_per_src.entry(src).or_default().insert(dst);
        }
    }

    // 0. Threat Intelligence & IDS Alerts — highest priority.
    if !threat_alerts.is_empty() {
        findings.push(Finding {
            severity: Severity::High,
            title: format!("Tehdit İstihbaratı ve IDS Alarmları ({})", threat_alerts.len()),
            detail: "Offline AbuseIPDB, URLhaus listeleri veya yerel Suricata/Snort kurallarıyla eşleşen trafik tespit edildi."
                .into(),
            evidence: threat_alerts.into_iter().take(10).collect(),
        });
    }

    // 1. Cleartext credentials — highest priority.
    if !creds.is_empty() {
        findings.push(Finding {
            severity: Severity::High,
            title: format!("Possible credential sent in cleartext ({})", creds.len()),
            detail: "Unencrypted HTTP payloads contained words like \"password\" or \"token\". \
                     Anyone between you and the server could read these — the site should use HTTPS."
                .into(),
            evidence: creds.into_iter().take(5).collect(),
        });
    }

    // 2. Unencrypted HTTP traffic.
    if !http_hosts.is_empty() {
        findings.push(Finding {
            severity: Severity::Warn,
            title: format!(
                "Unencrypted HTTP to {} site{}",
                http_hosts.len(),
                plural(http_hosts.len())
            ),
            detail: "Plain HTTP is readable by anyone on the network path (your ISP, Wi-Fi \
                     operator, etc.). Prefer HTTPS."
                .into(),
            evidence: http_hosts.iter().take(6).cloned().collect(),
        });
    }

    // 3. Connection problems.
    if resets + malformed >= 5 {
        findings.push(Finding {
            severity: Severity::Warn,
            title: format!("{resets} resets, {malformed} malformed packets"),
            detail: "A burst of connection resets or malformed packets can mean an unstable link, \
                     a firewall cutting connections, or scanning activity."
                .into(),
            evidence: vec![],
        });
    }

    // 4. Possible port scan (one source probing many ports on one target).
    for ((src, dst), ports) in &ports_per_target {
        if ports.len() >= 15 {
            findings.push(Finding {
                severity: Severity::High,
                title: format!("Possible port scan: {src} → {dst}"),
                detail: format!(
                    "{src} contacted {} different ports on {dst}. Hitting many ports on one host \
                     is a classic scan pattern.",
                    ports.len()
                ),
                evidence: vec![],
            });
        }
    }

    // 5. High fan-out (one host reaching an unusually large number of hosts).
    for (src, hosts) in &hosts_per_src {
        if hosts.len() >= 40 {
            findings.push(Finding {
                severity: Severity::Info,
                title: format!("{src} contacted {} different hosts", hosts.len()),
                detail: "A single host reaching very many destinations can be normal (a browser, \
                         an updater) or can indicate scanning or beaconing. Worth a glance."
                    .into(),
                evidence: vec![],
            });
        }
    }

    // 6. Plaintext DNS exposure + unusual domains.
    if !dns_domains.is_empty() {
        let mut top: Vec<(&String, &u32)> = dns_domains.iter().collect();
        top.sort_by(|a, b| b.1.cmp(a.1));
        findings.push(Finding {
            severity: Severity::Info,
            title: format!(
                "{} domain{} looked up in cleartext",
                dns_domains.len(),
                plural(dns_domains.len())
            ),
            detail:
                "Standard DNS is unencrypted, so your network and ISP can see every domain you \
                     resolve — even for HTTPS sites. Consider DNS-over-HTTPS/TLS for privacy."
                    .into(),
            evidence: top
                .iter()
                .take(6)
                .map(|(d, n)| format!("{d} ({n})"))
                .collect(),
        });
    }
    if !suspicious_domains.is_empty() {
        findings.push(Finding {
            severity: Severity::Warn,
            title: format!(
                "{} unusual domain name{}",
                suspicious_domains.len(),
                plural(suspicious_domains.len())
            ),
            detail: "Very long or high-digit domain labels can indicate DNS tunneling or \
                     algorithmically-generated malware domains."
                .into(),
            evidence: suspicious_domains.into_iter().take(5).collect(),
        });
    }

    // 7. Data exfiltration shape — large outbound transfer from a private host
    // to a single public destination (uses the flow table's byte counts).
    const EXFIL_BYTES: u64 = 2 * 1024 * 1024;
    let mut big_uploads: Vec<(String, u64)> = flows
        .flows()
        .iter()
        .filter(|f| is_private(f.client_addr) && !is_private(f.server_addr))
        .filter(|f| f.byte_count >= EXFIL_BYTES)
        .map(|f| {
            (
                format!("{} → {}", f.client_addr, f.server_addr),
                f.byte_count,
            )
        })
        .collect();
    big_uploads.sort_by_key(|b| std::cmp::Reverse(b.1));
    for (pair, bytes) in big_uploads.into_iter().take(5) {
        findings.push(Finding {
            severity: Severity::Warn,
            title: format!("Large outbound transfer: {pair} ({})", format_bytes(bytes)),
            detail: "A local host sent an unusually large amount of data to a single external \
                     destination. Normal for backups/uploads, but this is the classic shape of \
                     data exfiltration — confirm it is expected."
                .into(),
            evidence: vec![],
        });
    }

    // 8. Privacy headline — encrypted vs cleartext web traffic.
    let web_bytes = tls_bytes + http_bytes;
    if web_bytes > 0 {
        if http_bytes == 0 {
            findings.push(Finding {
                severity: Severity::Ok,
                title: "All web traffic was encrypted".into(),
                detail:
                    "Every web (HTTP/TLS) byte in this capture used HTTPS. Good — its contents \
                         are private in transit."
                        .into(),
                evidence: vec![],
            });
        } else {
            let enc = (tls_bytes as f64 / web_bytes as f64 * 100.0).round() as u32;
            findings.push(Finding {
                severity: if enc >= 80 { Severity::Info } else { Severity::Warn },
                title: format!("{enc}% of web traffic was encrypted"),
                detail: format!(
                    "{} went over HTTPS and {} over plain HTTP. The plain part is readable in transit.",
                    format_bytes(tls_bytes),
                    format_bytes(http_bytes)
                ),
                evidence: vec![],
            });
        }
    }

    findings.sort_by_key(|f| f.severity);
    findings
}

fn plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_000_000 {
        format!("{:.1} MB", bytes as f64 / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{:.1} KB", bytes as f64 / 1_000.0)
    } else {
        format!("{bytes} B")
    }
}

/// RFC 1918 / loopback / link-local — "is this a local host?".
fn is_private(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

/// Extract `example.com` from a "DNS Query — example.com" style summary.
fn dns_query_name(summary: &str) -> Option<String> {
    for marker in [" — ", " - "] {
        if let Some(idx) = summary.find(marker) {
            let rest = summary[idx + marker.len()..].trim();
            let name = rest.split_whitespace().next()?;
            if name.contains('.') {
                return Some(name.to_string());
            }
        }
    }
    None
}

/// The first ~2 KiB of a TCP/UDP payload as text (lossy), for keyword scanning.
/// Walks Ethernet (+ VLAN) → IPv4/IPv6 → TCP/UDP over the raw frame.
fn payload_text(pkt: &Packet) -> Option<String> {
    let raw = &pkt.data;
    if raw.len() < 14 {
        return None;
    }
    let mut p = 12;
    let mut et = ((raw[p] as u16) << 8) | raw[p + 1] as u16;
    while matches!(et, 0x8100 | 0x88a8 | 0x9100) && p + 6 <= raw.len() {
        p += 4;
        et = ((raw[p] as u16) << 8) | raw[p + 1] as u16;
    }
    let l3 = p + 2;
    let (ip_proto, l4) = if et == 0x0800 && raw.len() >= l3 + 20 {
        let ihl = (raw[l3] & 0x0f) as usize * 4;
        (raw[l3 + 9], l3 + ihl)
    } else if et == 0x86dd && raw.len() >= l3 + 40 {
        (raw[l3 + 6], l3 + 40)
    } else {
        return None;
    };
    let payload_off = match ip_proto {
        6 if raw.len() >= l4 + 20 => l4 + ((raw[l4 + 12] >> 4) as usize & 0x0f) * 4,
        17 if raw.len() >= l4 + 8 => l4 + 8,
        _ => return None,
    };
    if payload_off >= raw.len() {
        return None;
    }
    let end = (payload_off + 2048).min(raw.len());
    Some(String::from_utf8_lossy(&raw[payload_off..end]).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use chrono::Utc;

    fn pkt(proto: Protocol, summary: &str, len: usize) -> Packet {
        Packet {
            timestamp: Utc::now(),
            src_addr: "192.168.1.5".parse().ok(),
            dst_addr: "93.184.216.34".parse().ok(),
            src_port: Some(50000),
            dst_port: Some(80),
            protocol: proto,
            length: len,
            summary: summary.into(),
            data: Bytes::new(),
        }
    }

    #[test]
    fn encryption_headline_all_encrypted() {
        let mut q = VecDeque::new();
        q.push_back(pkt(Protocol::Tls, "TLS", 1000));
        let f = analyze(&q, &FlowTable::new());
        assert!(f.iter().any(|x| x.title == "All web traffic was encrypted"));
    }

    #[test]
    fn flags_unencrypted_http_and_mixed_headline() {
        let mut q = VecDeque::new();
        q.push_back(pkt(Protocol::Tls, "TLS", 800));
        q.push_back(pkt(Protocol::Http, "GET /", 200));
        let f = analyze(&q, &FlowTable::new());
        assert!(f.iter().any(|x| x.title.starts_with("Unencrypted HTTP to")));
        assert!(f
            .iter()
            .any(|x| x.title.contains("% of web traffic was encrypted")));
    }

    #[test]
    fn detects_cleartext_dns_and_suspicious_domain() {
        let mut q = VecDeque::new();
        q.push_back(pkt(Protocol::Dns, "DNS Query — example.com", 60));
        q.push_back(pkt(
            Protocol::Dns,
            "DNS Query — a1b2c3d4e5f6g7h8i9j0k1234567890.evil.net",
            60,
        ));
        let f = analyze(&q, &FlowTable::new());
        assert!(f.iter().any(|x| x.title.contains("looked up in cleartext")));
        assert!(f.iter().any(|x| x.title.contains("unusual domain name")));
    }

    #[test]
    fn port_scan_shape() {
        let mut q = VecDeque::new();
        for port in 1u16..=20 {
            let mut p = pkt(Protocol::Tcp, "TCP", 60);
            p.dst_port = Some(port);
            q.push_back(p);
        }
        let f = analyze(&q, &FlowTable::new());
        assert!(f.iter().any(|x| x.title.starts_with("Possible port scan")));
    }
}
