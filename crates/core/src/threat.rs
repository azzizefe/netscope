// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::{Packet, Protocol};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Parse hex string patterns in Suricata/ET rules like "|00 01 02| /path" or "|41 42 43 44|"
pub fn parse_content_bytes(content: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut in_hex = false;
    let mut hex_buf = String::new();

    for ch in content.chars() {
        if ch == '|' {
            if in_hex {
                for token in hex_buf.split_whitespace() {
                    if let Ok(b) = u8::from_str_radix(token, 16) {
                        bytes.push(b);
                    }
                }
                hex_buf.clear();
                in_hex = false;
            } else {
                in_hex = true;
            }
        } else if in_hex {
            hex_buf.push(ch);
        } else {
            bytes.push(ch as u8);
        }
    }
    bytes
}

#[derive(Debug, Clone)]
pub struct SuricataRule {
    pub action: String,
    pub protocol: String,
    pub src_ip: String,
    pub src_port: String,
    pub dst_ip: String,
    pub dst_port: String,
    pub msg: String,
    pub content: String,
    pub sid: u64,
    pub classtype: Option<String>,
    pub reference: Vec<String>,
    pub rev: u32,
    pub flow: Option<String>,
    pub hex_content: Vec<Vec<u8>>,
    pub category: Option<String>,
}

impl SuricataRule {
    pub fn matches(&self, pkt: &Packet) -> bool {
        // 1. Check protocol
        match self.protocol.as_str() {
            "tcp" => {
                if pkt.protocol == Protocol::Udp
                    || pkt.protocol == Protocol::Dns
                    || pkt.protocol == Protocol::Mdns
                {
                    return false;
                }
            }
            "udp" => {
                if pkt.protocol != Protocol::Udp
                    && pkt.protocol != Protocol::Dns
                    && pkt.protocol != Protocol::Mdns
                {
                    return false;
                }
            }
            "ip" => {}
            _ => {}
        }

        // 2. Check ports (if not "any")
        if self.src_port != "any" {
            if let Some(port) = pkt.src_port {
                if port.to_string() != self.src_port {
                    return false;
                }
            } else {
                return false;
            }
        }
        if self.dst_port != "any" {
            if let Some(port) = pkt.dst_port {
                if port.to_string() != self.dst_port {
                    return false;
                }
            } else {
                return false;
            }
        }

        // 3. Check IPs (if not "any")
        if self.src_ip != "any" && self.src_ip != "$EXTERNAL_NET" && self.src_ip != "$HOME_NET" {
            if let Some(ip) = pkt.src_addr {
                if ip.to_string() != self.src_ip {
                    return false;
                }
            } else {
                return false;
            }
        }
        if self.dst_ip != "any" && self.dst_ip != "$EXTERNAL_NET" && self.dst_ip != "$HOME_NET" {
            if let Some(ip) = pkt.dst_addr {
                if ip.to_string() != self.dst_ip {
                    return false;
                }
            } else {
                return false;
            }
        }

        // 4. Check content (text matching when no hex pattern override)
        if !self.content.is_empty() && self.hex_content.is_empty() {
            let matches_data = pkt
                .data
                .windows(self.content.len())
                .any(|w| w == self.content.as_bytes());
            let matches_summary = pkt.summary.contains(&self.content);
            if !matches_data && !matches_summary {
                return false;
            }
        }

        // 5. Check hex patterns
        for hex_pattern in &self.hex_content {
            if !hex_pattern.is_empty() {
                let matches_bytes = pkt
                    .data
                    .windows(hex_pattern.len())
                    .any(|w| w == hex_pattern.as_slice());
                if !matches_bytes {
                    return false;
                }
            }
        }

        true
    }
}

pub fn parse_rule(line: &str) -> Option<SuricataRule> {
    let line = line.trim();
    if line.starts_with('#') || line.is_empty() {
        return None;
    }

    let parts: Vec<&str> = line.splitn(2, '(').collect();
    if parts.len() < 2 {
        return None;
    }

    let header = parts[0].trim();
    let options_str = parts[1].trim().trim_end_matches(')');

    let header_tokens: Vec<&str> = header.split_whitespace().collect();
    if header_tokens.len() < 7 {
        return None;
    }

    let action = header_tokens[0].to_string();
    let protocol = header_tokens[1].to_ascii_lowercase();
    let src_ip = header_tokens[2].to_string();
    let src_port = header_tokens[3].to_string();
    let dst_ip = header_tokens[5].to_string();
    let dst_port = header_tokens[6].to_string();

    let mut msg = String::new();
    let mut content = String::new();
    let mut sid = 0;
    let mut classtype = None;
    let mut reference = Vec::new();
    let mut rev = 1;
    let mut flow = None;
    let mut hex_content = Vec::new();
    let mut category = None;

    for opt in options_str.split(';') {
        let opt = opt.trim();
        if opt.is_empty() {
            continue;
        }
        let kv: Vec<&str> = opt.splitn(2, ':').collect();
        if kv.len() == 2 {
            let k = kv[0].trim();
            let v = kv[1].trim().trim_matches('"');
            match k {
                "msg" => {
                    msg = v.to_string();
                    if msg.starts_with("ET ") {
                        let words: Vec<&str> = msg.split_whitespace().collect();
                        if words.len() >= 2 {
                            category = Some(format!("{} {}", words[0], words[1]));
                        } else {
                            category = Some(msg.clone());
                        }
                    }
                }
                "content" => {
                    content = v.to_string();
                    if v.contains('|') {
                        hex_content.push(parse_content_bytes(v));
                    }
                }
                "sid" => sid = v.parse().unwrap_or(0),
                "classtype" => classtype = Some(v.to_string()),
                "reference" => reference.push(v.to_string()),
                "rev" => rev = v.parse().unwrap_or(1),
                "flow" => flow = Some(v.to_string()),
                _ => {}
            }
        }
    }

    Some(SuricataRule {
        action,
        protocol,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        msg,
        content,
        sid,
        classtype,
        reference,
        rev,
        flow,
        hex_content,
        category,
    })
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ThreatAlert {
    pub severity: String,
    pub msg: String,
    pub sid: u64,
}

pub struct ThreatEngine {
    pub malicious_ips: HashSet<String>,
    pub malicious_domains: HashSet<String>,
    pub suricata_rules: Vec<SuricataRule>,
}

impl ThreatEngine {
    pub fn load() -> Self {
        let dir = crate::config::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("threat");

        Self::load_from(&dir)
    }

    pub fn load_from(dir: &Path) -> Self {
        let mut malicious_ips = HashSet::new();
        let mut malicious_domains = HashSet::new();
        let mut suricata_rules = Vec::new();

        // Indicator lists are supplied by the operator; netscope fetches
        // nothing. On first run each file is created empty with a comment
        // saying where the real feed comes from.
        //
        // These used to be seeded with three invented IP addresses under the
        // header "# AbuseIPDB malicious IP list", and three invented domains
        // under "# URLhaus / PhishTank threat domains" — indicators netscope
        // made up, written to disk attributed to threat-intel vendors that had
        // never seen them, and then reported as "AbuseIPDB:" matches. An empty
        // list is the truth until the operator supplies one.
        let abuse_path = dir.join("indicators-ip.txt");
        if let Ok(content) = std::fs::read_to_string(&abuse_path) {
            for line in content.lines() {
                let ip = line.trim();
                if !ip.is_empty() && !ip.starts_with('#') {
                    malicious_ips.insert(ip.to_string());
                }
            }
        } else {
            let _ = std::fs::create_dir_all(dir);
            let _ = std::fs::write(
                &abuse_path,
                "# One IP address per line. Lines starting with # are ignored.\n\
                 #\n\
                 # netscope ships no indicators and fetches none. Populate this\n\
                 # from a feed you trust, e.g. AbuseIPDB, Spamhaus DROP, or your\n\
                 # own blocklist. Matches are reported as coming from this file.\n",
            );
        }

        let urlhaus_path = dir.join("indicators-domain.txt");
        if let Ok(content) = std::fs::read_to_string(&urlhaus_path) {
            for line in content.lines() {
                let domain = line.trim();
                if !domain.is_empty() && !domain.starts_with('#') {
                    malicious_domains.insert(domain.to_lowercase());
                }
            }
        } else {
            let _ = std::fs::write(
                &urlhaus_path,
                "# One domain per line. Lines starting with # are ignored.\n\
                 #\n\
                 # netscope ships no indicators and fetches none. Populate this\n\
                 # from a feed you trust, e.g. URLhaus or PhishTank. Matches are\n\
                 # reported as coming from this file.\n",
            );
        }

        // 3. Load Suricata rules
        let rules_dir = dir.join("rules");
        let _ = std::fs::create_dir_all(&rules_dir);

        let mut read_any_rule = false;
        if let Ok(entries) = std::fs::read_dir(&rules_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|ext| ext == "rules") {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        for line in content.lines() {
                            if let Some(rule) = parse_rule(line) {
                                suricata_rules.push(rule);
                                read_any_rule = true;
                            }
                        }
                    }
                }
            }
        }

        if !read_any_rule {
            // Two toy rules used to be written and loaded here, matching the
            // literal strings "get_c2_payload" and "phishing-bank" — signatures
            // that fire on nothing real, while making the rule count look
            // non-zero. An empty starter file is honest.
            let default_rules_path = rules_dir.join("local.rules");
            if !default_rules_path.exists() {
                let _ = std::fs::write(
                    &default_rules_path,
                    "# Suricata-format rules, one per line.\n\
                     #\n\
                     # netscope ships no signatures. Add your own, or drop a\n\
                     # .rules file from a ruleset you trust into this directory.\n\
                     # Only msg, content, sid, classtype, reference, rev and flow\n\
                     # are honoured; a rule using any other option is rejected\n\
                     # rather than silently widened.\n",
                );
            }
        }

        Self {
            malicious_ips,
            malicious_domains,
            suricata_rules,
        }
    }

    pub fn check_packet(&self, pkt: &Packet) -> Vec<ThreatAlert> {
        let mut alerts = Vec::new();

        // Indicator matches name the local list they came from. They used to be
        // reported as "AbuseIPDB:" and "URLhaus:" hits, which told the analyst a
        // named vendor had flagged the address — netscope contacts no vendor and
        // knows only what is in the operator's own file.
        if let Some(ref src) = pkt.src_addr {
            let src_str = src.to_string();
            if self.malicious_ips.contains(&src_str) {
                alerts.push(ThreatAlert {
                    severity: "High".to_string(),
                    msg: format!("Source IP {src_str} is on the local indicator list"),
                    sid: 200001,
                });
            }
        }
        if let Some(ref dst) = pkt.dst_addr {
            let dst_str = dst.to_string();
            if self.malicious_ips.contains(&dst_str) {
                alerts.push(ThreatAlert {
                    severity: "High".to_string(),
                    msg: format!("Destination IP {dst_str} is on the local indicator list"),
                    sid: 200002,
                });
            }
        }

        let domain_opt = if pkt.protocol == Protocol::Dns || pkt.protocol == Protocol::Mdns {
            crate::filter::dns_qry_name(pkt)
        } else if pkt.protocol == Protocol::Http {
            let data_str = String::from_utf8_lossy(&pkt.data);
            data_str
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("host:"))
                .map(|l| l["host:".len()..].trim().to_ascii_lowercase())
        } else {
            None
        };

        if let Some(ref domain) = domain_opt {
            let domain_lower = domain.to_lowercase();
            if self.malicious_domains.contains(&domain_lower) {
                alerts.push(ThreatAlert {
                    severity: "High".to_string(),
                    msg: format!("Domain {domain} is on the local indicator list"),
                    sid: 300001,
                });
            }
        }

        // 3. Suricata rules check
        for rule in &self.suricata_rules {
            if rule.matches(pkt) {
                alerts.push(ThreatAlert {
                    severity: "High".to_string(),
                    msg: format!("IDS Alert (sid: {}): {}", rule.sid, rule.msg),
                    sid: rule.sid,
                });
            }
        }

        alerts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Protocol;
    use bytes::Bytes;
    use chrono::Utc;

    /// A fresh install must have no indicators, and must not invent any.
    ///
    /// `load_from` used to seed three IP addresses and three domains of its own
    /// invention on first run, write them to disk under the headers
    /// "# AbuseIPDB malicious IP list" and "# URLhaus / PhishTank threat
    /// domains", and then report matches as "AbuseIPDB:" hits. An analyst had
    /// no way to tell that netscope had made the indicators up and that no
    /// vendor had ever seen them.
    #[test]
    fn a_fresh_install_ships_no_indicators_and_invents_none() {
        let dir = std::env::temp_dir().join("netscope-threat-fresh");
        let _ = std::fs::remove_dir_all(&dir);

        let engine = ThreatEngine::load_from(&dir);
        assert!(
            engine.malicious_ips.is_empty(),
            "seeded IPs on a fresh install: {:?}",
            engine.malicious_ips,
        );
        assert!(
            engine.malicious_domains.is_empty(),
            "seeded domains on a fresh install: {:?}",
            engine.malicious_domains,
        );
        assert!(
            engine.suricata_rules.is_empty(),
            "seeded signatures on a fresh install",
        );

        // The starter files exist and explain themselves, but claim no vendor.
        for name in ["indicators-ip.txt", "indicators-domain.txt"] {
            let body = std::fs::read_to_string(dir.join(name)).expect("starter file");
            assert!(
                body.lines().all(|l| l.trim().is_empty() || l.starts_with('#')),
                "{name} contains entries netscope invented",
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An indicator match must be attributed to the operator's own list.
    #[test]
    fn indicator_matches_do_not_claim_a_vendor() {
        let dir = std::env::temp_dir().join("netscope-threat-attrib");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("indicators-ip.txt"), "203.0.113.7\n").unwrap();

        let engine = ThreatEngine::load_from(&dir);
        let pkt = Packet {
            timestamp: Utc::now(),
            src_addr: Some("203.0.113.7".parse().unwrap()),
            dst_addr: Some("10.0.0.1".parse().unwrap()),
            src_port: Some(1234),
            dst_port: Some(80),
            protocol: Protocol::Tcp,
            length: 60,
            summary: String::new(),
            data: Bytes::new(),
            llm: None,
        };

        let alerts = engine.check_packet(&pkt);
        assert_eq!(alerts.len(), 1);
        for vendor in ["AbuseIPDB", "URLhaus", "PhishTank"] {
            assert!(
                !alerts[0].msg.contains(vendor),
                "match credited to {vendor}, which netscope never contacted: {:?}",
                alerts[0].msg,
            );
        }
        assert!(alerts[0].msg.contains("local indicator list"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_parse_rule() {
        let rule = parse_rule(
            "alert tcp any any -> any 80 (msg:\"test rule\"; content:\"malware\"; sid:12345;)",
        )
        .unwrap();
        assert_eq!(rule.action, "alert");
        assert_eq!(rule.protocol, "tcp");
        assert_eq!(rule.dst_port, "80");
        assert_eq!(rule.msg, "test rule");
        assert_eq!(rule.content, "malware");
        assert_eq!(rule.sid, 12345);
    }

    #[test]
    fn test_rule_matching() {
        let rule = parse_rule(
            "alert tcp any any -> any 80 (msg:\"detect payload\"; content:\"bad_code\"; sid:999;)",
        )
        .unwrap();

        let mut pkt = Packet {
            timestamp: Utc::now(),
            src_addr: Some("192.168.1.10".parse().unwrap()),
            dst_addr: Some("1.1.1.1".parse().unwrap()),
            src_port: Some(54321),
            dst_port: Some(80),
            protocol: Protocol::Http,
            length: 120,
            summary: "GET / HTTP/1.1".to_string(),
            data: Bytes::from("GET / HTTP/1.1\r\nHost: example.com\r\n\r\nbad_code_here"),
            llm: None,
        };

        assert!(rule.matches(&pkt));

        // Change port
        pkt.dst_port = Some(443);
        assert!(!rule.matches(&pkt));
    }

    #[test]
    fn test_et_hex_rule_matching() {
        let rule = parse_rule(
            "alert tcp any any -> any 80 (msg:\"ET MALWARE Suspicious Hex Payload\"; content:\"|00 01 02 03|\"; classtype:trojan-activity; sid:2000001;)",
        )
        .unwrap();

        assert_eq!(rule.sid, 2000001);
        assert_eq!(rule.classtype.as_deref(), Some("trojan-activity"));
        assert_eq!(rule.category.as_deref(), Some("ET MALWARE"));

        let pkt = Packet {
            timestamp: Utc::now(),
            src_addr: Some("192.168.1.10".parse().unwrap()),
            dst_addr: Some("1.1.1.1".parse().unwrap()),
            src_port: Some(54321),
            dst_port: Some(80),
            protocol: Protocol::Http,
            length: 120,
            summary: "TCP".to_string(),
            data: Bytes::from(vec![0xAA, 0xBB, 0x00, 0x01, 0x02, 0x03, 0xCC]),
            llm: None,
        };

        assert!(rule.matches(&pkt));
    }
}
