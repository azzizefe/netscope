// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use crate::models::{Packet, Protocol};

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
}

impl SuricataRule {
    pub fn matches(&self, pkt: &Packet) -> bool {
        // 1. Check protocol
        match self.protocol.as_str() {
            "tcp" => {
                if pkt.protocol == Protocol::Udp || pkt.protocol == Protocol::Dns || pkt.protocol == Protocol::Mdns {
                    return false;
                }
            }
            "udp" => {
                if pkt.protocol != Protocol::Udp && pkt.protocol != Protocol::Dns && pkt.protocol != Protocol::Mdns {
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
        
        // 4. Check content
        if !self.content.is_empty() {
            let matches_data = pkt.data.windows(self.content.len()).any(|w| w == self.content.as_bytes());
            let matches_summary = pkt.summary.contains(&self.content);
            if !matches_data && !matches_summary {
                return false;
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
                "msg" => msg = v.to_string(),
                "content" => content = v.to_string(),
                "sid" => sid = v.parse().unwrap_or(0),
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

        // 1. Load AbuseIPDB malicious IPs
        let abuse_path = dir.join("abuseipdb.txt");
        if let Ok(content) = std::fs::read_to_string(&abuse_path) {
            for line in content.lines() {
                let ip = line.trim();
                if !ip.is_empty() && !ip.starts_with('#') {
                    malicious_ips.insert(ip.to_string());
                }
            }
        } else {
            let defaults = vec!["185.220.101.5", "45.143.203.2", "80.82.77.33"];
            for ip in defaults {
                malicious_ips.insert(ip.to_string());
            }
            let _ = std::fs::create_dir_all(dir);
            let _ = std::fs::write(&abuse_path, "# AbuseIPDB malicious IP list\n185.220.101.5\n45.143.203.2\n80.82.77.33\n");
        }

        // 2. Load URLhaus malicious domains
        let urlhaus_path = dir.join("urlhaus.txt");
        if let Ok(content) = std::fs::read_to_string(&urlhaus_path) {
            for line in content.lines() {
                let domain = line.trim();
                if !domain.is_empty() && !domain.starts_with('#') {
                    malicious_domains.insert(domain.to_lowercase());
                }
            }
        } else {
            let defaults = vec!["malicious-c2.com", "phishing-bank-update.org", "get-malware-now.ru"];
            for d in defaults {
                malicious_domains.insert(d.to_string());
            }
            let _ = std::fs::write(&urlhaus_path, "# URLhaus / PhishTank threat domains\nmalicious-c2.com\nphishing-bank-update.org\nget-malware-now.ru\n");
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
            let rule_str = "alert tcp any any -> any 80 (msg:\"MALWARE payload detected\"; content:\"get_c2_payload\"; sid:100001;)\n\
                            alert udp any any -> any 53 (msg:\"Suspicious DNS lookup request\"; content:\"phishing-bank\"; sid:100002;)\n";
            let default_rules_path = rules_dir.join("local.rules");
            let _ = std::fs::write(&default_rules_path, rule_str);
            for line in rule_str.lines() {
                if let Some(rule) = parse_rule(line) {
                    suricata_rules.push(rule);
                }
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

        // 1. IP check (AbuseIPDB)
        if let Some(ref src) = pkt.src_addr {
            let src_str = src.to_string();
            if self.malicious_ips.contains(&src_str) {
                alerts.push(ThreatAlert {
                    severity: "High".to_string(),
                    msg: format!("AbuseIPDB: Connection from malicious source IP ({})", src_str),
                    sid: 200001,
                });
            }
        }
        if let Some(ref dst) = pkt.dst_addr {
            let dst_str = dst.to_string();
            if self.malicious_ips.contains(&dst_str) {
                alerts.push(ThreatAlert {
                    severity: "High".to_string(),
                    msg: format!("AbuseIPDB: Traffic to malicious destination IP ({})", dst_str),
                    sid: 200002,
                });
            }
        }

        // 2. Domain check (URLhaus / PhishTank)
        let domain_opt = if pkt.protocol == Protocol::Dns || pkt.protocol == Protocol::Mdns {
            crate::filter::dns_qry_name(pkt)
        } else if pkt.protocol == Protocol::Http {
            let data_str = String::from_utf8_lossy(&pkt.data);
            data_str.lines()
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
                    msg: format!("URLhaus: Malicious threat domain referenced ({})", domain),
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

    #[test]
    fn test_parse_rule() {
        let rule = parse_rule("alert tcp any any -> any 80 (msg:\"test rule\"; content:\"malware\"; sid:12345;)").unwrap();
        assert_eq!(rule.action, "alert");
        assert_eq!(rule.protocol, "tcp");
        assert_eq!(rule.dst_port, "80");
        assert_eq!(rule.msg, "test rule");
        assert_eq!(rule.content, "malware");
        assert_eq!(rule.sid, 12345);
    }

    #[test]
    fn test_rule_matching() {
        let rule = parse_rule("alert tcp any any -> any 80 (msg:\"detect payload\"; content:\"bad_code\"; sid:999;)").unwrap();
        
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
        };

        assert!(rule.matches(&pkt));

        // Change port
        pkt.dst_port = Some(443);
        assert!(!rule.matches(&pkt));
    }
}
