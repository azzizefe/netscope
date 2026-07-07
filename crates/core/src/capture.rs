use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;

use anyhow::{Context, Result};
use crossbeam_channel::Sender;

use crate::dissectors::{self, DissectedResult};
use crate::models::Packet;

/// Translate human-friendly protocol names in a filter expression into valid
/// BPF syntax. Tokens that are already valid BPF (ports, hostnames, operators)
/// are left untouched, so "http or tls" becomes "tcp port 80 or tcp port 443".
pub fn translate_bpf_filter(raw: &str) -> String {
    // Longer names first so "https" is matched before "http".
    const MAP: &[(&str, &str)] = &[
        // web
        ("https", "tcp port 443"),
        ("http", "tcp port 80"),
        ("tls", "tcp port 443"),
        ("ssl", "tcp port 443"),
        // mail
        ("smtps", "tcp port 465"),
        ("smtp", "tcp port 25"),
        ("imaps", "tcp port 993"),
        ("imap", "tcp port 143"),
        ("pop3s", "tcp port 995"),
        ("pop3", "tcp port 110"),
        // infrastructure
        ("dns", "udp port 53"),
        ("dhcp", "udp port 67 or udp port 68"),
        ("bootp", "udp port 67 or udp port 68"),
        ("ntp", "udp port 123"),
        ("snmp", "udp port 161"),
        ("ssh", "tcp port 22"),
        ("ftp", "tcp port 21"),
        ("telnet", "tcp port 23"),
        ("rdp", "tcp port 3389"),
        ("ldaps", "tcp port 636"),
        ("ldap", "tcp port 389"),
        // databases
        ("mysql", "tcp port 3306"),
        ("postgres", "tcp port 5432"),
        ("redis", "tcp port 6379"),
        ("mongodb", "tcp port 27017"),
        // already-valid BPF tokens — pass through (listed only so
        // sub-word matches like "icmp" inside "icmp6" are avoided)
        ("icmp6", "icmp6"),
        ("icmp", "icmp"),
        ("arp", "arp"),
    ];

    let mut result = String::with_capacity(raw.len() + 64);
    let mut i = 0;
    let bytes = raw.as_bytes();
    // When true, the next token is a hostname / address — skip protocol
    // translation. Set by the BPF keyword "host" and cleared after one token.
    let mut next_is_host = false;

    while i < bytes.len() {
        // Skip whitespace and parentheses verbatim.
        if bytes[i].is_ascii_whitespace() || bytes[i] == b'(' || bytes[i] == b')' {
            result.push(bytes[i] as char);
            i += 1;
            continue;
        }

        // Collect a token (letters, digits, underscore, dot, hyphen).
        let start = i;
        while i < bytes.len()
            && (bytes[i].is_ascii_alphanumeric()
                || bytes[i] == b'_'
                || bytes[i] == b'.'
                || bytes[i] == b'-')
        {
            i += 1;
        }
        let token = &raw[start..i];

        // If this token follows "host", it is a hostname — never
        // translate it. "host http.example.com" stays untouched.
        let replacement = if next_is_host {
            next_is_host = false;
            None
        } else {
            MAP.iter().find_map(|(k, v)| {
                if token.len() == k.len() && token.eq_ignore_ascii_case(k) {
                    Some(*v)
                } else {
                    None
                }
            })
        };

        match replacement {
            Some(r) => {
                result.push_str(r);
                // Replacement is valid BPF (e.g. "tcp port 80") — no
                // host-keyword tracking needed inside it.
            }
            None => {
                // Remember whether this token is the BPF "host" keyword
                // so the NEXT token isn't translated.
                if token.eq_ignore_ascii_case("host") {
                    next_is_host = true;
                }
                result.push_str(token);
            }
        }
    }

    result
}

pub fn list_interfaces() -> Result<Vec<pcap::Device>> {
    pcap::Device::list().context("Failed to list network interfaces.\n  On Windows: Install Npcap from https://npcap.com\n  On Linux/macOS: Run with sudo or set CAP_NET_RAW capability")
}

/// Pick the best interface for zero-config capture: a connected,
/// non-loopback device with a routable IPv4 address. Plain `.first()`
/// often lands on a WAN Miniport or virtual adapter that sees no traffic.
pub fn default_interface() -> Result<pcap::Device> {
    let devices = list_interfaces()?;
    devices
        .iter()
        .max_by_key(|d| interface_score(d))
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("No network interfaces found"))
}

fn interface_score(dev: &pcap::Device) -> i32 {
    let mut score = 0;
    if dev.flags.is_loopback() {
        return -100;
    }
    if dev.flags.connection_status == pcap::ConnectionStatus::Connected {
        score += 4;
    }
    if dev.flags.is_up() && dev.flags.is_running() {
        score += 2;
    }
    let has_routable_v4 = dev.addresses.iter().any(|a| match a.addr {
        std::net::IpAddr::V4(v4) => {
            !v4.is_loopback() && !v4.is_link_local() && !v4.is_unspecified()
        }
        _ => false,
    });
    if has_routable_v4 {
        score += 3;
    }
    // Virtual adapters (Hyper-V, VMware, WSL) rarely carry the user's traffic.
    if let Some(desc) = &dev.desc {
        let d = desc.to_lowercase();
        if d.contains("miniport") || d.contains("virtual") || d.contains("hyper-v") {
            score -= 3;
        }
    }
    score
}

/// Human-friendly label for a device: its description when available
/// (e.g. "Intel(R) Wi-Fi 6 AX201"), otherwise the raw name.
pub fn friendly_name(dev: &pcap::Device) -> String {
    dev.desc.clone().unwrap_or_else(|| dev.name.clone())
}

/// Look up the friendly label for a device by its raw name.
pub fn friendly_name_of(raw_name: &str) -> String {
    list_interfaces()
        .ok()
        .and_then(|devs| devs.iter().find(|d| d.name == raw_name).map(friendly_name))
        .unwrap_or_else(|| raw_name.to_string())
}

pub struct CaptureEngine {
    running: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Default for CaptureEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl CaptureEngine {
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            handle: None,
        }
    }

    pub fn start_live(
        &mut self,
        interface: &str,
        bpf_filter: Option<&str>,
        output_path: Option<&str>,
        packet_tx: Sender<Packet>,
    ) -> Result<()> {
        let running = self.running.clone();
        running.store(true, Ordering::SeqCst);

        let mut cap = pcap::Capture::from_device(interface)
            .map_err(|e| {
                if cfg!(target_os = "windows") {
                    anyhow::anyhow!(
                        "Failed to open interface '{interface}': {e}\n  Ensure Npcap is installed: https://npcap.com"
                    )
                } else if cfg!(unix) {
                    anyhow::anyhow!(
                        "Failed to open interface '{interface}': {e}\n  Run with sudo or set CAP_NET_RAW capability"
                    )
                } else {
                    anyhow::anyhow!("Failed to open interface '{interface}': {e}")
                }
            })?
            .promisc(true)
            .snaplen(65535)
            .timeout(1000)
            .open()
            .map_err(|e| {
                if cfg!(target_os = "windows") {
                    anyhow::anyhow!(
                        "Failed to open capture on '{interface}': {e}\n  Ensure Npcap is installed and WinPcap is not conflicting"
                    )
                } else {
                    anyhow::anyhow!("Failed to open capture on '{interface}': {e}")
                }
            })?;

        if let Some(filter) = bpf_filter {
            let translated = translate_bpf_filter(filter);
            cap.filter(&translated, true)
                .map_err(|e| anyhow::anyhow!("Invalid BPF filter '{filter}': {e}"))?;
        }

        let output_path = output_path.map(|s| s.to_string());

        let handle = thread::Builder::new()
            .name("capture".into())
            .spawn(move || {
                let mut savefile = output_path
                    .as_ref()
                    .and_then(|path| match cap.savefile(path) {
                        Ok(sf) => Some(sf),
                        Err(e) => {
                            eprintln!("Warning: Failed to create savefile '{}': {}", path, e);
                            None
                        }
                    });
                while running.load(Ordering::SeqCst) {
                    match cap.next_packet() {
                        Ok(pkt) => {
                            if let Some(ref mut sf) = savefile {
                                sf.write(&pkt);
                            }
                            let packet = build_packet(pkt);
                            if packet_tx.send(packet).is_err() {
                                break;
                            }
                        }
                        Err(pcap::Error::TimeoutExpired) => continue,
                        Err(pcap::Error::NoMorePackets) => break,
                        Err(e) => {
                            eprintln!("Capture error: {e}");
                            break;
                        }
                    }
                }
            })
            .context("Failed to spawn capture thread")?;

        self.handle = Some(handle);
        Ok(())
    }

    pub fn start_offline(
        &mut self,
        filepath: &str,
        bpf_filter: Option<&str>,
        output_path: Option<&str>,
        packet_tx: Sender<Packet>,
    ) -> Result<()> {
        let running = self.running.clone();
        running.store(true, Ordering::SeqCst);

        let mut cap = pcap::Capture::from_file(filepath)
            .map_err(|e| anyhow::anyhow!("Failed to open pcap file '{filepath}': {e}"))?;

        if let Some(filter) = bpf_filter {
            let translated = translate_bpf_filter(filter);
            cap.filter(&translated, true)
                .map_err(|e| anyhow::anyhow!("Invalid BPF filter '{filter}': {e}"))?;
        }

        let output_path = output_path.map(|s| s.to_string());

        let handle = thread::Builder::new()
            .name("capture".into())
            .spawn(move || {
                let mut savefile = output_path
                    .as_ref()
                    .and_then(|path| match cap.savefile(path) {
                        Ok(sf) => Some(sf),
                        Err(e) => {
                            eprintln!("Warning: Failed to create savefile '{}': {}", path, e);
                            None
                        }
                    });
                while running.load(Ordering::SeqCst) {
                    match cap.next_packet() {
                        Ok(pkt) => {
                            if let Some(ref mut sf) = savefile {
                                sf.write(&pkt);
                            }
                            let packet = build_packet(pkt);
                            if packet_tx.send(packet).is_err() {
                                break;
                            }
                        }
                        Err(pcap::Error::TimeoutExpired) => continue,
                        Err(pcap::Error::NoMorePackets) => break,
                        Err(e) => {
                            eprintln!("Capture error: {e}");
                            break;
                        }
                    }
                }
            })
            .context("Failed to spawn capture thread")?;

        self.handle = Some(handle);
        Ok(())
    }

    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

impl Drop for CaptureEngine {
    fn drop(&mut self) {
        self.stop();
    }
}

fn build_packet(pkt: pcap::Packet) -> Packet {
    // tv_sec is i32 on Windows but already i64 on Linux/macOS, so the cast
    // is platform-necessary even where clippy flags it as i64 -> i64.
    #[allow(clippy::unnecessary_cast)]
    let secs = pkt.header.ts.tv_sec as i64;
    let timestamp = chrono::DateTime::from_timestamp(secs, pkt.header.ts.tv_usec as u32 * 1000)
        .unwrap_or_default();

    let DissectedResult {
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        protocol,
        summary,
    } = dissectors::dissect(pkt.data);

    Packet {
        timestamp,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        protocol,
        length: pkt.header.len as usize,
        summary,
        data: pkt.data.to_vec(),
    }
}

#[cfg(test)]
mod filter_tests {
    use super::translate_bpf_filter;

    #[test]
    fn simple_http() {
        assert_eq!(translate_bpf_filter("http"), "tcp port 80");
        assert_eq!(translate_bpf_filter("HTTP"), "tcp port 80");
    }

    #[test]
    fn http_or_tls() {
        assert_eq!(
            translate_bpf_filter("http or tls"),
            "tcp port 80 or tcp port 443"
        );
    }

    #[test]
    fn compound_expression() {
        assert_eq!(
            translate_bpf_filter("http or tls or dns"),
            "tcp port 80 or tcp port 443 or udp port 53"
        );
    }

    #[test]
    fn parenthesized() {
        assert_eq!(
            translate_bpf_filter("(http or tls) and host 1.2.3.4"),
            "(tcp port 80 or tcp port 443) and host 1.2.3.4"
        );
    }

    #[test]
    fn already_valid_bpf_unchanged() {
        let bpf = "tcp port 80 or udp port 53";
        assert_eq!(translate_bpf_filter(bpf), bpf);
    }

    #[test]
    fn icmp_arp_pass_through() {
        assert_eq!(translate_bpf_filter("icmp or arp"), "icmp or arp");
    }

    #[test]
    fn https_takes_precedence_over_http() {
        // "https" must NOT become "tcp port 443s" (substring match bug).
        assert_eq!(translate_bpf_filter("https"), "tcp port 443");
    }

    #[test]
    fn mixed_ports_and_protocols() {
        assert_eq!(
            translate_bpf_filter("ssh or tcp port 8080"),
            "tcp port 22 or tcp port 8080"
        );
    }

    #[test]
    fn empty_and_whitespace() {
        assert_eq!(translate_bpf_filter(""), "");
        assert_eq!(translate_bpf_filter("  "), "  ");
    }

    #[test]
    fn host_keyword_protects_hostname() {
        // "host http" means a host named "http" — do not translate.
        assert_eq!(translate_bpf_filter("host http"), "host http");
        // Dotted hostname stays intact.
        assert_eq!(
            translate_bpf_filter("host http.example.com"),
            "host http.example.com"
        );
    }

    #[test]
    fn host_keyword_then_protocol_elsewhere() {
        // "host 1.2.3.4 and http" — only the second "http" is translated.
        assert_eq!(
            translate_bpf_filter("host 10.0.0.1 and http"),
            "host 10.0.0.1 and tcp port 80"
        );
    }

    #[test]
    fn host_keyword_with_dns_hostname() {
        assert_eq!(
            translate_bpf_filter("host dns.google.com or dns"),
            "host dns.google.com or udp port 53"
        );
    }

    #[test]
    fn multiple_host_keywords() {
        assert_eq!(
            translate_bpf_filter("host ssh-server and host tls.example"),
            "host ssh-server and host tls.example"
        );
    }

    #[test]
    fn protocol_before_host_still_translated() {
        // "tls" before "host" is a protocol, not a hostname.
        assert_eq!(
            translate_bpf_filter("tls and host example.com"),
            "tcp port 443 and host example.com"
        );
    }
}
