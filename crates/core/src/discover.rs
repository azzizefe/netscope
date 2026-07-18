// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Active LAN host discovery.
//!
//! Finding the silent devices on your own subnet without crafting raw ARP
//! frames — which would need the local MAC and elevation. Instead we lean on
//! the OS: sending a stray UDP datagram to an on-link address makes the kernel
//! resolve that address (an ARP request) and cache the result, even though the
//! datagram itself is dropped. After a short settle we read the OS neighbour
//! table back. No raw sockets, no elevation, works the same whether or not a
//! capture is running.
//!
//! Scope is deliberately the local IPv4 subnet only: that is what "who is on my
//! WiFi" means, and it keeps the sweep bounded.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::time::Duration;

/// One discovered neighbour.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Neighbour {
    pub ip: String,
    pub mac: String,
}

/// Enumerate host addresses of the IPv4 subnet `ip`/`mask`, excluding the
/// network, broadcast and `ip` itself. Capped so an accidental large mask
/// (say a /16) can't turn into a 65k-packet flood.
fn subnet_hosts(ip: Ipv4Addr, mask: Ipv4Addr) -> Vec<Ipv4Addr> {
    let ip_u = u32::from(ip);
    let mask_u = u32::from(mask);
    if mask_u == 0 {
        return Vec::new();
    }
    let network = ip_u & mask_u;
    let broadcast = network | !mask_u;
    const MAX_HOSTS: usize = 1024;
    let mut hosts = Vec::new();
    let mut addr = network + 1;
    while addr < broadcast && hosts.len() < MAX_HOSTS {
        if addr != ip_u {
            hosts.push(Ipv4Addr::from(addr));
        }
        addr += 1;
    }
    hosts
}

/// The routable IPv4 address and netmask of a capture interface. `name` empty
/// or `"__all__"` picks the first interface that has one; a specific name falls
/// back to any usable interface if the named one carries no IPv4 (common when
/// "all interfaces" maps to a virtual device). Keeps the pcap dependency inside
/// core so callers work in terms of interface names.
pub fn interface_ipv4(name: &str) -> Option<(Ipv4Addr, Ipv4Addr)> {
    let devices = crate::capture::list_interfaces().ok()?;
    let pick = |d: &pcap::Device| {
        d.addresses.iter().find_map(|a| match (a.addr, a.netmask) {
            (IpAddr::V4(ip), Some(IpAddr::V4(mask)))
                if !ip.is_loopback() && !ip.is_unspecified() =>
            {
                Some((ip, mask))
            }
            _ => None,
        })
    };
    if name.is_empty() || name == "__all__" {
        devices.iter().find_map(pick)
    } else {
        devices
            .iter()
            .find(|d| d.name == name)
            .and_then(pick)
            .or_else(|| devices.iter().find_map(pick))
    }
}

/// Convenience over [`arp_scan`]: resolve the interface's subnet by name and
/// sweep it. Returns an error string if no interface has a routable IPv4.
pub fn arp_scan_interface(name: &str) -> Result<Vec<Neighbour>, String> {
    let (ip, mask) = interface_ipv4(name).ok_or_else(|| {
        "No interface with a routable IPv4 address was found to scan.".to_string()
    })?;
    Ok(arp_scan(ip, mask))
}

/// Nudge every host in the subnet so the OS resolves and caches its MAC, then
/// read the neighbour table. `local_ip`/`netmask` come from the capture
/// interface's addresses. Returns neighbours sorted by IP.
pub fn arp_scan(local_ip: Ipv4Addr, netmask: Ipv4Addr) -> Vec<Neighbour> {
    let hosts = subnet_hosts(local_ip, netmask);

    // A dropped UDP packet to a rarely-used port is enough to trigger on-link
    // ARP resolution; bind once and reuse. Port 9 is discard.
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
        let _ = sock.set_write_timeout(Some(Duration::from_millis(50)));
        for host in &hosts {
            let _ = sock.send_to(&[0u8], (IpAddr::V4(*host), 9));
        }
    }

    // Give replies time to arrive and the cache to populate.
    std::thread::sleep(Duration::from_millis(1500));

    let network = u32::from(local_ip) & u32::from(netmask);
    let mask_u = u32::from(netmask);
    read_neighbour_table()
        .into_values()
        // BTreeMap is keyed by IP, so this is already sorted by address.
        .filter(|n| {
            n.ip.parse::<Ipv4Addr>()
                .map(|a| (u32::from(a) & mask_u) == network)
                .unwrap_or(false)
        })
        .collect()
}

/// Read the OS ARP/neighbour cache into a map keyed by IP (dedupes, sorts).
/// Platform-specific parsing; unknown platforms return empty.
fn read_neighbour_table() -> BTreeMap<String, Neighbour> {
    #[cfg(windows)]
    let raw = run("arp", &["-a"]);
    #[cfg(target_os = "linux")]
    let raw = run("ip", &["neigh", "show"]);
    #[cfg(target_os = "macos")]
    let raw = run("arp", &["-an"]);
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    let raw = String::new();

    parse_neighbours(&raw)
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn run(cmd: &str, args: &[&str]) -> String {
    std::process::Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// Parse the neighbour table from any of the supported tools. Rather than three
/// bespoke parsers, scan each line for the first IPv4 and the first MAC-shaped
/// token — every one of `arp -a`, `ip neigh` and `arp -an` puts both on one
/// line. Incomplete/placeholder entries (no real MAC) are skipped.
fn parse_neighbours(text: &str) -> BTreeMap<String, Neighbour> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let ip = line.split_whitespace().find_map(parse_v4);
        let mac = line.split_whitespace().find_map(parse_mac);
        if let (Some(ip), Some(mac)) = (ip, mac) {
            out.entry(ip.clone()).or_insert(Neighbour { ip, mac });
        }
    }
    out
}

fn parse_v4(tok: &str) -> Option<String> {
    // Windows brackets the address in some locales; strip surrounding junk.
    let t = tok.trim_matches(|c: char| c == '(' || c == ')' || c == '[' || c == ']');
    t.parse::<Ipv4Addr>().ok().map(|a| a.to_string())
}

fn parse_mac(tok: &str) -> Option<String> {
    // Accept aa:bb:cc:dd:ee:ff and Windows' aa-bb-cc-dd-ee-ff; reject the
    // all-zero / broadcast placeholders that mean "not resolved".
    let sep = if tok.contains(':') {
        ':'
    } else if tok.contains('-') {
        '-'
    } else {
        return None;
    };
    let parts: Vec<&str> = tok.split(sep).collect();
    if parts.len() != 6
        || !parts
            .iter()
            .all(|p| p.len() == 2 && u8::from_str_radix(p, 16).is_ok())
    {
        return None;
    }
    let norm = parts
        .iter()
        .map(|p| p.to_lowercase())
        .collect::<Vec<_>>()
        .join(":");
    if norm == "00:00:00:00:00:00" || norm == "ff:ff:ff:ff:ff:ff" {
        return None;
    }
    Some(norm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subnet_hosts_excludes_network_broadcast_and_self() {
        let hosts = subnet_hosts(
            Ipv4Addr::new(192, 168, 1, 61),
            Ipv4Addr::new(255, 255, 255, 0),
        );
        assert_eq!(hosts.len(), 253); // .1..=.254 minus self (.61)
        assert!(hosts.contains(&Ipv4Addr::new(192, 168, 1, 1)));
        assert!(hosts.contains(&Ipv4Addr::new(192, 168, 1, 254)));
        assert!(!hosts.contains(&Ipv4Addr::new(192, 168, 1, 0)));
        assert!(!hosts.contains(&Ipv4Addr::new(192, 168, 1, 255)));
        assert!(!hosts.contains(&Ipv4Addr::new(192, 168, 1, 61)));
    }

    #[test]
    fn subnet_hosts_capped_for_large_masks() {
        let hosts = subnet_hosts(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(255, 255, 0, 0));
        assert!(hosts.len() <= 1024);
    }

    #[test]
    fn parses_windows_arp_output() {
        let sample = "\
Interface: 192.168.1.61 --- 0xb
  Internet Address      Physical Address      Type
  192.168.1.1           e0-19-54-37-07-72     dynamic
  192.168.1.42          a4-83-e7-11-22-33     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static";
        let n = parse_neighbours(sample);
        assert_eq!(n.get("192.168.1.1").unwrap().mac, "e0:19:54:37:07:72");
        assert_eq!(n.get("192.168.1.42").unwrap().mac, "a4:83:e7:11:22:33");
        // broadcast placeholder dropped
        assert!(!n.contains_key("192.168.1.255"));
    }

    #[test]
    fn parses_linux_ip_neigh_output() {
        let sample = "\
192.168.1.1 dev wlan0 lladdr e0:19:54:37:07:72 REACHABLE
192.168.1.42 dev wlan0 lladdr a4:83:e7:11:22:33 STALE
192.168.1.99 dev wlan0 FAILED";
        let n = parse_neighbours(sample);
        assert_eq!(n.get("192.168.1.1").unwrap().mac, "e0:19:54:37:07:72");
        assert_eq!(n.len(), 2); // the FAILED entry has no MAC
    }

    #[test]
    fn rejects_unresolved_macs() {
        assert_eq!(parse_mac("00:00:00:00:00:00"), None);
        assert_eq!(parse_mac("ff-ff-ff-ff-ff-ff"), None);
        assert_eq!(
            parse_mac("a4:83:e7:11:22:33"),
            Some("a4:83:e7:11:22:33".to_string())
        );
        assert_eq!(parse_mac("not-a-mac"), None);
    }
}
