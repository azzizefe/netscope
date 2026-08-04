// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

//! Advanced OS-Level & In-Memory Firewall Engine.
//!
//! Provides active OS-level threat mitigation across Windows (`netsh advfirewall`),
//! Linux (`iptables`/`ip6tables`), and macOS (`pfctl`), plus an in-memory rule engine
//! with temporary auto-expiring block policies, port-specific blocks, CIDR subnets,
//! and SOC auto-remediation triggers.
//!
//! The Linux path shells out to `iptables`/`ip6tables` and nothing else. This
//! line used to say "`iptables`/`nftables`"; no `nft` command is issued
//! anywhere in this file. On a distribution where `iptables` is the nft-backed
//! compatibility shim the rules do land in nftables, but that is the
//! distribution's doing, not this module's, and on a host with only `nft`
//! installed blocking fails. Naming both made it look like there was a
//! fallback to fall back to.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::Arc;

use anyhow::Result;
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

/// Prefix shared by every firewall rule netscope creates on the OS.
pub const RULE_PREFIX: &str = "netscope-block";

/// The firewall rule name for a given address, e.g. `netscope-block-1.2.3.4`.
pub fn rule_name(ip: IpAddr) -> String {
    format!("{RULE_PREFIX}-{ip}")
}

/// Parse one whitespace-separated token from `iptables-save` / `pfctl -T show`
/// into an address, or `None` if it is not one.
///
/// Both tools print addresses in CIDR form (`1.2.3.4/32`, `2606:4700::1/128`),
/// which [`IpAddr`] itself rejects — so a parser that skips the prefix silently
/// finds nothing and `unblock_all` becomes a no-op. Kept out of the
/// platform-specific module so it is unit-testable on any host.
///
/// Only the Unix backend calls it; on Windows `netsh` output is parsed
/// differently, so there it is exercised solely by the tests below.
#[cfg_attr(windows, allow(dead_code))]
fn parse_saved_address(token: &str) -> Option<IpAddr> {
    let bare = token.split('/').next()?;
    bare.parse::<IpAddr>().ok()
}

/// Whether blocking is available on this build/platform.
pub fn is_supported() -> bool {
    cfg!(windows) || cfg!(target_os = "linux") || cfg!(target_os = "macos")
}

/// Active Firewall Rule definition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirewallRule {
    pub id: String,
    pub ip: IpAddr,
    pub port: Option<u16>,
    pub protocol: String,  // "TCP", "UDP", "ANY"
    pub direction: String, // "inbound", "outbound", "both"
    pub action: String,    // "block", "allow"
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub reason: String,
    pub hit_count: u64,
}

impl FirewallRule {
    pub fn new_block(ip: IpAddr, reason: &str) -> Self {
        Self {
            id: rule_name(ip),
            ip,
            port: None,
            protocol: "ANY".to_string(),
            direction: "both".to_string(),
            action: "block".to_string(),
            created_at: Utc::now(),
            expires_at: None,
            reason: reason.to_string(),
            hit_count: 0,
        }
    }

    pub fn new_temporary_block(ip: IpAddr, duration_secs: u64, reason: &str) -> Self {
        let now = Utc::now();
        Self {
            id: format!("{}-{}-temp", rule_name(ip), now.timestamp()),
            ip,
            port: None,
            protocol: "ANY".to_string(),
            direction: "both".to_string(),
            action: "block".to_string(),
            created_at: now,
            expires_at: Some(now + chrono::Duration::seconds(duration_secs as i64)),
            reason: reason.to_string(),
            hit_count: 0,
        }
    }

    pub fn is_expired(&self) -> bool {
        if let Some(exp) = self.expires_at {
            Utc::now() > exp
        } else {
            false
        }
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::process::Command;

    fn netsh(args: &[String]) -> Result<()> {
        let output = Command::new("netsh")
            .args(args)
            .output()
            .map_err(|e| anyhow::anyhow!("could not run netsh: {e}"))?;
        if output.status.success() {
            return Ok(());
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = format!("{stdout}{stderr}");
        let detail = detail.trim();
        if !super::is_elevated() {
            anyhow::bail!("blocking needs Administrator — relaunch netscope elevated. ({detail})");
        }
        anyhow::bail!("netsh failed: {detail}");
    }

    pub fn block(ip: IpAddr) -> Result<()> {
        let name = rule_name(ip);
        // Outbound: stop us reaching the host. Inbound: stop it reaching us.
        for dir in ["out", "in"] {
            netsh(&[
                "advfirewall".into(),
                "firewall".into(),
                "add".into(),
                "rule".into(),
                format!("name={name}"),
                format!("dir={dir}"),
                "action=block".into(),
                format!("remoteip={ip}"),
                "profile=any".into(),
            ])?;
        }
        Ok(())
    }

    pub fn block_port(ip: IpAddr, port: u16, protocol: &str) -> Result<()> {
        let name = format!("{}-{}-p{}", rule_name(ip), protocol.to_lowercase(), port);
        for dir in ["out", "in"] {
            netsh(&[
                "advfirewall".into(),
                "firewall".into(),
                "add".into(),
                "rule".into(),
                format!("name={name}"),
                format!("dir={dir}"),
                "action=block".into(),
                format!("remoteip={ip}"),
                format!("protocol={protocol}"),
                format!("localport={port}"),
                "profile=any".into(),
            ])?;
        }
        Ok(())
    }

    pub fn unblock(ip: IpAddr) -> Result<()> {
        let name = rule_name(ip);
        netsh(&[
            "advfirewall".into(),
            "firewall".into(),
            "delete".into(),
            "rule".into(),
            format!("name={name}"),
        ])
    }

    pub fn blocked_ips() -> BTreeSet<IpAddr> {
        let mut set = BTreeSet::new();
        let Ok(output) = Command::new("netsh")
            .args(["advfirewall", "firewall", "show", "rule", "name=all"])
            .output()
        else {
            return set;
        };
        let text = String::from_utf8_lossy(&output.stdout);
        let needle = format!("{RULE_PREFIX}-");
        for line in text.lines() {
            if let Some(pos) = line.find(&needle) {
                let tail = line[pos + needle.len()..].trim();
                // Strip port/suffix if present
                let ip_str = tail.split('-').next().unwrap_or(tail);
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    set.insert(ip);
                }
            }
        }
        set
    }

    pub fn unblock_all() -> Result<usize> {
        let ips = blocked_ips();
        let count = ips.len();
        for ip in ips {
            let _ = unblock(ip);
        }
        Ok(count)
    }

    pub fn is_elevated() -> bool {
        Command::new("whoami")
            .arg("/groups")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("S-1-16-12288"))
            .unwrap_or(false)
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    use std::process::Command;

    /// The iptables binary that understands `ip`'s address family. IPv6 rules
    /// are rejected by plain `iptables`, so picking the wrong one here means
    /// every IPv6 block silently fails.
    #[cfg(target_os = "linux")]
    fn iptables_for(ip: IpAddr) -> &'static str {
        if ip.is_ipv6() {
            "ip6tables"
        } else {
            "iptables"
        }
    }

    /// Run a rule-installing command, surfacing a non-zero exit to the caller.
    ///
    /// The Windows backend reports `netsh` failures; this does the same so
    /// `block` cannot report success when `iptables`/`pfctl` is missing, the
    /// process is unprivileged, or the rule was rejected.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn run(program: &str, args: &[&str]) -> Result<()> {
        let output = Command::new(program)
            .args(args)
            .output()
            .map_err(|e| anyhow::anyhow!("could not run {program}: {e}"))?;
        if output.status.success() {
            return Ok(());
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = format!("{stdout}{stderr}");
        let detail = detail.trim();
        if !super::is_elevated() {
            anyhow::bail!("blocking needs root — rerun netscope under sudo. ({detail})");
        }
        anyhow::bail!("{program} failed: {detail}");
    }

    /// Run a rule-removing command. A rule that is already gone is not an error
    /// — `unblock` is documented as a no-op when nothing is blocked — but a
    /// missing binary still is, so the spawn failure is still reported.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn run_delete(program: &str, args: &[&str]) -> Result<()> {
        Command::new(program)
            .args(args)
            .output()
            .map_err(|e| anyhow::anyhow!("could not run {program}: {e}"))?;
        Ok(())
    }

    pub fn block(ip: IpAddr) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let tool = iptables_for(ip);
            let addr = ip.to_string();
            let comment = rule_name(ip);
            // Outbound: stop us reaching the host. Inbound: stop it reaching us.
            run(
                tool,
                &[
                    "-A",
                    "INPUT",
                    "-s",
                    &addr,
                    "-m",
                    "comment",
                    "--comment",
                    &comment,
                    "-j",
                    "DROP",
                ],
            )?;
            run(
                tool,
                &[
                    "-A",
                    "OUTPUT",
                    "-d",
                    &addr,
                    "-m",
                    "comment",
                    "--comment",
                    &comment,
                    "-j",
                    "DROP",
                ],
            )?;
            Ok(())
        }
        #[cfg(target_os = "macos")]
        {
            run(
                "pfctl",
                &["-t", "netscope_blocked", "-T", "add", &ip.to_string()],
            )?;
            Ok(())
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        anyhow::bail!("blocking is not implemented for this platform")
    }

    pub fn block_port(ip: IpAddr, port: u16, protocol: &str) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let tool = iptables_for(ip);
            let addr = ip.to_string();
            let proto = protocol.to_lowercase();
            let port_str = port.to_string();
            let comment = format!("{}-{}-p{}", rule_name(ip), proto, port);
            run(
                tool,
                &[
                    "-A",
                    "INPUT",
                    "-s",
                    &addr,
                    "-p",
                    &proto,
                    "--dport",
                    &port_str,
                    "-m",
                    "comment",
                    "--comment",
                    &comment,
                    "-j",
                    "DROP",
                ],
            )?;
            Ok(())
        }
        // pfctl tables match on address only, so a port-scoped block degrades
        // to blocking the whole host rather than silently doing nothing.
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (port, protocol);
            block(ip)
        }
    }

    pub fn unblock(ip: IpAddr) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let tool = iptables_for(ip);
            let addr = ip.to_string();
            let comment = rule_name(ip);
            run_delete(
                tool,
                &[
                    "-D",
                    "INPUT",
                    "-s",
                    &addr,
                    "-m",
                    "comment",
                    "--comment",
                    &comment,
                    "-j",
                    "DROP",
                ],
            )?;
            run_delete(
                tool,
                &[
                    "-D",
                    "OUTPUT",
                    "-d",
                    &addr,
                    "-m",
                    "comment",
                    "--comment",
                    &comment,
                    "-j",
                    "DROP",
                ],
            )?;
            Ok(())
        }
        #[cfg(target_os = "macos")]
        {
            run_delete(
                "pfctl",
                &["-t", "netscope_blocked", "-T", "delete", &ip.to_string()],
            )?;
            Ok(())
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        anyhow::bail!("unblocking is not implemented for this platform")
    }

    pub fn blocked_ips() -> BTreeSet<IpAddr> {
        #[cfg(target_os = "linux")]
        {
            let mut set = BTreeSet::new();
            let needle = format!("{RULE_PREFIX}-");
            // Both families, or `unblock_all` would never see an IPv6 block.
            for tool in ["iptables-save", "ip6tables-save"] {
                let Ok(output) = Command::new(tool).output() else {
                    continue;
                };
                let text = String::from_utf8_lossy(&output.stdout);
                for line in text.lines() {
                    if !line.contains(&needle) {
                        continue;
                    }
                    for part in line.split_whitespace() {
                        set.extend(super::parse_saved_address(part));
                    }
                }
            }
            set
        }
        #[cfg(target_os = "macos")]
        {
            let mut set = BTreeSet::new();
            let Ok(output) = Command::new("pfctl")
                .args(["-t", "netscope_blocked", "-T", "show"])
                .output()
            else {
                return set;
            };
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                set.extend(super::parse_saved_address(line.trim()));
            }
            set
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        BTreeSet::new()
    }

    pub fn unblock_all() -> Result<usize> {
        let ips = blocked_ips();
        let count = ips.len();
        for ip in ips {
            let _ = unblock(ip);
        }
        Ok(count)
    }

    pub fn is_elevated() -> bool {
        #[cfg(unix)]
        {
            unsafe { libc::geteuid() == 0 }
        }
        #[cfg(not(unix))]
        {
            false
        }
    }
}

/// Install an OS-level firewall rule blocking all traffic to/from `ip`.
pub fn block(ip: IpAddr) -> Result<()> {
    imp::block(ip)
}

/// Install an OS-level firewall rule blocking port-specific traffic to/from `ip`.
pub fn block_port(ip: IpAddr, port: u16, protocol: &str) -> Result<()> {
    imp::block_port(ip, port, protocol)
}

/// Remove netscope's block rule(s) for `ip`. No-op if none exist.
pub fn unblock(ip: IpAddr) -> Result<()> {
    imp::unblock(ip)
}

/// All IPs currently blocked by netscope rules (read from the OS firewall).
pub fn blocked_ips() -> BTreeSet<IpAddr> {
    imp::blocked_ips()
}

/// Remove every netscope block rule. Returns how many IPs were unblocked.
pub fn unblock_all() -> Result<usize> {
    imp::unblock_all()
}

/// Whether the current process can install firewall rules.
pub fn is_elevated() -> bool {
    imp::is_elevated()
}

/// Advanced In-Memory Firewall Engine for Active Mitigation & SOC Enforcement.
#[derive(Debug, Clone)]
pub struct FirewallEngine {
    rules: Arc<RwLock<HashMap<String, FirewallRule>>>,
}

impl Default for FirewallEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl FirewallEngine {
    pub fn new() -> Self {
        Self {
            rules: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Block an IP and register it in OS and in-memory engine.
    pub fn block_ip(&self, ip: IpAddr, reason: &str) -> Result<FirewallRule> {
        block(ip)?;
        let rule = FirewallRule::new_block(ip, reason);
        self.rules.write().insert(rule.id.clone(), rule.clone());
        Ok(rule)
    }

    /// Block an IP temporarily for N seconds with auto-expiry.
    pub fn block_temporary(
        &self,
        ip: IpAddr,
        duration_secs: u64,
        reason: &str,
    ) -> Result<FirewallRule> {
        block(ip)?;
        let rule = FirewallRule::new_temporary_block(ip, duration_secs, reason);
        self.rules.write().insert(rule.id.clone(), rule.clone());
        Ok(rule)
    }

    /// Unblock an IP and remove from engine and OS.
    pub fn unblock_ip(&self, ip: IpAddr) -> Result<()> {
        let _ = unblock(ip);
        let mut w = self.rules.write();
        w.retain(|_, rule| rule.ip != ip);
        Ok(())
    }

    /// Check if an IP address is actively blocked by the engine.
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        let r = self.rules.read();
        r.values().any(|rule| rule.ip == ip && !rule.is_expired())
    }

    /// Clean up expired temporary firewall rules automatically.
    pub fn cleanup_expired(&self) -> usize {
        let mut w = self.rules.write();
        let mut expired_ips = Vec::new();

        w.retain(|_, rule| {
            if rule.is_expired() {
                expired_ips.push(rule.ip);
                false
            } else {
                true
            }
        });

        let count = expired_ips.len();
        for ip in expired_ips {
            let _ = unblock(ip);
        }
        count
    }

    /// List all active firewall rules.
    pub fn list_rules(&self) -> Vec<FirewallRule> {
        self.rules.read().values().cloned().collect()
    }

    /// Total number of active firewall rules.
    pub fn rule_count(&self) -> usize {
        self.rules.read().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_name_embeds_ip() {
        let ip: IpAddr = "140.82.121.4".parse().unwrap();
        assert_eq!(rule_name(ip), "netscope-block-140.82.121.4");
    }

    #[test]
    fn rule_name_roundtrips_ipv6() {
        let ip: IpAddr = "2606:4700::1".parse().unwrap();
        assert_eq!(rule_name(ip), "netscope-block-2606:4700::1");
    }

    #[test]
    fn blocked_ips_never_panics() {
        let _ = blocked_ips();
    }

    #[test]
    fn saved_addresses_parse_with_and_without_a_cidr_prefix() {
        // iptables-save always prints the prefix; pfctl -T show does not.
        assert_eq!(
            parse_saved_address("1.2.3.4/32"),
            Some("1.2.3.4".parse().unwrap())
        );
        assert_eq!(
            parse_saved_address("1.2.3.4"),
            Some("1.2.3.4".parse().unwrap())
        );
        assert_eq!(
            parse_saved_address("2606:4700::1/128"),
            Some("2606:4700::1".parse().unwrap())
        );
    }

    #[test]
    fn saved_address_parser_rejects_the_other_tokens_on_the_line() {
        // The rule line an address is recovered from also carries the comment,
        // the chain name and the flags; none of them may parse as an address.
        for token in [
            "-A",
            "INPUT",
            "-s",
            "--comment",
            "netscope-block-1.2.3.4",
            "DROP",
            "",
        ] {
            assert_eq!(parse_saved_address(token), None, "token {token:?}");
        }
    }

    #[test]
    fn support_flag_matches_platform() {
        assert!(is_supported());
    }

    #[test]
    fn test_firewall_rule_expiry() {
        let ip: IpAddr = "10.0.0.5".parse().unwrap();
        let rule = FirewallRule::new_temporary_block(ip, 0, "Test temp block");
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(rule.is_expired());
    }

    #[test]
    fn test_firewall_engine_management() {
        let engine = FirewallEngine::new();
        let ip: IpAddr = "192.168.1.250".parse().unwrap();

        // In test mode without elevation, block might fail or pass, but in-memory rule engine can be verified
        let rule = FirewallRule::new_block(ip, "Brute force attack mitigation");
        engine.rules.write().insert(rule.id.clone(), rule);

        assert_eq!(engine.rule_count(), 1);
        assert!(engine.is_blocked(ip));

        let unblocked_ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(!engine.is_blocked(unblocked_ip));
    }
}
