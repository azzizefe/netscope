//! Blocking traffic by remote IP.
//!
//! netscope captures passively (libpcap/Npcap can't drop packets inline), so
//! "blocking" here means installing an OS-level firewall rule that stops
//! *future* traffic to/from an address. On Windows that's a pair of
//! `netsh advfirewall` rules; the rule name carries the IP so we can find and
//! remove our own rules later without parsing localized output.
//!
//! Rules are tagged `netscope-block-<ip>` and persist until removed (via
//! [`unblock`], `--unblock-all`, or Windows Firewall itself). Blocking needs
//! administrator/root privileges — see [`is_elevated`].

use std::collections::BTreeSet;
use std::net::IpAddr;

use anyhow::Result;

/// Prefix shared by every firewall rule netscope creates.
pub const RULE_PREFIX: &str = "netscope-block";

/// The firewall rule name for a given address, e.g. `netscope-block-1.2.3.4`.
/// Locale-independent: the value is identical on every Windows language.
pub fn rule_name(ip: IpAddr) -> String {
    format!("{RULE_PREFIX}-{ip}")
}

/// Whether blocking is available on this build/platform.
pub fn is_supported() -> bool {
    cfg!(windows)
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
        // Match on the rule-name value, which contains our prefix and is not
        // localized, so this works on Turkish/English/any Windows.
        let text = String::from_utf8_lossy(&output.stdout);
        let needle = format!("{RULE_PREFIX}-");
        for line in text.lines() {
            if let Some(pos) = line.find(&needle) {
                let tail = line[pos + needle.len()..].trim();
                if let Ok(ip) = tail.parse::<IpAddr>() {
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
        // High Mandatory Level SID (S-1-16-12288) appears in an elevated
        // token. The SID string is constant across Windows languages.
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

    pub fn block(_ip: IpAddr) -> Result<()> {
        anyhow::bail!("blocking is currently implemented for Windows only")
    }
    pub fn unblock(_ip: IpAddr) -> Result<()> {
        anyhow::bail!("blocking is currently implemented for Windows only")
    }
    pub fn blocked_ips() -> BTreeSet<IpAddr> {
        BTreeSet::new()
    }
    pub fn unblock_all() -> Result<usize> {
        Ok(0)
    }
    pub fn is_elevated() -> bool {
        // On Unix, treat root (uid 0) as elevated.
        std::env::var("USER").map(|u| u == "root").unwrap_or(false)
    }
}

/// Install a firewall rule blocking all traffic to/from `ip`.
/// Requires elevation; returns a descriptive error otherwise.
pub fn block(ip: IpAddr) -> Result<()> {
    imp::block(ip)
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
        // Reads the real firewall; must return cleanly whether or not any
        // netscope rules exist and regardless of privileges.
        let _ = blocked_ips();
    }

    #[test]
    fn support_flag_matches_platform() {
        assert_eq!(is_supported(), cfg!(windows));
    }
}
