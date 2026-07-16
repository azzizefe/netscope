// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Declarative protocol plugins — recognise new protocols without touching
//! Rust or recompiling (ROADMAP §2.3).
//!
//! A plugin is a small TOML file dropped into `~/.netscope/plugins/`:
//!
//! ```toml
//! # ~/.netscope/plugins/redis.toml
//! name = "Redis"               # protocol column label
//! transport = "tcp"            # "tcp" or "udp"
//! ports = [6379]               # match when src or dst port is listed
//! description = "Redis key-value store wire protocol (RESP)."
//!
//! [match]                      # optional payload heuristics — all must hold
//! prefix = "*"                 # payload starts with this text…
//! # prefix_hex = "2a31"        # …or with these hex bytes (wins over prefix)
//! # contains = "PING"          # payload contains this text
//!
//! [display]
//! summary = "Redis — {first_line}"   # {name} {len} {src_port} {dst_port} {first_line}
//! ```
//!
//! Plugins run **after** every built-in dissector and **before** the generic
//! "TCP/UDP — N bytes" fallback, so they can claim unknown traffic but never
//! shadow a built-in protocol. Matched packets get
//! [`Protocol::Plugin`](crate::models::Protocol::Plugin), which flows through
//! coloring, filtering (`redis` in a display filter matches a plugin named
//! "Redis"), flows and Learn mode like any built-in.
//!
//! The registry is process-global because dissection runs on hot paths with
//! no room for threading a context through; [`load_dir`] / [`install`]
//! replace its contents atomically.

use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{OnceLock, RwLock};

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::dissectors::{first_text_line, truncate, DissectedResult};
use crate::models::{PluginProto, PluginTransport, Protocol};

/// One user-defined protocol definition, as parsed from a plugin TOML file.
#[derive(Debug, Clone, Deserialize)]
pub struct Plugin {
    /// Display name shown in the protocol column (e.g. "Redis").
    pub name: String,
    /// Transport the protocol rides on: "tcp" or "udp".
    pub transport: TransportKind,
    /// Ports that select this plugin (src or dst). Must be non-empty.
    pub ports: Vec<u16>,
    /// Optional one-liner surfaced in UIs listing loaded plugins.
    #[serde(default)]
    pub description: String,
    /// Optional payload heuristics; every stated condition must hold.
    #[serde(default, rename = "match")]
    pub matcher: Matcher,
    #[serde(default)]
    pub display: Display,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportKind {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Matcher {
    /// Payload must start with this text.
    pub prefix: String,
    /// Payload must start with these bytes, written in hex ("2a31"). When
    /// set, takes precedence over `prefix`.
    pub prefix_hex: String,
    /// Payload must contain this text somewhere.
    pub contains: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Display {
    /// Summary template. Placeholders: `{name}`, `{len}`, `{src_port}`,
    /// `{dst_port}`, `{first_line}`.
    pub summary: String,
}

impl Default for Display {
    fn default() -> Self {
        Self {
            summary: "{name} — {len} bytes".into(),
        }
    }
}

impl Plugin {
    /// Parse and validate a plugin from TOML text.
    pub fn parse(text: &str) -> Result<Self> {
        let plugin: Plugin = toml::from_str(text).context("invalid plugin TOML")?;
        if plugin.name.trim().is_empty() {
            anyhow::bail!("plugin has an empty name");
        }
        if plugin.ports.is_empty() {
            anyhow::bail!("plugin '{}' lists no ports", plugin.name);
        }
        if !plugin.matcher.prefix_hex.is_empty() {
            decode_hex(&plugin.matcher.prefix_hex).with_context(|| {
                format!("plugin '{}': prefix_hex is not valid hex", plugin.name)
            })?;
        }
        Ok(plugin)
    }

    /// Does this plugin claim a payload on the given ports?
    fn matches(&self, src_port: u16, dst_port: u16, payload: &[u8]) -> bool {
        if !self.ports.iter().any(|&p| p == src_port || p == dst_port) {
            return false;
        }
        if !self.matcher.prefix_hex.is_empty() {
            // Validated in `parse`, so decode can't fail here.
            let bytes = decode_hex(&self.matcher.prefix_hex).unwrap_or_default();
            if !payload.starts_with(&bytes) {
                return false;
            }
        } else if !self.matcher.prefix.is_empty()
            && !payload.starts_with(self.matcher.prefix.as_bytes())
        {
            return false;
        }
        if !self.matcher.contains.is_empty() {
            // SIMD-accelerated substring search (ROADMAP §4.1) — the naive
            // windows() scan was O(n·m) on every unclaimed payload.
            let needle = self.matcher.contains.as_bytes();
            if memchr::memmem::find(payload, needle).is_none() {
                return false;
            }
        }
        true
    }

    /// Render the summary template for a matched payload.
    fn summary(&self, src_port: u16, dst_port: u16, payload: &[u8]) -> String {
        self.display
            .summary
            .replace("{name}", &self.name)
            .replace("{len}", &payload.len().to_string())
            .replace("{src_port}", &src_port.to_string())
            .replace("{dst_port}", &dst_port.to_string())
            .replace("{first_line}", &truncate(&first_text_line(payload), 60))
    }
}

/// Hex string ("2a31" or "2A 31") to bytes.
fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !clean.len().is_multiple_of(2) {
        anyhow::bail!("odd number of hex digits");
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).map_err(Into::into))
        .collect()
}

// ---- Global registry -------------------------------------------------------

/// Fast-path flag: dissectors skip the registry lock entirely while no
/// plugins are installed (the overwhelmingly common case).
static ACTIVE: AtomicBool = AtomicBool::new(false);

fn registry() -> &'static RwLock<Vec<Plugin>> {
    static REGISTRY: OnceLock<RwLock<Vec<Plugin>>> = OnceLock::new();
    REGISTRY.get_or_init(|| RwLock::new(Vec::new()))
}

/// Replace the installed plugin set. An empty vector disables the hook.
pub fn install(plugins: Vec<Plugin>) {
    let mut guard = registry().write().unwrap_or_else(|e| e.into_inner());
    ACTIVE.store(!plugins.is_empty(), Ordering::Release);
    *guard = plugins;
}

/// Load every `*.toml` in `dir` and install the result, replacing whatever
/// was installed before. Files that fail to parse are skipped and reported in
/// the returned list; a missing directory simply installs nothing.
pub fn load_dir(dir: &Path) -> LoadOutcome {
    let mut outcome = LoadOutcome::default();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => {
            install(Vec::new());
            return outcome;
        }
    };
    let mut plugins = Vec::new();
    let mut paths: Vec<_> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("toml"))
        .collect();
    paths.sort();
    for path in paths {
        let label = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("plugin")
            .to_string();
        let parsed = std::fs::read_to_string(&path)
            .map_err(anyhow::Error::from)
            .and_then(|text| Plugin::parse(&text));
        match parsed {
            Ok(p) => plugins.push(p),
            Err(e) => outcome.errors.push(format!("{label}: {e:#}")),
        }
    }
    outcome.loaded = plugins.len();
    install(plugins);
    outcome
}

/// Load plugins according to a [`Config`](crate::config::Config): from its
/// plugin directory when enabled, otherwise install none.
pub fn load_from_config(cfg: &crate::config::Config) -> LoadOutcome {
    if cfg.plugins.enabled {
        load_dir(&cfg.plugins_dir())
    } else {
        install(Vec::new());
        LoadOutcome::default()
    }
}

/// Result of a [`load_dir`] pass: how many plugins installed, and per-file
/// error messages for the ones that didn't parse.
#[derive(Debug, Default, Clone)]
pub struct LoadOutcome {
    pub loaded: usize,
    pub errors: Vec<String>,
}

/// Snapshot of the installed plugins (for UI listings).
pub fn installed() -> Vec<Plugin> {
    registry().read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Dissection hook. Called by the TCP/UDP dissectors for payloads no built-in
/// dissector claimed; returns the first matching plugin's result.
pub(crate) fn try_dissect(
    transport: TransportKind,
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<DissectedResult> {
    if !ACTIVE.load(Ordering::Acquire) || payload.is_empty() {
        return None;
    }
    let guard = registry().read().unwrap_or_else(|e| e.into_inner());
    let plugin = guard
        .iter()
        .find(|p| p.transport == transport && p.matches(src_port, dst_port, payload))?;
    Some(DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Plugin(PluginProto {
            name: plugin.name.clone(),
            transport: match transport {
                TransportKind::Tcp => PluginTransport::Tcp,
                TransportKind::Udp => PluginTransport::Udp,
            },
        }),
        summary: plugin.summary(src_port, dst_port, payload),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// The registry is process-global; every test that touches it serialises
    /// on this lock and restores an empty registry before releasing it.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn with_registry(plugins: Vec<Plugin>, f: impl FnOnce()) {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        install(plugins);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        install(Vec::new());
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }

    const REDIS_TOML: &str = r#"
        name = "Redis"
        transport = "tcp"
        ports = [16379]
        description = "Redis RESP"

        [match]
        prefix = "*"

        [display]
        summary = "Redis — {first_line}"
    "#;

    #[test]
    fn parses_a_full_plugin() {
        let p = Plugin::parse(REDIS_TOML).unwrap();
        assert_eq!(p.name, "Redis");
        assert_eq!(p.transport, TransportKind::Tcp);
        assert_eq!(p.ports, vec![16379]);
        assert_eq!(p.matcher.prefix, "*");
    }

    #[test]
    fn rejects_missing_ports_and_bad_hex() {
        let err = Plugin::parse("name = \"X\"\ntransport = \"tcp\"\nports = []")
            .unwrap_err()
            .to_string();
        assert!(err.contains("no ports"), "{err}");

        let bad_hex = r#"
            name = "X"
            transport = "udp"
            ports = [9]
            [match]
            prefix_hex = "zz"
        "#;
        assert!(Plugin::parse(bad_hex).is_err());
    }

    #[test]
    fn port_and_prefix_matching() {
        let p = Plugin::parse(REDIS_TOML).unwrap();
        assert!(p.matches(50000, 16379, b"*1\r\n$4\r\nPING\r\n"));
        assert!(p.matches(16379, 50000, b"*done"));
        // Wrong port:
        assert!(!p.matches(50000, 6380, b"*1\r\n"));
        // Right port, wrong prefix:
        assert!(!p.matches(50000, 16379, b"+PONG\r\n"));
    }

    #[test]
    fn hex_prefix_and_contains() {
        let toml = r#"
            name = "MyProto"
            transport = "udp"
            ports = [17777]
            [match]
            prefix_hex = "cafe"
            contains = "hello"
        "#;
        let p = Plugin::parse(toml).unwrap();
        assert!(p.matches(1, 17777, b"\xca\xfe say hello"));
        assert!(!p.matches(1, 17777, b"\xca\xfe no greeting"));
        assert!(!p.matches(1, 17777, b"\x00\x00 hello"));
    }

    #[test]
    fn summary_template_renders() {
        let p = Plugin::parse(REDIS_TOML).unwrap();
        assert_eq!(
            p.summary(50000, 16379, b"*1\r\n$4\r\nPING\r\n"),
            "Redis — *1"
        );
    }

    #[test]
    fn tcp_dissector_uses_plugin_after_builtins() {
        use crate::dissectors::ip::dissect_ipv4;
        use crate::dissectors::tcp::dissect_tcp;
        use crate::dissectors::test_helpers::{build_tcp_packet, TcpFlags};

        with_registry(vec![Plugin::parse(REDIS_TOML).unwrap()], || {
            let data = build_tcp_packet(
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                50000,
                16379,
                TcpFlags {
                    ack: true,
                    ..Default::default()
                },
                b"*1\r\n$4\r\nPING\r\n",
            );
            let (_s, _d, _p, tcp_data) = dissect_ipv4(&data[14..]);
            let result = dissect_tcp(
                Some("10.0.0.1".parse().unwrap()),
                Some("10.0.0.2".parse().unwrap()),
                &tcp_data,
            );
            assert_eq!(
                result.protocol,
                Protocol::Plugin(PluginProto {
                    name: "Redis".into(),
                    transport: PluginTransport::Tcp,
                })
            );
            assert_eq!(result.summary, "Redis — *1");

            // An HTTP payload on the plugin's port still goes to the plugin
            // only if no built-in claims it — but HTTP heuristics only run on
            // port 80/upgrade, so this stays with the plugin's port rule…
            // whereas a WebSocket frame chain (built-in, any port) wins:
            let ws = build_tcp_packet(
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                50000,
                16379,
                TcpFlags {
                    ack: true,
                    ..Default::default()
                },
                &[0x81, 0x02, b'h', b'i'],
            );
            let (_s, _d, _p, ws_tcp) = dissect_ipv4(&ws[14..]);
            let ws_result = dissect_tcp(None, None, &ws_tcp);
            assert_eq!(ws_result.protocol, Protocol::WebSocket);
        });
    }

    #[test]
    fn udp_dissector_uses_plugin_after_builtins() {
        use crate::dissectors::ip::dissect_ipv4;
        use crate::dissectors::test_helpers::build_udp_packet;
        use crate::dissectors::udp::dissect_udp;

        let toml = r#"
            name = "GameProto"
            transport = "udp"
            ports = [17777]
            [display]
            summary = "{name} on :{dst_port} ({len} bytes)"
        "#;
        with_registry(vec![Plugin::parse(toml).unwrap()], || {
            let data = build_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 40000, 17777, b"state");
            let (_s, _d, _p, udp_data) = dissect_ipv4(&data[14..]);
            let result = dissect_udp(
                Some("10.0.0.1".parse().unwrap()),
                Some("10.0.0.2".parse().unwrap()),
                &udp_data,
            );
            assert_eq!(
                result.protocol,
                Protocol::Plugin(PluginProto {
                    name: "GameProto".into(),
                    transport: PluginTransport::Udp,
                })
            );
            assert_eq!(result.summary, "GameProto on :17777 (5 bytes)");

            // DNS on port 53 keeps beating the plugin even if it lists 53.
            let dns = crate::dissectors::test_helpers::build_dns_query("x.dev", 7);
            let dns_pkt = build_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 40000, 53, &dns);
            let (_s, _d, _p, dns_udp) = dissect_ipv4(&dns_pkt[14..]);
            let dns_result = dissect_udp(None, None, &dns_udp);
            assert_eq!(dns_result.protocol, Protocol::Dns);
        });
    }

    #[test]
    fn empty_registry_is_inert() {
        with_registry(Vec::new(), || {
            assert!(try_dissect(TransportKind::Tcp, None, None, 1, 16379, b"*1\r\n").is_none());
        });
    }

    #[test]
    fn load_dir_reads_and_reports() {
        let dir = std::env::temp_dir().join("netscope-plugins-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("redis.toml"), REDIS_TOML).unwrap();
        std::fs::write(dir.join("broken.toml"), "name = ").unwrap();
        std::fs::write(dir.join("notes.txt"), "ignored").unwrap();

        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let outcome = load_dir(&dir);
        assert_eq!(outcome.loaded, 1);
        assert_eq!(outcome.errors.len(), 1);
        assert!(
            outcome.errors[0].starts_with("broken.toml"),
            "{:?}",
            outcome.errors
        );
        assert_eq!(installed().len(), 1);

        // Missing directory clears the registry.
        let outcome = load_dir(&dir.join("missing"));
        assert_eq!(outcome.loaded, 0);
        assert!(installed().is_empty());
    }
}
