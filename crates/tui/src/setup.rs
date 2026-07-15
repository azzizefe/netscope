// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Shared capture bootstrap for the TUI and headless modes: turns the CLI
//! options into a running [`CaptureEngine`] — local interfaces, `-i -`
//! (pcap stream on stdin), Windows USBPcap devices, or a remote host over
//! SSH — plus the Wireshark-style `-a` autostop and `-b` ring-buffer
//! condition parsers.

use anyhow::{bail, Context, Result};
use crossbeam_channel::Sender;
use netscope_core::capture::{CaptureEngine, CaptureOptions, StopConditions};
use netscope_core::models::Packet;
use netscope_core::remote::RemoteSpec;
use netscope_core::rotate::RingBufferOptions;

use crate::Cli;

/// Build the engine-level options from the CLI flags.
pub fn capture_options(cli: &Cli) -> Result<CaptureOptions> {
    Ok(CaptureOptions {
        bpf_filter: cli.filter.clone(),
        output_path: cli.write.clone(),
        monitor: cli.monitor,
        stop: parse_autostop(&cli.autostop)?,
        ring: parse_ring(&cli.ring)?,
        ..Default::default()
    })
}

#[derive(Debug)]
pub struct TempFileGuard {
    pub path: std::path::PathBuf,
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Start whichever capture the CLI describes on `engine`. Returns the label
/// to show for the capture source (interface name, file, `ssh:user@host`…)
/// along with an optional temporary file guard for decrypted files.
pub fn start_capture(
    cli: &Cli,
    engine: &mut CaptureEngine,
    tx: Sender<Packet>,
) -> Result<(String, Option<TempFileGuard>)> {
    let opts = capture_options(cli)?;

    // Remote capture over SSH (sshdump-style): -f runs on the remote side.
    if let Some(host) = cli.remote_host.clone() {
        let spec = RemoteSpec {
            host,
            user: cli.remote_user.clone(),
            port: cli.remote_port,
            identity_file: cli.remote_identity.clone(),
            interface: cli.remote_interface.clone(),
            capture_filter: cli.filter.clone(),
            remote_command: cli.remote_command.clone(),
            use_sudo: cli.remote_sudo,
        };
        let label = format!("ssh:{}", spec.describe());
        let opts = CaptureOptions {
            bpf_filter: None,
            ..opts
        };
        engine.start_remote(&spec, &opts, tx)?;
        return Ok((label, None));
    }

    if let Some(iface) = cli.interface.as_deref() {
        // `-i -` reads a pcap/pcapng stream from stdin, extcap-style:
        //   ssh host "tcpdump -U -w -" | netscope -i - --headless
        if iface == "-" {
            let opts = CaptureOptions {
                bpf_filter: None, // no local BPF on a byte stream
                ..opts
            };
            engine.start_read_stream(Box::new(std::io::stdin()), "stdin", &opts, tx)?;
            return Ok(("stdin".into(), None));
        }

        let ifaces: Vec<&str> = iface
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();

        // Windows USBPcap devices capture through USBPcapCMD, not libpcap.
        if let Some(usb) = ifaces
            .iter()
            .find(|i| i.to_ascii_lowercase().starts_with(r"\\.\usbpcap"))
        {
            if ifaces.len() > 1 {
                bail!("USBPcap devices can't be combined with other interfaces in one capture");
            }
            let (program, args) = netscope_core::remote::usbpcap_capture_command(usb)?;
            let opts = CaptureOptions {
                bpf_filter: None,
                ..opts
            };
            engine.start_pipe(&program, &args, usb, &opts, tx)?;
            return Ok((usb.to_string(), None));
        }

        engine.start_with(&ifaces, &opts, tx)?;
        let label = match ifaces.as_slice() {
            [one] => netscope_core::capture::friendly_name_of(one),
            many => format!("{} interfaces", many.len()),
        };
        return Ok((label, None));
    }

    if let Some(path) = cli.read.as_deref() {
        let mut actual_path = path.to_string();
        let mut temp_guard = None;

        if let Ok(bytes) = std::fs::read(path) {
            if netscope_core::crypto::is_encrypted(&bytes) {
                use std::io::Write;
                let passphrase = if let Some(ref p) = cli.passphrase {
                    p.clone()
                } else if let Ok(p) = std::env::var("NETSCOPE_PASSPHRASE") {
                    p
                } else {
                    print!("Enter passphrase to decrypt {}: ", path);
                    let _ = std::io::stdout().flush();
                    rpassword::read_password()?
                };

                let decrypted = netscope_core::crypto::decrypt(&bytes, &passphrase)
                    .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

                let temp_dir = std::env::temp_dir();
                let temp_file_path = temp_dir.join(format!(
                    "netscope_decrypted_{}.pcap",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos()
                ));
                std::fs::write(&temp_file_path, decrypted)?;
                actual_path = temp_file_path.to_string_lossy().to_string();
                temp_guard = Some(TempFileGuard {
                    path: temp_file_path,
                });
            }
        }

        engine.start_offline(
            &actual_path,
            opts.bpf_filter.as_deref(),
            opts.output_path.as_deref(),
            tx,
        )?;
        return Ok((path.to_string(), temp_guard));
    }

    let dev = netscope_core::capture::default_interface()?;
    let label = netscope_core::capture::friendly_name(&dev);
    engine.start_with(&[dev.name.as_str()], &opts, tx)?;
    Ok((label, None))
}

/// Parse repeated `-a` conditions: `duration:SECONDS`, `packets:COUNT`,
/// `filesize:kB` (Wireshark units).
pub fn parse_autostop(conds: &[String]) -> Result<StopConditions> {
    let mut stop = StopConditions::default();
    for cond in conds {
        let (key, n) = split_condition(cond, "autostop")?;
        match key {
            "duration" => stop.duration_secs = Some(n),
            "packets" => stop.packets = Some(n),
            "filesize" => stop.bytes = Some(n.saturating_mul(1024)),
            other => bail!(
                "unknown autostop condition '{other}' — use duration:SECONDS, packets:COUNT or filesize:kB"
            ),
        }
    }
    Ok(stop)
}

/// Parse repeated `-b` conditions: `filesize:kB`, `duration:SECONDS`,
/// `files:COUNT` (Wireshark units). `None` when no `-b` was given.
pub fn parse_ring(conds: &[String]) -> Result<Option<RingBufferOptions>> {
    if conds.is_empty() {
        return Ok(None);
    }
    let mut ring = RingBufferOptions::default();
    for cond in conds {
        let (key, n) = split_condition(cond, "ring buffer")?;
        match key {
            "filesize" => ring.filesize_kb = Some(n),
            "duration" => ring.duration_secs = Some(n),
            "files" => ring.files = Some(n as usize),
            other => bail!(
                "unknown ring-buffer condition '{other}' — use filesize:kB, duration:SECONDS or files:COUNT"
            ),
        }
    }
    if !ring.rotates() {
        bail!("a ring buffer needs filesize:kB or duration:SECONDS to rotate on");
    }
    Ok(Some(ring))
}

fn split_condition<'a>(cond: &'a str, what: &str) -> Result<(&'a str, u64)> {
    let (key, value) = cond
        .split_once(':')
        .with_context(|| format!("invalid {what} condition '{cond}' — expected KEY:VALUE"))?;
    let n: u64 = value
        .trim()
        .parse()
        .with_context(|| format!("invalid number in {what} condition '{cond}'"))?;
    if n == 0 {
        bail!("{what} value must be greater than zero in '{cond}'");
    }
    Ok((key.trim(), n))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn autostop_all_conditions() {
        let s = parse_autostop(&v(&["duration:60", "packets:1000", "filesize:10"])).unwrap();
        assert_eq!(s.duration_secs, Some(60));
        assert_eq!(s.packets, Some(1000));
        assert_eq!(s.bytes, Some(10 * 1024));
    }

    #[test]
    fn autostop_rejects_junk() {
        assert!(parse_autostop(&v(&["duration"])).is_err());
        assert!(parse_autostop(&v(&["duration:abc"])).is_err());
        assert!(parse_autostop(&v(&["packets:0"])).is_err());
        assert!(parse_autostop(&v(&["bogus:5"])).is_err());
    }

    #[test]
    fn ring_conditions() {
        let r = parse_ring(&v(&["filesize:2048", "files:5"]))
            .unwrap()
            .unwrap();
        assert_eq!(r.filesize_kb, Some(2048));
        assert_eq!(r.files, Some(5));
        assert!(parse_ring(&[]).unwrap().is_none());
    }

    #[test]
    fn ring_files_alone_is_rejected() {
        let err = parse_ring(&v(&["files:5"])).err().unwrap();
        assert!(err.to_string().contains("rotate"), "{err}");
    }
}
