// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Multicast DNS and DNS service discovery — what is announcing itself on a LAN.
//!
//! Every printer, television, speaker, phone and laptop on a home or office
//! network shouts about itself on UDP 5353, and it does so in the clear. So this
//! is the most direct answer available to "what is actually on this network" —
//! not a MAC address to look up, but the device saying `Kitchen HomePod` and
//! `_airplay._tcp` about itself.
//!
//! The wire format is ordinary DNS, but the names carry the meaning: a service
//! instance is `<instance>._<service>._<protocol>.local`, and splitting it back
//! into those parts is what turns a query into "someone is looking for printers".

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// What a service type is for, in words rather than in its wire name. Restricted
/// to types common enough to be worth translating; anything else keeps the name
/// it announced, which is already readable.
fn service_purpose(service: &str) -> Option<&'static str> {
    Some(match service {
        "_airplay" => "AirPlay",
        "_raop" => "AirPlay audio",
        "_googlecast" => "Chromecast",
        "_spotify-connect" => "Spotify Connect",
        "_ipp" | "_ipps" => "printing",
        "_pdl-datastream" => "printing",
        "_printer" => "printing",
        "_scanner" | "_uscan" | "_uscans" => "scanning",
        "_smb" => "Windows file sharing",
        "_afpovertcp" => "Apple file sharing",
        "_nfs" => "NFS",
        "_ssh" => "SSH",
        "_sftp-ssh" => "SFTP",
        "_http" | "_https" => "a web interface",
        "_homekit" | "_hap" => "HomeKit",
        "_matter" | "_matterc" | "_matterd" => "Matter smart home",
        "_companion-link" => "Apple device pairing",
        "_rdlink" | "_sleep-proxy" => "Apple device services",
        "_workstation" => "a workstation announcement",
        "_device-info" => "device information",
        "_googlezone" | "_googlerpc" => "Google device services",
        "_amzn-wplay" => "Amazon device",
        "_sonos" => "Sonos",
        "_daap" | "_dacp" => "iTunes sharing",
        "_touch-able" => "Apple TV remote",
        "_teamviewer" => "TeamViewer",
        "_adb-tls-connect" => "Android debugging",
        _ => return None,
    })
}

/// A service instance name split into what it is and what it is called.
struct Instance {
    /// The friendly name the device chose, when there is one.
    label: Option<String>,
    /// The service type, e.g. `_airplay`.
    service: String,
}

/// Split `Kitchen Speaker._airplay._tcp.local` into its parts.
///
/// A bare service type (`_airplay._tcp.local`, which is what a browse query
/// asks for) has no instance label, and saying so is the difference between
/// "someone is looking for speakers" and "a speaker is here".
fn split_instance(name: &str) -> Option<Instance> {
    let name = name.trim_end_matches('.');
    let stripped = name
        .strip_suffix(".local")
        .or_else(|| name.strip_suffix(".local."))?;
    // The transport label is the last component.
    let rest = stripped
        .strip_suffix("._tcp")
        .or_else(|| stripped.strip_suffix("._udp"))?;
    // What remains is either "_service" or "instance._service".
    let (label, service) = match rest.rfind("._") {
        Some(at) => (Some(rest[..at].to_string()), rest[at + 1..].to_string()),
        None => (None, rest.to_string()),
    };
    if !service.starts_with('_') {
        return None;
    }
    Some(Instance { label, service })
}

/// Describe one service name as a phrase.
fn describe_instance(name: &str) -> Option<String> {
    let parsed = split_instance(name)?;
    let what = match service_purpose(&parsed.service) {
        Some(purpose) => purpose.to_string(),
        None => parsed.service.clone(),
    };
    Some(match parsed.label {
        Some(label) => format!("{label} ({what})"),
        None => what,
    })
}

/// Dissect an mDNS message (UDP 5353).
pub fn dissect_mdns(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let result = |summary: String| DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Mdns,
        summary,
    };

    let Ok(pkt) = dns_parser::Packet::parse(payload) else {
        return result(format!("mDNS ({})", super::bytes(payload.len() as u64)));
    };

    // A query is a device looking for something; a response is a device saying
    // what it is. The second is far more useful and deserves to lead.
    if pkt.header.query {
        let names: Vec<String> = pkt
            .questions
            .iter()
            .filter_map(|q| describe_instance(&q.qname.to_string()))
            .collect();
        return result(match names.first() {
            Some(first) if names.len() > 1 => {
                format!("mDNS query — {first} (+{} more)", names.len() - 1)
            }
            Some(first) => format!("mDNS query — {first}"),
            None => match pkt.questions.first() {
                Some(q) => format!("mDNS query — {}", super::truncate(&q.qname.to_string(), 60)),
                None => "mDNS query".to_string(),
            },
        });
    }

    // Prefer a record that names an instance over one that only names a type,
    // because the instance is the device telling you what it is called.
    let mut best: Option<String> = None;
    let mut count = 0usize;
    for record in pkt.answers.iter().chain(pkt.additional.iter()) {
        let Some(parsed) = split_instance(&record.name.to_string()) else {
            continue;
        };
        count += 1;
        let named = parsed.label.is_some();
        if best.is_none() || (named && !best.as_ref().is_some_and(|b| b.contains('('))) {
            best = describe_instance(&record.name.to_string());
        }
    }

    result(match best {
        Some(text) if count > 1 => format!("mDNS announcement — {text} (+{} more)", count - 1),
        Some(text) => format!("mDNS announcement — {text}"),
        None => match pkt.answers.first() {
            Some(a) => format!(
                "mDNS response — {}",
                super::truncate(&a.name.to_string(), 60)
            ),
            None => "mDNS response".to_string(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a DNS name.
    fn name(n: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for part in n.split('.') {
            out.push(part.len() as u8);
            out.extend_from_slice(part.as_bytes());
        }
        out.push(0);
        out
    }

    /// A query for the given service name.
    fn query(n: &str) -> Vec<u8> {
        let mut buf = vec![0x00, 0x00, 0x00, 0x00];
        buf.extend_from_slice(&[0x00, 0x01]); // questions: 1
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        buf.extend_from_slice(&name(n));
        buf.extend_from_slice(&[0x00, 0x0C, 0x00, 0x01]); // PTR, IN
        buf
    }

    /// A response whose answer is a PTR record for the given name.
    fn response(n: &str, target: &str) -> Vec<u8> {
        let mut buf = vec![0x00, 0x00, 0x84, 0x00];
        buf.extend_from_slice(&[0x00, 0x00]); // questions: 0
        buf.extend_from_slice(&[0x00, 0x01]); // answers: 1
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        buf.extend_from_slice(&name(n));
        buf.extend_from_slice(&[0x00, 0x0C, 0x00, 0x01]); // PTR, IN
        buf.extend_from_slice(&[0x00, 0x00, 0x11, 0x94]); // TTL
        let target = name(target);
        buf.extend_from_slice(&(target.len() as u16).to_be_bytes());
        buf.extend_from_slice(&target);
        buf
    }

    /// The point of the whole dissector: a device saying what it is called and
    /// what it does, in the clear, without anything having to be looked up.
    #[test]
    fn an_announcement_names_the_device_and_what_it_offers() {
        let p = response("Kitchen Speaker._airplay._tcp.local", "speaker.local");
        let r = dissect_mdns(None, None, 5353, 5353, &p);
        assert_eq!(r.protocol, Protocol::Mdns);
        assert_eq!(r.summary, "mDNS announcement — Kitchen Speaker (AirPlay)");
    }

    /// A browse query asks for a service type with no instance, and reading it
    /// as an announcement would report a device that is not there.
    #[test]
    fn a_browse_query_is_not_read_as_a_device() {
        let r = dissect_mdns(None, None, 5353, 5353, &query("_ipp._tcp.local"));
        assert_eq!(r.summary, "mDNS query — printing");
        assert!(!r.summary.contains("announcement"));
    }

    /// A query for a specific instance is a device being looked for by name.
    #[test]
    fn a_query_can_name_an_instance() {
        let r = dissect_mdns(None, None, 5353, 5353, &query("Office HP._ipp._tcp.local"));
        assert_eq!(r.summary, "mDNS query — Office HP (printing)");
    }

    /// The service type says what a device is for, which is the part a reader
    /// cannot infer from a name like "living-room-2".
    #[test]
    fn common_service_types_are_translated() {
        for (service, expected) in [
            ("_googlecast", "Chromecast"),
            ("_smb", "Windows file sharing"),
            ("_ssh", "SSH"),
            ("_hap", "HomeKit"),
            ("_uscan", "scanning"),
        ] {
            let n = format!("Thing.{service}._tcp.local");
            let r = dissect_mdns(None, None, 5353, 5353, &response(&n, "x.local"));
            assert!(r.summary.contains(expected), "{service}: {}", r.summary);
        }
    }

    /// An unknown service keeps the name it announced, which is already
    /// readable, rather than being dropped or guessed at.
    #[test]
    fn an_unknown_service_keeps_its_announced_name() {
        let p = response("Thing._weirdproto._tcp.local", "x.local");
        let r = dissect_mdns(None, None, 5353, 5353, &p);
        assert_eq!(r.summary, "mDNS announcement — Thing (_weirdproto)");
    }

    /// A name that is not a service instance must not be forced into the
    /// instance-service-transport shape.
    #[test]
    fn a_plain_hostname_is_not_split_into_a_service() {
        assert!(split_instance("laptop.local").is_none());
        assert!(split_instance("example.com").is_none());
        assert!(split_instance("").is_none());
        // A transport label with no service is not an instance either.
        assert!(split_instance("_tcp.local").is_none());
    }

    /// The service type is the *last* underscore label, not the first. DNS-SD
    /// subtype browsing puts another one in front — `_universal._sub._ipp._tcp`
    /// asks for printers supporting a subtype — and searching from the left
    /// would report the service as `_sub._ipp`, which is not a service at all.
    #[test]
    fn the_split_takes_the_last_underscore_label_not_the_first() {
        let parsed = split_instance("_universal._sub._ipp._tcp.local").unwrap();
        assert_eq!(parsed.service, "_ipp");
        assert_eq!(parsed.label.unwrap(), "_universal._sub");

        let r = dissect_mdns(
            None,
            None,
            5353,
            5353,
            &query("_universal._sub._ipp._tcp.local"),
        );
        assert!(r.summary.contains("printing"), "{}", r.summary);
    }

    /// An instance label may contain dots and spaces of its own.
    #[test]
    fn an_instance_label_may_contain_dots() {
        let parsed = split_instance("Ed's MacBook Pro (2).._airplay._tcp.local").unwrap();
        assert_eq!(parsed.service, "_airplay");
        assert!(parsed.label.unwrap().starts_with("Ed's MacBook Pro"));
    }

    #[test]
    fn malformed_input_does_not_panic() {
        let r = dissect_mdns(None, None, 5353, 5353, &[0xFF; 3]);
        assert!(r.summary.starts_with("mDNS"), "{}", r.summary);
        let r = dissect_mdns(None, None, 5353, 5353, &[]);
        assert!(r.summary.starts_with("mDNS"), "{}", r.summary);
    }
}
