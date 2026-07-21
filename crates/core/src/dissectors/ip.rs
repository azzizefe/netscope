// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(Hash, PartialEq, Eq, Clone, Debug)]
struct DefragKey {
    src: IpAddr,
    dst: IpAddr,
    id: u32,
    proto: u8,
}

struct Fragment {
    offset: usize,
    data: Vec<u8>,
}

struct Reassembly {
    fragments: Vec<Fragment>,
    total_len: Option<usize>,
    inserted_at: Instant,
}

static DEFRAGMENTER: OnceLock<Mutex<HashMap<DefragKey, Reassembly>>> = OnceLock::new();

fn get_defragmenter() -> &'static Mutex<HashMap<DefragKey, Reassembly>> {
    DEFRAGMENTER.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn dissect_ipv4(data: &[u8]) -> (Option<IpAddr>, Option<IpAddr>, Option<u8>, Vec<u8>) {
    let header = match etherparse::Ipv4Header::from_slice(data) {
        Ok((h, rest)) => (h, rest.to_vec()),
        Err(_) => return (None, None, None, Vec::new()),
    };

    let (h, rest) = header;
    let src = IpAddr::V4(Ipv4Addr::from(h.source));
    let dst = IpAddr::V4(Ipv4Addr::from(h.destination));
    let proto = h.protocol.0;

    let fragment_offset = ((h.fragment_offset.value() & 0x1fff) as usize) * 8;
    let more_fragments = h.more_fragments;

    if fragment_offset > 0 || more_fragments {
        let key = DefragKey {
            src,
            dst,
            id: h.identification as u32,
            proto,
        };

        let mut defrag = get_defragmenter().lock().unwrap();
        let now = Instant::now();
        defrag.retain(|_, val| now.duration_since(val.inserted_at) < Duration::from_secs(30));

        let entry = defrag.entry(key.clone()).or_insert_with(|| Reassembly {
            fragments: Vec::new(),
            total_len: None,
            inserted_at: now,
        });

        if !entry.fragments.iter().any(|f| f.offset == fragment_offset) {
            entry.fragments.push(Fragment {
                offset: fragment_offset,
                data: rest.clone(),
            });
        }

        if !more_fragments {
            entry.total_len = Some(fragment_offset + rest.len());
        }

        if let Some(total) = entry.total_len {
            entry.fragments.sort_by_key(|f| f.offset);

            let mut expected_offset = 0;
            let mut complete = true;
            for frag in &entry.fragments {
                if frag.offset == expected_offset {
                    expected_offset += frag.data.len();
                } else if frag.offset < expected_offset {
                    if frag.offset + frag.data.len() > expected_offset {
                        expected_offset = frag.offset + frag.data.len();
                    }
                } else {
                    complete = false;
                    break;
                }
            }

            if complete && expected_offset >= total {
                let mut reassembled = vec![0u8; total];
                for frag in &entry.fragments {
                    let end = (frag.offset + frag.data.len()).min(total);
                    if end > frag.offset {
                        let len = end - frag.offset;
                        reassembled[frag.offset..end].copy_from_slice(&frag.data[..len]);
                    }
                }
                defrag.remove(&key);
                return (Some(src), Some(dst), Some(proto), reassembled);
            }
        }

        (Some(src), Some(dst), Some(proto), Vec::new())
    } else {
        (Some(src), Some(dst), Some(proto), rest)
    }
}

/// IPv6 extension headers that sit between the fixed header and the transport
/// protocol, and can simply be stepped over.
///
/// Each carries its own next-header byte and a length, so the chain is a linked
/// list. Not walking it is not a harmless omission: a hop-by-hop options header
/// is what carries the router-alert option that MLD requires, so every
/// multicast-listener message on an IPv6 network would otherwise be reported as
/// "IP protocol 0" with the extension header mistaken for its payload.
const EXT_HOP_BY_HOP: u8 = 0;
const EXT_ROUTING: u8 = 43;
const EXT_DEST_OPTIONS: u8 = 60;
const EXT_MOBILITY: u8 = 135;
const EXT_HIP: u8 = 139;
const EXT_SHIM6: u8 = 140;
/// Authentication headers measure their length differently from the rest.
const EXT_AUTH: u8 = 51;
/// "No next header" ends the chain with nothing after it.
const NO_NEXT_HEADER: u8 = 59;

/// A chain longer than this is not something a real packet does; the cap keeps
/// a malformed one from spinning.
const MAX_EXTENSION_HEADERS: usize = 8;

/// Step over the extension headers, returning the protocol that follows and the
/// payload starting at it.
///
/// The fragment header is deliberately left in place: reassembly needs it, and
/// the caller handles it.
/// How long one extension header is, or `None` if `next_header` is not one.
///
/// Shared with [`crate::dissectors::srv6`], which walks the same chain looking
/// for the segment routing header. Keeping the length rule in one place is the
/// point: the authentication header measures itself differently from every
/// other extension header, and two copies of that rule would drift.
pub(crate) fn ext_header_len(next_header: u8, payload: &[u8]) -> Option<usize> {
    match next_header {
        EXT_HOP_BY_HOP | EXT_ROUTING | EXT_DEST_OPTIONS | EXT_MOBILITY | EXT_HIP | EXT_SHIM6 => {
            // Length is in 8-octet units, not counting the first 8 bytes.
            payload.get(1).map(|&len| (len as usize + 1) * 8)
        }
        EXT_AUTH => {
            // The authentication header counts 4-octet units and excludes two
            // of them, which is a different rule from every other extension
            // header.
            payload.get(1).map(|&len| (len as usize + 2) * 4)
        }
        _ => None,
    }
}

fn skip_extension_headers(mut next_header: u8, mut payload: &[u8]) -> (u8, &[u8]) {
    for _ in 0..MAX_EXTENSION_HEADERS {
        if next_header == NO_NEXT_HEADER {
            return (next_header, &[]);
        }
        // Anything that is not an extension header is the transport protocol,
        // or a fragment header the caller deals with.
        let Some(length) = ext_header_len(next_header, payload) else {
            return (next_header, payload);
        };
        let Some(&following) = payload.first() else {
            return (next_header, payload);
        };
        let Some(rest) = payload.get(length..) else {
            return (following, &[]);
        };
        next_header = following;
        payload = rest;
    }
    (next_header, payload)
}

pub fn dissect_ipv6(data: &[u8]) -> (Option<IpAddr>, Option<IpAddr>, Option<u8>, Vec<u8>) {
    let header = match etherparse::Ipv6Header::from_slice(data) {
        Ok((h, rest)) => (h, rest.to_vec()),
        Err(_) => return (None, None, None, Vec::new()),
    };

    let (h, rest) = header;
    let src = IpAddr::V6(Ipv6Addr::from(h.source));
    let dst = IpAddr::V6(Ipv6Addr::from(h.destination));
    // Walk past any extension headers before deciding what the transport is.
    let (next_header, stripped) = skip_extension_headers(h.next_header.0, &rest);
    let payload = stripped.to_vec();

    if next_header == 44 {
        if payload.len() < 8 {
            return (Some(src), Some(dst), Some(next_header), Vec::new());
        }
        let next_proto = payload[0];
        let offset_m = u16::from_be_bytes([payload[2], payload[3]]);
        let fragment_offset = ((offset_m >> 3) * 8) as usize;
        let more_fragments = (offset_m & 1) != 0;
        let identification = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let frag_data = payload[8..].to_vec();

        let key = DefragKey {
            src,
            dst,
            id: identification,
            proto: next_proto,
        };

        let mut defrag = get_defragmenter().lock().unwrap();
        let now = Instant::now();
        defrag.retain(|_, val| now.duration_since(val.inserted_at) < Duration::from_secs(30));

        let entry = defrag.entry(key.clone()).or_insert_with(|| Reassembly {
            fragments: Vec::new(),
            total_len: None,
            inserted_at: now,
        });

        if !entry.fragments.iter().any(|f| f.offset == fragment_offset) {
            entry.fragments.push(Fragment {
                offset: fragment_offset,
                data: frag_data.clone(),
            });
        }

        if !more_fragments {
            entry.total_len = Some(fragment_offset + frag_data.len());
        }

        if let Some(total) = entry.total_len {
            entry.fragments.sort_by_key(|f| f.offset);

            let mut expected_offset = 0;
            let mut complete = true;
            for frag in &entry.fragments {
                if frag.offset == expected_offset {
                    expected_offset += frag.data.len();
                } else if frag.offset < expected_offset {
                    if frag.offset + frag.data.len() > expected_offset {
                        expected_offset = frag.offset + frag.data.len();
                    }
                } else {
                    complete = false;
                    break;
                }
            }

            if complete && expected_offset >= total {
                let mut reassembled = vec![0u8; total];
                for frag in &entry.fragments {
                    let end = (frag.offset + frag.data.len()).min(total);
                    if end > frag.offset {
                        let len = end - frag.offset;
                        reassembled[frag.offset..end].copy_from_slice(&frag.data[..len]);
                    }
                }
                defrag.remove(&key);
                return (Some(src), Some(dst), Some(next_proto), reassembled);
            }
        }

        return (Some(src), Some(dst), Some(next_proto), Vec::new());
    }

    (Some(src), Some(dst), Some(next_header), payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::{IpNumber, Ipv6FlowLabel};

    /// MLD is IPv6's multicast group membership protocol and is on every IPv6
    /// network. It always arrives behind a hop-by-hop router-alert header, so
    /// without walking the extension chain it is invisible: the hop-by-hop
    /// header would be reported as "IP protocol 0" and its own bytes mistaken
    /// for the payload.
    #[test]
    fn hop_by_hop_header_is_stepped_over_to_reach_mld() {
        // Hop-by-hop: next header 58 (ICMPv6), length 0 (meaning 8 bytes),
        // then the router-alert option.
        let hop_by_hop = [58u8, 0, 0x05, 0x02, 0x00, 0x00, 0x01, 0x00];
        // MLDv2 report.
        let icmpv6 = [143u8, 0, 0, 0];

        let mut payload = hop_by_hop.to_vec();
        payload.extend_from_slice(&icmpv6);

        let (proto, rest) = skip_extension_headers(0, &payload);
        assert_eq!(proto, 58, "should have reached ICMPv6");
        assert_eq!(rest, &icmpv6, "payload should start at the ICMPv6 header");
    }

    /// Several extension headers can be chained, and each has to be stepped
    /// over in turn.
    #[test]
    fn a_chain_of_extension_headers_is_walked() {
        // Hop-by-hop, then destination options, then TCP.
        let mut payload = vec![60u8, 0, 0, 0, 0, 0, 0, 0]; // hop-by-hop → dest opts
        payload.extend_from_slice(&[6u8, 0, 0, 0, 0, 0, 0, 0]); // dest opts → TCP
        payload.extend_from_slice(&[0xAA; 20]); // the TCP header
        let (proto, rest) = skip_extension_headers(0, &payload);
        assert_eq!(proto, 6, "should have reached TCP");
        assert_eq!(rest.len(), 20);
    }

    /// The authentication header measures its length in different units from
    /// every other extension header; using the common rule would land in the
    /// middle of the payload.
    #[test]
    fn authentication_header_uses_its_own_length_rule() {
        // AH with length 4 means (4 + 2) * 4 = 24 bytes.
        let mut payload = vec![17u8, 4]; // next header UDP, length 4
        payload.extend_from_slice(&[0u8; 22]);
        payload.extend_from_slice(&[0xBB; 8]); // the UDP header
        let (proto, rest) = skip_extension_headers(51, &payload);
        assert_eq!(proto, 17, "should have reached UDP");
        assert_eq!(rest.len(), 8);
    }

    /// A transport protocol is returned untouched — the walk must not consume
    /// the header it was looking for.
    #[test]
    fn a_transport_protocol_is_left_alone() {
        let tcp = [0xAA; 20];
        let (proto, rest) = skip_extension_headers(6, &tcp);
        assert_eq!(proto, 6);
        assert_eq!(rest, &tcp);
    }

    /// The fragment header is deliberately not stepped over, because
    /// reassembly needs it.
    #[test]
    fn fragment_header_is_left_for_the_caller() {
        let frag = [58u8, 0, 0, 0, 0, 0, 0, 1];
        let (proto, rest) = skip_extension_headers(44, &frag);
        assert_eq!(proto, 44);
        assert_eq!(rest, &frag);
    }

    /// A malformed chain must terminate rather than spin.
    #[test]
    fn a_malformed_chain_terminates() {
        // Every header points at another hop-by-hop, forever.
        let payload = vec![0u8; 256];
        let (_, rest) = skip_extension_headers(0, &payload);
        assert!(rest.len() <= payload.len());
    }

    #[test]
    fn no_next_header_ends_the_chain() {
        let (proto, rest) = skip_extension_headers(59, &[0xAA; 8]);
        assert_eq!(proto, 59);
        assert!(rest.is_empty());
    }

    #[test]
    fn ipv4_valid() {
        let mut buf = Vec::new();
        let ip = etherparse::Ipv4Header::new(
            0,
            64,
            etherparse::IpNumber::TCP,
            [192, 168, 1, 1],
            [192, 168, 1, 2],
        )
        .unwrap();
        ip.write(&mut buf).unwrap();
        buf.extend_from_slice(b"PAYLOAD");

        let (src, dst, proto, payload) = dissect_ipv4(&buf);
        assert_eq!(src, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert_eq!(dst, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))));
        assert_eq!(proto, Some(6)); // TCP
        assert_eq!(&payload, b"PAYLOAD");
    }

    #[test]
    fn ipv4_too_short() {
        let (src, dst, proto, payload) = dissect_ipv4(&[0; 5]);
        assert!(src.is_none());
        assert!(dst.is_none());
        assert!(proto.is_none());
        assert!(payload.is_empty());
    }

    #[test]
    fn ipv6_valid() {
        let mut buf = Vec::new();
        let ip = etherparse::Ipv6Header {
            traffic_class: 0,
            flow_label: Ipv6FlowLabel::default(),
            payload_length: 7,
            next_header: IpNumber::UDP,
            hop_limit: 64,
            source: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            destination: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
        };
        ip.write(&mut buf).unwrap();
        buf.extend_from_slice(b"PAYLOAD");

        let (src, dst, proto, payload) = dissect_ipv6(&buf);
        assert_eq!(src, Some(IpAddr::V6("2001:db8::1".parse().unwrap())));
        assert_eq!(dst, Some(IpAddr::V6("2001:db8::2".parse().unwrap())));
        assert_eq!(proto, Some(17)); // UDP
        assert_eq!(&payload, b"PAYLOAD");
    }

    #[test]
    fn ipv6_too_short() {
        let (src, dst, proto, payload) = dissect_ipv6(&[0; 10]);
        assert!(src.is_none());
        assert!(dst.is_none());
        assert!(proto.is_none());
        assert!(payload.is_empty());
    }

    #[test]
    fn ipv4_defragmentation() {
        let mut f1_buf = Vec::new();
        let mut ip1 = etherparse::Ipv4Header::new(
            0,
            64,
            etherparse::IpNumber::TCP,
            [192, 168, 1, 1],
            [192, 168, 1, 2],
        )
        .unwrap();
        ip1.identification = 42;
        ip1.fragment_offset = etherparse::IpFragOffset::try_from(0).unwrap();
        ip1.more_fragments = true;
        ip1.write(&mut f1_buf).unwrap();
        f1_buf.extend_from_slice(b"PART1___"); // 8 bytes

        let mut f2_buf = Vec::new();
        let mut ip2 = etherparse::Ipv4Header::new(
            0,
            64,
            etherparse::IpNumber::TCP,
            [192, 168, 1, 1],
            [192, 168, 1, 2],
        )
        .unwrap();
        ip2.identification = 42;
        ip2.fragment_offset = etherparse::IpFragOffset::try_from(1).unwrap(); // 1 * 8 = 8 bytes
        ip2.more_fragments = false;
        ip2.write(&mut f2_buf).unwrap();
        f2_buf.extend_from_slice(b"PART2");

        let (src, dst, proto, payload1) = dissect_ipv4(&f1_buf);
        assert_eq!(src, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert_eq!(dst, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))));
        assert_eq!(proto, Some(6));
        assert!(payload1.is_empty());

        let (src, dst, proto, payload2) = dissect_ipv4(&f2_buf);
        assert_eq!(src, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert_eq!(dst, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))));
        assert_eq!(proto, Some(6));
        assert_eq!(&payload2, b"PART1___PART2");
    }
}
