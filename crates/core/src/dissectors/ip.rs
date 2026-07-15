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

pub fn dissect_ipv6(data: &[u8]) -> (Option<IpAddr>, Option<IpAddr>, Option<u8>, Vec<u8>) {
    let header = match etherparse::Ipv6Header::from_slice(data) {
        Ok((h, rest)) => (h, rest.to_vec()),
        Err(_) => return (None, None, None, Vec::new()),
    };

    let (h, rest) = header;
    let src = IpAddr::V6(Ipv6Addr::from(h.source));
    let dst = IpAddr::V6(Ipv6Addr::from(h.destination));
    let next_header = h.next_header.0;
    let payload = rest;

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
