use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn dissect_ipv4(data: &[u8]) -> (Option<IpAddr>, Option<IpAddr>, Option<u8>, Vec<u8>) {
    let header = match etherparse::Ipv4Header::from_slice(data) {
        Ok((h, rest)) => (h, rest.to_vec()),
        Err(_) => return (None, None, None, Vec::new()),
    };

    let (h, rest) = header;
    (
        Some(IpAddr::V4(Ipv4Addr::from(h.source))),
        Some(IpAddr::V4(Ipv4Addr::from(h.destination))),
        Some(h.protocol.0),
        rest,
    )
}

pub fn dissect_ipv6(data: &[u8]) -> (Option<IpAddr>, Option<IpAddr>, Option<u8>, Vec<u8>) {
    let header = match etherparse::Ipv6Header::from_slice(data) {
        Ok((h, rest)) => (h, rest.to_vec()),
        Err(_) => return (None, None, None, Vec::new()),
    };

    let (h, rest) = header;
    (
        Some(IpAddr::V6(Ipv6Addr::from(h.source))),
        Some(IpAddr::V6(Ipv6Addr::from(h.destination))),
        Some(h.next_header.0),
        rest,
    )
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
}
