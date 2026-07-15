// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
pub struct EthernetFrame {
    pub source: [u8; 6],
    pub destination: [u8; 6],
    pub ethertype: etherparse::EtherType,
    pub payload: Vec<u8>,
}

pub fn dissect_ethernet(data: &[u8]) -> Option<EthernetFrame> {
    use etherparse::Ethernet2Header;

    let eth = Ethernet2Header::from_slice(data).ok()?;
    let (header, payload) = eth;
    Some(EthernetFrame {
        source: header.source,
        destination: header.destination,
        ethertype: header.ether_type,
        payload: payload.to_vec(),
    })
}

pub fn mac_to_string(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_ethernet() {
        use etherparse::Ethernet2Header;
        let mut buf = Vec::new();
        let eth = Ethernet2Header {
            source: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            destination: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            ether_type: etherparse::EtherType::IPV4,
        };
        eth.write(&mut buf).unwrap();
        buf.extend_from_slice(&[0x45, 0x00, 0x00, 0x14]); // dummy IP header start

        let result = dissect_ethernet(&buf).unwrap();
        assert_eq!(result.source, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(result.destination, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        assert_eq!(result.ethertype, etherparse::EtherType::IPV4);
    }

    #[test]
    fn invalid_ethernet_too_short() {
        assert!(dissect_ethernet(&[0; 5]).is_none());
    }

    #[test]
    fn mac_to_string_format() {
        let mac = [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e];
        assert_eq!(mac_to_string(&mac), "00:1a:2b:3c:4d:5e");
    }

    #[test]
    fn payload_extracted_correctly() {
        let mut buf = Vec::new();
        let eth = etherparse::Ethernet2Header {
            source: [0; 6],
            destination: [0; 6],
            ether_type: etherparse::EtherType::IPV4,
        };
        eth.write(&mut buf).unwrap();
        buf.extend_from_slice(b"PAYLOAD");
        let result = dissect_ethernet(&buf).unwrap();
        assert_eq!(result.payload, b"PAYLOAD");
        assert_eq!(result.ethertype, etherparse::EtherType::IPV4);
    }

    #[test]
    fn unknown_ethertype_produces_expected_output() {
        let mut buf = Vec::new();
        let eth = etherparse::Ethernet2Header {
            source: [0; 6],
            destination: [0; 6],
            ether_type: etherparse::EtherType(0x1234),
        };
        eth.write(&mut buf).unwrap();
        let result = dissect_ethernet(&buf).unwrap();
        assert_eq!(result.ethertype, etherparse::EtherType(0x1234));
        assert_eq!(result.payload, &[] as &[u8]);
    }
}
