use crate::models::Protocol;

use super::{truncate, DissectedResult};

/// Dissect an LLDP frame (EtherType 0x88CC).
///
/// LLDP (Link Layer Discovery Protocol) is how switches and other network gear
/// announce themselves to their directly connected neighbours — "I'm switch X,
/// this is port Y". It's the backbone of network topology maps. The frame is a
/// list of TLVs; the first three are mandatory (Chassis ID, Port ID, TTL) and a
/// System Name TLV usually follows. We surface the system name and port so a
/// capture reads like a wiring diagram.
pub fn dissect_lldp(payload: &[u8]) -> DissectedResult {
    let base = DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Lldp,
        summary: String::new(),
    };

    let mut chassis_id = None;
    let mut port_id = None;
    let mut system_name = None;

    let mut i = 0;
    while i + 2 <= payload.len() {
        let header = u16::from_be_bytes([payload[i], payload[i + 1]]);
        let tlv_type = (header >> 9) as u8;
        let tlv_len = (header & 0x01ff) as usize;
        i += 2;
        if tlv_type == 0 {
            break; // End-of-LLDPDU
        }
        let Some(value) = payload.get(i..i + tlv_len) else {
            break;
        };
        i += tlv_len;
        match tlv_type {
            1 => chassis_id = id_string(value),
            2 => port_id = id_string(value),
            5 => system_name = Some(String::from_utf8_lossy(value).to_string()),
            _ => {}
        }
    }

    let summary = match (system_name, port_id, chassis_id) {
        (Some(name), Some(port), _) => {
            format!(
                "LLDP — {} port {}",
                truncate(&name, 40),
                truncate(&port, 20)
            )
        }
        (Some(name), None, _) => format!("LLDP — {}", truncate(&name, 40)),
        (None, Some(port), Some(chassis)) => format!(
            "LLDP — chassis {} port {}",
            truncate(&chassis, 20),
            truncate(&port, 20)
        ),
        _ => "LLDP advertisement".to_string(),
    };

    DissectedResult { summary, ..base }
}

/// Chassis-ID and Port-ID TLVs begin with a 1-byte subtype; when the subtype
/// marks a text form we render the rest as a string, otherwise as hex (MAC-like).
fn id_string(value: &[u8]) -> Option<String> {
    let rest = value.get(1..)?;
    if rest.is_empty() {
        return None;
    }
    // A printable ASCII value is most likely a name/interface string.
    if rest.iter().all(|&b| b.is_ascii_graphic() || b == b' ') {
        Some(String::from_utf8_lossy(rest).to_string())
    } else {
        Some(
            rest.iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv(tlv_type: u8, value: &[u8]) -> Vec<u8> {
        let header = ((tlv_type as u16) << 9) | (value.len() as u16 & 0x01ff);
        let mut p = header.to_be_bytes().to_vec();
        p.extend_from_slice(value);
        p
    }

    #[test]
    fn system_name_and_port() {
        let mut frame = Vec::new();
        // Chassis ID (subtype 4 = MAC) then Port ID (subtype 5 = ifname) + System Name.
        frame.extend_from_slice(&tlv(1, &[4, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
        frame.extend_from_slice(&tlv(2, &[5, b'G', b'i', b'0', b'/', b'1']));
        frame.extend_from_slice(&tlv(3, &[0, 120])); // TTL
        frame.extend_from_slice(&tlv(5, b"switch-core"));
        frame.extend_from_slice(&tlv(0, &[])); // End

        let r = dissect_lldp(&frame);
        assert_eq!(r.protocol, Protocol::Lldp);
        assert_eq!(r.summary, "LLDP — switch-core port Gi0/1");
    }

    #[test]
    fn chassis_and_port_without_name() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&tlv(1, &[4, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
        frame.extend_from_slice(&tlv(2, &[5, b'e', b't', b'h', b'0']));
        frame.extend_from_slice(&tlv(3, &[0, 120]));
        let r = dissect_lldp(&frame);
        assert!(r
            .summary
            .starts_with("LLDP — chassis aa:bb:cc:dd:ee:ff port eth0"));
    }

    #[test]
    fn empty_is_safe() {
        let r = dissect_lldp(&[]);
        assert_eq!(r.summary, "LLDP advertisement");
    }
}
