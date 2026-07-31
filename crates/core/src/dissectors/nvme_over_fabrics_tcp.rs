use std::net::IpAddr;

use crate::dissectors::DissectedResult;
use crate::models::Protocol;

/// Name the PDU types from the NVMe/TCP transport binding.
///
/// The type is the first byte of every PDU, and it is what says whether the
/// bytes after the common header are a command capsule, a response, or a data
/// transfer — so it carries most of what a reader wants from the summary.
fn pdu_type_name(pdu_type: u8) -> Option<&'static str> {
    Some(match pdu_type {
        0x00 => "ICReq",
        0x01 => "ICResp",
        0x02 => "H2CTermReq",
        0x03 => "C2HTermReq",
        0x04 => "CapsuleCmd",
        0x05 => "CapsuleResp",
        0x06 => "H2CData",
        0x07 => "C2HData",
        0x09 => "R2T",
        _ => return None,
    })
}

/// Dissect an NVMe over Fabrics TCP PDU.
///
/// Every PDU opens with the same 8-byte common header: type, flags, header
/// length, PDU data offset, then the total length. NVMe is a little-endian
/// protocol, so PLEN is read as such — reading it big-endian turns a 120-byte
/// capsule into 2013265920 and makes the summary useless.
pub fn dissect_nvme_over_fabrics_tcp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 8 {
        let pdu_type = payload[0];
        let hlen = payload[2];
        let plen = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);

        let name = pdu_type_name(pdu_type)
            .map(|n| n.to_string())
            .unwrap_or_else(|| format!("type 0x{pdu_type:02x}"));

        // The command identifier lives inside the capsule, not the common
        // header, and at a different offset for a command than for a response:
        // a submission entry carries CID in its third and fourth bytes, while a
        // completion entry carries it after the two queue fields. Only report
        // it where the offset is known, rather than reading bytes 8..10 for
        // every PDU and labelling whatever turns up as a CID.
        let cid = match pdu_type {
            0x04 if payload.len() >= 12 => Some(u16::from_le_bytes([payload[10], payload[11]])),
            0x05 if payload.len() >= 14 => Some(u16::from_le_bytes([payload[12], payload[13]])),
            _ => None,
        };

        match cid {
            Some(cid) => format!("NVMe/TCP {name} cid={cid} hlen={hlen} plen={plen}"),
            None => format!("NVMe/TCP {name} hlen={hlen} plen={plen}"),
        }
    } else {
        "NVMe/TCP (short frame)".into()
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::NvmeOverFabricsTcp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn ips() -> (Option<IpAddr>, Option<IpAddr>) {
        (
            Some("10.0.0.1".parse::<IpAddr>().unwrap()),
            Some("10.0.0.2".parse::<IpAddr>().unwrap()),
        )
    }

    #[test]
    fn an_initialise_request_reports_its_length() {
        let (src, dst) = ips();
        let mut buf = vec![0u8; 128];
        buf[0] = 0x00; // ICReq
        buf[2] = 128; // HLEN
        buf[4..8].copy_from_slice(&128u32.to_le_bytes());

        let r = dissect_nvme_over_fabrics_tcp(src, dst, 40000, 4420, &buf);
        assert_eq!(r.protocol, Protocol::NvmeOverFabricsTcp);
        assert!(r.summary.contains("ICReq"), "{}", r.summary);
        assert!(r.summary.contains("plen=128"), "{}", r.summary);
    }

    /// PLEN is little-endian. Read the other way round this is 2013265920.
    #[test]
    fn the_pdu_length_is_read_little_endian() {
        let (src, dst) = ips();
        let mut buf = vec![0u8; 72];
        buf[0] = 0x04; // CapsuleCmd
        buf[2] = 72;
        buf[4..8].copy_from_slice(&120u32.to_le_bytes());
        buf[10..12].copy_from_slice(&5u16.to_le_bytes()); // CID, inside the SQE

        let r = dissect_nvme_over_fabrics_tcp(src, dst, 40000, 4420, &buf);
        assert!(r.summary.contains("plen=120"), "{}", r.summary);
        assert!(r.summary.contains("cid=5"), "{}", r.summary);
    }

    /// A completion entry keeps its CID two fields further in than a command.
    #[test]
    fn a_response_takes_its_command_id_from_the_completion_entry() {
        let (src, dst) = ips();
        let mut buf = vec![0u8; 24];
        buf[0] = 0x05; // CapsuleResp
        buf[2] = 24;
        buf[4..8].copy_from_slice(&24u32.to_le_bytes());
        buf[12..14].copy_from_slice(&9u16.to_le_bytes());

        let r = dissect_nvme_over_fabrics_tcp(src, dst, 4420, 40000, &buf);
        assert!(r.summary.contains("CapsuleResp"), "{}", r.summary);
        assert!(r.summary.contains("cid=9"), "{}", r.summary);
    }

    /// An unknown type is still reported rather than guessed at, and a PDU with
    /// no capsule behind it must not have bytes read as a command identifier.
    #[test]
    fn an_unknown_type_is_named_by_its_number_and_carries_no_command_id() {
        let (src, dst) = ips();
        let mut buf = vec![0u8; 16];
        buf[0] = 0x7f;
        buf[2] = 8;
        buf[4..8].copy_from_slice(&16u32.to_le_bytes());

        let r = dissect_nvme_over_fabrics_tcp(src, dst, 40000, 4420, &buf);
        assert!(r.summary.contains("0x7f"), "{}", r.summary);
        assert!(!r.summary.contains("cid="), "{}", r.summary);
    }

    #[test]
    fn a_truncated_header_is_reported_not_panicked() {
        let (src, dst) = ips();
        for len in 0..8 {
            let r = dissect_nvme_over_fabrics_tcp(src, dst, 40000, 4420, &vec![0u8; len]);
            assert!(r.summary.contains("short frame"), "len {len}");
        }
    }
}
