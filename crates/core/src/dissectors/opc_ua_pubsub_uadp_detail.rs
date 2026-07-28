use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

fn uadp_extended_flags1(flags: u8) -> Vec<&'static str> {
    let mut f = Vec::new();
    if flags & 0x01 != 0 {
        f.push("PublisherId");
    }
    if flags & 0x02 != 0 {
        f.push("WriterGroupId");
    }
    if flags & 0x04 != 0 {
        f.push("WriterId");
    }
    if flags & 0x08 != 0 {
        f.push("DataSetWriterId");
    }
    if flags & 0x10 != 0 {
        f.push("PayloadHeader");
    }
    if flags & 0x20 != 0 {
        f.push("MetaData");
    }
    if flags & 0x40 != 0 {
        f.push("SeqNum");
    }
    if flags & 0x80 != 0 {
        f.push("Chunk");
    }
    f
}

fn uadp_extended_flags2(flags: u8) -> Vec<&'static str> {
    let mut f = Vec::new();
    if flags & 0x01 != 0 {
        f.push("SampleOffset");
    }
    if flags & 0x02 != 0 {
        f.push("Duration");
    }
    if flags & 0x04 != 0 {
        f.push("Picoseconds");
    }
    if flags & 0x08 != 0 {
        f.push("DataClassId");
    }
    if flags & 0x10 != 0 {
        f.push("PromotedFields");
    }
    if flags & 0x20 != 0 {
        f.push("CoherentData");
    }
    f
}

// This dissector reads the UADP NetworkMessage header and stops there. The
// DataSetMessage tables that used to sit here (message type, field encoding)
// were never called: reaching a DataSetMessage means walking the group header
// and the payload header first, and both are variable-length on the extended
// flags. Reinstate them together with that walk, not before it — see git
// history for the tables themselves.

fn publisher_id_type(flags: u8) -> &'static str {
    match (flags >> 4) & 0x03 {
        0 => "UInt16",
        1 => "UInt32",
        2 => "UInt64",
        3 => "String",
        _ => "?",
    }
}

pub fn dissect_opc_ua_pubsub_uadp_detail(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let fallback = |s: String| DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::OpcUaPubsubUadpDetail,
        summary: s,
    };
    if payload.len() < 4 {
        return fallback("OPC UA UADP Detail (partial)".into());
    }
    let version = payload[0] >> 4;
    let uadp_flags = payload[0];
    let ext_flags1 = payload[1];
    let ext_flags2 = if payload.len() > 2 { payload[2] } else { 0 };
    let has_ext1 = uadp_flags & 0x01 != 0;
    let has_ext2 = uadp_flags & 0x02 != 0;
    let published_id_type = publisher_id_type(uadp_flags);
    let tags1 = if has_ext1 {
        uadp_extended_flags1(ext_flags1)
    } else {
        vec![]
    };
    let tags2 = if has_ext2 {
        uadp_extended_flags2(ext_flags2)
    } else {
        vec![]
    };
    let mut parts = vec![format!("UADP v{version}")];
    parts.push(format!("pubIdType={published_id_type}"));
    if !tags1.is_empty() {
        parts.push(format!("flags1=[{}]", tags1.join(",")));
    }
    if !tags2.is_empty() {
        parts.push(format!("flags2=[{}]", tags2.join(",")));
    }
    if payload.len() >= 4 && (payload[0] & 0x0F) != 0 {
        let count = payload[0] & 0x0F;
        parts.push(format!("dataSets={count}"));
    }
    if payload.len() >= 8 {
        let pkt_type = &payload[4..8];
        if let Ok(s) = std::str::from_utf8(pkt_type) {
            if s.chars().all(|c| c.is_ascii_alphabetic()) {
                parts.push(format!("networkMsgType=\"{s}\""));
            }
        }
    }
    fallback(format!("OPC UA UADP Detail: {}", parts.join(" ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uadp_detail_basic() {
        let buf = &[0x10, 0x00, 0x00, 0x00];
        let r = dissect_opc_ua_pubsub_uadp_detail(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::OpcUaPubsubUadpDetail);
        assert!(r.summary.contains("UADP"));
    }

    #[test]
    fn test_uadp_detail_ext_flags1() {
        let buf = &[0x11, 0xFF, 0x00, 0x00];
        let r = dissect_opc_ua_pubsub_uadp_detail(None, None, 0, 0, buf);
        assert!(r.summary.contains("PublisherId"));
    }

    #[test]
    fn test_uadp_detail_multiple_data_sets() {
        let buf = &[0x13, 0x00, 0x00, 0x00];
        let r = dissect_opc_ua_pubsub_uadp_detail(None, None, 0, 0, buf);
        assert!(r.summary.contains("dataSets=3"));
    }

    #[test]
    fn test_uadp_detail_network_msg_type() {
        let buf = b"\x10\x00\x00\x00UADP";
        let r = dissect_opc_ua_pubsub_uadp_detail(None, None, 0, 0, buf);
        assert!(r.summary.contains("UADP"));
        assert!(r.summary.contains("networkMsgType"));
    }

    #[test]
    fn test_uadp_detail_partial() {
        let r = dissect_opc_ua_pubsub_uadp_detail(None, None, 0, 0, b"");
        assert!(r.summary.contains("partial"));
    }

    #[test]
    fn test_uadp_detail_ext_flags2() {
        let buf = &[0x12, 0x00, 0xFF, 0x00];
        let r = dissect_opc_ua_pubsub_uadp_detail(None, None, 0, 0, buf);
        assert!(r.summary.contains("flags2"));
    }

    #[test]
    fn test_uadp_detail_string_pub_id() {
        let buf = &[0x30, 0x00, 0x00, 0x00];
        let r = dissect_opc_ua_pubsub_uadp_detail(None, None, 0, 0, buf);
        assert!(r.summary.contains("pubIdType=String"));
    }

    #[test]
    fn test_uadp_detail_uadp_key() {
        let buf = b"\x10\x00\x00\x00UADP";
        let r = dissect_opc_ua_pubsub_uadp_detail(None, None, 0, 0, buf);
        assert!(r.summary.contains("\"UADP\""));
    }

    #[test]
    fn test_uadp_detail_no_ext() {
        let buf = &[0x10, 0x00, 0x00, 0x00];
        let r = dissect_opc_ua_pubsub_uadp_detail(None, None, 0, 0, buf);
        assert!(!r.summary.contains("flags1"));
    }
}
