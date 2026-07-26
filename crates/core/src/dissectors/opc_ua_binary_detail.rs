use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

fn node_id_kind(encoding: u8) -> &'static str {
    match encoding & 0x3F {
        0x00 => "TwoByte",
        0x01 => "FourByte",
        0x02 => "Numeric",
        0x03 => "String",
        0x04 => "Guid",
        0x05 => "ByteString",
        _ => "?",
    }
}

fn variant_type(tag: u8) -> &'static str {
    match tag {
        0 => "Null",
        1 => "Boolean",
        2 => "SByte",
        3 => "Byte",
        4 => "Int16",
        5 => "UInt16",
        6 => "Int32",
        7 => "UInt32",
        8 => "Int64",
        9 => "UInt64",
        10 => "Float",
        11 => "Double",
        12 => "String",
        13 => "DateTime",
        14 => "Guid",
        15 => "ByteString",
        16 => "XmlElement",
        17 => "NodeId",
        18 => "ExpandedNodeId",
        19 => "StatusCode",
        20 => "QualifiedName",
        21 => "LocalizedText",
        22 => "ExtensionObject",
        23 => "DataValue",
        24 => "Variant",
        25 => "DiagnosticInfo",
        26 => "Decimal",
        27 => "Enumeration",
        28 => "Structure",
        29 => "Optional",
        30..=31 => "Reserved",
        _ => "Unknown",
    }
}

fn diagnostic_info_name(sym: i32) -> &'static str {
    match sym {
        0 => "NoDiagnostic",
        1..=99 => "SymbolicId",
        100..=199 => "NamespaceUri",
        200..=299 => "Locale",
        300..=399 => "LocalizedText",
        _ => "Complex",
    }
}

fn parse_node_id_str(payload: &[u8], offset: &mut usize) -> String {
    if *offset >= payload.len() {
        return "?".into();
    }
    let encoding = payload[*offset];
    *offset += 1;
    let kind = node_id_kind(encoding);
    let ns = if encoding & 0x40 != 0 {
        if *offset + 2 > payload.len() { return "?".into(); }
        let v = u16::from_le_bytes([payload[*offset], payload[*offset + 1]]);
        *offset += 2;
        format!("ns={v}")
    } else {
        String::new()
    };
    match encoding & 0x3F {
        0x00 => {
            if *offset >= payload.len() { return "?".into(); }
            let v = payload[*offset];
            *offset += 1;
            format!("TwoByte({kind} i={v})")
        }
        0x01 => {
            if *offset + 2 > payload.len() { return "?".into(); }
            let v = u16::from_le_bytes([payload[*offset], payload[*offset + 1]]);
            *offset += 2;
            if ns.is_empty() {
                format!("FourByte({kind} i={v})")
            } else {
                format!("FourByte({kind} {ns} i={v})")
            }
        }
        0x02 => {
            if *offset + 4 > payload.len() { return "?".into(); }
            let v = u32::from_le_bytes([payload[*offset], payload[*offset + 1], payload[*offset + 2], payload[*offset + 3]]);
            *offset += 4;
            if ns.is_empty() {
                format!("Numeric(i={v})")
            } else {
                format!("Numeric({ns} i={v})")
            }
        }
        0x03 => {
            if *offset + 4 > payload.len() { return "?".into(); }
            let len = u32::from_le_bytes([payload[*offset], payload[*offset + 1], payload[*offset + 2], payload[*offset + 3]]) as usize;
            *offset += 4;
            if len == 0 || len == 0xFFFFFFFF || *offset + len > payload.len() {
                return format!("String({ns} s=<empty>)");
            }
            let s = String::from_utf8_lossy(&payload[*offset..*offset + len]);
            *offset += len;
            format!("String({ns} s=\"{s}\")")
        }
        0x04 => {
            if *offset + 16 > payload.len() { return "?".into(); }
            let hex: String = payload[*offset..*offset + 16].iter().map(|b| format!("{b:02X}")).collect();
            *offset += 16;
            format!("Guid({ns} {hex})")
        }
        0x05 => {
            if *offset + 4 > payload.len() { return "?".into(); }
            let len = u32::from_le_bytes([payload[*offset], payload[*offset + 1], payload[*offset + 2], payload[*offset + 3]]) as usize;
            *offset += 4;
            if len == 0 || len == 0xFFFFFFFF || *offset + len > payload.len() {
                return format!("ByteString({ns} bs=<empty>)");
            }
            *offset += len;
            format!("ByteString({ns} {len} bytes)")
        }
        _ => "?".into(),
    }
}

fn parse_variant_str(payload: &[u8], offset: &mut usize) -> String {
    if *offset >= payload.len() {
        return "?".into();
    }
    let tag = payload[*offset];
    *offset += 1;
    let kind = variant_type(tag);
    let array = tag & 0x80 != 0;
    let dimensions = tag & 0x40 != 0;
    let mut desc = if array {
        format!("Variant[{kind}]")
    } else {
        format!("Variant({kind})")
    };
    if dimensions {
        desc.push_str(" dim");
    }
    if !array {
        match tag {
            1 | 3 | 4 | 5 => { if *offset < payload.len() { desc.push_str(&format!(" value={}", payload[*offset])); *offset += 1; } }
            6 | 7 => { if *offset + 4 <= payload.len() { let v = u32::from_le_bytes([payload[*offset], payload[*offset + 1], payload[*offset + 2], payload[*offset + 3]]); desc.push_str(&format!(" value={v}")); *offset += 4; if tag == 6 { desc.truncate(desc.len() - format!("{v}").len() - 7); desc.push_str(&format!(" value={}", v as i32)); } } }
            11 => { if *offset + 8 <= payload.len() { let v = f64::from_le_bytes([payload[*offset], payload[*offset + 1], payload[*offset + 2], payload[*offset + 3], payload[*offset + 4], payload[*offset + 5], payload[*offset + 6], payload[*offset + 7]]); desc.push_str(&format!(" value={v}")); *offset += 8; } }
            12 => { if *offset + 4 <= payload.len() { let len = u32::from_le_bytes([payload[*offset], payload[*offset + 1], payload[*offset + 2], payload[*offset + 3]]) as usize; *offset += 4; if len > 0 && len < 80 && *offset + len <= payload.len() { let s = String::from_utf8_lossy(&payload[*offset..*offset + len]); desc.push_str(&format!(" \"{s}\"")); *offset += len; } } }
            _ => {}
        }
    }
    desc
}

pub fn dissect_opc_ua_binary_detail(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let fallback = |s: String| DissectedResult {
        src_addr: src_ip, dst_addr: dst_ip,
        src_port: Some(src_port), dst_port: Some(dst_port),
        protocol: Protocol::OpcUaBinaryDetail, summary: s,
    };
    if payload.is_empty() {
        return fallback("OPC UA Binary Detail (empty)".into());
    }
    let mut off = 0;
    let first = payload[0];
    if (first & 0xC0) == 0 && first < 0x3F {
        let node_id = parse_node_id_str(payload, &mut off);
        return fallback(format!("OPC UA Binary NodeId: {node_id}"));
    }
    if first <= 29 || (first >= 32 && first <= 63) {
        let variant = parse_variant_str(payload, &mut off);
        return fallback(format!("OPC UA Binary {variant}"));
    }
    if payload.len() >= 4 {
        let type_id = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        if type_id == 1 || type_id == 2 || type_id == 3 {
            return fallback(format!("OPC UA Binary ExtensionObject typeId={type_id}"));
        }
    }
    fallback(format!("OPC UA Binary Detail ({})", super::bytes(payload.len() as u64)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_two_byte_node_id() {
        let r = dissect_opc_ua_binary_detail(None, None, 0, 0, &[0x00, 0x2A]);
        assert_eq!(r.protocol, Protocol::OpcUaBinaryDetail);
        assert!(r.summary.contains("TwoByte"));
        assert!(r.summary.contains("i=42"));
    }

    #[test]
    fn test_numeric_node_id() {
        let r = dissect_opc_ua_binary_detail(None, None, 0, 0, &[0x02, 0xE7, 0x03, 0x00, 0x00]);
        assert!(r.summary.contains("Numeric"));
        assert!(r.summary.contains("i=999"));
    }

    #[test]
    fn test_four_byte_node_id() {
        let r = dissect_opc_ua_binary_detail(None, None, 0, 0, &[0x01, 0x2A, 0x00]);
        assert!(r.summary.contains("FourByte"));
    }

    #[test]
    fn test_string_node_id() {
        let buf = b"\x03\x0C\x00\x00\x00test_value";
        let r = dissect_opc_ua_binary_detail(None, None, 0, 0, buf);
        assert!(r.summary.contains("String"));
        assert!(r.summary.contains("test_value"));
    }

    #[test]
    fn test_variant_boolean() {
        let r = dissect_opc_ua_binary_detail(None, None, 0, 0, &[0x01, 0x01]);
        assert!(r.summary.contains("Boolean"));
    }

    #[test]
    fn test_variant_int32() {
        let r = dissect_opc_ua_binary_detail(None, None, 0, 0, &[0x06, 0x2A, 0x00, 0x00, 0x00]);
        assert!(r.summary.contains("Int32"));
    }

    #[test]
    fn test_variant_string() {
        let buf = b"\x0C\x0A\x00\x00\x00hello UA";
        let r = dissect_opc_ua_binary_detail(None, None, 0, 0, buf);
        assert!(r.summary.contains("String"));
        assert!(r.summary.contains("hello"));
    }

    #[test]
    fn test_extension_object() {
        let buf = &[0x01, 0x00, 0x00, 0x00];
        let r = dissect_opc_ua_binary_detail(None, None, 0, 0, buf);
        assert!(r.summary.contains("ExtensionObject"));
    }

    #[test]
    fn test_guid_node_id() {
        let mut buf = vec![0x04];
        buf.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]);
        let r = dissect_opc_ua_binary_detail(None, None, 0, 0, &buf);
        assert!(r.summary.contains("Guid"));
    }

    #[test]
    fn test_variant_double() {
        let buf = &[0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x3F];
        let r = dissect_opc_ua_binary_detail(None, None, 0, 0, buf);
        assert!(r.summary.contains("Double"));
    }

    #[test]
    fn test_empty() {
        let r = dissect_opc_ua_binary_detail(None, None, 0, 0, &[]);
        assert!(r.summary.contains("empty"));
    }

    #[test]
    fn test_variant_array_flag() {
        let r = dissect_opc_ua_binary_detail(None, None, 0, 0, &[0x81]);
        assert!(r.summary.contains("Variant["));
    }

    #[test]
    fn test_ns_numeric_node_id() {
        let buf = &[0x42, 0x02, 0x00, 0xE7, 0x03, 0x00, 0x00];
        let r = dissect_opc_ua_binary_detail(None, None, 0, 0, buf);
        assert!(r.summary.contains("Numeric"));
        assert!(r.summary.contains("ns=2"));
    }
}
