use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

fn security_token_state(tok_id: u32) -> &'static str {
    match tok_id {
        0 => "initial",
        1..=100 => "active",
        101..=1000 => "renewed",
        _ => "unknown",
    }
}

fn security_header_type(payload: &[u8], offset: usize) -> &'static str {
    if offset + 12 <= payload.len() {
        let zero_seq = u32::from_le_bytes([payload[offset], payload[offset+1], payload[offset+2], payload[offset+3]]) == 0;
        let first_req = u32::from_le_bytes([payload[offset+4], payload[offset+5], payload[offset+6], payload[offset+7]]) == 0;
        if zero_seq && first_req {
            "AsymmetricHeader"
        } else {
            "SymmetricHeader"
        }
    } else {
        "SymmetricHeader"
    }
}

fn channel_state(channel_id: u32, token_id: u32) -> &'static str {
    if channel_id == 0 { "pre-handshake" }
    else if token_id == 0 { "opening" }
    else { "established" }
}

pub fn dissect_opc_ua_secure_conversation(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let fallback = |s: String| DissectedResult {
        src_addr: src_ip, dst_addr: dst_ip,
        src_port: Some(src_port), dst_port: Some(dst_port),
        protocol: Protocol::OpcUaSecureConversation, summary: s,
    };
    if payload.len() < 12 {
        return fallback("OPC UA SecureConv (partial)".into());
    }
    if !matches!(&payload[0..3], b"OPN" | b"MSG" | b"CLO" | b"HEL" | b"ACK" | b"ERR") {
        return fallback("OPC UA SecureConv (unrecognized)".into());
    }
    let msg_type = std::str::from_utf8(&payload[0..3]).unwrap_or("???");
    let chunk_type = payload[3];
    let size = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]) as usize;
    let body = &payload[8..payload.len().min(size)];
    if body.len() < 8 {
        return fallback(format!("OPC UA SecureConv {msg_type} (partial body, {size} bytes)"));
    }
    let channel_id = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
    let token_id = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
    let state = channel_state(channel_id, token_id);
    let tok_state = security_token_state(token_id);
    let sec_header = security_header_type(payload, 8);
    if body.len() >= 16 {
        let seq_num = u32::from_le_bytes([body[8], body[9], body[10], body[11]]);
        let req_id = u32::from_le_bytes([body[12], body[13], body[14], body[15]]);
        let chunk_name = match chunk_type { b'F' => "final", b'C' => "intermediate", b'A' => "abort", _ => "?" };
        return fallback(format!(
            "OPC UA SecureConv {msg_type} ch={channel_id} tok={token_id}({tok_state}) seq={seq_num} req={req_id} {sec_header} {state} {chunk_name}"
        ));
    }
    fallback(format!(
        "OPC UA SecureConv {msg_type} ch={channel_id} tok={token_id}({tok_state}) {sec_header} {state}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sec_conv(msg_type: &[u8; 3], channel_id: u32, token_id: u32, seq_num: u32, req_id: u32) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(msg_type);
        p.push(b'F');
        let body_len = 16;
        let total = 8 + body_len;
        p.extend_from_slice(&(total as u32).to_le_bytes());
        p.extend_from_slice(&channel_id.to_le_bytes());
        p.extend_from_slice(&token_id.to_le_bytes());
        p.extend_from_slice(&seq_num.to_le_bytes());
        p.extend_from_slice(&req_id.to_le_bytes());
        p
    }

    #[test]
    fn test_sec_conv_opn() {
        let p = make_sec_conv(b"OPN", 1, 100, 1, 0);
        let r = dissect_opc_ua_secure_conversation(None, None, 0, 0, &p);
        assert_eq!(r.protocol, Protocol::OpcUaSecureConversation);
        assert!(r.summary.contains("ch=1"));
        assert!(r.summary.contains("tok=100"));
    }

    #[test]
    fn test_sec_conv_msg() {
        let p = make_sec_conv(b"MSG", 1, 100, 42, 7);
        let r = dissect_opc_ua_secure_conversation(None, None, 0, 0, &p);
        assert!(r.summary.contains("seq=42"));
        assert!(r.summary.contains("req=7"));
    }

    #[test]
    fn test_sec_conv_clo() {
        let p = make_sec_conv(b"CLO", 1, 100, 99, 0);
        let r = dissect_opc_ua_secure_conversation(None, None, 0, 0, &p);
        assert!(r.summary.contains("CLO"));
    }

    #[test]
    fn test_sec_conv_pre_handshake() {
        let p = make_sec_conv(b"OPN", 0, 0, 0, 0);
        let r = dissect_opc_ua_secure_conversation(None, None, 0, 0, &p);
        assert!(r.summary.contains("pre-handshake"));
    }

    #[test]
    fn test_sec_conv_partial() {
        let r = dissect_opc_ua_secure_conversation(None, None, 0, 0, b"");
        assert!(r.summary.contains("partial"));
    }

    #[test]
    fn test_sec_conv_unrecognized() {
        let r = dissect_opc_ua_secure_conversation(None, None, 0, 0, b"GET / ");
        assert!(r.summary.contains("unrecognized"));
    }

    #[test]
    fn test_sec_conv_asymmetric_header() {
        let p = make_sec_conv(b"OPN", 0, 0, 0, 0);
        let r = dissect_opc_ua_secure_conversation(None, None, 0, 0, &p);
        assert!(r.summary.contains("AsymmetricHeader"));
    }

    #[test]
    fn test_sec_conv_symmetric_header() {
        let p = make_sec_conv(b"MSG", 1, 100, 5, 1);
        let r = dissect_opc_ua_secure_conversation(None, None, 0, 0, &p);
        assert!(r.summary.contains("SymmetricHeader"));
    }

    #[test]
    fn test_sec_conv_intermediate_chunk() {
        let mut p = make_sec_conv(b"MSG", 1, 100, 5, 1);
        p[3] = b'C';
        let r = dissect_opc_ua_secure_conversation(None, None, 0, 0, &p);
        assert!(r.summary.contains("intermediate"));
    }

    #[test]
    fn test_sec_conv_token_renewed() {
        let p = make_sec_conv(b"MSG", 1, 200, 10, 2);
        let r = dissect_opc_ua_secure_conversation(None, None, 0, 0, &p);
        assert!(r.summary.contains("renewed"));
    }
}
