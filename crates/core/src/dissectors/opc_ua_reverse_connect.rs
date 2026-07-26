use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

fn reverse_connect_phase(payload: &[u8]) -> &'static str {
    let raw = String::from_utf8_lossy(payload);
    if raw.contains("ReverseHello") || raw.contains("RHE") { return "ReverseHello"; }
    if raw.contains("SessionActivate") { return "SessionActivate"; }
    if raw.contains("CreateSession") { return "CreateSession"; }
    if raw.contains("CloseSession") { return "CloseSession"; }
    if raw.contains("Discover") || raw.contains("FindServers") { return "Discovery"; }
    if raw.contains("register") || raw.contains("RegisterServer") { return "Registration"; }
    if raw.contains("token") || raw.contains("Token") { return "TokenExchange"; }
    "Active"
}

fn reverse_parse_rhe(payload: &[u8]) -> Option<String> {
    if payload.len() < 28 {
        return None;
    }
    if &payload[0..3] == b"RHE" {
        let mut size = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]) as usize;
        if size > payload.len() { size = payload.len(); }
        let body = &payload[8..size];
        if body.len() >= 20 {
            let proto_ver = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
            let mut off = 20;
            if off + 4 <= body.len() {
                let len = u32::from_le_bytes([body[off], body[off+1], body[off+2], body[off+3]]) as usize;
                off += 4;
                if off + len <= body.len() && len > 0 && len < 512 {
                    let url = String::from_utf8_lossy(&body[off..off + len]);
                    return Some(format!("v{proto_ver} serverUrl=\"{url}\""));
                }
            }
            return Some(format!("v{proto_ver}"));
        }
    }
    None
}

fn endpoint_uri(payload: &[u8]) -> Option<String> {
    let raw = String::from_utf8_lossy(payload);
    if let Some(pos) = raw.find("opc.tcp://") {
        let start = pos;
        let remaining = &raw[start..];
        let relative_end = remaining.find(|c: char| c.is_whitespace() || c == ',' || c == '}').unwrap_or(remaining.len());
        let actual_end = relative_end.min(remaining.len());
        return Some(raw[start..start + actual_end].to_string());
    }
    None
}

pub fn dissect_opc_ua_reverse_connect(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let fallback = |s: String| DissectedResult {
        src_addr: src_ip, dst_addr: dst_ip,
        src_port: Some(src_port), dst_port: Some(dst_port),
        protocol: Protocol::OpcUaReverseConnect, summary: s,
    };
    if payload.len() < 4 {
        return fallback("OPC UA Reverse Connect (partial)".into());
    }
    let phase = reverse_connect_phase(payload);
    let mut parts = vec![format!("OPC UA ReverseConnect: {phase}")];
    if let Some(rhe) = reverse_parse_rhe(payload) {
        parts.push(rhe);
    }
    if let Some(ep) = endpoint_uri(payload) {
        parts.push(ep);
    }
    let raw = String::from_utf8_lossy(payload);
    if raw.contains("reverse") || raw.contains("Reverse") || raw.contains("client_") {
        parts.push("reversed".to_string());
    }
    if raw.contains("server_") || raw.contains("ServerUri") {
        parts.push("hasServerUri".to_string());
    }
    fallback(parts.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reverse_connect_rhe() {
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&65536u32.to_le_bytes());
        body.extend_from_slice(&65536u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        let url = b"opc.tcp://server:4840";
        body.extend_from_slice(&(url.len() as u32).to_le_bytes());
        body.extend_from_slice(url);
        let total_len = 8 + body.len();
        let mut p = Vec::with_capacity(total_len);
        p.extend_from_slice(b"RHE");
        p.push(b'F');
        p.extend_from_slice(&(total_len as u32).to_le_bytes());
        p.extend_from_slice(&body);
        let r = dissect_opc_ua_reverse_connect(None, None, 50000, 4840, &p);
        assert_eq!(r.protocol, Protocol::OpcUaReverseConnect);
        assert!(r.summary.contains("ReverseConnect"));
        assert!(r.summary.contains("server"));
    }

    #[test]
    fn test_reverse_connect_session() {
        let buf = b"CreateSession:reverse:opc.tcp://remote:4840";
        let r = dissect_opc_ua_reverse_connect(None, None, 50000, 0, buf);
        assert!(r.summary.contains("CreateSession"));
        assert!(r.summary.contains("opc.tcp"));
    }

    #[test]
    fn test_reverse_connect_discovery() {
        let buf = b"FindServers:reverse:opc.tcp://localhost:4840";
        let r = dissect_opc_ua_reverse_connect(None, None, 50000, 0, buf);
        assert!(r.summary.contains("Discovery"));
    }

    #[test]
    fn test_reverse_connect_partial() {
        let r = dissect_opc_ua_reverse_connect(None, None, 0, 0, b"");
        assert!(r.summary.contains("partial"));
    }

    #[test]
    fn test_reverse_connect_default_phase() {
        let buf = b"some unknown data";
        let r = dissect_opc_ua_reverse_connect(None, None, 0, 0, buf);
        assert!(r.summary.contains("Active"));
    }

    #[test]
    fn test_reverse_connect_server_uri() {
        let buf = b"ServerUri=opc.tcp://plc:4840:reverse";
        let r = dissect_opc_ua_reverse_connect(None, None, 0, 0, buf);
        assert!(r.summary.contains("hasServerUri"));
    }

    #[test]
    fn test_reverse_connect_token() {
        let buf = b"TokenExchange:reverse:token_id=100";
        let r = dissect_opc_ua_reverse_connect(None, None, 0, 0, buf);
        assert!(r.summary.contains("TokenExchange"));
    }

    #[test]
    fn test_reverse_connect_register() {
        let buf = b"RegisterServer:reverse:opc.tcp://gds:4840";
        let r = dissect_opc_ua_reverse_connect(None, None, 0, 0, buf);
        assert!(r.summary.contains("Registration"));
    }
}
