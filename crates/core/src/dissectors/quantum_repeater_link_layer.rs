use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_quantum_repeater_link_layer(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Quantum Repeater Link (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("repeater") && (raw.contains("entanglement") || raw.contains("purify")) {
            let end = raw.len().min(80);
            format!("Quantum Repeater Link: {}", &raw[..end])
        } else if raw.contains("link_layer") || raw.contains("bell_state") && raw.contains("swap") {
            let end = raw.len().min(80);
            format!("Quantum Repeater Link: {}", &raw[..end])
        } else {
            format!("Quantum Repeater Link ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::QuantumRepeaterLinkLayer,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quantum_repeater_swap() {
        let buf = b"repeater:entanglement:bell_state:swap:hop=3";
        let r = dissect_quantum_repeater_link_layer(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::QuantumRepeaterLinkLayer);
        assert!(r.summary.contains("Repeater"));
    }

    #[test]
    fn test_quantum_repeater_malformed() {
        let buf = b"short";
        let r = dissect_quantum_repeater_link_layer(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
