use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_nintendo_npln_p2p(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "Nintendo NPLN P2P (malformed)".into()
    } else {
        let magic = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let msg_type = payload[4];
        let flags = payload[5];
        let seq = u32::from_be_bytes([payload[6], payload[7], payload[8], payload[9]]);
        let session = u16::from_be_bytes([payload[10], payload[11]]);
        let type_name = match msg_type {
            0x01 => "Connect",
            0x02 => "ConnectAck",
            0x03 => "Matchmake",
            0x04 => "MatchmakeAck",
            0x05 => "Disconnect",
            0x06 => "Ping",
            0x07 => "Pong",
            _ => "Unknown",
        };
        let is_npln = magic == 0x4e504c4e;
        format!(
            "Nintendo NPLN {} seq={} session={} flags=0x{:02x}{}",
            type_name,
            seq,
            session,
            flags,
            if is_npln { "" } else { " (raw)" },
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::NintendoNplnP2p,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nintendo_npln_matchmake() {
        let r = dissect_nintendo_npln_p2p(
            None,
            None,
            30211,
            30211,
            b"\x4e\x50\x4c\x4e\x03\x00\x00\x00\x00\x01\x00\x01\xde\xad",
        );
        assert_eq!(r.protocol, Protocol::NintendoNplnP2p);
        assert!(r.summary.contains("Matchmake"));
        assert!(r.summary.contains("seq=1"));
    }
}
