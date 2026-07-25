use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_secondlife_lludp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 7 {
        "Second Life LLUDP (malformed)".into()
    } else {
        let flags = payload[0];
        let seq = u32::from_be_bytes(payload[1..5].try_into().unwrap());
        let ack = u16::from_be_bytes(payload[5..7].try_into().unwrap());
        let is_acked = (flags & 0x80) != 0;
        let is_resend = (flags & 0x40) != 0;
        format!(
            "Second Life LLUDP seq={} ack={}{}{}",
            seq,
            ack,
            if is_acked { " ACK" } else { "" },
            if is_resend { " RESEND" } else { "" }
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::SecondlifeLludp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secondlife_lludp_basic() {
        let buf = vec![0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0xAA, 0xBB];
        let r = dissect_secondlife_lludp(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::SecondlifeLludp);
        assert!(r.summary.contains("ACK"));
    }

    #[test]
    fn test_secondlife_lludp_resend() {
        let buf = vec![0x40, 0x00, 0x00, 0x00, 0x05, 0x00, 0x01];
        let r = dissect_secondlife_lludp(None, None, 0, 0, &buf);
        assert!(r.summary.contains("RESEND"));
    }

    #[test]
    fn test_secondlife_lludp_malformed() {
        let buf = vec![0x00, 0x00, 0x00];
        let r = dissect_secondlife_lludp(None, None, 0, 0, &buf);
        assert!(r.summary.contains("malformed"));
    }
}
