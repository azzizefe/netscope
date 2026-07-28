use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_apex_legends_netprop(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Apex Netprop (malformed)".into()
    } else {
        let seq = u32::from_le_bytes(payload[..4].try_into().unwrap());
        let flags = payload[4];
        let num_props = payload[5];
        let tick = u16::from_le_bytes(payload[6..8].try_into().unwrap());
        let is_delta = (flags & 0x01) != 0;
        let is_reliable = (flags & 0x02) != 0;
        format!(
            "Apex Netprop seq={}{}{} props={} tick={} len={}",
            seq,
            if is_delta { " DELTA" } else { "" },
            if is_reliable { " RELIABLE" } else { "" },
            num_props,
            tick,
            payload.len(),
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::ApexLegendsNetprop,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apex_netprop() {
        let mut buf = vec![0u8; 12];
        buf[..4].copy_from_slice(&100u32.to_le_bytes());
        buf[4] = 0x03;
        buf[5] = 5;
        buf[6..8].copy_from_slice(&1280u16.to_le_bytes());
        let r = dissect_apex_legends_netprop(None, None, 30000, 30000, &buf);
        assert_eq!(r.protocol, Protocol::ApexLegendsNetprop);
        assert!(r.summary.contains("seq=100"));
        assert!(r.summary.contains("props=5"));
    }
}
