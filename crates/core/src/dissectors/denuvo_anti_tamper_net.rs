use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_denuvo_anti_tamper_net(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "Denuvo Anti-Tamper Net (malformed)".into()
    } else {
        let version = payload[0];
        let msg_type = payload[1];
        let token = u64::from_be_bytes(payload[4..12].try_into().unwrap());
        let type_name = match msg_type {
            0x01 => "Activate",
            0x02 => "Verify",
            0x03 => "Heartbeat",
            0x04 => "Deactivate",
            _ => "Unknown",
        };
        format!(
            "Denuvo Anti-Tamper Net v={} type={} token=0x{:016x}",
            version, type_name, token
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::DenuvoAntiTamperNet,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_denuvo_anti_tamper_net_verify() {
        let buf = vec![
            0x01, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        let r = dissect_denuvo_anti_tamper_net(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::DenuvoAntiTamperNet);
        assert!(r.summary.contains("Verify"));
    }

    #[test]
    fn test_denuvo_anti_tamper_net_malformed() {
        let buf = vec![0x01, 0x02, 0x00, 0x00];
        let r = dissect_denuvo_anti_tamper_net(None, None, 0, 0, &buf);
        assert!(r.summary.contains("malformed"));
    }
}
