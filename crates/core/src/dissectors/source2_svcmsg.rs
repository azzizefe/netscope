use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_source2_svcmsg(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 4 {
        "Source 2 SVC_Msg (malformed)".into()
    } else {
        let svc_type = payload[0];
        let data_len = u16::from_be_bytes([payload[1], payload[2]]);
        let flags = payload[3];
        let svc_name = match svc_type {
            0 => "SVC_ServerInfo",
            1 => "SVC_SendTable",
            2 => "SVC_ClassInfo",
            3 => "SVC_SetPause",
            4 => "SVC_CreateStringTable",
            5 => "SVC_UpdateStringTable",
            6 => "SVC_VoiceData",
            7 => "SVC_PacketEntities",
            8 => "SVC_TempEntities",
            9 => "SVC_Prefetch",
            10 => "SVC_GameEvent",
            11 => "SVC_UserMessage",
            _ => "SVC_Other",
        };
        format!("Source 2 {} ({} bytes, flags 0x{:02x})", svc_name, data_len, flags)
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Source2Svcmsg,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_source2_svcmsg_server_info() {
        let r = dissect_source2_svcmsg(None, None, 27015, 27015, b"\x00\x00\x14\x00\x48\x65\x6c\x6c\x6f");
        assert_eq!(r.protocol, Protocol::Source2Svcmsg);
        assert!(r.summary.contains("SVC_ServerInfo"));
    }

    #[test]
    fn test_source2_svcmsg_packet_entities() {
        let r = dissect_source2_svcmsg(None, None, 27015, 27015, b"\x07\x00\x20\x01\xde\xad\xbe\xef");
        assert_eq!(r.protocol, Protocol::Source2Svcmsg);
        assert!(r.summary.contains("SVC_PacketEntities"));
    }
}
