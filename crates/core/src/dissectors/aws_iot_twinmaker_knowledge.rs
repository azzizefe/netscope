use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_aws_iot_twinmaker_knowledge(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "AWS IoT TwinMaker (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("TwinMaker") || raw.contains("twinmaker") {
            let end = raw.len().min(80);
            format!("AWS IoT TwinMaker Knowledge: {}", &raw[..end])
        } else if raw.contains("workspace") || raw.contains("componentType") || raw.contains("entity") {
            format!("AWS IoT TwinMaker Knowledge: {}", &raw[..raw.len().min(80)])
        } else {
            format!("AWS IoT TwinMaker Knowledge ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::AwsIotTwinmakerKnowledge,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_iot_twinmaker_knowledge_graph() {
        let buf = b"{\"TwinMaker\":\"workspace\",\"entity\":\"Thermostat_1\"}";
        let r = dissect_aws_iot_twinmaker_knowledge(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::AwsIotTwinmakerKnowledge);
        assert!(r.summary.contains("TwinMaker"));
    }

    #[test]
    fn test_aws_iot_twinmaker_knowledge_malformed() {
        let buf = b"short";
        let r = dissect_aws_iot_twinmaker_knowledge(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
