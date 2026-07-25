use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_opc_ua_pubsub_mqtt(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "OPC UA PubSub MQTT (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("OpcUa") || raw.contains("ua_pubsub") {
            let end = raw.len().min(80);
            format!("OPC UA PubSub MQTT: {}", &raw[..end])
        } else if raw.contains("DataSetWriter") || raw.contains("PublishedDataSet") {
            format!("OPC UA PubSub MQTT: {}", &raw[..raw.len().min(80)])
        } else {
            format!("OPC UA PubSub MQTT ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::OpcUaPubsubMqtt,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opc_ua_pubsub_mqtt_json() {
        let buf = b"{\"OpcUa\":{\"DataSetWriter\":{\"name\":\"sensor1\"}}}";
        let r = dissect_opc_ua_pubsub_mqtt(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::OpcUaPubsubMqtt);
        assert!(r.summary.contains("OpcUa"));
    }

    #[test]
    fn test_opc_ua_pubsub_mqtt_malformed() {
        let buf = b"short";
        let r = dissect_opc_ua_pubsub_mqtt(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
