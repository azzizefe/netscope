use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

fn mqtt_json_network_message(payload: &[u8]) -> &'static str {
    let raw = String::from_utf8_lossy(payload);
    if raw.contains("\"MessageType\":\"ua-data\"")
        || raw.contains("MessageType") && raw.contains("ua-data")
    {
        return "DataSetMessage";
    }
    if raw.contains("\"MessageType\":\"ua-metadata\"")
        || raw.contains("MessageType") && raw.contains("ua-metadata")
    {
        return "MetaData";
    }
    if raw.contains("\"MessageType\":\"ua-keepalive\"")
        || raw.contains("MessageType") && raw.contains("ua-keepalive")
    {
        return "KeepAlive";
    }
    if raw.contains("\"MessageType\":\"ua-event\"")
        || raw.contains("MessageType") && raw.contains("ua-event")
    {
        return "Event";
    }
    if raw.contains("PublishedDataSets") {
        return "DataSetMessage";
    }
    if raw.contains("WriterGroup") || raw.contains("WriterGroupId") {
        return "WriterGroupConfiguration";
    }
    if raw.contains("DataSetWriter") || raw.contains("DataSetWriterId") {
        return "DataSetWriterConfiguration";
    }
    if raw.contains("ReaderGroup") || raw.contains("ReaderGroupId") {
        return "ReaderGroupConfiguration";
    }
    if raw.contains("DataSetReader") {
        return "DataSetReaderConfiguration";
    }
    if raw.contains("Status") || raw.contains("ConnectionStatus") {
        return "StatusMessage";
    }
    "Unknown"
}

fn mqtt_topic_hint(payload: &[u8]) -> Option<String> {
    let raw = String::from_utf8_lossy(payload);
    let topics = [
        "/ua-data",
        "/ua-metadata",
        "/ua-keepalive",
        "/ua-event",
        "/status",
    ];
    for topic in &topics {
        if raw.contains(topic) {
            return Some(topic.trim_start_matches('/').to_string());
        }
    }
    if raw.contains("DataSetMessage") {
        if raw.contains("Temperature") {
            return Some("sensor/Temperature".into());
        }
        if raw.contains("Pressure") {
            return Some("sensor/Pressure".into());
        }
    }
    None
}

fn mqtt_payload_format(payload: &[u8]) -> &'static str {
    let raw = String::from_utf8_lossy(payload);
    if raw.contains("\"Payload\":") && raw.contains("\"Value\":") {
        return "KeyValuePair";
    }
    if raw.contains("\"Payload\":[") {
        return "RawData";
    }
    if raw.contains("Values") && !raw.contains("KeyValue") {
        return "DataSetArray";
    }
    if raw.contains("{") && raw.contains("}") {
        "JSON"
    } else {
        "Raw"
    }
}

fn extract_mqtt_field(payload: &[u8], field: &str) -> Option<String> {
    let raw = String::from_utf8_lossy(payload);
    let search = format!("\"{field}\"");
    if let Some(pos) = raw.find(&search) {
        let after = &raw[pos + search.len()..];
        if let Some(colon) = after.find(':') {
            let val = after[colon + 1..].trim();
            let end = val.find([',', '}', ']']).unwrap_or(val.len().min(40));
            let v = val[..end].trim().trim_matches('"').to_string();
            if v.len() < 40 {
                return Some(v);
            }
        }
    }
    None
}

pub fn dissect_opc_ua_mqtt_json_network(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let fallback = |s: String| DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::OpcUaMqttJsonNetwork,
        summary: s,
    };
    if payload.len() < 4 {
        return fallback("OPC UA MQTT JSON Network (partial)".into());
    }
    let msg_kind = mqtt_json_network_message(payload);
    let payload_fmt = mqtt_payload_format(payload);
    let mut parts = vec![format!("OPC UA MQTT JSON: {msg_kind}")];
    parts.push(payload_fmt.to_string());
    if let Some(topic) = mqtt_topic_hint(payload) {
        parts.push(format!("topic=opcua/{topic}"));
    }
    if let Some(id) = extract_mqtt_field(payload, "MessageId") {
        parts.push(format!("id={id}"));
    }
    if let Some(wg) = extract_mqtt_field(payload, "WriterGroupId") {
        parts.push(format!("group={wg}"));
    }
    if let Some(ds) = extract_mqtt_field(payload, "DataSetWriterId") {
        parts.push(format!("writer={ds}"));
    }
    if let Some(pub_id) = extract_mqtt_field(payload, "PublisherId") {
        parts.push(format!("pub={pub_id}"));
    }
    if let Some(seq) = extract_mqtt_field(payload, "SequenceNumber") {
        parts.push(format!("seq={seq}"));
    }
    if msg_kind == "StatusMessage" {
        if let Some(st) = extract_mqtt_field(payload, "Status") {
            parts.push(format!("status={st}"));
        }
    }
    fallback(parts.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mqtt_json_data_set() {
        let buf = b"{\"MessageType\":\"ua-data\",\"DataSetWriterId\":100,\"SequenceNumber\":42}";
        let r = dissect_opc_ua_mqtt_json_network(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::OpcUaMqttJsonNetwork);
        assert!(r.summary.contains("DataSetMessage"));
        assert!(r.summary.contains("writer=100"));
        assert!(r.summary.contains("seq=42"));
    }

    #[test]
    fn test_mqtt_json_metadata() {
        let buf = b"{\"MessageType\":\"ua-metadata\",\"PublisherId\":\"plc01\"}";
        let r = dissect_opc_ua_mqtt_json_network(None, None, 0, 0, buf);
        assert!(r.summary.contains("MetaData"));
        assert!(r.summary.contains("pub=plc01"));
    }

    #[test]
    fn test_mqtt_json_keepalive() {
        let buf = b"{\"MessageType\":\"ua-keepalive\"}";
        let r = dissect_opc_ua_mqtt_json_network(None, None, 0, 0, buf);
        assert!(r.summary.contains("KeepAlive"));
    }

    #[test]
    fn test_mqtt_json_event() {
        let buf = b"{\"MessageType\":\"ua-event\",\"DataSetWriterId\":200}";
        let r = dissect_opc_ua_mqtt_json_network(None, None, 0, 0, buf);
        assert!(r.summary.contains("Event"));
    }

    #[test]
    fn test_mqtt_json_status() {
        let buf = b"{\"Status\":\"Connected\",\"ConnectionStatus\":\"active\"}";
        let r = dissect_opc_ua_mqtt_json_network(None, None, 0, 0, buf);
        assert!(r.summary.contains("StatusMessage"));
    }

    #[test]
    fn test_mqtt_json_writer_group() {
        let buf = b"{\"WriterGroupId\":5,\"PublisherId\":\"sensor1\"}";
        let r = dissect_opc_ua_mqtt_json_network(None, None, 0, 0, buf);
        assert!(r.summary.contains("WriterGroupConfiguration"));
    }

    #[test]
    fn test_mqtt_json_partial() {
        let r = dissect_opc_ua_mqtt_json_network(None, None, 0, 0, b"");
        assert!(r.summary.contains("partial"));
    }

    #[test]
    fn test_mqtt_json_unknown() {
        let buf = b"{\"foo\":\"bar\"}";
        let r = dissect_opc_ua_mqtt_json_network(None, None, 0, 0, buf);
        assert!(r.summary.contains("Unknown"));
    }

    #[test]
    fn test_mqtt_json_key_value() {
        let buf = b"{\"Payload\":{\"Value\":42},\"DataSetWriterId\":1}";
        let r = dissect_opc_ua_mqtt_json_network(None, None, 0, 0, buf);
        assert!(r.summary.contains("KeyValuePair"));
    }
}
