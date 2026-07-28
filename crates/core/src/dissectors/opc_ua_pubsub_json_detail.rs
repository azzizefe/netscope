use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

fn json_msg_type(payload: &[u8]) -> Option<&'static str> {
    let raw = String::from_utf8_lossy(payload);
    if raw.contains("\"MessageId\"") && raw.contains("\"PublishedDataSets\"") {
        return Some("DataSetMessage");
    }
    if raw.contains("\"MessageType\"") {
        if raw.contains("\"ua-data\"") || raw.contains("ua-data") {
            return Some("KeyValueDataSet");
        }
        if raw.contains("\"ua-metadata\"") || raw.contains("ua-metadata") {
            return Some("MetaData");
        }
        if raw.contains("\"ua-keepalive\"") {
            return Some("KeepAlive");
        }
        if raw.contains("\"ua-event\"") {
            return Some("Event");
        }
    }
    if raw.contains("\"DataSetWriterId\"") {
        return Some("DataSetWriterData");
    }
    if raw.contains("\"WriterGroupId\"") {
        return Some("WriterGroup");
    }
    None
}

fn json_extract_field(payload: &[u8], field: &str) -> Option<String> {
    let raw = String::from_utf8_lossy(payload);
    let search = format!("\"{field}\"");
    if let Some(pos) = raw.find(&search) {
        let after = &raw[pos + search.len()..];
        if let Some(colon) = after.find(':') {
            let val = after[colon + 1..].trim();
            let end = val.find([',', '}', ']']).unwrap_or(val.len().min(40));
            let v = val[..end].trim().trim_matches('"').to_string();
            return Some(v);
        }
    }
    None
}

pub fn dissect_opc_ua_pubsub_json_detail(
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
        protocol: Protocol::OpcUaPubsubJsonDetail,
        summary: s,
    };
    if payload.len() < 4 {
        return fallback("OPC UA PubSub JSON Detail (partial)".into());
    }
    let raw = String::from_utf8_lossy(payload);
    let msg_kind = json_msg_type(payload).unwrap_or("Unknown");
    let mut parts = vec![format!("OPC UA PubSub JSON: {msg_kind}")];
    if let Some(msg_id) = json_extract_field(payload, "MessageId") {
        parts.push(format!("id={msg_id}"));
    }
    if let Some(dsw_id) = json_extract_field(payload, "DataSetWriterId") {
        parts.push(format!("writer={dsw_id}"));
    }
    if let Some(wg_id) = json_extract_field(payload, "WriterGroupId") {
        parts.push(format!("group={wg_id}"));
    }
    if let Some(pub_id) = json_extract_field(payload, "PublisherId") {
        parts.push(format!("pub={pub_id}"));
    }
    if let Some(seq) = json_extract_field(payload, "SequenceNumber") {
        parts.push(format!("seq={seq}"));
    }
    if let Some(ts) = json_extract_field(payload, "TimeStamp") {
        let t = ts.trim_matches('"');
        if t.len() < 30 {
            parts.push(format!("ts={t}"));
        }
    }
    if parts.len() == 1 && raw.len() > 80 {
        parts.push(format!("raw: {}...", &raw[..80]));
    } else if parts.len() == 1 {
        parts.push(format!("raw: {raw}"));
    }
    fallback(parts.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_detail_dataset_message() {
        let buf = b"{\"MessageId\":\"1\",\"PublishedDataSets\":[{\"Name\":\"sensor1\"}]}";
        let r = dissect_opc_ua_pubsub_json_detail(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::OpcUaPubsubJsonDetail);
        assert!(r.summary.contains("DataSetMessage"));
    }

    #[test]
    fn test_json_detail_key_value() {
        let buf = b"{\"MessageType\":\"ua-data\",\"DataSetWriterId\":100}";
        let r = dissect_opc_ua_pubsub_json_detail(None, None, 0, 0, buf);
        assert!(r.summary.contains("KeyValueDataSet"));
        assert!(r.summary.contains("writer=100"));
    }

    #[test]
    fn test_json_detail_writer_group() {
        let buf = b"{\"WriterGroupId\":5,\"PublisherId\":\"plc01\",\"SequenceNumber\":42}";
        let r = dissect_opc_ua_pubsub_json_detail(None, None, 0, 0, buf);
        assert!(r.summary.contains("group=5"));
        assert!(r.summary.contains("pub=plc01"));
        assert!(r.summary.contains("seq=42"));
    }

    #[test]
    fn test_json_detail_partial() {
        let r = dissect_opc_ua_pubsub_json_detail(None, None, 0, 0, b"");
        assert!(r.summary.contains("partial"));
    }

    #[test]
    fn test_json_detail_unknown() {
        let buf = b"{\"foo\":\"bar\"}";
        let r = dissect_opc_ua_pubsub_json_detail(None, None, 0, 0, buf);
        assert!(r.summary.contains("Unknown"));
    }

    #[test]
    fn test_json_detail_keepalive() {
        let buf = b"{\"MessageType\":\"ua-keepalive\",\"PublisherId\":\"sensor1\"}";
        let r = dissect_opc_ua_pubsub_json_detail(None, None, 0, 0, buf);
        assert!(r.summary.contains("KeepAlive"));
    }

    #[test]
    fn test_json_detail_event() {
        let buf = b"{\"MessageType\":\"ua-event\",\"DataSetWriterId\":200}";
        let r = dissect_opc_ua_pubsub_json_detail(None, None, 0, 0, buf);
        assert!(r.summary.contains("Event"));
    }

    #[test]
    fn test_json_detail_metadata() {
        let buf = b"{\"MessageType\":\"ua-metadata\",\"DataSetWriterId\":300}";
        let r = dissect_opc_ua_pubsub_json_detail(None, None, 0, 0, buf);
        assert!(r.summary.contains("MetaData"));
    }
}
