use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_opc_ua_alarm_condition(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "OPC UA Alarm Condition (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("AlarmCondition") || raw.contains("Acknowledgeable") {
            let end = raw.len().min(80);
            format!("OPC UA Alarm Condition: {}", &raw[..end])
        } else if raw.contains("ActiveState") || raw.contains("Severity") {
            format!("OPC UA Alarm Condition: {}", &raw[..raw.len().min(80)])
        } else {
            format!("OPC UA Alarm Condition ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::OpcUaAlarmCondition,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opc_ua_alarm_condition_event() {
        let buf = b"{\"AlarmCondition\":true,\"Severity\":500,\"ActiveState\":true}";
        let r = dissect_opc_ua_alarm_condition(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::OpcUaAlarmCondition);
        assert!(r.summary.contains("AlarmCondition"));
    }

    #[test]
    fn test_opc_ua_alarm_condition_malformed() {
        let buf = b"short";
        let r = dissect_opc_ua_alarm_condition(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
