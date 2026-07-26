use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

fn alarm_state(val: &str) -> String {
    match val {
        "Active" | "active" | "TRUE" | "true" | "1" => "Active".into(),
        "Inactive" | "inactive" | "FALSE" | "false" | "0" => "Inactive".into(),
        "Acknowledged" | "acknowledged" => "Acknowledged".into(),
        "Unacknowledged" | "unacknowledged" => "Unacknowledged".into(),
        "Confirmed" | "confirmed" => "Confirmed".into(),
        "Unconfirmed" | "unconfirmed" => "Unconfirmed".into(),
        "Suppressed" | "suppressed" => "Suppressed".into(),
        "Shelved" | "shelved" => "Shelved".into(),
        _ => val.to_string(),
    }
}

fn alarm_severity(s: u32) -> &'static str {
    if s >= 900 { "Critical" }
    else if s >= 700 { "High" }
    else if s >= 500 { "Medium" }
    else if s >= 200 { "Low" }
    else { "None" }
}

fn alarm_type(type_str: &str) -> &'static str {
    if type_str.contains("ExclusiveLimit") || type_str.contains("Exclusive") { "ExclusiveLimitAlarm" }
    else if type_str.contains("InclusiveLimit") || type_str.contains("Inclusive") { "InclusiveLimitAlarm" }
    else if type_str.contains("Trip") { "TripAlarm" }
    else if type_str.contains("Rate") || type_str.contains("RateOfChange") { "RateOfChangeAlarm" }
    else if type_str.contains("Discrete") { "DiscreteAlarm" }
    else if type_str.contains("Acknowledgeable") { "AcknowledgeableCondition" }
    else if type_str.contains("AlarmCondition") { "AlarmCondition" }
    else { "AlarmCondition" }
}

pub fn dissect_opc_ua_alarm_shell(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let fallback = |s: String| DissectedResult {
        src_addr: src_ip, dst_addr: dst_ip,
        src_port: Some(src_port), dst_port: Some(dst_port),
        protocol: Protocol::OpcUaAlarmShell, summary: s,
    };
    if payload.len() < 4 {
        return fallback("OPC UA Alarm Shell (partial)".into());
    }
    let raw = String::from_utf8_lossy(payload);
    let a_type = alarm_type(&raw);
    let mut parts = vec![format!("OPC UA Alarm: {a_type}")];
    for &keyword in &["Active", "Inactive", "Acknowledged", "Unacknowledged", "Confirmed", "Unconfirmed", "Suppressed", "Shelved"] {
        if raw.contains(keyword) {
            parts.push(alarm_state(keyword));
            break;
        }
    }
    if let Some(pos) = raw.find("Severity") {
        let after = &raw[pos + 8..];
        let after_eq = after.trim_start_matches(&['=', ':', ' '][..]);
        let num: String = after_eq.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(v) = num.parse::<u32>() {
            parts.push(format!("severity={}({})", v, alarm_severity(v)));
        }
    }
    if raw.contains("AlarmCondition") || raw.contains("Condition") {
        if raw.contains("True") || raw.contains("true") || raw.contains("TRUE") {
            parts.push("active".to_string());
        }
    }
    if raw.contains("Time") && (raw.contains("iso8601") || raw.contains("timestamp")) {
        parts.push("hasTimestamp".to_string());
    }
    if raw.contains("Message") && (raw.contains("text") || raw.contains("string")) {
        parts.push("hasMessage".to_string());
    }
    fallback(parts.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alarm_active() {
        let buf = b"AlarmCondition:Active:Severity=800";
        let r = dissect_opc_ua_alarm_shell(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::OpcUaAlarmShell);
        assert!(r.summary.contains("AlarmCondition"));
        assert!(r.summary.contains("Active"));
    }

    #[test]
    fn test_alarm_exclusive_limit() {
        let buf = b"ExclusiveLimitAlarm:HighHigh:Severity=950";
        let r = dissect_opc_ua_alarm_shell(None, None, 0, 0, buf);
        assert!(r.summary.contains("ExclusiveLimitAlarm"));
        assert!(r.summary.contains("Critical"));
    }

    #[test]
    fn test_alarm_acknowledge() {
        let buf = b"AcknowledgeableCondition:Unacknowledged:Severity=500";
        let r = dissect_opc_ua_alarm_shell(None, None, 0, 0, buf);
        assert!(r.summary.contains("AcknowledgeableCondition"));
        assert!(r.summary.contains("Unacknowledged"));
    }

    #[test]
    fn test_alarm_rate_of_change() {
        let buf = b"RateOfChangeAlarm:Active:Severity=700";
        let r = dissect_opc_ua_alarm_shell(None, None, 0, 0, buf);
        assert!(r.summary.contains("RateOfChangeAlarm"));
    }

    #[test]
    fn test_alarm_discrete() {
        let buf = b"DiscreteAlarm:Active:Severity=400";
        let r = dissect_opc_ua_alarm_shell(None, None, 0, 0, buf);
        assert!(r.summary.contains("DiscreteAlarm"));
    }

    #[test]
    fn test_alarm_partial() {
        let r = dissect_opc_ua_alarm_shell(None, None, 0, 0, b"");
        assert!(r.summary.contains("partial"));
    }

    #[test]
    fn test_alarm_trip() {
        let buf = b"TripAlarm:Active:Severity=1000";
        let r = dissect_opc_ua_alarm_shell(None, None, 0, 0, buf);
        assert!(r.summary.contains("TripAlarm"));
    }

    #[test]
    fn test_alarm_medium_severity() {
        let buf = b"AlarmCondition:Inactive:Severity=500";
        let r = dissect_opc_ua_alarm_shell(None, None, 0, 0, buf);
        assert!(r.summary.contains("Medium"));
    }
}
