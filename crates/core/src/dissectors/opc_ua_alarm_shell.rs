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
    if s >= 900 {
        "Critical"
    } else if s >= 700 {
        "High"
    } else if s >= 500 {
        "Medium"
    } else if s >= 200 {
        "Low"
    } else {
        "None"
    }
}

/// OPC UA Part 9 alarm types, longest-first where one name contains another.
///
/// The order is the whole correctness argument. `NonExclusiveLimitAlarm`
/// literally contains the text `ExclusiveLimitAlarm`, and `SystemOffNormalAlarm`
/// contains `OffNormalAlarm` — so a `contains` test for the shorter name claims
/// the longer one's traffic. Every `NonExclusive*` alarm used to be reported as
/// `ExclusiveLimitAlarm`, and every `Exclusive*` subtype — Level, Deviation,
/// RateOfChange — was flattened onto Limit.
const ALARM_TYPES: &[&str] = &[
    "NonExclusiveRateOfChangeAlarm",
    "NonExclusiveDeviationAlarm",
    "NonExclusiveLevelAlarm",
    "NonExclusiveLimitAlarm",
    "ExclusiveRateOfChangeAlarm",
    "ExclusiveDeviationAlarm",
    "ExclusiveLevelAlarm",
    "ExclusiveLimitAlarm",
    "CertificateExpirationAlarm",
    "InstrumentDiagnosticAlarm",
    "SystemDiagnosticAlarm",
    "SystemOffNormalAlarm",
    "DiscrepancyAlarm",
    "OffNormalAlarm",
    "DiscreteAlarm",
    "TripAlarm",
    // Unprefixed shorthand some servers use for the abstract type.
    "RateOfChangeAlarm",
    // The two condition types the alarms derive from, last because any of the
    // above is the more useful answer when both appear.
    "AcknowledgeableCondition",
    "AlarmCondition",
];

/// The alarm type named in the payload, or `None` if it names none.
///
/// `None` is the honest answer: this used to fall back to `AlarmCondition`,
/// which reported a specific type for traffic that never mentioned one.
fn alarm_type(type_str: &str) -> Option<&'static str> {
    ALARM_TYPES.iter().copied().find(|t| type_str.contains(t))
}

pub fn dissect_opc_ua_alarm_shell(
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
        protocol: Protocol::OpcUaAlarmShell,
        summary: s,
    };
    if payload.len() < 4 {
        return fallback("OPC UA Alarm Shell (partial)".into());
    }
    let raw = String::from_utf8_lossy(payload);
    let mut parts = vec![match alarm_type(&raw) {
        Some(t) => format!("OPC UA Alarm: {t}"),
        None => "OPC UA Alarm: (type not named)".to_string(),
    }];
    let mut state_named = false;
    for &keyword in &[
        "Active",
        "Inactive",
        "Acknowledged",
        "Unacknowledged",
        "Confirmed",
        "Unconfirmed",
        "Suppressed",
        "Shelved",
    ] {
        if raw.contains(keyword) {
            parts.push(alarm_state(keyword));
            state_named = true;
            break;
        }
    }
    if let Some(pos) = raw.find("Severity") {
        let after = &raw[pos + 8..];
        let after_eq = after.trim_start_matches(&['=', ':', ' '][..]);
        let num: String = after_eq
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if let Ok(v) = num.parse::<u32>() {
            parts.push(format!("severity={}({})", v, alarm_severity(v)));
        }
    }
    // A condition can report its state as a bare boolean instead of one of the
    // state keywords above. Only worth saying when the loop found nothing —
    // otherwise the same fact gets printed twice, once as `Active` and again as
    // `active`. (`contains("AlarmCondition")` was redundant here: the
    // `Condition` test it was OR'd with already covers it.)
    if !state_named
        && raw.contains("Condition")
        && (raw.contains("True") || raw.contains("true") || raw.contains("TRUE"))
    {
        parts.push("active".to_string());
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

    /// The bug this guards: `NonExclusiveLimitAlarm` contains the text
    /// `ExclusiveLimitAlarm`, so testing for the shorter name first claimed the
    /// whole `NonExclusive*` family — a different alarm model with a different
    /// meaning for the operator.
    #[test]
    fn a_non_exclusive_alarm_is_not_reported_as_exclusive() {
        for name in [
            "NonExclusiveLimitAlarm",
            "NonExclusiveLevelAlarm",
            "NonExclusiveDeviationAlarm",
            "NonExclusiveRateOfChangeAlarm",
        ] {
            let buf = format!("{name}:Active:Severity=800");
            let r = dissect_opc_ua_alarm_shell(None, None, 0, 0, buf.as_bytes());
            assert!(r.summary.contains(name), "{}", r.summary);
        }
    }

    /// The `Exclusive*` subtypes are distinct alarm types, not all Limit.
    #[test]
    fn each_exclusive_subtype_keeps_its_own_name() {
        for name in [
            "ExclusiveLimitAlarm",
            "ExclusiveLevelAlarm",
            "ExclusiveDeviationAlarm",
            "ExclusiveRateOfChangeAlarm",
        ] {
            let buf = format!("{name}:Active:Severity=800");
            let r = dissect_opc_ua_alarm_shell(None, None, 0, 0, buf.as_bytes());
            assert_eq!(
                alarm_type(&String::from_utf8_lossy(buf.as_bytes())),
                Some(name),
            );
            assert!(r.summary.contains(name), "{}", r.summary);
        }
    }

    /// `SystemOffNormalAlarm` contains `OffNormalAlarm` — the same trap, a
    /// different pair.
    #[test]
    fn a_system_off_normal_alarm_keeps_its_prefix() {
        let buf = b"SystemOffNormalAlarm:Active:Severity=600";
        let r = dissect_opc_ua_alarm_shell(None, None, 0, 0, buf);
        assert!(r.summary.contains("SystemOffNormalAlarm"), "{}", r.summary);

        let plain = b"OffNormalAlarm:Active:Severity=600";
        let r = dissect_opc_ua_alarm_shell(None, None, 0, 0, plain);
        assert!(r.summary.contains("OffNormalAlarm"), "{}", r.summary);
        assert!(!r.summary.contains("System"), "{}", r.summary);
    }

    /// A payload that names no alarm type says so, rather than being reported
    /// as a definite `AlarmCondition`.
    #[test]
    fn an_unnamed_type_is_not_invented() {
        assert_eq!(alarm_type("something else entirely"), None);
        let r = dissect_opc_ua_alarm_shell(None, None, 0, 0, b"Severity=300 payload");
        assert!(r.summary.contains("type not named"), "{}", r.summary);
        assert!(!r.summary.contains("AlarmCondition"), "{}", r.summary);
    }

    /// The boolean-state fallback only speaks when the keyword scan found
    /// nothing, so one state is never printed twice.
    #[test]
    fn the_state_is_reported_once() {
        let buf = b"AlarmCondition:Active:ActiveState=True:Severity=800";
        let r = dissect_opc_ua_alarm_shell(None, None, 0, 0, buf);
        assert!(r.summary.contains("Active"), "{}", r.summary);
        assert!(!r.summary.contains(" active"), "{}", r.summary);

        // With no keyword present, the boolean is the only signal there is.
        let boolean = b"SomeCondition:EnabledState=True:Severity=800";
        let r = dissect_opc_ua_alarm_shell(None, None, 0, 0, boolean);
        assert!(r.summary.contains("active"), "{}", r.summary);
    }
}
