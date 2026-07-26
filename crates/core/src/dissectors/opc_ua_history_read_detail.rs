use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

fn history_read_type(payload: &[u8]) -> &'static str {
    let raw = String::from_utf8_lossy(payload);
    if raw.contains("ReadRaw") || raw.contains("read_raw") { return "ReadRaw"; }
    if raw.contains("ReadProcessed") || raw.contains("read_processed") { return "ReadProcessed"; }
    if raw.contains("ReadAtTime") || raw.contains("read_at_time") { return "ReadAtTime"; }
    if raw.contains("HistoryRead") && raw.contains("Raw") { return "ReadRawModified"; }
    if raw.contains("HistoryRead") && raw.contains("Processed") { return "ReadProcessed"; }
    if raw.contains("HistoryRead") { return "HistoryRead"; }
    "Unknown"
}

fn aggregate_fn(payload: &[u8]) -> Option<&'static str> {
    let raw = String::from_utf8_lossy(payload);
    if raw.contains("Interpolative") { Some("Interpolative") }
    else if raw.contains("Average") || raw.contains("Avg") { Some("Average") }
    else if raw.contains("TimeAverage") { Some("TimeAverage") }
    else if raw.contains("Count") { Some("Count") }
    else if raw.contains("Minimum") || raw.contains("Min") { Some("Minimum") }
    else if raw.contains("Maximum") || raw.contains("Max") { Some("Maximum") }
    else if raw.contains("StdDev") || raw.contains("StandardDeviation") { Some("StdDev") }
    else if raw.contains("DurationInState") { Some("DurationInState") }
    else if raw.contains("Annotation") { Some("Annotation") }
    else { None }
}

fn continuation_hint(payload: &[u8]) -> Option<String> {
    let raw = String::from_utf8_lossy(payload);
    if let Some(pos) = raw.find("ContinuationPoint") {
        let after = &raw[pos + 16..];
        let v = after.chars().take_while(|c| !c.is_whitespace() && *c != ',' && *c != '}').collect::<String>();
        let len = v.len().min(12);
        return Some(format!("cont={}..", &v[..len]));
    }
    None
}

fn time_range(payload: &[u8]) -> Option<String> {
    let raw = String::from_utf8_lossy(payload);
    let start = if let Some(p) = raw.find("StartTime") {
        let after = &raw[p + 9..];
        Some(after.chars().take_while(|c| !c.is_whitespace() && *c != ',' && *c != '}').collect::<String>())
    } else { None };
    let end = if let Some(p) = raw.find("EndTime") {
        let after = &raw[p + 7..];
        Some(after.chars().take_while(|c| !c.is_whitespace() && *c != ',' && *c != '}').collect::<String>())
    } else { None };
    match (start, end) {
        (Some(s), Some(e)) => Some(format!("range=[{s}..{e}]")),
        (Some(s), None) => Some(format!("start={s}")),
        (None, Some(e)) => Some(format!("end={e}")),
        _ => None,
    }
}

pub fn dissect_opc_ua_history_read_detail(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let fallback = |s: String| DissectedResult {
        src_addr: src_ip, dst_addr: dst_ip,
        src_port: Some(src_port), dst_port: Some(dst_port),
        protocol: Protocol::OpcUaHistoryReadDetail, summary: s,
    };
    if payload.len() < 4 {
        return fallback("OPC UA History Read Detail (partial)".into());
    }
    let read_type = history_read_type(payload);
    let raw = String::from_utf8_lossy(payload);
    let mut parts = vec![format!("OPC UA History: {read_type}")];
    if let Some(agg) = aggregate_fn(payload) {
        parts.push(format!("aggregate={agg}"));
    }
    if let Some(hint) = continuation_hint(payload) {
        parts.push(hint);
    }
    if let Some(range) = time_range(payload) {
        parts.push(range);
    }
    if raw.contains("numValues") || raw.contains("Values") || raw.contains("data") {
        if let Some(pos) = raw.find("numValues") {
            let after = &raw[pos + 9..];
            let n: String = after.trim_start_matches('=').chars().take_while(|c| c.is_ascii_digit()).collect();
            if !n.is_empty() {
                parts.push(format!("values={n}"));
            }
        }
    }
    if raw.contains("StatusCode") || raw.contains("Bad_") || raw.contains("status") {
        parts.push("hasStatus".to_string());
    }
    fallback(parts.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_history_read_raw() {
        let buf = b"HistoryRead:ReadRaw:StartTime=2025-01-01:EndTime=2025-06-01";
        let r = dissect_opc_ua_history_read_detail(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::OpcUaHistoryReadDetail);
        assert!(r.summary.contains("ReadRaw"));
        assert!(r.summary.contains("range"));
    }

    #[test]
    fn test_history_read_processed() {
        let buf = b"HistoryRead:ReadProcessed:Aggregate=Average:StartTime=T1";
        let r = dissect_opc_ua_history_read_detail(None, None, 0, 0, buf);
        assert!(r.summary.contains("ReadProcessed"));
        assert!(r.summary.contains("Average"));
    }

    #[test]
    fn test_history_read_at_time() {
        let buf = b"HistoryRead:ReadAtTime:timestamps";
        let r = dissect_opc_ua_history_read_detail(None, None, 0, 0, buf);
        assert!(r.summary.contains("ReadAtTime"));
    }

    #[test]
    fn test_history_read_continuation() {
        let buf = b"HistoryRead:ReadRaw:ContinuationPoint=abc123:numValues=100";
        let r = dissect_opc_ua_history_read_detail(None, None, 0, 0, buf);
        assert!(r.summary.contains("cont="));
        assert!(r.summary.contains("values=100"));
    }

    #[test]
    fn test_history_read_interpolative() {
        let buf = b"HistoryRead:ReadProcessed:Interpolative:StartTime=T0:EndTime=T1";
        let r = dissect_opc_ua_history_read_detail(None, None, 0, 0, buf);
        assert!(r.summary.contains("Interpolative"));
    }

    #[test]
    fn test_history_read_partial() {
        let r = dissect_opc_ua_history_read_detail(None, None, 0, 0, b"");
        assert!(r.summary.contains("partial"));
    }

    #[test]
    fn test_history_read_min_max() {
        let buf = b"HistoryRead:ReadProcessed:Minimum:Maximum";
        let r = dissect_opc_ua_history_read_detail(None, None, 0, 0, buf);
        assert!(r.summary.contains("Minimum"));
    }

    #[test]
    fn test_history_read_status() {
        let buf = b"HistoryRead:ReadRaw:numValues=50:StatusCode=Bad_NoData";
        let r = dissect_opc_ua_history_read_detail(None, None, 0, 0, buf);
        assert!(r.summary.contains("hasStatus"));
    }
}
