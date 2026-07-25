use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_ptc_thingworx_alwayson(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "ThingWorx AlwaysOn (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("ThingWorx") || raw.contains("thingworx") || raw.contains("AlwaysOn") {
            let end = raw.len().min(80);
            format!("ThingWorx AlwaysOn: {}", &raw[..end])
        } else if raw.contains("property") || raw.contains("service") || raw.contains("subscription") {
            format!("ThingWorx AlwaysOn: {}", &raw[..raw.len().min(80)])
        } else {
            format!("ThingWorx AlwaysOn ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::PtcThingworxAlwayson,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ptc_thingworx_alwayson_property() {
        let buf = b"ThingWorx:AlwaysOn:property:temperature";
        let r = dissect_ptc_thingworx_alwayson(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::PtcThingworxAlwayson);
        assert!(r.summary.contains("ThingWorx"));
    }

    #[test]
    fn test_ptc_thingworx_alwayson_malformed() {
        let buf = b"short";
        let r = dissect_ptc_thingworx_alwayson(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
