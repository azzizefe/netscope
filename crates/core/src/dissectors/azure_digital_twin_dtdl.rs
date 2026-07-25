use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_azure_digital_twin_dtdl(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Azure Digital Twins DTDL (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("dtmi:") || raw.contains("DigitalTwins") || raw.contains("dtdl") {
            let end = raw.len().min(80);
            format!("Azure Digital Twins DTDL: {}", &raw[..end])
        } else if raw.contains("@context") || raw.contains("@type") {
            format!("Azure Digital Twins DTDL: {}", &raw[..raw.len().min(80)])
        } else {
            format!("Azure Digital Twins DTDL ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::AzureDigitalTwinDtdl,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_azure_digital_twin_dtdl_model() {
        let buf = b"{\"@id\":\"dtmi:example:Thermostat;1\",\"@type\":\"Interface\"}";
        let r = dissect_azure_digital_twin_dtdl(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::AzureDigitalTwinDtdl);
        assert!(r.summary.contains("dtmi"));
    }

    #[test]
    fn test_azure_digital_twin_dtdl_malformed() {
        let buf = b"short";
        let r = dissect_azure_digital_twin_dtdl(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
