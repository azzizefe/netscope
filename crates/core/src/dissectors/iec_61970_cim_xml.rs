use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_iec_61970_cim_xml(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "IEC 61970 CIM XML (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("cim:") || raw.contains("CIM") || raw.contains("61970") {
            let end = raw.len().min(80);
            format!("IEC 61970 CIM XML: {}", &raw[..end])
        } else if raw.contains("PowerSystemResource") || raw.contains("ConductingEquipment") {
            format!("IEC 61970 CIM XML: {}", &raw[..raw.len().min(80)])
        } else {
            format!("IEC 61970 CIM XML ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Iec61970CimXml,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iec_61970_cim_xml_model() {
        let buf = b"<cim:PowerSystemResource rdf:ID=\"PSR_1\"/>";
        let r = dissect_iec_61970_cim_xml(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::Iec61970CimXml);
        assert!(r.summary.contains("cim"));
    }

    #[test]
    fn test_iec_61970_cim_xml_malformed() {
        let buf = b"short";
        let r = dissect_iec_61970_cim_xml(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
