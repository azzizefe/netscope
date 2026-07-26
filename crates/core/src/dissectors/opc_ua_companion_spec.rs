use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

fn companion_spec(spec: &str) -> &'static str {
    match spec {
        "ISA-95" | "isa95" | "ISA95" => "ISA-95 (IEC 62264)",
        "MTConnect" | "mtconnect" => "MTConnect",
        "AutoID" | "autoid" | "AutoId" => "AutoID (IEC 62794)",
        "ADI" | "adi" => "Analyser Device Integration",
        "PLCopen" | "plcopen" => "PLCopen",
        "IO-Link" | "iolink" => "IO-Link",
        "Sercos" | "sercos" => "Sercos",
        "POWERLINK" | "powerlink" => "Ethernet POWERLINK",
        "PROFINET" | "profinet" => "PROFINET",
        "EtherNet/IP" | "ethernet_ip" => "EtherNet/IP",
        "MODBUS" | "modbus" => "MODBUS (IEC 61158)",
        "PROFIBUS" | "profibus" => "PROFIBUS",
        "BACnet" | "bacnet" => "BACnet",
        "KNX" | "knx" => "KNX",
        "CS" | "cs" | "CommercialSecurity" => "Commercial Security",
        "MDIS" | "mdis" => "MDIS (IEC 62769)",
        "MTP" | "mtp" => "MTP (Module Type Package)",
        "NCP" | "ncp" => "NCP (NAMUR)",
        "FDI" | "fdi" => "FDI (IEC 62769)",
        "PACKML" | "PackML" | "packml" => "PackML (ISA-TR88)",
        "Weihenstephan" | "weihenstephan" => "Weihenstephan (WS-Brew)",
        "OPC 400" | "opc400" => "OPC 400 Series",
        "OPC 300" | "opc300" => "OPC 300 Series",
        "VDMA" | "vdma" => "VDMA",
        "Euromap" | "euromap" => "Euromap",
        _ => "Unknown",
    }
}

fn spec_version(v: &str) -> String {
    match v {
        "1.00" | "1.0" => "v1.00".to_string(),
        "1.01" => "v1.01".to_string(),
        "1.02" => "v1.02".to_string(),
        "1.50" => "v1.50".to_string(),
        "2.00" | "2.0" => "v2.00".to_string(),
        _ => format!("v{v}"),
    }
}

pub fn dissect_opc_ua_companion_spec(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let fallback = |s: String| DissectedResult {
        src_addr: src_ip, dst_addr: dst_ip,
        src_port: Some(src_port), dst_port: Some(dst_port),
        protocol: Protocol::OpcUaCompanionSpec, summary: s,
    };
    if payload.len() < 4 {
        return fallback("OPC UA Companion Spec (partial)".into());
    }
    let raw = String::from_utf8_lossy(payload);
    let lower = raw.to_lowercase();
    for &(key, canonical) in &[
        ("isa-95", "ISA-95"), ("isa95", "ISA-95"), ("mtconnect", "MTConnect"),
        ("autoid", "AutoID"), ("adi", "ADI"), ("plcopen", "PLCopen"),
        ("io-link", "IO-Link"), ("sercos", "Sercos"), ("powerlink", "POWERLINK"),
        ("profinet", "PROFINET"), ("ethernet/ip", "EtherNet/IP"), ("modbus", "MODBUS"),
        ("profibus", "PROFIBUS"), ("bacnet", "BACnet"), ("knx", "KNX"),
        ("mdis", "MDIS"), ("mtp", "MTP"), ("ncp", "NCP"),
        ("fdi", "FDI"), ("packml", "PackML"), ("weihenstephan", "Weihenstephan"),
        ("opc 400", "OPC 400"), ("opc 300", "OPC 300"), ("vdma", "VDMA"),
        ("euromap", "Euromap"),
    ] {
        if lower.contains(key) {
            let name = companion_spec(canonical);
            let v = if raw.contains("1.02") { "v1.02" } else if raw.contains("1.01") { "v1.01" } else if raw.contains("1.00") { "v1.00" } else if raw.contains("2.00") { "v2.00" } else { "" };
            if v.is_empty() {
                return fallback(format!("OPC UA Companion: {name}"));
            }
            return fallback(format!("OPC UA Companion: {name} {v}"));
        }
    }
    let ns = raw.find("ns=").or_else(|| raw.find("Namespace"));
    if let Some(pos) = ns {
        let end = (pos + 40).min(raw.len());
        let ctx = &raw[pos..end];
        return fallback(format!("OPC UA Companion: namespace={}", ctx.trim()));
    }
    fallback(format!("OPC UA Companion Spec ({})", super::bytes(payload.len() as u64)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_companion_isa95() {
        let buf = b"ISA-95:OPCUA:namespace";
        let r = dissect_opc_ua_companion_spec(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::OpcUaCompanionSpec);
        assert!(r.summary.contains("ISA-95"));
    }

    #[test]
    fn test_companion_mtconnect() {
        let buf = b"MTConnect:v1.02:namespace_uri";
        let r = dissect_opc_ua_companion_spec(None, None, 0, 0, buf);
        assert!(r.summary.contains("MTConnect"));
        assert!(r.summary.contains("v1.02"));
    }

    #[test]
    fn test_companion_plcopen() {
        let buf = b"PLCopen:namespace=http://PLCopen.org/OpcUa/";
        let r = dissect_opc_ua_companion_spec(None, None, 0, 0, buf);
        assert!(r.summary.contains("PLCopen"));
    }

    #[test]
    fn test_companion_packml() {
        let buf = b"PackML:ISA-TR88:namespace";
        let r = dissect_opc_ua_companion_spec(None, None, 0, 0, buf);
        assert!(r.summary.contains("PackML"));
    }

    #[test]
    fn test_companion_bacnet() {
        let buf = b"BACnet:namespace_uri";
        let r = dissect_opc_ua_companion_spec(None, None, 0, 0, buf);
        assert!(r.summary.contains("BACnet"));
    }

    #[test]
    fn test_companion_partial() {
        let r = dissect_opc_ua_companion_spec(None, None, 0, 0, b"");
        assert!(r.summary.contains("partial"));
    }

    #[test]
    fn test_companion_unknown() {
        let buf = b"some random data here";
        let r = dissect_opc_ua_companion_spec(None, None, 0, 0, buf);
        assert!(r.summary.contains("bytes"));
    }

    #[test]
    fn test_companion_namespace_fallback() {
        let buf = b"ns=http://opcfoundation.org/UA/DI/";
        let r = dissect_opc_ua_companion_spec(None, None, 0, 0, buf);
        assert!(r.summary.contains("namespace"));
        assert!(r.summary.contains("DI"));
    }

    #[test]
    fn test_companion_io_link() {
        let buf = b"IO-Link:namespace=v1.00";
        let r = dissect_opc_ua_companion_spec(None, None, 0, 0, buf);
        assert!(r.summary.contains("IO-Link"));
    }
}
