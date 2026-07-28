use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_siemens_opc_ua_model(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 8 {
        let namespace = u16::from_be_bytes([payload[0], payload[1]]);
        let node_id_type = payload.get(2).copied().unwrap_or(0);
        let node_id = u32::from_be_bytes([
            payload.get(4).copied().unwrap_or(0),
            payload.get(5).copied().unwrap_or(0),
            payload.get(6).copied().unwrap_or(0),
            payload.get(7).copied().unwrap_or(0),
        ]);

        let type_name = match node_id_type {
            0x01 => "Variable",
            0x02 => "Object",
            0x03 => "Method",
            0x04 => "DataType",
            _ => "Node",
        };

        let ns_map = match namespace {
            1 => "Siemens S7-1500",
            2 => "Siemens Drive",
            3 => "Siemens HMI",
            12000..=12010 => "Siemens companion",
            _ => "base",
        };

        format!(
            "Siemens OPC UA — {type_name} ns:{namespace} ({ns_map}) id:{node_id} ({len} bytes)",
            len = payload.len()
        )
    } else {
        format!("Siemens OPC UA Model — {len} bytes", len = payload.len())
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::SiemensOpcUaModel,
        summary,
    }
}
