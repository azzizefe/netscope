use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

const COE_OBJECT_COUNTER: u16 = 0x6000;
const COE_OBJECT_MODULE_ID: u16 = 0x6020;

pub fn dissect_ethercat_beckhoff_mdp(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 6 {
        let mdp_idx = u16::from_be_bytes([payload[0], payload[1]]);
        let sub_idx = payload.get(2).copied().unwrap_or(0);
        let slot = payload.get(3).copied().unwrap_or(0);
        let value = u32::from_be_bytes([payload.get(4).copied().unwrap_or(0), payload.get(5).copied().unwrap_or(0), payload.get(6).copied().unwrap_or(0), payload.get(7).copied().unwrap_or(0)]);

        let obj_name = match mdp_idx {
            COE_OBJECT_COUNTER => "ModuleCounter",
            COE_OBJECT_MODULE_ID => "ModuleID",
            idx if (0x8000..=0xFFFF).contains(&idx) => "Beckhoff CoE vendor obj",
            idx if (0x1000..=0x1FFF).contains(&idx) => "MDP standard",
            _ => "CoE object",
        };

        format!("EtherCAT MDP (Beckhoff) — {obj_name} idx:0x{mdp_idx:04x} sub:{sub_idx} slot:{slot} val:{value} ({len} bytes)", len = payload.len())
    } else {
        format!("EtherCAT MDP (Beckhoff) — {len} bytes", len = payload.len())
    };

    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::EthercatBeckhoffMdp,
        summary,
    }
}
