use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_warzone_netcode_rigid(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 24 {
        "Warzone Rigid Body (malformed)".into()
    } else {
        let entity_id = u32::from_le_bytes(payload[..4].try_into().unwrap());
        let pos_x = f32::from_le_bytes(payload[4..8].try_into().unwrap());
        let pos_y = f32::from_le_bytes(payload[8..12].try_into().unwrap());
        let pos_z = f32::from_le_bytes(payload[12..16].try_into().unwrap());
        let rot = i16::from_be_bytes(payload[16..18].try_into().unwrap());
        let vel = i16::from_be_bytes(payload[18..20].try_into().unwrap());
        let seq = u32::from_le_bytes(payload[20..24].try_into().unwrap());
        format!(
            "Warzone Rigid entity={} pos=({:.1},{:.1},{:.1}) rot={} vel={} seq={}",
            entity_id, pos_x, pos_y, pos_z, rot, vel, seq
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::WarzoneNetcodeRigid,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_warzone_rigid() {
        let mut buf = vec![0u8; 28];
        buf[..4].copy_from_slice(&100u32.to_le_bytes());
        buf[4..8].copy_from_slice(&(1.0f32).to_le_bytes());
        buf[8..12].copy_from_slice(&(2.0f32).to_le_bytes());
        buf[12..16].copy_from_slice(&(3.0f32).to_le_bytes());
        buf[16..18].copy_from_slice(&42i16.to_be_bytes());
        buf[18..20].copy_from_slice(&(-5i16).to_be_bytes());
        buf[20..24].copy_from_slice(&1u32.to_le_bytes());
        let r = dissect_warzone_netcode_rigid(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::WarzoneNetcodeRigid);
        assert!(r.summary.contains("entity=100"));
    }
}
