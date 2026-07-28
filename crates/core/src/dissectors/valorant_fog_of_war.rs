use super::DissectedResult;
use crate::models::Protocol;
use std::fmt::Write;
use std::net::IpAddr;

pub fn dissect_valorant_fog_of_war(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Valorant FoW (malformed)".into()
    } else {
        let seq = u32::from_le_bytes(payload[..4].try_into().unwrap());
        let visibility_count = u16::from_le_bytes(payload[4..6].try_into().unwrap());
        let flags = payload[6];
        let _reserved = payload[7];
        let mut visible_entities = String::new();
        if payload.len() > 8 && visibility_count > 0 {
            let max_visible = visibility_count.min(16) as usize;
            for i in 0..max_visible {
                if i * 4 + 12 <= payload.len() {
                    let eid = u32::from_le_bytes(
                        payload[8 + i * 4..12 + i * 4].try_into().unwrap_or([0; 4]),
                    );
                    if !visible_entities.is_empty() {
                        visible_entities.push(',');
                    }
                    let _ = write!(visible_entities, "{}", eid);
                }
            }
        }
        let is_visible = (flags & 0x01) != 0;
        format!(
            "Valorant FoW seq={} visible={} flags=0x{:02x}{}{}",
            seq,
            visibility_count,
            flags,
            if is_visible { " TEAM_VISIBLE" } else { "" },
            if !visible_entities.is_empty() {
                format!(" entities=[{}]", visible_entities)
            } else {
                String::new()
            },
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::ValorantFogOfWar,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valorant_fow() {
        let payload = b"\x01\x00\x00\x00\x02\x00\x01\x00\x0a\x00\x00\x00\x14\x00\x00\x00";
        let r = dissect_valorant_fog_of_war(None, None, 0, 0, payload);
        assert_eq!(r.protocol, Protocol::ValorantFogOfWar);
        assert!(r.summary.contains("seq=1"));
    }
}
