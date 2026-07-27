use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_valorant_net_var(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 6 {
        "Valorant NetVar (malformed)".into()
    } else {
        let var_id = u16::from_le_bytes(payload[..2].try_into().unwrap());
        let seq = u16::from_be_bytes(payload[2..4].try_into().unwrap());
        let value_type = payload[4];
        let has_value = payload.len() > 5;
        let type_name = match value_type {
            0x01 => "Int32",
            0x02 => "Float",
            0x03 => "Bool",
            0x04 => "String",
            0x05 => "Vector3",
            0x06 => "UInt64",
            _ => "Raw",
        };
        let value_str = if has_value {
            match value_type {
                0x01 if payload.len() >= 10 => {
                    let v = i32::from_le_bytes(payload[6..10].try_into().unwrap());
                    format!(" val={}", v)
                }
                0x02 if payload.len() >= 10 => {
                    let v = f32::from_le_bytes(payload[6..10].try_into().unwrap());
                    format!(" val={:.2}", v)
                }
                0x03 => format!(" val={}", payload[6] != 0),
                0x05 if payload.len() >= 18 => {
                    let x = f32::from_le_bytes(payload[6..10].try_into().unwrap());
                    let y = f32::from_le_bytes(payload[10..14].try_into().unwrap());
                    let z = f32::from_le_bytes(payload[14..18].try_into().unwrap());
                    format!(" val=({:.1},{:.1},{:.1})", x, y, z)
                }
                _ => format!(" len={}", payload.len()),
            }
        } else {
            String::new()
        };
        format!(
            "Valorant NetVar id={} seq={} type={}{}",
            var_id, seq, type_name, value_str,
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::ValorantNetVar,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valorant_netvar_int() {
        let mut buf = vec![0u8; 10];
        buf[..2].copy_from_slice(&5u16.to_le_bytes());
        buf[2..4].copy_from_slice(&1u16.to_be_bytes());
        buf[4] = 0x01;
        buf[6..10].copy_from_slice(&(-42i32).to_le_bytes());
        let r = dissect_valorant_net_var(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::ValorantNetVar);
        assert!(r.summary.contains("id=5"));
        assert!(r.summary.contains("val=-42"));
    }

    #[test]
    fn test_valorant_netvar_float() {
        let mut buf = vec![0u8; 10];
        buf[..2].copy_from_slice(&1u16.to_le_bytes());
        buf[2..4].copy_from_slice(&2u16.to_be_bytes());
        buf[4] = 0x02;
        buf[6..10].copy_from_slice(&2.75f32.to_le_bytes());
        let r = dissect_valorant_net_var(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::ValorantNetVar);
        assert!(r.summary.contains("val=2.75"));
    }
}
