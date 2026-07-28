use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_nvidia_gfn_ctrl(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "NVIDIA GFN Control (malformed)".into()
    } else {
        let magic = u32::from_be_bytes(payload[..4].try_into().unwrap());
        let opcode = u16::from_be_bytes(payload[4..6].try_into().unwrap());
        let flags = payload[6];
        let seq = payload[7];
        let op_name = match opcode {
            0x0001 => "KeyDown",
            0x0002 => "KeyUp",
            0x0003 => "MouseMove",
            0x0004 => "MouseDown",
            0x0005 => "MouseUp",
            0x0006 => "GamepadState",
            0x0007 => "TouchEvent",
            0x0008 => "GyroSample",
            0x0101 => "HapticFeedback",
            0x0102 => "LEDUpdate",
            0x0103 => "BatteryStatus",
            _ => "Unknown",
        };
        let is_down = (flags & 0x01) != 0;
        let has_coords = (flags & 0x02) != 0;
        let coord_str = if has_coords && payload.len() >= 12 {
            let x = i16::from_be_bytes(payload[8..10].try_into().unwrap());
            let y = i16::from_be_bytes(payload[10..12].try_into().unwrap());
            format!(" ({},{})", x, y)
        } else {
            String::new()
        };
        format!(
            "GFN Ctrl op={}(0x{:04x}) seq={}{}{} magic=0x{:08x} len={}",
            op_name,
            opcode,
            seq,
            if is_down { " DOWN" } else { "" },
            coord_str,
            magic,
            payload.len(),
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::NvidiaGfnCtrl,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gfn_ctrl_key() {
        let mut buf = vec![0u8; 12];
        buf[..4].copy_from_slice(&0x474658u32.to_be_bytes());
        buf[4..6].copy_from_slice(&1u16.to_be_bytes());
        buf[6] = 0x01;
        buf[7] = 5;
        let r = dissect_nvidia_gfn_ctrl(None, None, 48000, 47999, &buf);
        assert_eq!(r.protocol, Protocol::NvidiaGfnCtrl);
        assert!(r.summary.contains("KeyDown"));
    }

    #[test]
    fn test_gfn_ctrl_mouse_move() {
        let mut buf = vec![0u8; 14];
        buf[..4].copy_from_slice(&0x474658u32.to_be_bytes());
        buf[4..6].copy_from_slice(&3u16.to_be_bytes());
        buf[6] = 0x02;
        buf[7] = 2;
        buf[8..10].copy_from_slice(&100i16.to_be_bytes());
        buf[10..12].copy_from_slice(&200i16.to_be_bytes());
        let r = dissect_nvidia_gfn_ctrl(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::NvidiaGfnCtrl);
        assert!(r.summary.contains("100,200"));
    }
}
