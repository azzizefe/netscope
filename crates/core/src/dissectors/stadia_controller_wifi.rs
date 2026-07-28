use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_stadia_controller_wifi(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Stadia Controller WiFi (malformed)".into()
    } else {
        let magic = u32::from_be_bytes(payload[..4].try_into().unwrap());
        let msg_type = payload[4];
        let _version = payload[5];
        let seq = u16::from_be_bytes(payload[6..8].try_into().unwrap());
        let type_name = match msg_type {
            0x01 => "ButtonState",
            0x02 => "JoystickState",
            0x03 => "TouchpadState",
            0x04 => "MotionSample",
            0x05 => "HapticEvent",
            0x06 => "ConfigRequest",
            0x07 => "ConfigResponse",
            0x08 => "KeepAlive",
            _ => "Unknown",
        };
        let has_buttons = msg_type == 0x01 && payload.len() >= 10;
        let has_stick = msg_type == 0x02 && payload.len() >= 12;
        let detail = if has_buttons {
            let btn = u16::from_be_bytes(payload[8..10].try_into().unwrap());
            format!(" buttons=0x{:04x}", btn)
        } else if has_stick {
            let x = f32::from_le_bytes(payload[8..12].try_into().unwrap_or([0; 4]));
            let y = f32::from_le_bytes(payload[12..16].try_into().unwrap_or([0; 4]));
            format!(" stick=({:.2},{:.2})", x, y)
        } else {
            String::new()
        };
        format!(
            "Stadia Ctrl msg={}(0x{:02x}) seq={} magic=0x{:08x}{} len={}",
            type_name,
            msg_type,
            seq,
            magic,
            detail,
            payload.len(),
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::StadiaControllerWifi,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stadia_button() {
        let mut buf = vec![0u8; 12];
        buf[..4].copy_from_slice(&0x534354u32.to_be_bytes());
        buf[4] = 0x01;
        buf[5] = 1;
        buf[6..8].copy_from_slice(&42u16.to_be_bytes());
        buf[8..10].copy_from_slice(&0x0003u16.to_be_bytes());
        let r = dissect_stadia_controller_wifi(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::StadiaControllerWifi);
        assert!(r.summary.contains("ButtonState"));
    }

    #[test]
    fn test_stadia_joystick() {
        let mut buf = vec![0u8; 16];
        buf[..4].copy_from_slice(&0x534354u32.to_be_bytes());
        buf[4] = 0x02;
        buf[5] = 1;
        buf[6..8].copy_from_slice(&7u16.to_be_bytes());
        buf[8..12].copy_from_slice(&(0.5f32).to_le_bytes());
        buf[12..16].copy_from_slice(&(-0.3f32).to_le_bytes());
        let r = dissect_stadia_controller_wifi(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::StadiaControllerWifi);
        assert!(r.summary.contains("JoystickState"));
    }
}
