//! IEEE 802.15.4 and Zigbee/ZCL protocol dissector (DLT 195).
//!
//! IEEE 802.15.4 is the link-layer protocol for low-power wireless PANs.
//! Zigbee sits on top of it, providing network, security, and application layers.
//! ZCL (Zigbee Cluster Library) defines clusters and commands for device profiles.

use super::DissectedResult;
use crate::models::Protocol;

pub fn dissect_ieee802154(data: &[u8]) -> DissectedResult {
    let base = DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Unknown("Zigbee/IEEE 802.15.4".into()),
        summary: String::new(),
    };

    if data.len() < 3 {
        return DissectedResult {
            summary: "Truncated IEEE 802.15.4 frame".into(),
            ..base
        };
    }

    // Frame Control Field (FCF): 16-bit
    let fcf = u16::from_le_bytes([data[0], data[1]]);
    let frame_type = fcf & 0x0007;
    let security_enabled = (fcf & 0x0008) != 0;
    let seq_num = data[2];

    let type_str = match frame_type {
        0 => "Beacon",
        1 => "Data",
        2 => "Ack",
        3 => "MAC Command",
        _ => "Reserved",
    };

    let mut summary = format!("IEEE 802.15.4 {type_str} (Seq: {seq_num})");

    if security_enabled {
        summary.push_str(" [Encrypted]");
    }

    // Zigbee starts at offset depending on addressing mode (typically 3 to 23 bytes).
    // For a typical MAC Data frame, the payload starts after addressing:
    // If it's a Zigbee frame (Data), we can parse the Zigbee Network Header.
    if frame_type == 1 && data.len() > 9 {
        // Simple heuristic offset: skip FCF(2), Seq(1), PAN(2), Dest(2), Src(2)
        let nwk_offset = 9;
        if data.len() >= nwk_offset + 2 {
            let nwk_ctrl = u16::from_le_bytes([data[nwk_offset], data[nwk_offset + 1]]);
            let nwk_type = nwk_ctrl & 0x0003;
            let protocol_version = (nwk_ctrl >> 2) & 0x000f;

            if protocol_version == 2 {
                // Zigbee 2007 / PRO
                let nwk_type_str = match nwk_type {
                    0 => "Data",
                    1 => "Command",
                    2 => "Inter-PAN",
                    _ => "Reserved",
                };
                summary = format!("Zigbee NWK {nwk_type_str} (IEEE 802.15.4 Seq: {seq_num})");

                // Check ZCL (Zigbee Cluster Library) payload heuristic
                // If it is Zigbee NWK Data, and payload is decrypted/cleartext
                let aps_offset = nwk_offset + 8; // skip NWK header fields
                if nwk_type == 0 && data.len() > aps_offset + 3 {
                    let aps_ctrl = data[aps_offset];
                    let aps_type = (aps_ctrl >> 2) & 3;
                    if aps_type == 0 {
                        // APS Data Frame
                        let zcl_offset = aps_offset + 5; // skip APS fields
                        if data.len() > zcl_offset + 3 {
                            let zcl_ctrl = data[zcl_offset];
                            let cluster_cmd = (zcl_ctrl & 0x01) != 0; // Command specific
                            let zcl_seq = data[zcl_offset + 1];
                            let cmd_id = data[zcl_offset + 2];

                            summary = format!(
                                "Zigbee ZCL Command 0x{cmd_id:02x} (Seq: {zcl_seq}, Specific: {cluster_cmd})"
                            );
                        }
                    }
                }
            }
        }
    }

    DissectedResult {
        protocol: Protocol::Unknown("Zigbee".into()),
        summary,
        ..base
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncated_frame() {
        let data = vec![0x00, 0x01];
        let res = dissect_ieee802154(&data);
        assert_eq!(res.summary, "Truncated IEEE 802.15.4 frame");
    }

    #[test]
    fn test_ieee802154_beacon() {
        // FCF: type = 0 (Beacon), seq = 42
        let data = vec![0x00, 0x00, 42];
        let res = dissect_ieee802154(&data);
        assert_eq!(res.summary, "IEEE 802.15.4 Beacon (Seq: 42)");
    }

    #[test]
    fn test_zigbee_data_frame() {
        // FCF: type = 1 (Data), seq = 100
        // PAN ID: 2 bytes, Dest: 2 bytes, Src: 2 bytes
        // Zigbee NWK header: protocol version = 2, type = 0 (Data)
        let mut data = vec![0x01, 0x00, 100, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        // NWK Ctrl: protocol version = 2 (shift 2), type = 0. ctrl = (2 << 2) | 0 = 8.
        data.push(0x08);
        data.push(0x00);
        let res = dissect_ieee802154(&data);
        assert_eq!(res.summary, "Zigbee NWK Data (IEEE 802.15.4 Seq: 100)");
    }
}
