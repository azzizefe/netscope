use super::record::{
    DataStatus, DecodeLayer, FieldbusDecodeRecord, FieldbusFamily, ProcessDataQuality,
    TransferStatus, VendorId,
};
#[cfg_attr(not(test), allow(dead_code))]
use super::record::{MAC_OUI_BECKHOFF, MAC_OUI_ROCKWELL, MAC_OUI_SIEMENS};

const ETHERTYPE_PROFINET: u16 = 0x8892;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88A8;

const DLT_EN10MB: i32 = 1;

const PROFINET_FRAME_PTCP: u16 = 0x0020;
const PROFINET_FRAME_DCP: u16 = 0xFEFC;

const ETHERCAT_CMD_APRD: u8 = 0x01;
const ETHERCAT_CMD_FPRD: u8 = 0x04;
const ETHERCAT_CMD_LRW: u8 = 0x08;
const ETHERCAT_CMD_BRD: u8 = 0x07;

pub enum DecodeStrategy {
    L1Only,
    L2Default,
    L3Auto,
}

pub fn decode_frame(data: &[u8], linktype: i32) -> Option<FieldbusDecodeRecord> {
    if linktype != DLT_EN10MB || data.len() < 14 {
        return None;
    }

    let mut rec = decode_l1(data);

    if rec.ethertype == 0 {
        return None;
    }

    let family = FieldbusFamily::from_ethertype(rec.ethertype)?;
    rec.protocol_family = family;

    let l2_payload = if data.len() > 14 { &data[14..] } else { &[] };
    decode_l2(&mut rec, l2_payload);

    let mac_src = rec.mac_src;
    decode_l3(&mut rec, mac_src, l2_payload);

    Some(rec)
}

pub fn decode_with_strategy(
    data: &[u8],
    linktype: i32,
    strategy: DecodeStrategy,
) -> Option<FieldbusDecodeRecord> {
    let mut rec = decode_frame(data, linktype)?;

    match strategy {
        DecodeStrategy::L1Only => {
            rec.decode_layer = DecodeLayer::L1Only;
            rec.decode_coverage_pct = 20;
        }
        DecodeStrategy::L2Default => {
            rec.decode_layer = DecodeLayer::L2BaseFamily;
            rec.decode_coverage_pct = 60;
        }
        DecodeStrategy::L3Auto => {
            rec.decode_layer = DecodeLayer::L3VendorFull;
            rec.decode_coverage_pct = 95;
        }
    }

    Some(rec)
}

fn decode_l1(data: &[u8]) -> FieldbusDecodeRecord {
    let mac_dst = data[..6].try_into().unwrap_or([0u8; 6]);
    let mac_src = data[6..12].try_into().unwrap_or([0u8; 6]);
    let ethertype = u16::from_be_bytes([data[12], data[13]]);

    let mut rec = FieldbusDecodeRecord {
        mac_dst,
        mac_src,
        ethertype,
        vlan_id: None,
        vlan_priority: None,
        is_tsn_frame: false,
        protocol_family: FieldbusFamily::Other,
        frame_id: 0,
        cycle_counter: 0,
        data_status: DataStatus::Good,
        transfer_status: TransferStatus::Ok,
        vendor_name: None,
        vendor_oui: None,
        vendor_device_id: None,
        vendor_fw_major: None,
        vendor_fw_minor: None,
        vendor_extension_id: None,
        io_data_length: 0,
        io_module_count: 0,
        process_data_quality: ProcessDataQuality::Full,
        alarm_count: 0,
        diagnostic_data_len: 0,
        has_safety_layer: false,
        safety_connection_id: None,
        safety_crc_valid: None,
        safety_watchdog_ms: None,
        frame_send_time_ns: 0,
        cycle_time_us: 0,
        jitter_ns: 0,
        is_late: false,
        propagation_delay_ns: 0,
        decode_coverage_pct: 20,
        unknown_bytes: 0,
        decode_layer: DecodeLayer::L1Only,
        needs_plugin_update: false,
    };

    if ethertype == ETHERTYPE_VLAN || ethertype == ETHERTYPE_QINQ {
        if data.len() >= 18 {
            let tci = u16::from_be_bytes([data[14], data[15]]);
            rec.vlan_id = Some(tci & 0x0FFF);
            rec.vlan_priority = Some((tci >> 13) as u8);
            rec.ethertype = u16::from_be_bytes([data[16], data[17]]);
        }
    }

    if ethertype == ETHERTYPE_PROFINET {
        rec.is_tsn_frame = true;
    }

    rec
}

fn decode_l2(rec: &mut FieldbusDecodeRecord, payload: &[u8]) {
    match rec.protocol_family {
        FieldbusFamily::Profinet => decode_l2_profinet(rec, payload),
        FieldbusFamily::EtherCat => decode_l2_ethercat(rec, payload),
        FieldbusFamily::EtherNetIp => decode_l2_ethernetip(rec, payload),
        FieldbusFamily::Powerlink => decode_l2_powerlink(rec, payload),
        FieldbusFamily::Sercos => decode_l2_sercos(rec, payload),
        _ => {}
    }
}

fn decode_l2_profinet(rec: &mut FieldbusDecodeRecord, payload: &[u8]) {
    if payload.len() < 2 {
        return;
    }
    let frame_id = u16::from_be_bytes([payload[0], payload[1]]);
    rec.frame_id = frame_id;

    rec.io_data_length = payload.len().saturating_sub(2) as u16;

    match frame_id {
        PROFINET_FRAME_PTCP => {
            rec.transfer_status = TransferStatus::Ok;
            if payload.len() >= 8 {
                let origin = &payload[4..8];
                rec.frame_send_time_ns =
                    u32::from_be_bytes([origin[0], origin[1], origin[2], origin[3]]) as u64;
            }
        }
        PROFINET_FRAME_DCP => {
            rec.transfer_status = TransferStatus::Ok;
            rec.io_data_length = 0;
        }
        0x0000..=0x00FF => {
            rec.data_status = DataStatus::Good;
            rec.cycle_counter = rec.cycle_counter.wrapping_add(1);

            if payload.len() >= 8 {
                rec.io_module_count = payload[6] & 0x0F;
            }
        }
        0x8000..=0xFBFF => {
            rec.data_status = if frame_id & 0x0100 != 0 {
                DataStatus::Bad
            } else {
                DataStatus::Good
            };
        }
        _ => {
            rec.unknown_bytes = payload.len() as u16;
        }
    }
}

fn decode_l2_ethercat(rec: &mut FieldbusDecodeRecord, payload: &[u8]) {
    if payload.len() < 2 {
        return;
    }

    let header_len_raw = u16::from_be_bytes([payload[0], payload[1]]);
    let length_11_4 = header_len_raw & 0x0FFF;
    let typ = (header_len_raw >> 12) & 0x0F;

    rec.io_data_length = length_11_4 as u16;
    rec.io_module_count = typ as u8;

    if payload.len() >= 4 {
        let cmd = payload[2];
        let idx = payload[3];

        rec.frame_id = u16::from(idx);
        rec.cycle_counter = rec.cycle_counter.wrapping_add(1);

        match cmd {
            ETHERCAT_CMD_APRD | ETHERCAT_CMD_FPRD => {
                rec.transfer_status = TransferStatus::Ok;
                rec.alarm_count = 0;
            }
            ETHERCAT_CMD_LRW => {
                rec.transfer_status = TransferStatus::Ok;
                rec.io_data_length = length_11_4 as u16;
            }
            ETHERCAT_CMD_BRD => {
                rec.transfer_status = TransferStatus::Ok;
            }
            _ => {
                rec.transfer_status = TransferStatus::Ok;
            }
        }
    }
}

fn decode_l2_ethernetip(rec: &mut FieldbusDecodeRecord, payload: &[u8]) {
    if payload.len() < 24 {
        return;
    }

    let command = u16::from_be_bytes([payload[0], payload[1]]);
    let length = u16::from_be_bytes([payload[2], payload[3]]);
    let session = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let status = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);

    rec.frame_id = command;
    rec.io_data_length = length;
    rec.vendor_extension_id = Some(session);

    if status == 0 {
        rec.transfer_status = TransferStatus::Ok;
        rec.data_status = DataStatus::Good;
    } else {
        rec.transfer_status = TransferStatus::Error;
        rec.data_status = DataStatus::Bad;
    }
}

fn decode_l2_powerlink(rec: &mut FieldbusDecodeRecord, payload: &[u8]) {
    if payload.len() < 2 {
        return;
    }

    let mtu = u16::from_be_bytes([payload[0], payload[1]]);
    rec.io_data_length = mtu.min(payload.len() as u16);

    if payload.len() >= 4 {
        rec.cycle_counter = u16::from_be_bytes([payload[2], payload[3]]);
    }
}

fn decode_l2_sercos(rec: &mut FieldbusDecodeRecord, payload: &[u8]) {
    if payload.len() < 2 {
        return;
    }

    let con_id = u16::from_be_bytes([payload[0], payload[1]]);
    rec.frame_id = con_id;
    rec.io_data_length = payload.len().saturating_sub(2) as u16;
}

fn decode_l3(rec: &mut FieldbusDecodeRecord, mac_src: [u8; 6], payload: &[u8]) {
    let oui = [mac_src[0], mac_src[1], mac_src[2]];

    rec.vendor_oui = Some(oui);

    if let Some(vendor) = VendorId::from_oui(oui) {
        rec.vendor_name = Some(vendor);
        rec.decode_layer = DecodeLayer::L3VendorFull;
        rec.decode_coverage_pct = if payload.len() > 8 { 95 } else { 80 };
    } else {
        rec.decode_layer = DecodeLayer::L2BaseFamily;
        rec.decode_coverage_pct = 60;
        rec.needs_plugin_update = true;
    }

    match rec.protocol_family {
        FieldbusFamily::Profinet => decode_l3_profinet_vendor(rec, oui, payload),
        FieldbusFamily::EtherCat => decode_l3_ethercat_vendor(rec, oui, payload),
        _ => {}
    }
}

fn decode_l3_profinet_vendor(rec: &mut FieldbusDecodeRecord, oui: [u8; 3], payload: &[u8]) {
    if MAC_OUI_SIEMENS.contains(&oui) {
        rec.vendor_name = Some(VendorId::Siemens);
        if payload.len() >= 8 {
            rec.vendor_device_id = Some(u16::from_be_bytes([payload[2], payload[3]]));
            rec.vendor_fw_major = Some(u16::from(payload[4]));
            rec.vendor_fw_minor = Some(u16::from(payload[5]));
        }
        if let Some(family) = rec.product_family() {
            if family.contains("SINAMICS") || family.contains("SINUMERIK") {
                rec.has_safety_layer = true;
                rec.safety_connection_id = Some(rec.frame_id);
                rec.safety_crc_valid = Some(true);
                rec.safety_watchdog_ms = Some(100);
            }
        }
    } else if MAC_OUI_ROCKWELL.contains(&oui) {
        rec.vendor_name = Some(VendorId::Rockwell);
    }
}

fn decode_l3_ethercat_vendor(rec: &mut FieldbusDecodeRecord, oui: [u8; 3], payload: &[u8]) {
    if MAC_OUI_BECKHOFF.contains(&oui) {
        rec.vendor_name = Some(VendorId::Beckhoff);
        if payload.len() >= 12 {
            rec.vendor_device_id = Some(u16::from_be_bytes([payload[8], payload[9]]));
            rec.vendor_fw_major = Some(u16::from(payload[10]));
        }
        if rec.frame_id & 0x80 != 0 {
            rec.has_safety_layer = true;
            rec.safety_connection_id = Some(rec.frame_id);
            rec.safety_watchdog_ms = Some(50);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_l1_non_fieldbus_returns_none() {
        let data = make_eth_frame(0x0800, b"hello"); // IPv4, not fieldbus
        assert!(decode_frame(&data, DLT_EN10MB).is_none());
    }

    #[test]
    fn decode_l1_profinet_detected() {
        let data = make_eth_frame(ETHERTYPE_PROFINET, &[0x00; 40]);
        let rec = decode_frame(&data, DLT_EN10MB).unwrap();
        assert_eq!(rec.ethertype, ETHERTYPE_PROFINET);
        assert_eq!(rec.protocol_family, FieldbusFamily::Profinet);
        assert_eq!(rec.is_tsn_frame, true);
    }

    #[test]
    fn decode_l1_ethercat_detected() {
        let data = make_eth_frame(0x88A4, &[0x00; 10]);
        let rec = decode_frame(&data, DLT_EN10MB).unwrap();
        assert_eq!(rec.protocol_family, FieldbusFamily::EtherCat);
    }

    #[test]
    fn decode_l1_vlan_skipped() {
        let data = make_vlan_frame(ETHERTYPE_PROFINET, &[0x00; 20]);
        let rec = decode_frame(&data, DLT_EN10MB).unwrap();
        assert_eq!(rec.ethertype, ETHERTYPE_PROFINET);
        assert_eq!(rec.vlan_id, Some(42));
        assert_eq!(rec.protocol_family, FieldbusFamily::Profinet);
    }

    #[test]
    fn decode_l2_profinet_frame_id() {
        let mut p = vec![0u8; 20];
        p[0] = 0x00; p[1] = 0x20;
        let data = make_eth_frame(ETHERTYPE_PROFINET, &p);
        let rec = decode_frame(&data, DLT_EN10MB).unwrap();
        assert_eq!(rec.frame_id, 0x0020); // PTCP
    }

    #[test]
    fn decode_l2_ethercat_command() {
        let payload = &[
            0x00, 0x08, // length=8, type=0
            ETHERCAT_CMD_APRD, 0x01, // cmd, idx
            0x00, 0x00, 0x00, 0x00, // addr
            0x00, 0x00, // len
        ];
        let data = make_eth_frame(0x88A4, payload);
        let rec = decode_frame(&data, DLT_EN10MB).unwrap();
        assert_eq!(rec.protocol_family, FieldbusFamily::EtherCat);
        assert_eq!(rec.io_data_length, 8);
    }

    #[test]
    fn decode_l2_ethernetip_command() {
        let payload = &[
            0x00, 0x65, // command = 0x0065 (RegisterSession)
            0x00, 0x04, // length = 4
            0x00, 0x00, 0x00, 0x01, // session = 1
            0x00, 0x00, 0x00, 0x00, // status = 0 (OK)
            0x00, 0x00, 0x00, 0x00, // sender context
            0x00, 0x00, 0x00, 0x00, // sender context (continued)
            0x00, 0x00, 0x00, 0x00, // options
        ];
        let data = make_eth_frame(0x80E1, payload);
        let rec = decode_frame(&data, DLT_EN10MB).unwrap();
        assert_eq!(rec.protocol_family, FieldbusFamily::EtherNetIp);
        assert_eq!(rec.frame_id, 0x0065);
        assert_eq!(rec.transfer_status, TransferStatus::Ok);
    }

    #[test]
    fn decode_l3_vendor_siemens_oui() {
        let payload = &[
            0x00, 0x00, // frame_id
            0x01, 0x00, // device_id = 0x0100 (S7-1200)
            0x04, 0x02, // fw major=4, minor=2
            0xAA, 0xBB, // padding
        ];
        let mut data = Vec::new();
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // dst
        data.extend_from_slice(&[0x00, 0x1B, 0x1B, 0x11, 0x22, 0x33]); // src - Siemens OUI
        data.extend_from_slice(&ETHERTYPE_PROFINET.to_be_bytes());
        data.extend_from_slice(payload);

        let rec = decode_frame(&data, DLT_EN10MB).unwrap();
        assert_eq!(rec.vendor_name, Some(VendorId::Siemens));
        assert_eq!(rec.vendor_device_id, Some(0x0100));
        assert_eq!(rec.product_family(), Some("SIMATIC S7-1200"));
    }

    #[test]
    fn decode_l3_vendor_rockwell_oui() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // dst
        data.extend_from_slice(&[0x00, 0x00, 0xBC, 0x11, 0x22, 0x33]); // src - Rockwell OUI
        data.extend_from_slice(&ETHERTYPE_PROFINET.to_be_bytes());
        data.extend_from_slice(&[0x00; 10]);

        let rec = decode_frame(&data, DLT_EN10MB).unwrap();
        assert_eq!(rec.vendor_name, Some(VendorId::Rockwell));
    }

    #[test]
    fn decode_l3_unknown_oui_sets_npd_flag() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // dst
        data.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00]); // src - unknown OUI
        data.extend_from_slice(&ETHERTYPE_PROFINET.to_be_bytes());
        data.extend_from_slice(&[0x00; 10]);

        let rec = decode_frame(&data, DLT_EN10MB).unwrap();
        assert_eq!(rec.needs_plugin_update, true);
        assert_eq!(rec.decode_layer, DecodeLayer::L2BaseFamily);
    }

    #[test]
    fn decode_with_l1_strategy() {
        let data = make_eth_frame(ETHERTYPE_PROFINET, &[0x00; 10]);
        let rec = decode_with_strategy(&data, DLT_EN10MB, DecodeStrategy::L1Only).unwrap();
        assert_eq!(rec.decode_layer, DecodeLayer::L1Only);
        assert_eq!(rec.decode_coverage_pct, 20);
    }

    #[test]
    fn decode_strategy_detects_non_fieldbus() {
        let data = make_eth_frame(0x0800, b"ip packet");
        assert!(decode_with_strategy(&data, DLT_EN10MB, DecodeStrategy::L3Auto).is_none());
    }

    #[test]
    fn powerlink_detected() {
        let data = make_eth_frame(0x88AB, &[0x00, 0x40, 0x00, 0x05]);
        let rec = decode_frame(&data, DLT_EN10MB).unwrap();
        assert_eq!(rec.protocol_family, FieldbusFamily::Powerlink);
        assert_eq!(rec.cycle_counter, 5);
    }

    #[test]
    fn sercos_detected() {
        let payload = &[0x00, 0x01, 0xAA, 0xBB];
        let data = make_eth_frame(0x88CD, payload);
        let rec = decode_frame(&data, DLT_EN10MB).unwrap();
        assert_eq!(rec.protocol_family, FieldbusFamily::Sercos);
        assert_eq!(rec.frame_id, 1);
    }

    fn make_eth_frame(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut data = Vec::with_capacity(14 + payload.len());
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // dst
        data.extend_from_slice(&[0x00, 0x1B, 0x1B, 0x11, 0x22, 0x33]); // src
        data.extend_from_slice(&ethertype.to_be_bytes());
        data.extend_from_slice(payload);
        data
    }

    fn make_vlan_frame(inner_ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut data = Vec::with_capacity(18 + payload.len());
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // dst
        data.extend_from_slice(&[0x00, 0x1B, 0x1B, 0x11, 0x22, 0x33]); // src
        data.extend_from_slice(&ETHERTYPE_VLAN.to_be_bytes());
        data.extend_from_slice(&[0x20, 0x2A]); // PCP=1, DEI=0, VID=42
        data.extend_from_slice(&inner_ethertype.to_be_bytes());
        data.extend_from_slice(payload);
        data
    }
}
