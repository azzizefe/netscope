
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldbusFamily {
    Profinet,
    EtherNetIp,
    EtherCat,
    Modbus,
    Profibus,
    Canopen,
    Sercos,
    Powerlink,
    CcLink,
    Interbus,
    ControlNet,
    Mechatrolink,
    VaranBus,
    PNet,
    S7comm,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataStatus {
    Good,
    Bad,
    Replacement,
    Default,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferStatus {
    Ok,
    Error,
    Timeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VendorId {
    Siemens,
    Rockwell,
    Beckhoff,
    Mitsubishi,
    Omron,
    Keyence,
    BrAutomation,
    Abb,
    Kuka,
    Fanuc,
    Yaskawa,
    BoschRexroth,
    Other(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessDataQuality {
    Full,
    Substitute,
    Force,
    Simulated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DecodeLayer {
    L1Only,
    L2BaseFamily,
    L3VendorFull,
}

#[derive(Debug, Clone)]
pub struct FieldbusDecodeRecord {
    // Layer 1: Physical / Link
    pub mac_src: [u8; 6],
    pub mac_dst: [u8; 6],
    pub ethertype: u16,
    pub vlan_id: Option<u16>,
    pub vlan_priority: Option<u8>,
    pub is_tsn_frame: bool,

    // Layer 2: Protocol Family
    pub protocol_family: FieldbusFamily,
    pub frame_id: u16,
    pub cycle_counter: u16,
    pub data_status: DataStatus,
    pub transfer_status: TransferStatus,

    // Layer 3: Vendor Extension
    pub vendor_name: Option<VendorId>,
    pub vendor_oui: Option<[u8; 3]>,
    pub vendor_device_id: Option<u16>,
    pub vendor_fw_major: Option<u16>,
    pub vendor_fw_minor: Option<u16>,
    pub vendor_extension_id: Option<u32>,

    // Data Payload
    pub io_data_length: u16,
    pub io_module_count: u8,
    pub process_data_quality: ProcessDataQuality,
    pub alarm_count: u8,
    pub diagnostic_data_len: u16,

    // Safety Layer
    pub has_safety_layer: bool,
    pub safety_connection_id: Option<u16>,
    pub safety_crc_valid: Option<bool>,
    pub safety_watchdog_ms: Option<u16>,

    // Timing
    pub frame_send_time_ns: u64,
    pub cycle_time_us: u32,
    pub jitter_ns: i64,
    pub is_late: bool,
    pub propagation_delay_ns: u32,

    // Decode Quality
    pub decode_coverage_pct: u8,
    pub unknown_bytes: u16,
    pub decode_layer: DecodeLayer,
    pub needs_plugin_update: bool,
}

#[allow(dead_code)]
pub(crate) const MAC_OUI_SIEMENS: &[[u8; 3]] = &[
    [0x00, 0x1B, 0x1B],
    [0x00, 0x0E, 0x8C],
    [0x00, 0x1C, 0x06],
    [0x28, 0x63, 0x36],
    [0x00, 0x0F, 0xD3],
];

#[allow(dead_code)]
pub(crate) const MAC_OUI_ROCKWELL: &[[u8; 3]] = &[
    [0x00, 0x00, 0xBC],
    [0x00, 0x1D, 0x9C],
    [0x00, 0x04, 0x4C],
];

#[allow(dead_code)]
pub(crate) const MAC_OUI_BECKHOFF: &[[u8; 3]] = &[
    [0x00, 0x01, 0x05],
    [0x00, 0x07, 0x63],
    [0x70, 0xB3, 0xD5],
];

impl VendorId {
    pub fn from_oui(oui: [u8; 3]) -> Option<VendorId> {
        if MAC_OUI_SIEMENS.contains(&oui) {
            Some(VendorId::Siemens)
        } else if MAC_OUI_ROCKWELL.contains(&oui) {
            Some(VendorId::Rockwell)
        } else if MAC_OUI_BECKHOFF.contains(&oui) {
            Some(VendorId::Beckhoff)
        } else {
            None
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            VendorId::Siemens => "Siemens",
            VendorId::Rockwell => "Rockwell",
            VendorId::Beckhoff => "Beckhoff",
            VendorId::Mitsubishi => "Mitsubishi",
            VendorId::Omron => "Omron",
            VendorId::Keyence => "Keyence",
            VendorId::BrAutomation => "B&R Automation",
            VendorId::Abb => "ABB",
            VendorId::Kuka => "KUKA",
            VendorId::Fanuc => "FANUC",
            VendorId::Yaskawa => "Yaskawa",
            VendorId::BoschRexroth => "Bosch Rexroth",
            VendorId::Other(_) => "Other",
        }
    }
}

impl FieldbusFamily {
    pub fn is_safety_capable(&self) -> bool {
        matches!(
            self,
            FieldbusFamily::Profinet | FieldbusFamily::EtherCat | FieldbusFamily::EtherNetIp
        )
    }

    pub fn from_ethertype(ethertype: u16) -> Option<FieldbusFamily> {
        match ethertype {
            0x8892 => Some(FieldbusFamily::Profinet),
            0x88A4 => Some(FieldbusFamily::EtherCat),
            0x80E1 => Some(FieldbusFamily::EtherNetIp),
            0x88AB => Some(FieldbusFamily::Powerlink),
            0x88CD => Some(FieldbusFamily::Sercos),
            _ => None,
        }
    }
}

impl FieldbusDecodeRecord {
    pub fn coverage_ok(&self) -> bool {
        self.decode_coverage_pct >= 95
    }

    pub fn has_vendor_extension(&self) -> bool {
        self.vendor_name.is_some() && self.decode_layer == DecodeLayer::L3VendorFull
    }

    pub fn product_family(&self) -> Option<&'static str> {
        match (self.vendor_name?, self.vendor_device_id?) {
            (VendorId::Siemens, id) if (0x0100..=0x01FF).contains(&id) => Some("SIMATIC S7-1200"),
            (VendorId::Siemens, id) if (0x0200..=0x02FF).contains(&id) => Some("SIMATIC S7-1500"),
            (VendorId::Siemens, id) if (0x0300..=0x03FF).contains(&id) => Some("SIMATIC ET 200SP"),
            (VendorId::Siemens, id) if (0x0400..=0x04FF).contains(&id) => Some("SINAMICS S120"),
            (VendorId::Siemens, id) if (0x0500..=0x05FF).contains(&id) => Some("SINUMERIK 828D/840D"),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendor_id_from_oui() {
        assert_eq!(VendorId::from_oui([0x00, 0x1B, 0x1B]), Some(VendorId::Siemens));
        assert_eq!(VendorId::from_oui([0x00, 0x00, 0xBC]), Some(VendorId::Rockwell));
        assert_eq!(VendorId::from_oui([0x00, 0x01, 0x05]), Some(VendorId::Beckhoff));
        assert_eq!(VendorId::from_oui([0xDE, 0xAD, 0xBE]), None);
    }

    #[test]
    fn ethertype_to_family() {
        assert_eq!(FieldbusFamily::from_ethertype(0x8892), Some(FieldbusFamily::Profinet));
        assert_eq!(FieldbusFamily::from_ethertype(0x88A4), Some(FieldbusFamily::EtherCat));
        assert_eq!(FieldbusFamily::from_ethertype(0x0800), None);
    }

    #[test]
    fn product_family_siemens_s7_1500() {
        let rec = FieldbusDecodeRecord {
            vendor_name: Some(VendorId::Siemens),
            vendor_device_id: Some(0x0200),
            ..default_record()
        };
        assert_eq!(rec.product_family(), Some("SIMATIC S7-1500"));
    }

    #[test]
    fn product_family_sinamics() {
        let rec = FieldbusDecodeRecord {
            vendor_name: Some(VendorId::Siemens),
            vendor_device_id: Some(0x0400),
            ..default_record()
        };
        assert_eq!(rec.product_family(), Some("SINAMICS S120"));
    }

    #[test]
    fn coverage_check() {
        let mut rec = default_record();
        rec.decode_coverage_pct = 96;
        assert!(rec.coverage_ok());
        rec.decode_coverage_pct = 80;
        assert!(!rec.coverage_ok());
    }

    #[test]
    fn has_vendor_extension_check() {
        let mut rec = default_record();
        rec.vendor_name = Some(VendorId::Siemens);
        rec.decode_layer = DecodeLayer::L3VendorFull;
        assert!(rec.has_vendor_extension());
        rec.decode_layer = DecodeLayer::L2BaseFamily;
        assert!(!rec.has_vendor_extension());
    }

    fn default_record() -> FieldbusDecodeRecord {
        FieldbusDecodeRecord {
            mac_src: [0; 6],
            mac_dst: [0; 6],
            ethertype: 0,
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
            decode_coverage_pct: 0,
            unknown_bytes: 0,
            decode_layer: DecodeLayer::L1Only,
            needs_plugin_update: false,
        }
    }
}
