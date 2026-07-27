use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct VendorPluginManifest {
    #[serde(rename = "plugin")]
    pub plugin: PluginMeta,
    #[serde(default)]
    pub compatibility: Compatibility,
    #[serde(default)]
    pub vendor_signatures: VendorSignatures,
    #[serde(default)]
    pub firmware_variants: FirmwareVariants,
    #[serde(default)]
    pub protocols: ProtocolsList,
    #[serde(default)]
    pub ports: PortsList,
    #[serde(default)]
    pub files: FilesList,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PluginMeta {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub vendor: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Compatibility {
    #[serde(default)]
    pub base_protocols: Vec<String>,
    #[serde(default)]
    pub min_netscope_version: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct VendorSignatures {
    #[serde(default)]
    pub mac_ouis: Vec<String>,
    #[serde(default)]
    pub pno_vendor_id: Option<u16>,
    #[serde(default)]
    pub device_id_ranges: Vec<DeviceIdRange>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeviceIdRange {
    pub from: String,
    pub to: String,
    #[serde(default)]
    pub family: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct FirmwareVariants {
    #[serde(default, rename = "protocol")]
    pub protocol: Vec<FirmwareProtocol>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FirmwareProtocol {
    pub name: String,
    #[serde(default)]
    pub variants: Vec<FirmwareVariant>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FirmwareVariant {
    pub fw_range: String,
    pub file: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ProtocolsList {
    #[serde(default)]
    pub protocols: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PortsList {
    #[serde(default)]
    pub default: Vec<u16>,
    #[serde(default)]
    pub udp_ports: Vec<u16>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct FilesList {
    #[serde(default)]
    pub dissectors: Vec<String>,
    #[serde(default)]
    pub test_pcaps: Vec<String>,
}

impl VendorPluginManifest {
    pub fn parse(toml_text: &str) -> Result<Self, String> {
        toml::from_str(toml_text).map_err(|e| format!("vendor manifest parse error: {e}"))
    }

    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        if self.plugin.name.is_empty() {
            errors.push("plugin.name is required".into());
        }
        if self.plugin.version.is_empty() {
            errors.push("plugin.version is required".into());
        }
        let invalid: &[char] = &['/', '\\', ':', ' ', '\t', '\n'];
        if self.plugin.name.contains(invalid) {
            errors.push(format!("plugin.name contains invalid characters: '{}'", self.plugin.name));
        }
        if !self.compatibility.base_protocols.is_empty() && self.compatibility.min_netscope_version.is_empty() {
            errors.push("compatibility.min_netscope_version is required when base_protocols are specified".into());
        }
        for (i, dr) in self.vendor_signatures.device_id_ranges.iter().enumerate() {
            if dr.from.is_empty() || dr.to.is_empty() {
                errors.push(format!("vendor_signatures.device_id_ranges[{}] needs non-empty from/to", i));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    pub fn protocols(&self) -> &[String] {
        &self.protocols.protocols
    }

    pub fn dissector_files(&self) -> &[String] {
        &self.files.dissectors
    }

    pub fn test_pcaps(&self) -> &[String] {
        &self.files.test_pcaps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_siemens_plugin_manifest() {
        let toml = r#"
[plugin]
name = "siemens-industrial-dissector"
version = "2.1.0"
description = "Siemens SIMATIC/SINUMERIK/SINAMICS proprietary protocol extensions"
author = "Netscope Industrial Community"
vendor = "Siemens AG"

[compatibility]
base_protocols = ["profinet_rt", "profinet_dcp", "s7comm", "ethercat"]
min_netscope_version = "0.9.0"

[vendor_signatures]
mac_ouis = ["00:1B:1B", "00:0E:8C", "00:1C:06", "28:63:36", "00:0F:D3"]
pno_vendor_id = 42
device_id_ranges = [
    { from = "0x0100", to = "0x01FF", family = "SIMATIC S7-1200" },
    { from = "0x0200", to = "0x02FF", family = "SIMATIC S7-1500" },
]

[protocols]
protocols = ["profinet_rt_siemens", "s7comm_plus_detail", "sinamics_drive_profile"]

[ports]
default = [102, 34964, 135, 443]
udp_ports = [34964, 2222, 2223]

[files]
dissectors = ["profinet_rt_siemens.rs", "s7comm_plus_detail.rs"]
test_pcaps = ["tests/s7-1500_tia_v17.pcap"]
"#;
        let m = VendorPluginManifest::parse(toml).unwrap();
        assert_eq!(m.plugin.name, "siemens-industrial-dissector");
        assert_eq!(m.plugin.version, "2.1.0");
        assert_eq!(m.plugin.vendor, "Siemens AG");
        assert_eq!(m.vendor_signatures.mac_ouis.len(), 5);
        assert_eq!(m.vendor_signatures.pno_vendor_id, Some(42));
        assert_eq!(m.vendor_signatures.device_id_ranges.len(), 2);
        assert_eq!(m.compatibility.base_protocols, vec!["profinet_rt", "profinet_dcp", "s7comm", "ethercat"]);
        assert_eq!(m.protocols(), &["profinet_rt_siemens", "s7comm_plus_detail", "sinamics_drive_profile"]);
        assert_eq!(m.dissector_files(), &["profinet_rt_siemens.rs", "s7comm_plus_detail.rs"]);
        assert_eq!(m.test_pcaps(), &["tests/s7-1500_tia_v17.pcap"]);
    }

    #[test]
    fn parse_firmware_variants() {
        let toml = r#"
[plugin]
name = "siemens-s7"
version = "1.0.0"

[firmware_variants]
[[firmware_variants.protocol]]
name = "s7comm_plus"
[[firmware_variants.protocol.variants]]
fw_range = ">= 4.0, < 5.0"
file = "s7comm_plus_v4.rs"
[[firmware_variants.protocol.variants]]
fw_range = ">= 5.0"
file = "s7comm_plus_v5.rs"
"#;
        let m = VendorPluginManifest::parse(toml).unwrap();
        assert_eq!(m.firmware_variants.protocol.len(), 1);
        assert_eq!(m.firmware_variants.protocol[0].name, "s7comm_plus");
        assert_eq!(m.firmware_variants.protocol[0].variants.len(), 2);
        assert_eq!(m.firmware_variants.protocol[0].variants[0].fw_range, ">= 4.0, < 5.0");
        assert_eq!(m.firmware_variants.protocol[0].variants[1].file, "s7comm_plus_v5.rs");
    }

    #[test]
    fn validate_rejects_empty_name() {
        let toml = r#"
[plugin]
name = ""
version = "1.0.0"
"#;
        let m = VendorPluginManifest::parse(toml).unwrap();
        assert!(m.validate().is_err());
    }
}
