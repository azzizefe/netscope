use super::record::{DecodeLayer, FieldbusDecodeRecord};

#[derive(Debug, Clone)]
pub struct DecodeQualityReport {
    pub total_bytes: u16,
    pub l1_bytes_decoded: u16,
    pub l2_bytes_decoded: u16,
    pub l3_bytes_decoded: u16,
    pub unknown_bytes: u16,
    pub coverage_pct: u8,
    pub decode_layer: DecodeLayer,
    pub warnings: Vec<QualityWarning>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QualityWarning {
    LowCoverage(u8),
    UnknownTrailer(u16),
    NeedsPluginUpdate,
    MissingVendorExtension,
    TruncatedPayload,
    SafetyLayerNotDecoded,
    UnexpectedFrameId(u16),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl DecodeQualityReport {
    pub fn generate(rec: &FieldbusDecodeRecord) -> Self {
        let total_bytes = rec.io_data_length + rec.diagnostic_data_len + 14;
        let (l1, l2, l3) = compute_layer_coverage(rec);
        let coverage_pct = rec.decode_coverage_pct;
        let unknown_bytes = rec.unknown_bytes;

        let mut warnings: Vec<QualityWarning> = Vec::new();

        // One threshold, because the warning carries the percentage and grades
        // itself from it. This used to be two branches — `< 50` and `< 80` —
        // that pushed the identical warning, so the severity the author was
        // reaching for never reached the reader.
        if coverage_pct < 80 {
            warnings.push(QualityWarning::LowCoverage(coverage_pct));
        }

        if unknown_bytes > 0 {
            warnings.push(QualityWarning::UnknownTrailer(unknown_bytes));
        }

        if rec.needs_plugin_update {
            warnings.push(QualityWarning::NeedsPluginUpdate);
        }

        if rec.decode_layer < DecodeLayer::L3VendorFull && rec.vendor_name.is_none() {
            warnings.push(QualityWarning::MissingVendorExtension);
        }

        if total_bytes < 14 {
            warnings.push(QualityWarning::TruncatedPayload);
        }

        if rec.protocol_family.is_safety_capable() && !rec.has_safety_layer {
            warnings.push(QualityWarning::SafetyLayerNotDecoded);
        }

        DecodeQualityReport {
            total_bytes,
            l1_bytes_decoded: l1,
            l2_bytes_decoded: l2,
            l3_bytes_decoded: l3,
            unknown_bytes,
            coverage_pct,
            decode_layer: rec.decode_layer,
            warnings,
        }
    }

    pub fn risk_level(&self) -> RiskLevel {
        if self.coverage_pct < 30 {
            return RiskLevel::Critical;
        }
        if self.coverage_pct < 50 || self.warnings.contains(&QualityWarning::NeedsPluginUpdate) {
            return RiskLevel::High;
        }
        if self.warnings.len() > 2 {
            return RiskLevel::Medium;
        }
        if self.warnings.is_empty() {
            RiskLevel::Low
        } else {
            RiskLevel::Medium
        }
    }

    pub fn summary_line(&self) -> String {
        let icon = match self.risk_level() {
            RiskLevel::Low => "✓",
            RiskLevel::Medium => "◇",
            RiskLevel::High => "⚠",
            RiskLevel::Critical => "✗",
        };
        format!(
            "{} %{} decoded — {} layer(s), {} warning(s)",
            icon,
            self.coverage_pct,
            layer_count(self.decode_layer),
            self.warnings.len()
        )
    }

    pub fn layer_breakdown(&self) -> Vec<(&'static str, u16, &'static str)> {
        let mut layers = Vec::with_capacity(3);
        layers.push((
            "L1 Ethernet",
            self.l1_bytes_decoded,
            if self.l1_bytes_decoded > 0 {
                "OK"
            } else {
                "FAIL"
            },
        ));
        if self.decode_layer >= DecodeLayer::L2BaseFamily {
            layers.push((
                "L2 Protocol",
                self.l2_bytes_decoded,
                if self.l2_bytes_decoded > 0 {
                    "OK"
                } else {
                    "FAIL"
                },
            ));
        }
        if self.decode_layer >= DecodeLayer::L3VendorFull {
            layers.push((
                "L3 Vendor",
                self.l3_bytes_decoded,
                if self.l3_bytes_decoded > 0 { "OK" } else { "?" },
            ));
        }
        layers
    }
}

fn compute_layer_coverage(rec: &FieldbusDecodeRecord) -> (u16, u16, u16) {
    let l1: u16 = 14;
    let l2: u16 = rec
        .io_data_length
        .min(rec.io_data_length.saturating_sub(rec.unknown_bytes));
    let l3: u16 = if rec.decode_layer >= DecodeLayer::L3VendorFull {
        rec.io_data_length.saturating_sub(rec.unknown_bytes)
    } else {
        0
    };
    (l1, l2, l3)
}

fn layer_count(layer: DecodeLayer) -> u8 {
    match layer {
        DecodeLayer::L1Only => 1,
        DecodeLayer::L2BaseFamily => 2,
        DecodeLayer::L3VendorFull => 3,
    }
}

impl QualityWarning {
    pub fn message(&self) -> &'static str {
        match self {
            // Below half decoded, the frame is barely understood at all; above
            // it, the base protocol came through and it is the vendor-specific
            // tail that is missing. Those call for different responses, so they
            // do not get to share a sentence.
            QualityWarning::LowCoverage(pct) if *pct < 50 => {
                "Very low decode coverage — most of the frame was not parsed"
            }
            QualityWarning::LowCoverage(_) => {
                "Partial decode coverage — some fields were not parsed"
            }
            QualityWarning::UnknownTrailer(_) => {
                "Unknown trailer bytes detected — plugin update may be required"
            }
            QualityWarning::NeedsPluginUpdate => "Plugin update recommended for complete decode",
            QualityWarning::MissingVendorExtension => {
                "Vendor extension not available — OUI not recognized"
            }
            QualityWarning::TruncatedPayload => "Payload is truncated or malformed",
            QualityWarning::SafetyLayerNotDecoded => "Safety layer present but not decoded",
            QualityWarning::UnexpectedFrameId(_) => {
                "Unexpected frame ID — possibly new firmware variant"
            }
        }
    }

    pub fn detail(&self) -> String {
        match *self {
            QualityWarning::LowCoverage(pct) => format!("Only {}% of bytes decoded", pct),
            QualityWarning::UnknownTrailer(n) => format!("{} unknown trailer bytes", n),
            QualityWarning::UnexpectedFrameId(id) => {
                format!("Frame ID 0x{:04X} not in known range", id)
            }
            _ => String::new(),
        }
    }
}

pub fn format_layers(rec: &FieldbusDecodeRecord) -> Vec<String> {
    let report = DecodeQualityReport::generate(rec);
    let mut lines = Vec::new();

    let bar = coverage_bar(report.coverage_pct);
    lines.push(format!("{} {}% decoded", bar, report.coverage_pct));

    for (name, bytes, status) in report.layer_breakdown() {
        lines.push(format!(
            "{} {}: {} bytes — {}",
            status_indicator(status),
            name,
            bytes,
            status
        ));
    }

    if report.unknown_bytes > 0 {
        lines.push(format!("✗ Unknown trailer: {} bytes", report.unknown_bytes));
    }

    if report.decode_layer < DecodeLayer::L2BaseFamily {
        lines.push("⚠ Only L1 (Ethernet) parsed — deeper decode not attempted".into());
    }

    lines
}

fn coverage_bar(pct: u8) -> String {
    let filled = (pct as usize / 5).min(20);
    let empty = 20 - filled;
    format!("[{}{}]", "█".repeat(filled), "░".repeat(empty))
}

fn status_indicator(status: &str) -> &'static str {
    match status {
        "OK" => "✓",
        "FAIL" => "✗",
        "?" => "?",
        _ => " ",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fieldbus::record::{
        DataStatus, FieldbusFamily, ProcessDataQuality, TransferStatus, VendorId,
    };

    #[test]
    fn full_decode_no_warnings() {
        let rec = make_good_record(95, 0);
        let report = DecodeQualityReport::generate(&rec);
        assert_eq!(report.risk_level(), RiskLevel::Low);
        assert!(report.warnings.is_empty());
    }

    #[test]
    fn low_coverage_warning() {
        let rec = make_good_record(45, 0);
        let report = DecodeQualityReport::generate(&rec);
        assert!(report
            .warnings
            .iter()
            .any(|w| matches!(w, QualityWarning::LowCoverage(_))));
        assert_eq!(report.risk_level(), RiskLevel::High);
    }

    #[test]
    fn critical_coverage() {
        let rec = make_good_record(20, 0);
        let report = DecodeQualityReport::generate(&rec);
        assert_eq!(report.risk_level(), RiskLevel::Critical);
    }

    /// The two coverage bands have to read differently, or the warning tells a
    /// reader nothing they could not see from the percentage alone.
    #[test]
    fn the_coverage_warning_grades_itself() {
        let barely = QualityWarning::LowCoverage(20);
        let mostly = QualityWarning::LowCoverage(75);
        assert_ne!(barely.message(), mostly.message());
        assert!(barely.message().contains("Very low"));
        assert!(mostly.message().contains("Partial"));

        // 49 and 50 straddle the boundary — the band is the whole point.
        assert_eq!(QualityWarning::LowCoverage(49).message(), barely.message(),);
        assert_eq!(QualityWarning::LowCoverage(50).message(), mostly.message(),);
    }

    /// Above the threshold there is nothing to warn about, and below it there
    /// is exactly one warning — not two for the same frame.
    #[test]
    fn coverage_warns_once_or_not_at_all() {
        for pct in [20u8, 49, 50, 79] {
            let report = DecodeQualityReport::generate(&make_good_record(pct, 0));
            let coverage: Vec<_> = report
                .warnings
                .iter()
                .filter(|w| matches!(w, QualityWarning::LowCoverage(_)))
                .collect();
            assert_eq!(coverage.len(), 1, "{pct}% produced {coverage:?}");
        }

        let fine = DecodeQualityReport::generate(&make_good_record(80, 0));
        assert!(!fine
            .warnings
            .iter()
            .any(|w| matches!(w, QualityWarning::LowCoverage(_))));
    }

    #[test]
    fn unknown_trailer_warning() {
        let rec = make_good_record(90, 24);
        let report = DecodeQualityReport::generate(&rec);
        assert!(report
            .warnings
            .iter()
            .any(|w| matches!(w, QualityWarning::UnknownTrailer(24))));
    }

    #[test]
    fn plugin_update_flag_warning() {
        let mut rec = make_good_record(90, 0);
        rec.needs_plugin_update = true;
        let report = DecodeQualityReport::generate(&rec);
        assert!(report.warnings.contains(&QualityWarning::NeedsPluginUpdate));
        assert_eq!(report.risk_level(), RiskLevel::High);
    }

    #[test]
    fn missing_vendor_extension() {
        let rec = FieldbusDecodeRecord {
            decode_layer: DecodeLayer::L2BaseFamily,
            vendor_name: None,
            ..make_good_record(90, 0)
        };
        let report = DecodeQualityReport::generate(&rec);
        assert!(report
            .warnings
            .iter()
            .any(|w| matches!(w, QualityWarning::MissingVendorExtension)));
    }

    #[test]
    fn safety_layer_not_decoded() {
        let mut rec = make_good_record(90, 0);
        rec.has_safety_layer = false;
        rec.protocol_family = FieldbusFamily::Profinet;
        let report = DecodeQualityReport::generate(&rec);
        assert!(report
            .warnings
            .iter()
            .any(|w| matches!(w, QualityWarning::SafetyLayerNotDecoded)));
    }

    #[test]
    fn summary_line_low_risk() {
        let rec = make_good_record(95, 0);
        let report = DecodeQualityReport::generate(&rec);
        assert!(report.summary_line().starts_with('✓'));
        assert!(report.summary_line().contains("95 decoded"));
    }

    #[test]
    fn coverage_bar_full() {
        assert_eq!(coverage_bar(100), "[████████████████████]");
    }

    #[test]
    fn coverage_bar_half() {
        assert_eq!(coverage_bar(50), "[██████████░░░░░░░░░░]");
    }

    #[test]
    fn layer_breakdown_count() {
        let rec = make_good_record(95, 0);
        let report = DecodeQualityReport::generate(&rec);
        assert_eq!(report.layer_breakdown().len(), 3);
    }

    fn make_good_record(coverage: u8, unknown: u16) -> FieldbusDecodeRecord {
        FieldbusDecodeRecord {
            mac_src: [0; 6],
            mac_dst: [0; 6],
            ethertype: 0x8892,
            vlan_id: None,
            vlan_priority: None,
            is_tsn_frame: true,
            protocol_family: FieldbusFamily::Profinet,
            frame_id: 0xC000,
            cycle_counter: 42,
            data_status: DataStatus::Good,
            transfer_status: TransferStatus::Ok,
            vendor_name: Some(VendorId::Siemens),
            vendor_oui: Some([0x00, 0x1B, 0x1B]),
            vendor_device_id: Some(0x0200),
            vendor_fw_major: Some(5),
            vendor_fw_minor: Some(0),
            vendor_extension_id: None,
            io_data_length: 120,
            io_module_count: 4,
            process_data_quality: ProcessDataQuality::Full,
            alarm_count: 0,
            diagnostic_data_len: 24,
            has_safety_layer: true,
            safety_connection_id: Some(0xC000),
            safety_crc_valid: Some(true),
            safety_watchdog_ms: Some(100),
            frame_send_time_ns: 1_000_000,
            cycle_time_us: 1000,
            jitter_ns: 50,
            is_late: false,
            propagation_delay_ns: 200,
            decode_coverage_pct: coverage,
            unknown_bytes: unknown,
            decode_layer: DecodeLayer::L3VendorFull,
            needs_plugin_update: false,
        }
    }
}
