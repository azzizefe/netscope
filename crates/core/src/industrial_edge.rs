use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// Re-export of chrono timestamp for industrial edge records.
pub type IndustrialTimestamp = DateTime<Utc>;

/// Category of industrial protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IndustrialCategory {
    PlcCpu,
    IoControl,
    Safety,
    Motion,
    Process,
    Building,
    Scada,
    SubStation,
    IndustrialIiot,
    Fieldbus,
    Semiconductor,
    Cnc,
    Vehicle,
    Other,
}

impl std::fmt::Display for IndustrialCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IndustrialCategory::PlcCpu => write!(f, "PLC CPU"),
            IndustrialCategory::IoControl => write!(f, "I/O Control"),
            IndustrialCategory::Safety => write!(f, "Functional Safety"),
            IndustrialCategory::Motion => write!(f, "Motion Control"),
            IndustrialCategory::Process => write!(f, "Process Automation"),
            IndustrialCategory::Building => write!(f, "Building Automation"),
            IndustrialCategory::Scada => write!(f, "SCADA Telecontrol"),
            IndustrialCategory::SubStation => write!(f, "Substation Automation"),
            IndustrialCategory::IndustrialIiot => write!(f, "Industrial IoT"),
            IndustrialCategory::Fieldbus => write!(f, "Fieldbus"),
            IndustrialCategory::Semiconductor => write!(f, "Semiconductor"),
            IndustrialCategory::Cnc => write!(f, "CNC"),
            IndustrialCategory::Vehicle => write!(f, "Vehicle"),
            IndustrialCategory::Other => write!(f, "Other"),
        }
    }
}

/// Severity of an industrial security event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IndustrialSeverity {
    Info,
    Warning,
    Critical,
}

impl std::fmt::Display for IndustrialSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IndustrialSeverity::Info => write!(f, "INFO"),
            IndustrialSeverity::Warning => write!(f, "WARN"),
            IndustrialSeverity::Critical => write!(f, "CRIT"),
        }
    }
}

/// OT-specific security anomaly types.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IndustrialAnomaly {
    UnauthorizedWrite,
    UnauthorizedPlcStop,
    UnauthorizedFirmwareWrite,
    UnauthorizedProgramDownload,
    UnauthorizedPlcModeChange,
    UnauthorizedParameterChange,
    UnauthorizedConfigChange,
    ExcessiveReadRate,
    BruteForceAttempt,
    PotentialScanning,
    ProtocolFuzzing,
    UnauthorizedAccess,
    UnknownFunctionCode,
    OutOfSequenceCommand,
    InvalidCrc,
    ReplayAttack,
}

impl std::fmt::Display for IndustrialAnomaly {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IndustrialAnomaly::UnauthorizedWrite => write!(f, "Unauthorized Write"),
            IndustrialAnomaly::UnauthorizedPlcStop => write!(f, "Unauthorized PLC Stop"),
            IndustrialAnomaly::UnauthorizedFirmwareWrite => {
                write!(f, "Unauthorized Firmware Write")
            }
            IndustrialAnomaly::UnauthorizedProgramDownload => {
                write!(f, "Unauthorized Program Download")
            }
            IndustrialAnomaly::UnauthorizedPlcModeChange => {
                write!(f, "Unauthorized PLC Mode Change")
            }
            IndustrialAnomaly::UnauthorizedParameterChange => {
                write!(f, "Unauthorized Parameter Change")
            }
            IndustrialAnomaly::UnauthorizedConfigChange => write!(f, "Unauthorized Config Change"),
            IndustrialAnomaly::ExcessiveReadRate => write!(f, "Excessive Read Rate"),
            IndustrialAnomaly::BruteForceAttempt => write!(f, "Brute Force Attempt"),
            IndustrialAnomaly::PotentialScanning => write!(f, "Potential Scanning"),
            IndustrialAnomaly::ProtocolFuzzing => write!(f, "Protocol Fuzzing"),
            IndustrialAnomaly::UnauthorizedAccess => write!(f, "Unauthorized Access"),
            IndustrialAnomaly::UnknownFunctionCode => write!(f, "Unknown Function Code"),
            IndustrialAnomaly::OutOfSequenceCommand => write!(f, "Out-of-Sequence Command"),
            IndustrialAnomaly::InvalidCrc => write!(f, "Invalid CRC"),
            IndustrialAnomaly::ReplayAttack => write!(f, "Replay Attack"),
        }
    }
}

/// Record of a single industrial protocol operation.
#[derive(Debug, Clone)]
pub struct IndustrialOperation {
    pub protocol: String,
    pub category: IndustrialCategory,
    pub function_code: String,
    pub operation_type: String,
    pub src_addr: String,
    pub dst_addr: String,
    pub timestamp: IndustrialTimestamp,
    pub is_anomalous: bool,
    pub anomaly: Option<IndustrialAnomaly>,
    pub raw_size: usize,
}

impl IndustrialOperation {
    pub fn new(
        protocol: impl Into<String>,
        category: IndustrialCategory,
        function_code: impl Into<String>,
        operation_type: impl Into<String>,
        src_addr: impl Into<String>,
        dst_addr: impl Into<String>,
    ) -> Self {
        IndustrialOperation {
            protocol: protocol.into(),
            category,
            function_code: function_code.into(),
            operation_type: operation_type.into(),
            src_addr: src_addr.into(),
            dst_addr: dst_addr.into(),
            timestamp: Utc::now(),
            is_anomalous: false,
            anomaly: None,
            raw_size: 0,
        }
    }
}

/// Industrial Edge Security & Analytics Engine.
#[derive(Debug, Clone)]
pub struct IndustrialSecurityAnalyzer {
    operations: Vec<IndustrialOperation>,
    anomaly_counter: HashMap<IndustrialAnomaly, u64>,
    protocol_counts: HashMap<String, u64>,
    category_counts: HashMap<IndustrialCategory, u64>,
    source_timestamps: HashMap<String, Vec<DateTime<Utc>>>,
    whitelist: HashMap<String, Vec<String>>,
}

impl IndustrialSecurityAnalyzer {
    pub fn new() -> Self {
        IndustrialSecurityAnalyzer {
            operations: Vec::new(),
            anomaly_counter: HashMap::new(),
            protocol_counts: HashMap::new(),
            category_counts: HashMap::new(),
            source_timestamps: HashMap::new(),
            whitelist: HashMap::new(),
        }
    }

    /// Add a source address to the whitelist for a given protocol.
    pub fn add_whitelist(&mut self, protocol: impl Into<String>, addr: impl Into<String>) {
        self.whitelist
            .entry(protocol.into())
            .or_default()
            .push(addr.into());
    }

    /// Record an industrial operation, running anomaly detection.
    pub fn record_operation(&mut self, op: IndustrialOperation) {
        let anomaly = self.detect_anomalies(&op);
        if let Some(ref a) = anomaly {
            *self.anomaly_counter.entry(a.clone()).or_insert(0) += 1;
        }
        let now = op.timestamp;
        self.source_timestamps
            .entry(op.src_addr.clone())
            .or_default()
            .push(now);
        *self.protocol_counts.entry(op.protocol.clone()).or_insert(0) += 1;
        *self.category_counts.entry(op.category).or_insert(0) += 1;
        self.operations.push(op);
    }

    /// Run all anomaly detection rules, returning the first match.
    fn detect_anomalies(&self, op: &IndustrialOperation) -> Option<IndustrialAnomaly> {
        if let Some(a) = self.check_whitelist(op) {
            return Some(a);
        }
        if let Some(a) = self.check_excessive_rate(op) {
            return Some(a);
        }
        if let Some(a) = self.check_write_frequency(op) {
            return Some(a);
        }
        self.check_plc_control(op)
    }

    /// Rule 1: Operation from non-whitelisted source.
    fn check_whitelist(&self, op: &IndustrialOperation) -> Option<IndustrialAnomaly> {
        if let Some(whitelisted) = self.whitelist.get(&op.protocol) {
            if !whitelisted.contains(&op.src_addr) {
                return Some(match op.operation_type.as_str() {
                    "write" => IndustrialAnomaly::UnauthorizedWrite,
                    "control" => IndustrialAnomaly::UnauthorizedPlcStop,
                    "config" => IndustrialAnomaly::UnauthorizedConfigChange,
                    "param" => IndustrialAnomaly::UnauthorizedParameterChange,
                    _ => IndustrialAnomaly::UnauthorizedAccess,
                });
            }
        }
        None
    }

    /// Rule 2: More than 100 operations/second from the same source.
    fn check_excessive_rate(&self, op: &IndustrialOperation) -> Option<IndustrialAnomaly> {
        if let Some(timestamps) = self.source_timestamps.get(&op.src_addr) {
            let recent = timestamps
                .iter()
                .filter(|t| (op.timestamp - **t).num_milliseconds().abs() < 100)
                .count();
            if recent >= 100 {
                return Some(IndustrialAnomaly::ExcessiveReadRate);
            }
        }
        None
    }

    /// Rule 3: More than 50 write operations from the same source in window.
    fn check_write_frequency(&self, op: &IndustrialOperation) -> Option<IndustrialAnomaly> {
        if op.operation_type != "write" {
            return None;
        }
        if let Some(timestamps) = self.source_timestamps.get(&op.src_addr) {
            let recent = timestamps
                .iter()
                .filter(|t| (op.timestamp - **t).num_seconds().abs() < 1)
                .count();
            if recent >= 50 {
                return Some(IndustrialAnomaly::UnauthorizedWrite);
            }
        }
        None
    }

    /// Rule 4: Dangerous PLC control commands.
    fn check_plc_control(&self, op: &IndustrialOperation) -> Option<IndustrialAnomaly> {
        match op.function_code.as_str() {
            "PLC Stop" | "PLC Reset" => Some(IndustrialAnomaly::UnauthorizedPlcStop),
            "Firmware Write" => Some(IndustrialAnomaly::UnauthorizedFirmwareWrite),
            "Program Download" => Some(IndustrialAnomaly::UnauthorizedProgramDownload),
            "CPU Mode Change" => Some(IndustrialAnomaly::UnauthorizedPlcModeChange),
            _ => None,
        }
    }

    /// Total operations recorded.
    pub fn total_operations(&self) -> usize {
        self.operations.len()
    }

    /// Total anomalies detected.
    pub fn anomaly_count(&self) -> u64 {
        self.anomaly_counter.values().sum()
    }

    /// Breakdown of anomalies by type.
    pub fn anomaly_breakdown(&self) -> Vec<(IndustrialAnomaly, u64)> {
        let mut result: Vec<_> = self
            .anomaly_counter
            .iter()
            .map(|(a, c)| (a.clone(), *c))
            .collect();
        result.sort_by_key(|e| std::cmp::Reverse(e.1));
        result
    }

    /// Protocol usage counts, sorted by frequency.
    pub fn protocol_usage(&self) -> Vec<(String, u64)> {
        let mut result: Vec<_> = self
            .protocol_counts
            .iter()
            .map(|(p, c)| (p.clone(), *c))
            .collect();
        result.sort_by_key(|e| std::cmp::Reverse(e.1));
        result
    }

    /// Category usage counts, sorted by frequency.
    pub fn category_usage(&self) -> Vec<(IndustrialCategory, u64)> {
        let mut result: Vec<_> = self.category_counts.iter().map(|(c, n)| (*c, *n)).collect();
        result.sort_by_key(|e| std::cmp::Reverse(e.1));
        result
    }

    /// Operation type distribution.
    pub fn operation_type_distribution(&self) -> Vec<(String, u64)> {
        let mut counts: HashMap<String, u64> = HashMap::new();
        for op in &self.operations {
            *counts.entry(op.operation_type.clone()).or_insert(0) += 1;
        }
        let mut result: Vec<_> = counts.into_iter().collect();
        result.sort_by_key(|e| std::cmp::Reverse(e.1));
        result
    }

    /// Generate a formatted OT security dashboard report.
    pub fn generate_report(&self) -> String {
        let total = self.total_operations();
        let anomalies = self.anomaly_count();
        let anomaly_rate = if total == 0 {
            0.0
        } else {
            anomalies as f64 / total as f64 * 100.0
        };

        let mut report = String::new();
        report.push_str("═══ Industrial Edge Security Dashboard ═══\n\n");

        report.push_str(&format!("Total Operations:     {total:>8}\n"));
        report.push_str(&format!("Total Anomalies:      {anomalies:>8}\n"));
        report.push_str(&format!("Anomaly Rate:         {anomaly_rate:>7.2}%\n\n"));

        report.push_str("── Anomaly Breakdown ──\n");
        let ab = self.anomaly_breakdown();
        if ab.is_empty() {
            report.push_str("   (no anomalies)\n");
        } else {
            for (anomaly, count) in &ab {
                let severity = match anomaly {
                    IndustrialAnomaly::UnauthorizedWrite
                    | IndustrialAnomaly::UnauthorizedPlcStop
                    | IndustrialAnomaly::UnauthorizedFirmwareWrite
                    | IndustrialAnomaly::UnauthorizedProgramDownload
                    | IndustrialAnomaly::UnauthorizedPlcModeChange => "CRIT",
                    IndustrialAnomaly::UnauthorizedParameterChange
                    | IndustrialAnomaly::UnauthorizedConfigChange
                    | IndustrialAnomaly::UnauthorizedAccess
                    | IndustrialAnomaly::BruteForceAttempt
                    | IndustrialAnomaly::ProtocolFuzzing => "WARN",
                    _ => "INFO",
                };
                report.push_str(&format!("   [{severity}] {anomaly:30} {count:>4}\n"));
            }
        }

        report.push_str("\n── Protocol Distribution ──\n");
        for (proto, count) in self.protocol_usage().iter().take(10) {
            let pct = *count as f64 / total.max(1) as f64 * 100.0;
            report.push_str(&format!("   {proto:25} {count:>4} ({pct:>5.1}%)\n"));
        }

        report.push_str("\n── Category Distribution ──\n");
        for (cat, count) in &self.category_usage() {
            let pct = *count as f64 / total.max(1) as f64 * 100.0;
            report.push_str(&format!("   {cat:25} {count:>4} ({pct:>5.1}%)\n"));
        }

        report.push_str("\n── Operation Type Distribution ──\n");
        for (op_type, count) in self.operation_type_distribution() {
            let pct = count as f64 / total.max(1) as f64 * 100.0;
            report.push_str(&format!("   {op_type:25} {count:>4} ({pct:>5.1}%)\n"));
        }

        report.push_str("\n── Security Recommendations ──\n");
        if anomaly_rate > 5.0 {
            report.push_str("   ⚠  Anomaly rate exceeds 5% — immediate review recommended\n");
        }
        let write_ops = self
            .operation_type_distribution()
            .iter()
            .find(|(t, _)| t == "write")
            .map(|(_, c)| *c)
            .unwrap_or(0);
        if write_ops > 100 {
            report.push_str("   ⚠  High write operation volume — verify write whitelist\n");
        }
        if self
            .anomaly_counter
            .contains_key(&IndustrialAnomaly::PotentialScanning)
        {
            report.push_str("   ⚠  Network scanning detected — consider network segmentation\n");
        }
        if self
            .anomaly_counter
            .contains_key(&IndustrialAnomaly::ProtocolFuzzing)
        {
            report.push_str("   ⚠  Protocol fuzzing detected — possible exploit attempt\n");
        }

        report.push_str("\n═══════════════════════════════════════════\n");
        report
    }
}

impl Default for IndustrialSecurityAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_analyzer() {
        let a = IndustrialSecurityAnalyzer::new();
        assert_eq!(a.total_operations(), 0);
        assert_eq!(a.anomaly_count(), 0);
    }

    #[test]
    fn records_normal_operation() {
        let mut a = IndustrialSecurityAnalyzer::new();
        a.record_operation(IndustrialOperation::new(
            "Modbus",
            IndustrialCategory::IoControl,
            "Read Holding Registers",
            "read",
            "10.0.0.1",
            "10.0.0.2",
        ));
        assert_eq!(a.total_operations(), 1);
        assert_eq!(a.anomaly_count(), 0);
    }

    #[test]
    fn whitelist_violation_detected() {
        let mut a = IndustrialSecurityAnalyzer::new();
        a.add_whitelist("Modbus", "10.0.0.1");
        a.record_operation(IndustrialOperation::new(
            "Modbus",
            IndustrialCategory::IoControl,
            "Write Single Coil",
            "write",
            "10.0.0.99",
            "10.0.0.2",
        ));
        assert_eq!(a.anomaly_count(), 1);
    }

    #[test]
    fn whitelisted_source_ok() {
        let mut a = IndustrialSecurityAnalyzer::new();
        a.add_whitelist("S7comm", "10.0.0.1");
        a.record_operation(IndustrialOperation::new(
            "S7comm",
            IndustrialCategory::PlcCpu,
            "DB Read",
            "read",
            "10.0.0.1",
            "192.168.1.1",
        ));
        assert_eq!(a.anomaly_count(), 0);
    }

    #[test]
    fn plc_stop_triggers_anomaly() {
        let mut a = IndustrialSecurityAnalyzer::new();
        a.record_operation(IndustrialOperation::new(
            "S7comm",
            IndustrialCategory::PlcCpu,
            "PLC Stop",
            "control",
            "10.0.0.99",
            "192.168.1.1",
        ));
        assert!(a.anomaly_count() > 0);
    }

    #[test]
    fn firmware_write_triggers_anomaly() {
        let mut a = IndustrialSecurityAnalyzer::new();
        a.record_operation(IndustrialOperation::new(
            "CIP",
            IndustrialCategory::IoControl,
            "Firmware Write",
            "write",
            "10.0.0.99",
            "10.0.0.2",
        ));
        assert!(a.anomaly_count() > 0);
    }

    #[test]
    fn anomaly_breakdown_ordered_by_count() {
        let mut a = IndustrialSecurityAnalyzer::new();
        a.record_operation(IndustrialOperation::new(
            "Modbus",
            IndustrialCategory::IoControl,
            "PLC Stop",
            "control",
            "10.0.0.99",
            "10.0.0.2",
        ));
        a.record_operation(IndustrialOperation::new(
            "Modbus",
            IndustrialCategory::IoControl,
            "PLC Stop",
            "control",
            "10.0.0.99",
            "10.0.0.2",
        ));
        a.record_operation(IndustrialOperation::new(
            "CIP",
            IndustrialCategory::IoControl,
            "Firmware Write",
            "write",
            "10.0.0.99",
            "10.0.0.2",
        ));
        let ab = a.anomaly_breakdown();
        assert!(!ab.is_empty());
        assert!(ab[0].1 >= ab[1].1); // sorted descending
    }

    #[test]
    fn protocol_usage_counts() {
        let mut a = IndustrialSecurityAnalyzer::new();
        a.record_operation(IndustrialOperation::new(
            "Modbus",
            IndustrialCategory::IoControl,
            "Read",
            "read",
            "10.0.0.1",
            "10.0.0.2",
        ));
        a.record_operation(IndustrialOperation::new(
            "Modbus",
            IndustrialCategory::IoControl,
            "Read",
            "read",
            "10.0.0.1",
            "10.0.0.2",
        ));
        a.record_operation(IndustrialOperation::new(
            "S7comm",
            IndustrialCategory::PlcCpu,
            "Read",
            "read",
            "10.0.0.1",
            "10.0.0.3",
        ));
        let usage = a.protocol_usage();
        assert_eq!(usage[0].0, "Modbus");
        assert_eq!(usage[0].1, 2);
    }

    #[test]
    fn category_usage_counts() {
        let mut a = IndustrialSecurityAnalyzer::new();
        a.record_operation(IndustrialOperation::new(
            "Modbus",
            IndustrialCategory::IoControl,
            "Read",
            "read",
            "10.0.0.1",
            "10.0.0.2",
        ));
        a.record_operation(IndustrialOperation::new(
            "BACnet",
            IndustrialCategory::Building,
            "Who-Is",
            "read",
            "10.0.0.1",
            "10.0.0.2",
        ));
        a.record_operation(IndustrialOperation::new(
            "KNX",
            IndustrialCategory::Building,
            "Write",
            "write",
            "10.0.0.1",
            "10.0.0.2",
        ));
        let cu = a.category_usage();
        assert_eq!(cu[0].0, IndustrialCategory::Building);
        assert_eq!(cu[0].1, 2);
    }

    #[test]
    fn generate_report_includes_all_sections() {
        let mut a = IndustrialSecurityAnalyzer::new();
        a.record_operation(IndustrialOperation::new(
            "Modbus",
            IndustrialCategory::IoControl,
            "Read Coils",
            "read",
            "10.0.0.1",
            "10.0.0.2",
        ));
        let report = a.generate_report();
        assert!(report.contains("Industrial Edge Security Dashboard"));
        assert!(report.contains("Total Operations"));
        assert!(report.contains("Anomaly Breakdown"));
        assert!(report.contains("Protocol Distribution"));
        assert!(report.contains("Category Distribution"));
        assert!(report.contains("Operation Type Distribution"));
        assert!(report.contains("Security Recommendations"));
    }

    #[test]
    fn record_excessive_read_rate() {
        let mut a = IndustrialSecurityAnalyzer::new();
        for _ in 0..120 {
            let mut op = IndustrialOperation::new(
                "Modbus",
                IndustrialCategory::IoControl,
                "Read Holding Registers",
                "read",
                "10.0.0.99",
                "10.0.0.2",
            );
            op.timestamp = Utc::now();
            a.record_operation(op);
        }
        assert!(a.anomaly_count() > 0);
    }

    #[test]
    fn record_operation_type_distribution() {
        let mut a = IndustrialSecurityAnalyzer::new();
        a.record_operation(IndustrialOperation::new(
            "Modbus",
            IndustrialCategory::IoControl,
            "Read",
            "read",
            "10.0.0.1",
            "10.0.0.2",
        ));
        a.record_operation(IndustrialOperation::new(
            "Modbus",
            IndustrialCategory::IoControl,
            "Read",
            "read",
            "10.0.0.1",
            "10.0.0.2",
        ));
        a.record_operation(IndustrialOperation::new(
            "Modbus",
            IndustrialCategory::IoControl,
            "Write",
            "write",
            "10.0.0.1",
            "10.0.0.2",
        ));
        let dist = a.operation_type_distribution();
        assert_eq!(dist[0].0, "read");
        assert_eq!(dist[0].1, 2);
    }
}
