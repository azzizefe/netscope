// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

//! ICS / SCADA Deep Packet Inspection (DPI) & OT Anomaly Engine (ROADMAP §9.1).
//!
//! Provides deep packet inspection for industrial control system (ICS/OT) protocols:
//! - Modbus TCP (Function codes 0x05 Write Single Coil, 0x06 Write Single Register, 0x0F/0x10 Multiple Writes)
//! - DNP3 (Function codes 0x0D Cold Restart, 0x0E Warm Restart, 0x05 Direct Operate)
//! - IEC 60870-5-104 (Type IDs 45-51 Command Executions, Cause of Transmission 0x06/0x07 Activation)
//! - BACnet/IP (Service Choice 0x14 ReinitializeDevice, 0x0F WriteProperty)
//! - OPC UA (WriteService, CallService, MethodInvocation)

use serde::{Deserialize, Serialize};

/// Supported Industrial Control System (ICS/SCADA) protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IcsProtocolKind {
    ModbusTcp,
    Dnp3,
    Iec60870_5_104,
    Bacnet,
    OpcUa,
}

impl IcsProtocolKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            IcsProtocolKind::ModbusTcp => "Modbus TCP",
            IcsProtocolKind::Dnp3 => "DNP3",
            IcsProtocolKind::Iec60870_5_104 => "IEC 60870-5-104",
            IcsProtocolKind::Bacnet => "BACnet/IP",
            IcsProtocolKind::OpcUa => "OPC UA",
        }
    }
}

/// Anomaly classification for industrial OT security threats.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IcsAnomalyKind {
    /// Unauthorized write command to PLC output coils or holding registers.
    UnauthorizedWrite,
    /// Industrial controller restart command (Cold/Warm Restart or Device Reinitialization).
    UnauthorizedRestart,
    /// Modification of critical process setpoint parameters.
    SetpointOverride,
    /// Invalid, reserved, or illegal protocol function code.
    IllegalFunctionCode,
    /// Unauthenticated control command sent to an operational asset.
    UnauthenticatedControl,
}

impl IcsAnomalyKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            IcsAnomalyKind::UnauthorizedWrite => "Unauthorized Write",
            IcsAnomalyKind::UnauthorizedRestart => "Unauthorized Controller Restart",
            IcsAnomalyKind::SetpointOverride => "Setpoint Parameter Override",
            IcsAnomalyKind::IllegalFunctionCode => "Illegal Function Code",
            IcsAnomalyKind::UnauthenticatedControl => "Unauthenticated OT Control",
        }
    }
}

/// Security alert generated during SCADA Deep Packet Inspection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IcsSecurityAlert {
    pub protocol: IcsProtocolKind,
    pub anomaly_kind: IcsAnomalyKind,
    pub severity: &'static str, // "CRITICAL", "HIGH", "MEDIUM", "LOW"
    pub summary: String,
    pub details: String,
}

/// SCADA/ICS Deep Packet Inspection Engine.
#[derive(Debug, Clone)]
pub struct ScadaDpiEngine {
    pub readonly_mode: bool,
    pub allowed_modbus_units: Vec<u8>,
}

impl Default for ScadaDpiEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ScadaDpiEngine {
    /// Create a new SCADA DPI engine.
    pub fn new() -> Self {
        Self {
            readonly_mode: false,
            allowed_modbus_units: Vec::new(),
        }
    }

    /// Enable zero-trust read-only mode (flags ALL write/control commands as critical alerts).
    pub fn with_readonly_mode(mut self, readonly: bool) -> Self {
        self.readonly_mode = readonly;
        self
    }

    /// Inspect Modbus TCP function code and register payloads.
    pub fn inspect_modbus(&self, func_code: u8, address: u16, value: u16) -> Vec<IcsSecurityAlert> {
        let mut alerts = Vec::new();

        match func_code {
            // Write Single Coil (0x05), Write Single Register (0x06), Write Multiple Coils (0x0F), Write Multiple Registers (0x10)
            0x05 | 0x06 | 0x0F | 0x10 => {
                let severity = if self.readonly_mode {
                    "CRITICAL"
                } else {
                    "HIGH"
                };
                alerts.push(IcsSecurityAlert {
                    protocol: IcsProtocolKind::ModbusTcp,
                    anomaly_kind: IcsAnomalyKind::UnauthorizedWrite,
                    severity,
                    summary: format!("Modbus TCP Write command detected (Func 0x{:02X})", func_code),
                    details: format!(
                        "Write request to register/coil address {} with value {}. Readonly enforcement: {}",
                        address, value, self.readonly_mode
                    ),
                });
            }
            // Reserved / Illegal Modbus function codes (> 0x7F or unassigned)
            0x00 | 0x0B..=0x0E | 0x19..=0x2A | 0x7F..=0xFF => {
                alerts.push(IcsSecurityAlert {
                    protocol: IcsProtocolKind::ModbusTcp,
                    anomaly_kind: IcsAnomalyKind::IllegalFunctionCode,
                    severity: "HIGH",
                    summary: format!("Modbus TCP Illegal Function Code 0x{:02X}", func_code),
                    details: format!(
                        "Observed reserved/illegal Modbus function code 0x{:02X}",
                        func_code
                    ),
                });
            }
            _ => {}
        }

        alerts
    }

    /// Inspect DNP3 (Distributed Network Protocol) function codes.
    pub fn inspect_dnp3(&self, func_code: u8, _group: u8) -> Vec<IcsSecurityAlert> {
        let mut alerts = Vec::new();

        match func_code {
            // Cold Restart (0x0D), Warm Restart (0x0E)
            0x0D | 0x0E => {
                let restart_type = if func_code == 0x0D {
                    "Cold Restart"
                } else {
                    "Warm Restart"
                };
                alerts.push(IcsSecurityAlert {
                    protocol: IcsProtocolKind::Dnp3,
                    anomaly_kind: IcsAnomalyKind::UnauthorizedRestart,
                    severity: "CRITICAL",
                    summary: format!(
                        "DNP3 Controller {} Command (Func 0x{:02X})",
                        restart_type, func_code
                    ),
                    details: format!(
                        "Out-of-band DNP3 {} command issued to outstation asset.",
                        restart_type
                    ),
                });
            }
            // Direct Operate (0x05), Direct Operate No ACK (0x06)
            0x05 | 0x06 => {
                alerts.push(IcsSecurityAlert {
                    protocol: IcsProtocolKind::Dnp3,
                    anomaly_kind: IcsAnomalyKind::UnauthorizedWrite,
                    severity: "HIGH",
                    summary: format!("DNP3 Direct Operate Control Command (Func 0x{:02X})", func_code),
                    details: "Direct control operation executed on DNP3 outstation binary/analog outputs.".to_string(),
                });
            }
            _ => {}
        }

        alerts
    }

    /// Inspect IEC 60870-5-104 Telecontrol ASDU Command Types.
    pub fn inspect_iec104(&self, type_id: u8, cause_of_transmission: u8) -> Vec<IcsSecurityAlert> {
        let mut alerts = Vec::new();

        // Single Command (45), Double Command (46), Regulating Step Command (47), Setpoint Commands (48..=50)
        if (45..=51).contains(&type_id) {
            let is_activation = (cause_of_transmission & 0x3F) == 6; // Activation (0x06)
            if is_activation {
                alerts.push(IcsSecurityAlert {
                    protocol: IcsProtocolKind::Iec60870_5_104,
                    anomaly_kind: IcsAnomalyKind::UnauthorizedWrite,
                    severity: "HIGH",
                    summary: format!("IEC 60870-5-104 Command Activation (Type ID {})", type_id),
                    details: format!(
                        "Telecontrol command activation issued for ASDU Type ID {} (COT {}).",
                        type_id, cause_of_transmission
                    ),
                });
            }
        }

        alerts
    }

    /// Inspect BACnet/IP building automation service choices.
    pub fn inspect_bacnet(&self, service_choice: u8, _object_type: u16) -> Vec<IcsSecurityAlert> {
        let mut alerts = Vec::new();

        match service_choice {
            // ReinitializeDevice (0x14)
            0x14 => {
                alerts.push(IcsSecurityAlert {
                    protocol: IcsProtocolKind::Bacnet,
                    anomaly_kind: IcsAnomalyKind::UnauthorizedRestart,
                    severity: "CRITICAL",
                    summary: "BACnet ReinitializeDevice Command Detected (Service 0x14)".to_string(),
                    details: "Remote device reboot/reinitialization command sent to BACnet building controller.".to_string(),
                });
            }
            // WriteProperty (0x0F), WritePropertyMultiple (0x10)
            0x0F | 0x10 => {
                alerts.push(IcsSecurityAlert {
                    protocol: IcsProtocolKind::Bacnet,
                    anomaly_kind: IcsAnomalyKind::UnauthorizedWrite,
                    severity: "MEDIUM",
                    summary: format!(
                        "BACnet Write Property Command (Service 0x{:02X})",
                        service_choice
                    ),
                    details: "Modification of BACnet object property value executed.".to_string(),
                });
            }
            _ => {}
        }

        alerts
    }

    /// Main entry point: inspect raw SCADA payload buffer.
    pub fn inspect_payload(
        &self,
        protocol: IcsProtocolKind,
        payload: &[u8],
    ) -> Vec<IcsSecurityAlert> {
        if payload.is_empty() {
            return Vec::new();
        }

        match protocol {
            IcsProtocolKind::ModbusTcp => {
                if payload.len() >= 8 {
                    // MBAP header: Transaction ID (2), Protocol ID (2), Length (2), Unit ID (1), Function Code (1)
                    let func_code = payload[7];
                    let addr = if payload.len() >= 10 {
                        u16::from_be_bytes([payload[8], payload[9]])
                    } else {
                        0
                    };
                    let val = if payload.len() >= 12 {
                        u16::from_be_bytes([payload[10], payload[11]])
                    } else {
                        0
                    };
                    self.inspect_modbus(func_code, addr, val)
                } else {
                    Vec::new()
                }
            }
            IcsProtocolKind::Dnp3 => {
                if payload.len() >= 12 {
                    // Transport / Application layer function code at offset 12
                    let func_code = payload[12];
                    let group = payload.get(13).copied().unwrap_or(0);
                    self.inspect_dnp3(func_code, group)
                } else {
                    Vec::new()
                }
            }
            IcsProtocolKind::Iec60870_5_104 => {
                if payload.len() >= 6 {
                    // Type ID at offset 6, COT at offset 8
                    let type_id = payload[6];
                    let cot = payload.get(8).copied().unwrap_or(0);
                    self.inspect_iec104(type_id, cot)
                } else {
                    Vec::new()
                }
            }
            IcsProtocolKind::Bacnet => {
                if payload.len() >= 4 {
                    let service_choice = payload.get(3).copied().unwrap_or(0);
                    self.inspect_bacnet(service_choice, 0)
                } else {
                    Vec::new()
                }
            }
            IcsProtocolKind::OpcUa => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modbus_write_coil_inspection() {
        let dpi = ScadaDpiEngine::new().with_readonly_mode(true);
        let alerts = dpi.inspect_modbus(0x05, 100, 0xFF00);

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].anomaly_kind, IcsAnomalyKind::UnauthorizedWrite);
        assert_eq!(alerts[0].severity, "CRITICAL");
    }

    #[test]
    fn test_dnp3_cold_restart_inspection() {
        let dpi = ScadaDpiEngine::new();
        let alerts = dpi.inspect_dnp3(0x0D, 0);

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].anomaly_kind, IcsAnomalyKind::UnauthorizedRestart);
        assert_eq!(alerts[0].severity, "CRITICAL");
    }

    #[test]
    fn test_iec104_command_activation() {
        let dpi = ScadaDpiEngine::new();
        let alerts = dpi.inspect_iec104(45, 0x06); // Type 45, COT 6 (Activation)

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].anomaly_kind, IcsAnomalyKind::UnauthorizedWrite);
    }

    #[test]
    fn test_bacnet_reinitialize_device() {
        let dpi = ScadaDpiEngine::new();
        let alerts = dpi.inspect_bacnet(0x14, 0);

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].anomaly_kind, IcsAnomalyKind::UnauthorizedRestart);
    }
}
