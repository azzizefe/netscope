// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! DCE/RPC — the remote-procedure-call layer behind most of Windows
//! administration (MS-RPCE).
//!
//! "DCE/RPC Bind" on its own says almost nothing, because everything from
//! printing to Active Directory replication rides on it. The fact that matters
//! is the *interface* being bound to, which is carried as a UUID in the bind
//! request. That UUID is the difference between a workstation listing file
//! shares and one asking a domain controller to replicate password hashes.
//!
//! Several of these interfaces are the well-known machinery of lateral
//! movement: `svcctl` creates a service on a remote machine (how PsExec and its
//! imitators run code), `atsvc` schedules a task to the same end, `drsuapi`
//! replicates directory data (the DCSync technique), and `spoolss` is the print
//! spooler behind PrintNightmare. Naming them turns a wall of identical bind
//! packets into something a reader can triage.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// The connection-oriented header is 16 bytes.
const HEADER: usize = 16;
/// Where the first context element's interface UUID begins in a bind PDU:
/// past the header, the fragment sizes, the association group and the context
/// element preamble.
const BIND_UUID_OFFSET: usize = 32;
const UUID_LEN: usize = 16;

const PTYPE_BIND: u8 = 11;
const PTYPE_ALTER_CONTEXT: u8 = 14;

/// Packet types (MS-RPCE §2.2.2.3).
fn packet_name(t: u8) -> &'static str {
    match t {
        0 => "Request",
        2 => "Response",
        3 => "Fault",
        11 => "Bind",
        12 => "Bind Ack",
        13 => "Bind Nak",
        14 => "Alter Context",
        15 => "Alter Context Response",
        16 => "Auth3",
        _ => "PDU",
    }
}

/// Well-known interface UUIDs, written in their canonical text form.
///
/// The list is deliberately weighted towards the interfaces that matter
/// operationally or for security rather than being exhaustive — an unknown
/// interface still has its UUID reported.
fn interface_name(uuid: &str) -> Option<&'static str> {
    Some(match uuid {
        "e1af8308-5d1f-11c9-91a4-08002b14a0fa" => "epmapper (endpoint mapper)",
        "367abb81-9844-35f1-ad32-98f038001003" => "svcctl (remote service control)",
        "1ff70682-0a51-30e8-076d-740be8cee98b" => "atsvc (scheduled tasks)",
        "86d35949-83c9-4044-b424-db363231fd0c" => "ITaskSchedulerService",
        "338cd001-2244-31f1-aaaa-900038001003" => "winreg (remote registry)",
        "4b324fc8-1670-01d3-1278-5a47bf6ee188" => "srvsvc (shares and sessions)",
        "6bffd098-a112-3610-9833-46c3f87e345a" => "wkssvc (workstation service)",
        "12345778-1234-abcd-ef00-0123456789ab" => "lsarpc (local security authority)",
        "3919286a-b10c-11d0-9ba8-00c04fd92ef5" => "lsat (security lookups)",
        "12345778-1234-abcd-ef00-01234567cffb" => "samr (account manager)",
        "e3514235-4b06-11d1-ab04-00c04fc2dcd2" => "drsuapi (directory replication)",
        "12345678-1234-abcd-ef00-0123456789ab" => "spoolss (print spooler)",
        "76f03f96-cdfd-44fc-a22c-64950a001209" => "IRemoteWinspool",
        "afa8bd80-7d8a-11c9-bef4-08002b102989" => "mgmt (RPC management)",
        "99fcfec4-5260-101b-bbcb-00aa0021347a" => "IObjectExporter (DCOM)",
        "000001a0-0000-0000-c000-000000000046" => "IRemoteSCMActivator (DCOM)",
        "8a885d04-1ceb-11c9-9fe8-08002b104860" => "NDR transfer syntax",
        "f5cc5a18-4264-101a-8c59-08002b2f8426" => "nspi (name service)",
        "897e2e5f-93f3-4376-9c9c-fd2277495c27" => "frsrpc (file replication)",
        "50abc2a4-574d-40b3-9d66-ee4fd5fba076" => "dnsserver",
        "82273fdc-e32a-18c3-3f78-827929dc23ea" => "eventlog",
        "5ca4a760-ebb1-11cf-8611-00a0245420ed" => "winstation (terminal services)",
        _ => return None,
    })
}

/// Render the interface UUID from a bind PDU's first context element.
///
/// A UUID is not stored as sixteen sequential bytes: the first three fields are
/// little-endian integers and the last two are byte arrays. Reading it straight
/// through would produce a plausible-looking string that matches nothing.
fn read_uuid(bytes: &[u8]) -> Option<String> {
    let b: &[u8; UUID_LEN] = bytes.get(..UUID_LEN)?.try_into().ok()?;
    Some(format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{}",
        u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        u16::from_le_bytes([b[4], b[5]]),
        u16::from_le_bytes([b[6], b[7]]),
        b[8],
        b[9],
        b[10..16]
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect::<String>()
    ))
}

/// Dissect a DCE/RPC (MSRPC) message — TCP 135 and the dynamic port range, and
/// also over SMB named pipes.
pub fn dissect_dcerpc(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match parse(payload) {
        Some(s) => s,
        None => format!("DCE/RPC ({})", super::bytes(payload.len() as u64)),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Dcerpc,
        summary,
    }
}

fn parse(payload: &[u8]) -> Option<String> {
    // Major version 5 is the only one in use.
    if *payload.first()? != 5 {
        return None;
    }
    let ptype = *payload.get(2)?;
    let name = packet_name(ptype);

    // Only a bind names an interface; requests reference it by context id.
    if !matches!(ptype, PTYPE_BIND | PTYPE_ALTER_CONTEXT) || payload.len() < HEADER {
        return Some(format!("DCE/RPC {name}"));
    }
    let Some(uuid) = payload.get(BIND_UUID_OFFSET..).and_then(read_uuid) else {
        return Some(format!("DCE/RPC {name}"));
    };
    Some(match interface_name(&uuid) {
        Some(interface) => format!("DCE/RPC {name} — {interface}"),
        None => format!("DCE/RPC {name} — interface {uuid}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a bind PDU whose first context element names `uuid`.
    fn bind(uuid: [u8; UUID_LEN]) -> Vec<u8> {
        let mut p = vec![0x05, 0x00, PTYPE_BIND, 0x03]; // version, type, flags
        p.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // data representation
        p.extend_from_slice(&72u16.to_le_bytes()); // fragment length
        p.extend_from_slice(&0u16.to_le_bytes()); // auth length
        p.extend_from_slice(&1u32.to_le_bytes()); // call id
        p.extend_from_slice(&4280u16.to_le_bytes()); // max transmit fragment
        p.extend_from_slice(&4280u16.to_le_bytes()); // max receive fragment
        p.extend_from_slice(&0u32.to_le_bytes()); // association group
        p.push(1); // context element count
        p.extend_from_slice(&[0, 0, 0]); // reserved
        p.extend_from_slice(&0u16.to_le_bytes()); // context id
        p.push(1); // transfer syntax count
        p.push(0); // reserved
        p.extend_from_slice(&uuid);
        p.extend_from_slice(&3u32.to_le_bytes()); // interface version
        p
    }

    /// The canonical text form as bytes, in the mixed-endian layout a UUID
    /// actually uses on the wire.
    fn uuid_bytes(d1: u32, d2: u16, d3: u16, rest: [u8; 8]) -> [u8; UUID_LEN] {
        let mut b = [0u8; UUID_LEN];
        b[0..4].copy_from_slice(&d1.to_le_bytes());
        b[4..6].copy_from_slice(&d2.to_le_bytes());
        b[6..8].copy_from_slice(&d3.to_le_bytes());
        b[8..16].copy_from_slice(&rest);
        b
    }

    #[test]
    fn plain_packet_types_still_decode() {
        let r = dissect_dcerpc(None, None, 40000, 135, &[0x05, 0x00, 0x00, 0x03]);
        assert_eq!(r.protocol, Protocol::Dcerpc);
        assert_eq!(r.summary, "DCE/RPC Request");
    }

    /// The interfaces behind remote code execution: a bind to either of these
    /// is what PsExec-style tooling does before it runs anything.
    #[test]
    fn remote_execution_interfaces_are_named() {
        let svcctl = uuid_bytes(
            0x367a_bb81,
            0x9844,
            0x35f1,
            [0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03],
        );
        let r = dissect_dcerpc(None, None, 40000, 135, &bind(svcctl));
        assert_eq!(r.summary, "DCE/RPC Bind — svcctl (remote service control)");

        let atsvc = uuid_bytes(
            0x1ff7_0682,
            0x0a51,
            0x30e8,
            [0x07, 0x6d, 0x74, 0x0b, 0xe8, 0xce, 0xe9, 0x8b],
        );
        let r = dissect_dcerpc(None, None, 40000, 135, &bind(atsvc));
        assert_eq!(r.summary, "DCE/RPC Bind — atsvc (scheduled tasks)");
    }

    /// Directory replication is the interface behind credential-dumping from a
    /// domain controller, so it is worth naming on sight.
    #[test]
    fn directory_replication_is_named() {
        let drsuapi = uuid_bytes(
            0xe351_4235,
            0x4b06,
            0x11d1,
            [0xab, 0x04, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2],
        );
        let r = dissect_dcerpc(None, None, 40000, 135, &bind(drsuapi));
        assert_eq!(r.summary, "DCE/RPC Bind — drsuapi (directory replication)");
    }

    #[test]
    fn everyday_interfaces_are_named() {
        let srvsvc = uuid_bytes(
            0x4b32_4fc8,
            0x1670,
            0x01d3,
            [0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88],
        );
        assert_eq!(
            dissect_dcerpc(None, None, 1, 135, &bind(srvsvc)).summary,
            "DCE/RPC Bind — srvsvc (shares and sessions)"
        );
    }

    /// A UUID is mixed-endian on the wire. Reading it straight through would
    /// produce a plausible string that matches no known interface.
    #[test]
    fn uuid_is_read_in_its_mixed_endian_layout() {
        let winreg = uuid_bytes(
            0x338c_d001,
            0x2244,
            0x31f1,
            [0xaa, 0xaa, 0x90, 0x00, 0x38, 0x00, 0x10, 0x03],
        );
        assert_eq!(
            read_uuid(&winreg).unwrap(),
            "338cd001-2244-31f1-aaaa-900038001003"
        );
        // The same bytes read straight through would not match anything.
        assert!(interface_name(
            &winreg
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        )
        .is_none());
    }

    /// An interface we do not have a name for still reports its UUID, which is
    /// enough to look up.
    #[test]
    fn unknown_interface_reports_its_uuid() {
        let unknown = uuid_bytes(0x1234_5678, 0x9abc, 0xdef0, [0u8; 8]);
        let r = dissect_dcerpc(None, None, 1, 135, &bind(unknown));
        assert_eq!(
            r.summary,
            "DCE/RPC Bind — interface 12345678-9abc-def0-0000-000000000000"
        );
    }

    /// A bind truncated before its context list keeps the plain label rather
    /// than reading past the end.
    #[test]
    fn truncated_bind_falls_back_to_the_packet_type() {
        let full = bind(uuid_bytes(1, 2, 3, [0u8; 8]));
        let r = dissect_dcerpc(None, None, 1, 135, &full[..HEADER + 4]);
        assert_eq!(r.summary, "DCE/RPC Bind");
    }

    #[test]
    fn foreign_payloads_are_not_claimed() {
        assert!(parse(b"GET / HTTP/1.1").is_none());
        assert!(parse(&[]).is_none());
        assert_eq!(
            dissect_dcerpc(None, None, 1, 135, b"GET /").summary,
            "DCE/RPC (5 bytes)"
        );
    }
}
