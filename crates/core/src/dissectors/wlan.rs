//! IEEE 802.11 (Wi-Fi) frame dissection.
//!
//! Handles the three frame classes — management (beacons, probe/assoc/auth),
//! control (ACK/RTS/CTS/Block-Ack) and data — and pulls the SSID out of
//! beacon and probe frames. Wi-Fi frames are link-layer, so no IP addresses
//! are set; the summary carries the SSID/BSSID and (from radiotap) the signal
//! and channel.

use crate::models::Protocol;

use super::ethernet::mac_to_string;
use super::{radiotap, DissectedResult};

/// Dissect a radiotap-prefixed 802.11 frame (monitor-mode capture,
/// `DLT_IEEE802_11_RADIO`).
pub fn dissect_radiotap(data: &[u8]) -> DissectedResult {
    match radiotap::parse(data) {
        Some(rt) if rt.header_len <= data.len() => {
            let frame = &data[rt.header_len..];
            dissect_80211(frame, Some(&rt))
        }
        // Not a valid radiotap header — treat the whole buffer as 802.11.
        _ => dissect_80211(data, None),
    }
}

/// Dissect a bare 802.11 frame (`DLT_IEEE802_11`), optionally annotated with
/// radiotap radio metadata.
pub fn dissect_80211(data: &[u8], radio: Option<&radiotap::Radiotap>) -> DissectedResult {
    let unknown = |summary: String| DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Wlan,
        summary,
    };

    if data.len() < 2 {
        return unknown("802.11 (truncated frame)".into());
    }

    let fc = data[0];
    let ftype = (fc >> 2) & 0x03;
    let subtype = (fc >> 4) & 0x0F;

    let mut summary = match ftype {
        0 => management_summary(data, subtype),
        1 => format!("802.11 {}", control_name(subtype)),
        2 => format!("802.11 {}", data_name(subtype)),
        _ => "802.11 Extension frame".to_string(),
    };

    if let Some(suffix) = radio_suffix(radio) {
        summary.push_str(&suffix);
    }

    unknown(summary)
}

/// Management frames carry a 24-byte header (FC, duration, addr1/2/3, seq).
/// Beacon and probe frames also carry an SSID we surface.
fn management_summary(data: &[u8], subtype: u8) -> String {
    let name = mgmt_name(subtype);

    // BSSID is address 3, at offset 16..22 in the management header.
    let bssid = data
        .get(16..22)
        .map(|b| mac_to_string(&[b[0], b[1], b[2], b[3], b[4], b[5]]));

    match subtype {
        // Beacon (8) and Probe Response (5): fixed params (12 bytes) then tags.
        8 | 5 => match ssid_label(data, 36) {
            Some(ssid) => format!("802.11 {name} — {ssid}"),
            None => match bssid {
                Some(b) => format!("802.11 {name} (BSSID {b})"),
                None => format!("802.11 {name}"),
            },
        },
        // Probe Request (4): tags start right after the 24-byte header.
        4 => match ssid_label(data, 24) {
            Some(ssid) => format!("802.11 {name} — {ssid}"),
            None => format!("802.11 {name}"),
        },
        _ => match bssid {
            Some(b) => format!("802.11 {name} (BSSID {b})"),
            None => format!("802.11 {name}"),
        },
    }
}

/// Read the SSID (tagged parameter id 0) starting at `start`, returning a
/// display label (`"MyWiFi"`, or `<hidden>` for a zero-length SSID).
fn ssid_label(frame: &[u8], start: usize) -> Option<String> {
    let mut i = start;
    while i + 2 <= frame.len() {
        let tag = frame[i];
        let len = frame[i + 1] as usize;
        let val_start = i + 2;
        if val_start + len > frame.len() {
            break;
        }
        if tag == 0 {
            return Some(if len == 0 {
                "<hidden>".to_string()
            } else {
                format!(
                    "\"{}\"",
                    String::from_utf8_lossy(&frame[val_start..val_start + len])
                )
            });
        }
        i = val_start + len;
    }
    None
}

fn radio_suffix(radio: Option<&radiotap::Radiotap>) -> Option<String> {
    let rt = radio?;
    let mut parts = Vec::new();
    if let Some(sig) = rt.signal_dbm {
        parts.push(format!("{sig} dBm"));
    }
    if let Some(ch) = rt.channel_mhz {
        parts.push(format!("{ch} MHz"));
    }
    if parts.is_empty() {
        None
    } else {
        Some(format!(" · {}", parts.join(" · ")))
    }
}

fn mgmt_name(subtype: u8) -> &'static str {
    match subtype {
        0 => "Association Request",
        1 => "Association Response",
        2 => "Reassociation Request",
        3 => "Reassociation Response",
        4 => "Probe Request",
        5 => "Probe Response",
        8 => "Beacon",
        9 => "ATIM",
        10 => "Disassociation",
        11 => "Authentication",
        12 => "Deauthentication",
        13 => "Action",
        _ => "Management",
    }
}

fn control_name(subtype: u8) -> &'static str {
    match subtype {
        8 => "Block Ack Request",
        9 => "Block Ack",
        10 => "PS-Poll",
        11 => "RTS",
        12 => "CTS",
        13 => "ACK",
        14 => "CF-End",
        _ => "Control",
    }
}

fn data_name(subtype: u8) -> &'static str {
    match subtype {
        0 => "Data",
        4 => "Null (no data)",
        8 => "QoS Data",
        12 => "QoS Null",
        _ => "Data",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a management frame header (24 bytes) with a given subtype and
    /// BSSID, plus an optional body.
    fn mgmt_frame(subtype: u8, body: &[u8]) -> Vec<u8> {
        let fc0 = subtype << 4; // type 0 (management), version 0
        let mut f = vec![fc0, 0x00]; // frame control
        f.extend_from_slice(&[0x00, 0x00]); // duration
        f.extend_from_slice(&[0xff; 6]); // addr1 (DA)
        f.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // addr2 (SA)
        f.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // addr3 (BSSID)
        f.extend_from_slice(&[0x00, 0x00]); // seq ctl
        f.extend_from_slice(body);
        f
    }

    fn beacon_body(ssid: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; 12]; // timestamp(8) + interval(2) + caps(2)
        b.push(0x00); // SSID tag id
        b.push(ssid.len() as u8);
        b.extend_from_slice(ssid);
        b
    }

    #[test]
    fn beacon_with_ssid() {
        let frame = mgmt_frame(8, &beacon_body(b"MyWiFi"));
        let r = dissect_80211(&frame, None);
        assert_eq!(r.protocol, Protocol::Wlan);
        assert_eq!(r.summary, "802.11 Beacon — \"MyWiFi\"");
    }

    #[test]
    fn hidden_ssid_beacon() {
        let frame = mgmt_frame(8, &beacon_body(b""));
        let r = dissect_80211(&frame, None);
        assert_eq!(r.summary, "802.11 Beacon — <hidden>");
    }

    #[test]
    fn probe_request_ssid() {
        // Probe Request (subtype 4): tags right after the 24-byte header.
        let mut body = vec![0x00, 6];
        body.extend_from_slice(b"coffee");
        let frame = mgmt_frame(4, &body);
        let r = dissect_80211(&frame, None);
        assert_eq!(r.summary, "802.11 Probe Request — \"coffee\"");
    }

    #[test]
    fn deauth_names_and_bssid() {
        let frame = mgmt_frame(12, &[]);
        let r = dissect_80211(&frame, None);
        assert_eq!(
            r.summary,
            "802.11 Deauthentication (BSSID aa:bb:cc:dd:ee:ff)"
        );
    }

    #[test]
    fn control_ack() {
        // Control (type 1), subtype 13 (ACK): fc0 = (13<<4)|(1<<2) = 0xD4
        let frame = [0xD4, 0x00, 0x00, 0x00];
        let r = dissect_80211(&frame, None);
        assert_eq!(r.summary, "802.11 ACK");
    }

    #[test]
    fn data_qos() {
        // Data (type 2), subtype 8 (QoS Data): fc0 = (8<<4)|(2<<2) = 0x88
        let frame = mgmt_frame(0, &[]); // reuse header shape
        let mut f = frame;
        f[0] = 0x88;
        let r = dissect_80211(&f, None);
        assert_eq!(r.summary, "802.11 QoS Data");
    }

    #[test]
    fn radiotap_suffix_appended() {
        let rt = radiotap::Radiotap {
            header_len: 0,
            signal_dbm: Some(-42),
            channel_mhz: Some(2412),
        };
        let frame = mgmt_frame(8, &beacon_body(b"Net"));
        let r = dissect_80211(&frame, Some(&rt));
        assert_eq!(r.summary, "802.11 Beacon — \"Net\" · -42 dBm · 2412 MHz");
    }

    #[test]
    fn truncated_frame() {
        let r = dissect_80211(&[0x80], None);
        assert_eq!(r.protocol, Protocol::Wlan);
        assert!(r.summary.contains("truncated"));
    }
}
