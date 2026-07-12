use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Heuristically dissect RTP/RTCP media traffic over UDP (ROADMAP §3.6).
///
/// RTP carries the actual audio/video of a VoIP or video call; SIP only sets the
/// call up (see [`super::sip`]) and hands RTP a dynamically negotiated UDP port,
/// so there is no fixed port to key on. We recognise it structurally: the first
/// two bits are the version (always 2), and RTP vs. RTCP is told apart by the
/// packet-type byte — RTCP uses 200–204 (Sender/Receiver Report, SDES, BYE,
/// APP), everything else is an RTP media packet. This mirrors Wireshark's
/// opt-in "RTP over UDP" heuristic, and only runs after the well-known-port
/// dissectors have passed.
///
/// Returns `None` when the payload doesn't structurally look like RTP/RTCP, so
/// the caller can fall through to the generic UDP summary.
pub fn try_dissect(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<DissectedResult> {
    if payload.len() < 8 {
        return None;
    }
    // Version must be 2 (top two bits of the first byte).
    if payload[0] >> 6 != 2 {
        return None;
    }

    let make = |protocol, summary: String| DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol,
        summary,
    };

    let pt_byte = payload[1];
    // RTCP control packets: packet-type byte in 200..=204.
    if (200..=204).contains(&pt_byte) {
        let name = rtcp_type(pt_byte);
        // SSRC of the sender sits at bytes 4..8 for SR/RR.
        let ssrc = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        return Some(make(
            Protocol::Rtcp,
            format!("RTCP {name} — SSRC 0x{ssrc:08x}"),
        ));
    }

    // Otherwise treat as an RTP media packet (needs the full 12-byte header).
    if payload.len() < 12 {
        return None;
    }
    let payload_type = pt_byte & 0x7f;
    // Reject implausible dynamic payload types to cut false positives: RTP uses
    // 0..=34 (static) and 96..=127 (dynamic); 35..=71 and 77..=95 are unassigned.
    if !(payload_type <= 34 || (96..=127).contains(&payload_type)) {
        return None;
    }
    let marker = pt_byte & 0x80 != 0;
    let seq = u16::from_be_bytes([payload[2], payload[3]]);
    let ssrc = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
    let codec = payload_type_name(payload_type);
    let mark = if marker { " [mark]" } else { "" };
    Some(make(
        Protocol::Rtp,
        format!("RTP {codec} — seq {seq}, SSRC 0x{ssrc:08x}{mark}"),
    ))
}

fn rtcp_type(pt: u8) -> &'static str {
    match pt {
        200 => "Sender Report",
        201 => "Receiver Report",
        202 => "Source Description",
        203 => "Goodbye",
        204 => "Application-Defined",
        _ => "packet",
    }
}

/// Well-known static RTP payload types (RFC 3551). Dynamic types (96–127) are
/// negotiated in SDP, which we don't track here.
fn payload_type_name(pt: u8) -> String {
    match pt {
        0 => "PCMU/8000".into(),
        3 => "GSM".into(),
        4 => "G723".into(),
        8 => "PCMA/8000".into(),
        9 => "G722".into(),
        10 => "L16/44100 stereo".into(),
        11 => "L16/44100".into(),
        13 => "comfort noise".into(),
        18 => "G729".into(),
        26 => "JPEG video".into(),
        31 => "H261 video".into(),
        32 => "MPV video".into(),
        34 => "H263 video".into(),
        96..=127 => format!("dynamic PT {pt}"),
        _ => format!("PT {pt}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rtp_packet(pt: u8, seq: u16, ssrc: u32) -> Vec<u8> {
        let mut p = vec![0x80, pt];
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&0u32.to_be_bytes()); // timestamp
        p.extend_from_slice(&ssrc.to_be_bytes());
        p.extend_from_slice(&[0u8; 4]); // some media payload
        p
    }

    #[test]
    fn rtp_g711_ulaw() {
        let p = rtp_packet(0, 1234, 0xdead_beef);
        let r = try_dissect(None, None, 40000, 40002, &p).unwrap();
        assert_eq!(r.protocol, Protocol::Rtp);
        assert_eq!(r.summary, "RTP PCMU/8000 — seq 1234, SSRC 0xdeadbeef");
    }

    #[test]
    fn rtcp_sender_report() {
        let mut p = vec![0x80, 200]; // V=2, PT=200 (SR)
        p.extend_from_slice(&0u16.to_be_bytes()); // length
        p.extend_from_slice(&0x1122_3344u32.to_be_bytes()); // SSRC
        let r = try_dissect(None, None, 40001, 40003, &p).unwrap();
        assert_eq!(r.protocol, Protocol::Rtcp);
        assert_eq!(r.summary, "RTCP Sender Report — SSRC 0x11223344");
    }

    #[test]
    fn rejects_wrong_version() {
        // Version 0 in the top bits.
        let p = vec![0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(try_dissect(None, None, 40000, 40002, &p).is_none());
    }

    #[test]
    fn rejects_implausible_payload_type() {
        // Version 2 but payload type 50 (unassigned) → not RTP.
        let p = rtp_packet(50, 1, 1);
        assert!(try_dissect(None, None, 40000, 40002, &p).is_none());
    }

    #[test]
    fn too_short_is_none() {
        assert!(try_dissect(None, None, 40000, 40002, &[0x80, 0, 0]).is_none());
    }
}
