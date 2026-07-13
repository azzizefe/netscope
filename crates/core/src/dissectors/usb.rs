//! USB dissector — bus captures from Linux usbmon (`LINKTYPE_USB_LINUX`
//! DLT 189, `LINKTYPE_USB_LINUX_MMAPPED` DLT 220) and Windows USBPcap
//! (`LINKTYPE_USBPCAP` DLT 249).
//!
//! Both formats prefix each URB (USB request block) with a pseudo-header
//! naming bus/device/endpoint, the transfer type and direction; the summary
//! shows exactly that, Wireshark-style: `USB 1.5.1 Bulk IN, 512 bytes`.

use super::DissectedResult;
use crate::models::Protocol;

fn result(summary: String) -> DissectedResult {
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Usb,
        summary,
    }
}

fn malformed(what: &str) -> DissectedResult {
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Unknown(format!("truncated {what}")),
        summary: format!("Malformed USB record (truncated {what} header)"),
    }
}

/// USBPcap pseudo-header (little-endian, Windows).
pub fn dissect_usbpcap(data: &[u8]) -> DissectedResult {
    if data.len() < 27 {
        return malformed("USBPcap");
    }
    // uint16 headerLen; uint64 irpId; uint32 status; uint16 function;
    // uint8 info; uint16 bus; uint16 device; uint8 endpoint; uint8 transfer;
    // uint32 dataLength;
    let info = data[16];
    let bus = u16::from_le_bytes([data[17], data[18]]);
    let device = u16::from_le_bytes([data[19], data[20]]);
    let endpoint = data[21];
    let transfer = data[22];
    let data_len = u32::from_le_bytes([data[23], data[24], data[25], data[26]]);

    let transfer_name = match transfer {
        0 => "Isochronous",
        1 => "Interrupt",
        2 => "Control",
        3 => "Bulk",
        254 => "IRP info",
        _ => "Unknown transfer",
    };
    // info bit 0: 0 = host→device (OUT leg), 1 = device→host (IN leg).
    let direction = if info & 0x01 != 0 { "IN" } else { "OUT" };
    let ep = endpoint & 0x7F;
    result(format!(
        "USB {bus}.{device}.{ep} {transfer_name} {direction}, {data_len} bytes"
    ))
}

/// Linux usbmon URB header (48 bytes for DLT 189, 64 for DLT 220; the fields
/// we show live in the shared first 40 bytes). usbmon writes in host byte
/// order — little-endian on effectively all Linux capture hosts.
pub fn dissect_usb_linux(data: &[u8]) -> DissectedResult {
    if data.len() < 40 {
        return malformed("usbmon");
    }
    let event = data[8]; // 'S' submit, 'C' complete, 'E' error
    let transfer = data[9];
    let epnum = data[10];
    let devnum = data[11];
    let busnum = u16::from_le_bytes([data[12], data[13]]);
    let urb_len = u32::from_le_bytes([data[36], data[37], data[38], data[39]]);

    let transfer_name = match transfer {
        0 => "Isochronous",
        1 => "Interrupt",
        2 => "Control",
        3 => "Bulk",
        _ => "Unknown transfer",
    };
    let event_name = match event {
        b'S' => "Submit",
        b'C' => "Complete",
        b'E' => "Error",
        _ => "?",
    };
    let direction = if epnum & 0x80 != 0 { "IN" } else { "OUT" };
    let ep = epnum & 0x7F;
    result(format!(
        "USB {busnum}.{devnum}.{ep} {transfer_name} {direction} ({event_name}), {urb_len} bytes"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usbpcap_bulk_in() {
        let mut h = vec![0u8; 27];
        h[0] = 27; // headerLen
        h[16] = 0x01; // info: device → host
        h[17] = 1; // bus 1
        h[19] = 5; // device 5
        h[21] = 0x81; // endpoint 1, IN
        h[22] = 3; // bulk
        h[23..27].copy_from_slice(&512u32.to_le_bytes());
        let r = dissect_usbpcap(&h);
        assert_eq!(r.protocol, Protocol::Usb);
        assert_eq!(r.summary, "USB 1.5.1 Bulk IN, 512 bytes");
    }

    #[test]
    fn usbpcap_control_out() {
        let mut h = vec![0u8; 27];
        h[17] = 2;
        h[19] = 3;
        h[21] = 0x00;
        h[22] = 2;
        let r = dissect_usbpcap(&h);
        assert_eq!(r.summary, "USB 2.3.0 Control OUT, 0 bytes");
    }

    #[test]
    fn usbmon_interrupt_submit() {
        let mut h = vec![0u8; 48];
        h[8] = b'S';
        h[9] = 1; // interrupt
        h[10] = 0x81; // ep1 IN
        h[11] = 7; // device 7
        h[12..14].copy_from_slice(&3u16.to_le_bytes()); // bus 3
        h[36..40].copy_from_slice(&8u32.to_le_bytes());
        let r = dissect_usb_linux(&h);
        assert_eq!(r.summary, "USB 3.7.1 Interrupt IN (Submit), 8 bytes");
    }

    #[test]
    fn truncated_records_are_malformed() {
        assert!(matches!(
            dissect_usbpcap(&[0; 10]).protocol,
            Protocol::Unknown(_)
        ));
        assert!(matches!(
            dissect_usb_linux(&[0; 20]).protocol,
            Protocol::Unknown(_)
        ));
    }
}
