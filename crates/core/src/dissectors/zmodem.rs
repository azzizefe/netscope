// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Check if payload looks like a ZMODEM header (`* * ^X B` or `ZPAD ZDLE`).
pub(crate) fn looks_like_zmodem(payload: &[u8]) -> bool {
    payload.starts_with(b"**\x18B") || payload.starts_with(b"* * \x18B") || payload.starts_with(b"**\x18C")
}

/// Dissect a ZMODEM File Transfer Protocol frame.
pub fn dissect_zmodem(payload: &[u8]) -> DissectedResult {
    let summary = if looks_like_zmodem(payload) && payload.len() >= 5 {
        let frame_type = payload.get(4).copied().unwrap_or(0);
        let type_name = match frame_type {
            0x00 => "ZRINIT (Init Request)",
            0x01 => "ZCRCW (Init Ack)",
            0x02 => "ZRPOS (Position)",
            0x03 => "ZACK (Ack)",
            0x04 => "ZFILE (File Info)",
            0x05 => "ZSKIP (Skip File)",
            0x06 => "ZNAK (Nak)",
            0x07 => "ZABORT (Abort)",
            0x08 => "ZFIN (Finish)",
            0x09 => "ZRPOS (File Pos)",
            0x0A => "ZDATA (Data Header)",
            0x0B => "ZEOF (End of File)",
            0x0C => "ZFERR (File Error)",
            0x0D => "ZCRC (CRC Request)",
            0x0E => "ZCHALLENGE",
            0x0F => "ZCOMPL (Completed)",
            0x10 => "CAN (Cancel)",
            _ => "Frame",
        };
        format!("ZMODEM {type_name}")
    } else {
        format!("ZMODEM ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Zmodem,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zmodem_rinit() {
        let payload = b"**\x18B\x00\x00\x00\x00\x00";
        assert!(looks_like_zmodem(payload));
        let r = dissect_zmodem(payload);
        assert_eq!(r.protocol, Protocol::Zmodem);
        assert_eq!(r.summary, "ZMODEM ZRINIT (Init Request)");
    }
}
