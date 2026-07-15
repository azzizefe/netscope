// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

/// Heuristically dissect NT LAN Manager Security Support Provider (NTLMSSP) traffic.
pub fn try_dissect(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<DissectedResult> {
    // Search for NTLMSSP magic block anywhere in the payload
    let offset = payload.windows(8).position(|w| w == b"NTLMSSP\0")?;
    let ntlm_payload = &payload[offset..];

    if ntlm_payload.len() < 12 {
        return None;
    }

    let msg_type = u32::from_le_bytes([
        ntlm_payload[8],
        ntlm_payload[9],
        ntlm_payload[10],
        ntlm_payload[11],
    ]);
    let summary = match msg_type {
        1 => {
            // Negotiate
            let mut domain = String::new();
            let mut work = String::new();
            if ntlm_payload.len() >= 16 {
                let flags = u32::from_le_bytes([
                    ntlm_payload[12],
                    ntlm_payload[13],
                    ntlm_payload[14],
                    ntlm_payload[15],
                ]);
                // Read domain if present
                if flags & 0x00001000 != 0 && ntlm_payload.len() >= 24 {
                    let dom_len = u16::from_le_bytes([ntlm_payload[16], ntlm_payload[17]]) as usize;
                    let dom_offset = u32::from_le_bytes([
                        ntlm_payload[20],
                        ntlm_payload[21],
                        ntlm_payload[22],
                        ntlm_payload[23],
                    ]) as usize;
                    if dom_offset + dom_len <= ntlm_payload.len() {
                        domain = String::from_utf8_lossy(
                            &ntlm_payload[dom_offset..dom_offset + dom_len],
                        )
                        .into_owned();
                    }
                }
                // Read workstation if present
                if flags & 0x00002000 != 0 && ntlm_payload.len() >= 32 {
                    let work_len =
                        u16::from_le_bytes([ntlm_payload[24], ntlm_payload[25]]) as usize;
                    let work_offset = u32::from_le_bytes([
                        ntlm_payload[28],
                        ntlm_payload[29],
                        ntlm_payload[30],
                        ntlm_payload[31],
                    ]) as usize;
                    if work_offset + work_len <= ntlm_payload.len() {
                        work = String::from_utf8_lossy(
                            &ntlm_payload[work_offset..work_offset + work_len],
                        )
                        .into_owned();
                    }
                }
            }
            let details = if !domain.is_empty() && !work.is_empty() {
                format!("Domain: {domain}, Workstation: {work}")
            } else if !domain.is_empty() {
                format!("Domain: {domain}")
            } else if !work.is_empty() {
                format!("Workstation: {work}")
            } else {
                "Negotiate".to_string()
            };
            format!("NTLM Negotiate — {details}")
        }
        2 => {
            // Challenge
            let mut target = String::new();
            if ntlm_payload.len() >= 20 {
                let target_len = u16::from_le_bytes([ntlm_payload[12], ntlm_payload[13]]) as usize;
                let target_offset = u32::from_le_bytes([
                    ntlm_payload[16],
                    ntlm_payload[17],
                    ntlm_payload[18],
                    ntlm_payload[19],
                ]) as usize;
                if target_offset + target_len <= ntlm_payload.len() {
                    target = String::from_utf8_lossy(
                        &ntlm_payload[target_offset..target_offset + target_len],
                    )
                    .into_owned();
                }
            }
            let details = if !target.is_empty() {
                format!("Target: {target}")
            } else {
                "Challenge".to_string()
            };
            format!("NTLM Challenge — {details}")
        }
        3 => {
            // Authenticate
            let mut domain = String::new();
            let mut user = String::new();
            let mut work = String::new();
            if ntlm_payload.len() >= 64 {
                // Read Domain
                let dom_len = u16::from_le_bytes([ntlm_payload[28], ntlm_payload[29]]) as usize;
                let dom_offset = u32::from_le_bytes([
                    ntlm_payload[32],
                    ntlm_payload[33],
                    ntlm_payload[34],
                    ntlm_payload[35],
                ]) as usize;
                if dom_offset + dom_len <= ntlm_payload.len() {
                    domain = String::from_utf16_lossy(&to_u16_slice(
                        &ntlm_payload[dom_offset..dom_offset + dom_len],
                    ));
                }

                // Read User
                let user_len = u16::from_le_bytes([ntlm_payload[36], ntlm_payload[37]]) as usize;
                let user_offset = u32::from_le_bytes([
                    ntlm_payload[40],
                    ntlm_payload[41],
                    ntlm_payload[42],
                    ntlm_payload[43],
                ]) as usize;
                if user_offset + user_len <= ntlm_payload.len() {
                    user = String::from_utf16_lossy(&to_u16_slice(
                        &ntlm_payload[user_offset..user_offset + user_len],
                    ));
                }

                // Read Workstation
                let work_len = u16::from_le_bytes([ntlm_payload[44], ntlm_payload[45]]) as usize;
                let work_offset = u32::from_le_bytes([
                    ntlm_payload[48],
                    ntlm_payload[49],
                    ntlm_payload[50],
                    ntlm_payload[51],
                ]) as usize;
                if work_offset + work_len <= ntlm_payload.len() {
                    work = String::from_utf16_lossy(&to_u16_slice(
                        &ntlm_payload[work_offset..work_offset + work_len],
                    ));
                }
            }
            // Fallback to utf8 if utf16 yielded empty/non-printable
            if user.is_empty() && ntlm_payload.len() >= 64 {
                let user_len = u16::from_le_bytes([ntlm_payload[36], ntlm_payload[37]]) as usize;
                let user_offset = u32::from_le_bytes([
                    ntlm_payload[40],
                    ntlm_payload[41],
                    ntlm_payload[42],
                    ntlm_payload[43],
                ]) as usize;
                if user_offset + user_len <= ntlm_payload.len() {
                    user =
                        String::from_utf8_lossy(&ntlm_payload[user_offset..user_offset + user_len])
                            .into_owned();
                }
            }
            let details = if !user.is_empty() {
                format!("User: {user}, Domain: {domain}, Workstation: {work}")
            } else {
                "Authenticate".to_string()
            };
            format!("NTLM Authenticate — {details}")
        }
        _ => return None,
    };

    Some(DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Ntlm,
        summary,
    })
}

fn to_u16_slice(bytes: &[u8]) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntlm_negotiate() {
        let mut payload = b"NTLMSSP\0".to_vec();
        payload.extend([1, 0, 0, 0]); // type 1
        payload.extend([0x01, 0x10, 0x00, 0x00]); // flags: domain present
        payload.extend([4, 0]); // domain len
        payload.extend([4, 0]); // domain max len
        payload.extend([24, 0, 0, 0]); // domain offset
        payload.extend(b"WORK");

        let r = try_dissect(None, None, 139, 50000, &payload).unwrap();
        assert_eq!(r.protocol, Protocol::Ntlm);
        assert_eq!(r.summary, "NTLM Negotiate — Domain: WORK");
    }
}
