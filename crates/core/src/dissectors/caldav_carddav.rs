// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect CalDAV / CardDAV Calendar and Contact Sync (TCP 80 / 443).
pub fn dissect_caldav_carddav(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"REPORT /") || payload.contains(&b"calendar-query") || payload.contains(&b"addressbook-query") {
        "CalDAV/CardDAV sync request".to_string()
    } else {
        format!("CalDAV/CardDAV ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::CaldavCarddav,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caldav_test() {
        let r = dissect_caldav_carddav(None, None, 40000, 80, b"REPORT /calendars/user/ HTTP/1.1\r\n");
        assert_eq!(r.protocol, Protocol::CaldavCarddav);
        assert_eq!(r.summary, "CalDAV/CardDAV sync request");
    }
}
