use std::net::IpAddr;

use crate::models::Protocol;

use super::{first_text_line, truncate, DissectedResult};

/// Dissect an IMAP segment (TCP 143). Client commands are tagged
/// (`a1 LOGIN …`, `a2 SELECT INBOX`); server data lines start with `*`. The
/// arguments to `LOGIN` are masked so credentials aren't echoed.
pub fn dissect_imap(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let line = first_text_line(payload);
    let summary = if line.is_empty() {
        format!("IMAP — {} bytes", payload.len())
    } else if let Some(tag) = login_tag(&line) {
        format!("IMAP {tag} LOGIN ⋯")
    } else {
        format!("IMAP {}", truncate(&line, 50))
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Imap,
        summary,
    }
}

/// If the line is a tagged `LOGIN` command, return its tag so the caller can
/// show `<tag> LOGIN ⋯` with the credentials masked.
fn login_tag(line: &str) -> Option<&str> {
    let mut parts = line.splitn(3, ' ');
    let tag = parts.next()?;
    let cmd = parts.next()?;
    cmd.eq_ignore_ascii_case("LOGIN").then_some(tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_is_masked() {
        let r = dissect_imap(None, None, 40000, 143, b"a1 LOGIN alice secret\r\n");
        assert_eq!(r.protocol, Protocol::Imap);
        assert_eq!(r.summary, "IMAP a1 LOGIN ⋯");
    }

    #[test]
    fn select_command_shown() {
        let r = dissect_imap(None, None, 40000, 143, b"a2 SELECT INBOX\r\n");
        assert_eq!(r.summary, "IMAP a2 SELECT INBOX");
    }

    #[test]
    fn server_untagged_reply() {
        let r = dissect_imap(None, None, 143, 40000, b"* OK IMAP4rev1 ready\r\n");
        assert_eq!(r.summary, "IMAP * OK IMAP4rev1 ready");
    }
}
