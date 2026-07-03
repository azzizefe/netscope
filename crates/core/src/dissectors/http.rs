use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

#[derive(Debug)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub version: String,
}

#[derive(Debug)]
pub struct HttpResponse {
    pub version: String,
    pub status_code: u16,
    pub reason: String,
}

pub fn dissect_http(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let body = match std::str::from_utf8(payload) {
        Ok(s) => s,
        Err(_) => {
            return DissectedResult {
                src_addr: src_ip,
                dst_addr: dst_ip,
                src_port: Some(src_port),
                dst_port: Some(dst_port),
                protocol: Protocol::Http,
                summary: "HTTP — non-UTF8 payload".into(),
            };
        }
    };

    let body = body.trim_start_matches('\0');

    if let Some(req) = parse_request(body) {
        DissectedResult {
            src_addr: src_ip,
            dst_addr: dst_ip,
            src_port: Some(src_port),
            dst_port: Some(dst_port),
            protocol: Protocol::Http,
            summary: format!("HTTP {} {} ({})", req.method, req.path, req.version),
        }
    } else if let Some(resp) = parse_response(body) {
        DissectedResult {
            src_addr: src_ip,
            dst_addr: dst_ip,
            src_port: Some(src_port),
            dst_port: Some(dst_port),
            protocol: Protocol::Http,
            summary: format!(
                "HTTP {} {} ({} bytes)",
                resp.status_code,
                resp.reason,
                payload.len()
            ),
        }
    } else {
        DissectedResult {
            src_addr: src_ip,
            dst_addr: dst_ip,
            src_port: Some(src_port),
            dst_port: Some(dst_port),
            protocol: Protocol::Http,
            summary: format!("HTTP — {} bytes of data", payload.len()),
        }
    }
}

fn parse_request(body: &str) -> Option<HttpRequest> {
    let first_line = body.lines().next()?;
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }
    let method = parts[0];
    if ![
        "GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OPTIONS", "CONNECT", "TRACE",
    ]
    .contains(&method)
    {
        return None;
    }
    let path = parts[1].to_string();
    let version = parts[2].to_string();
    Some(HttpRequest {
        method: method.to_string(),
        path,
        version,
    })
}

fn parse_response(body: &str) -> Option<HttpResponse> {
    let first_line = body.lines().next()?;
    let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return None;
    }
    let version = parts[0];
    if !version.starts_with("HTTP/") {
        return None;
    }
    let status_code: u16 = parts[1].parse().ok()?;
    let reason = parts.get(2).unwrap_or(&"").to_string();
    Some(HttpResponse {
        version: version.to_string(),
        status_code,
        reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_request() {
        let req = b"GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = dissect_http(None, None, 12345, 80, req);
        assert_eq!(result.protocol, Protocol::Http);
        assert_eq!(result.summary, "HTTP GET /api/users (HTTP/1.1)");
    }

    #[test]
    fn http_response() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n{\"ok\":true}";
        let result = dissect_http(None, None, 80, 12345, resp);
        assert_eq!(result.protocol, Protocol::Http);
        assert_eq!(result.summary, "HTTP 200 OK (50 bytes)");
    }

    #[test]
    fn http_non_utf8() {
        let result = dissect_http(None, None, 80, 12345, &[0xff, 0xfe, 0x00]);
        assert_eq!(result.summary, "HTTP — non-UTF8 payload");
    }

    #[test]
    fn http_garbage() {
        let result = dissect_http(None, None, 80, 12345, b"not http data");
        assert_eq!(result.summary, "HTTP — 13 bytes of data");
    }

    #[test]
    fn http_post_request() {
        let req =
            b"POST /api/data HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"key\":\"value\"}";
        let result = dissect_http(None, None, 12345, 80, req);
        assert_eq!(result.protocol, Protocol::Http);
        assert_eq!(result.summary, "HTTP POST /api/data (HTTP/1.1)");
    }

    #[test]
    fn http_empty_request_line() {
        let result = dissect_http(None, None, 80, 12345, b"\r\n");
        assert_eq!(result.summary, "HTTP — 2 bytes of data");
    }

    #[test]
    fn http_unknown_method() {
        let req = b"INVALID /path HTTP/1.1\r\n\r\n";
        let result = dissect_http(None, None, 12345, 80, req);
        assert_eq!(result.summary, "HTTP — 26 bytes of data");
    }
}
