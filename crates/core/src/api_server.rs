// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Lightweight, zero-dependency REST API server (ROADMAP §7.1).
//! Listens on a TCP port and exposes packet list, statistics, and control endpoints.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::capture::CaptureEngine;
use crate::models::Packet;
use chrono::Utc;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum UserRole {
    Admin,
    Analyst,
    Viewer,
}

impl UserRole {
    pub fn from_str(s: &str) -> Self {
        match s {
            "Admin" => Self::Admin,
            "Analyst" => Self::Analyst,
            "Viewer" => Self::Viewer,
            _ => Self::Viewer,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct User {
    pub username: String,
    pub role: UserRole,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct BookmarkRequest {
    capture_file: String,
    packet_index: i64,
    tag: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct AnnotationRequest {
    capture_file: String,
    packet_index: i64,
    comment: String,
}

fn hash_password(password: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn generate_token() -> String {
    let mut bytes = [0u8; 16];
    let _ = getrandom::getrandom(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// A thread-safe buffer storing the most recent packets for the API to serve.
#[derive(Clone, Default)]
pub struct ApiPacketBuffer {
    packets: Arc<Mutex<Vec<Packet>>>,
}

impl ApiPacketBuffer {
    pub fn new() -> Self {
        Self {
            packets: Arc::new(Mutex::new(Vec::with_capacity(1000))),
        }
    }

    pub fn push(&self, pkt: Packet) {
        let mut lock = self.packets.lock().unwrap();
        if lock.len() >= 1000 {
            lock.remove(0);
        }
        lock.push(pkt);
    }

    pub fn clear(&self) {
        self.packets.lock().unwrap().clear();
    }

    pub fn get_all(&self) -> Vec<Packet> {
        self.packets.lock().unwrap().clone()
    }
}

pub struct ApiServer {
    port: u16,
    packet_buffer: ApiPacketBuffer,
    engine: Arc<Mutex<CaptureEngine>>,
    sessions: Arc<Mutex<HashMap<String, User>>>,
    db: Arc<Mutex<crate::db::Database>>,
}

impl ApiServer {
    pub fn new(port: u16, packet_buffer: ApiPacketBuffer, engine: CaptureEngine) -> Self {
        let db = crate::db::Database::open().expect("Failed to open SQLite database");

        Self {
            port,
            packet_buffer,
            engine: Arc::new(Mutex::new(engine)),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            db: Arc::new(Mutex::new(db)),
        }
    }

    pub fn engine(&self) -> Arc<Mutex<CaptureEngine>> {
        self.engine.clone()
    }

    /// Spawn the API server on a background thread.
    pub fn start(self) -> thread::JoinHandle<()> {
        let port = self.port;
        let buffer = self.packet_buffer.clone();
        let engine = self.engine.clone();
        let sessions = self.sessions.clone();
        let db = self.db.clone();

        thread::spawn(move || {
            let listener = match TcpListener::bind(format!("127.0.0.1:{}", port)) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("API Server: Failed to bind to port {}: {}", port, e);
                    return;
                }
            };
            println!("API Server: Listening on http://127.0.0.1:{}", port);

            for stream in listener.incoming() {
                let stream = match stream {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let buffer = buffer.clone();
                let engine = engine.clone();
                let sessions = sessions.clone();
                let db = db.clone();
                thread::spawn(move || {
                    let _ = handle_connection(stream, buffer, engine, sessions, db);
                });
            }
        })
    }
}

fn handle_connection(
    mut stream: TcpStream,
    buffer: ApiPacketBuffer,
    engine: Arc<Mutex<CaptureEngine>>,
    sessions: Arc<Mutex<HashMap<String, User>>>,
    db: Arc<Mutex<crate::db::Database>>,
) -> std::io::Result<()> {
    let mut request_bytes = [0u8; 4096];
    let read_len = stream.read(&mut request_bytes)?;
    let request_str = String::from_utf8_lossy(&request_bytes[..read_len]);

    let parts: Vec<&str> = request_str.split("\r\n\r\n").collect();
    let header_part = parts.get(0).copied().unwrap_or("");

    let mut content_length = 0;
    for line in header_part.lines() {
        if line.to_ascii_lowercase().starts_with("content-length:") {
            if let Some(val) = line.split(':').nth(1) {
                content_length = val.trim().parse::<usize>().unwrap_or(0);
            }
        }
    }

    let mut body_bytes = Vec::new();
    let header_bytes_len = header_part.as_bytes().len() + 4; // including \r\n\r\n
    if read_len > header_bytes_len {
        body_bytes.extend_from_slice(&request_bytes[header_bytes_len..read_len]);
    }

    while body_bytes.len() < content_length {
        let mut buf = vec![0u8; 4096.min(content_length - body_bytes.len())];
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        body_bytes.extend_from_slice(&buf[..n]);
    }

    let body_part_str = String::from_utf8_lossy(&body_bytes);
    let body_part = &body_part_str;

    let first_line = header_part.lines().next().unwrap_or("");
    let request_line_parts: Vec<&str> = first_line.split_whitespace().collect();
    if request_line_parts.len() < 2 {
        return send_response(&mut stream, 400, "Bad Request", "text/plain", "Bad Request");
    }

    let method = request_line_parts[0];
    let path = request_line_parts[1];

    // 1. Check Login (POST /api/v1/auth/login)
    if method == "POST" && path == "/api/v1/auth/login" {
        let json_body: Result<serde_json::Value, _> = serde_json::from_str(body_part);
        if let Ok(json) = json_body {
            let username = json.get("username").and_then(|v| v.as_str()).unwrap_or("");
            let password = json.get("password").and_then(|v| v.as_str()).unwrap_or("");

            let password_hash = hash_password(password);
            let role_opt = db
                .lock()
                .unwrap()
                .get_user_role(username, &password_hash)
                .unwrap_or(None);

            if let Some(role_str) = role_opt {
                let role = UserRole::from_str(&role_str);
                let token = generate_token();
                let user = User {
                    username: username.to_string(),
                    role: role.clone(),
                };
                sessions.lock().unwrap().insert(token.clone(), user);

                let _ = db.lock().unwrap().log_action(username, "Login", "-");

                let json_resp = format!(
                    "{{\n  \"token\": \"{}\",\n  \"role\": \"{:?}\"\n}}",
                    token, role
                );
                return send_response(&mut stream, 200, "OK", "application/json", &json_resp);
            }
        }
        return send_response(
            &mut stream,
            401,
            "Unauthorized",
            "application/json",
            "{\"error\":\"Invalid credentials\"}",
        );
    }

    // 2. Auth Interceptor for all other routes
    let mut auth_token = None;
    for line in header_part.lines() {
        if line.to_ascii_lowercase().starts_with("authorization:") {
            let val = line["authorization:".len()..].trim();
            if val.to_ascii_lowercase().starts_with("bearer ") {
                auth_token = Some(val["bearer ".len()..].trim().to_string());
            }
        }
    }

    let user = if let Some(ref tok) = auth_token {
        sessions.lock().unwrap().get(tok).cloned()
    } else {
        None
    };

    let Some(user) = user else {
        return send_response(
            &mut stream,
            401,
            "Unauthorized",
            "application/json",
            "{\"error\":\"Unauthorized. Bearer token required.\"}",
        );
    };

    // 3. RBAC checks
    match user.role {
        UserRole::Viewer => {
            if path != "/api/v1/stats"
                && path != "/api/v1/packets"
                && !path.starts_with("/api/v1/bookmarks")
                && !path.starts_with("/api/v1/annotations")
            {
                return send_response(
                    &mut stream,
                    403,
                    "Forbidden",
                    "application/json",
                    "{\"error\":\"Forbidden. Viewer role has insufficient permissions.\"}",
                );
            }
            if method != "GET" {
                return send_response(
                    &mut stream,
                    403,
                    "Forbidden",
                    "application/json",
                    "{\"error\":\"Forbidden. Viewers cannot modify resources.\"}",
                );
            }
        }
        UserRole::Analyst => {
            if path == "/api/v1/audit" {
                return send_response(
                    &mut stream,
                    403,
                    "Forbidden",
                    "application/json",
                    "{\"error\":\"Forbidden. Analyst role has insufficient permissions.\"}",
                );
            }
        }
        UserRole::Admin => {}
    }

    // 4. Handle Authenticated Routes
    let base_path = path.split('?').next().unwrap_or(path);
    let query_str = path.split('?').nth(1).unwrap_or("");
    let query_params: HashMap<&str, &str> = query_str
        .split('&')
        .filter_map(|kv| {
            let mut p = kv.splitn(2, '=');
            let k = p.next()?;
            let v = p.next().unwrap_or("");
            Some((k, v))
        })
        .collect();

    match (method, base_path) {
        ("GET", "/api/v1/stats") => {
            let stats_lock = engine.lock().unwrap();
            let stats = stats_lock.pipeline_stats().unwrap_or_default();
            let json = format!(
                "{{\"received\":{},\"dropped\":{},\"dissected\":{}}}",
                stats.received, stats.dropped, stats.dissected
            );
            let _ = db
                .lock()
                .unwrap()
                .log_action(&user.username, "Read Stats", "-");
            send_response(&mut stream, 200, "OK", "application/json", &json)
        }
        ("GET", "/api/v1/packets") => {
            let packets = buffer.get_all();
            let mut json = String::from("[");
            for (i, p) in packets.iter().enumerate() {
                if i > 0 {
                    json.push(',');
                }
                json.push_str(&format!(
                    "{{\"number\":{},\"time\":\"{:?}\",\"src\":\"{}\",\"dst\":\"{}\",\"protocol\":\"{}\",\"length\":{},\"summary\":\"{}\"}}",
                    i + 1,
                    p.timestamp,
                    p.src_addr.map(|a| a.to_string()).unwrap_or_default(),
                    p.dst_addr.map(|a| a.to_string()).unwrap_or_default(),
                    p.protocol,
                    p.length,
                    p.summary.replace('"', "\\\"")
                ));
            }
            json.push(']');
            let _ = db
                .lock()
                .unwrap()
                .log_action(&user.username, "Read Packets", "-");
            send_response(&mut stream, 200, "OK", "application/json", &json)
        }
        ("POST", "/api/v1/capture/stop") => {
            let mut engine_lock = engine.lock().unwrap();
            engine_lock.stop();
            let _ = db
                .lock()
                .unwrap()
                .log_action(&user.username, "Stop Capture", "-");
            send_response(
                &mut stream,
                200,
                "OK",
                "application/json",
                "{\"status\":\"stopped\"}",
            )
        }
        // Bookmarking
        ("GET", "/api/v1/bookmarks") => {
            let file = query_params.get("file").copied().unwrap_or("default.pcap");
            let list = db.lock().unwrap().list_bookmarks(file).unwrap_or_default();
            let mut json = String::from("[");
            for (i, (idx, tag)) in list.iter().enumerate() {
                if i > 0 {
                    json.push(',');
                }
                json.push_str(&format!("{{\"packet_index\":{},\"tag\":\"{}\"}}", idx, tag));
            }
            json.push(']');
            send_response(&mut stream, 200, "OK", "application/json", &json)
        }
        ("POST", "/api/v1/bookmarks") => {
            if let Ok(req) = serde_json::from_str::<BookmarkRequest>(body_part) {
                let _ =
                    db.lock()
                        .unwrap()
                        .add_bookmark(&req.capture_file, req.packet_index, &req.tag);
                let _ = db.lock().unwrap().log_action(
                    &user.username,
                    "Add Bookmark",
                    &req.capture_file,
                );
                send_response(
                    &mut stream,
                    200,
                    "OK",
                    "application/json",
                    "{\"status\":\"bookmarked\"}",
                )
            } else {
                send_response(
                    &mut stream,
                    400,
                    "Bad Request",
                    "application/json",
                    "{\"error\":\"Invalid bookmark body\"}",
                )
            }
        }
        // Annotations
        ("GET", "/api/v1/annotations") => {
            let file = query_params.get("file").copied().unwrap_or("default.pcap");
            let list = db
                .lock()
                .unwrap()
                .list_annotations(file)
                .unwrap_or_default();
            let mut json = String::from("[");
            for (i, (idx, comment, author, time)) in list.iter().enumerate() {
                if i > 0 {
                    json.push(',');
                }
                json.push_str(&format!(
                    "{{\"packet_index\":{},\"comment\":\"{}\",\"username\":\"{}\",\"timestamp\":\"{}\"}}",
                    idx, comment.replace('"', "\\\""), author, time
                ));
            }
            json.push(']');
            send_response(&mut stream, 200, "OK", "application/json", &json)
        }
        ("POST", "/api/v1/annotations") => {
            if let Ok(req) = serde_json::from_str::<AnnotationRequest>(body_part) {
                let _ = db.lock().unwrap().add_annotation(
                    &req.capture_file,
                    req.packet_index,
                    &req.comment,
                    &user.username,
                );
                let _ = db.lock().unwrap().log_action(
                    &user.username,
                    "Add Annotation",
                    &req.capture_file,
                );
                send_response(
                    &mut stream,
                    200,
                    "OK",
                    "application/json",
                    "{\"status\":\"annotated\"}",
                )
            } else {
                send_response(
                    &mut stream,
                    400,
                    "Bad Request",
                    "application/json",
                    "{\"error\":\"Invalid annotation body\"}",
                )
            }
        }
        // Audit Logs (Admin Only)
        ("GET", "/api/v1/audit") => {
            let list = db.lock().unwrap().list_audit_logs().unwrap_or_default();
            let mut json = String::from("[");
            for (i, (usr, act, file, time)) in list.iter().enumerate() {
                if i > 0 {
                    json.push(',');
                }
                json.push_str(&format!(
                    "{{\"username\":\"{}\",\"action\":\"{}\",\"capture_file\":\"{}\",\"timestamp\":\"{}\"}}",
                    usr, act, file, time
                ));
            }
            json.push(']');
            send_response(&mut stream, 200, "OK", "application/json", &json)
        }
        // Executive Forensic Report (HTML/JSON format)
        ("GET", "/api/v1/report") => {
            let packets = buffer.get_all();
            let _ = db
                .lock()
                .unwrap()
                .log_action(&user.username, "Export Report", "-");

            let mut html =
                String::from("<!DOCTYPE html><html><head><title>netscope Forensic Report</title>");
            html.push_str("<style>body{font-family:sans-serif;background:#0f172a;color:#f8fafc;padding:24px;}h1,h2{color:#38bdf8;}table{width:100%;border-collapse:collapse;margin-top:16px;}th,td{border:1px solid #334155;padding:12px;text-align:left;}th{background:#1e293b;}</style>");
            html.push_str("</head><body><h1>netscope Incident Forensic Report</h1>");
            html.push_str(&format!(
                "<p>Generated by <strong>{}</strong> at {}</p>",
                user.username,
                Utc::now().to_rfc3339()
            ));
            html.push_str("<h2>Executive Summary</h2><p>This report documents parsed packet records captured via netscope.</p>");
            html.push_str(&format!(
                "<p>Total packets analyzed: <strong>{}</strong></p>",
                packets.len()
            ));

            html.push_str("<h2>Captured Packet Timeline</h2><table><tr><th>#</th><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Length</th><th>Summary</th></tr>");
            for (i, p) in packets.iter().enumerate() {
                html.push_str(&format!(
                    "<tr><td>{}</td><td>{:?}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    i + 1, p.timestamp,
                    p.src_addr.map(|a| a.to_string()).unwrap_or_default(),
                    p.dst_addr.map(|a| a.to_string()).unwrap_or_default(),
                    p.protocol, p.length, p.summary
                ));
            }
            html.push_str("</table></body></html>");

            send_response(&mut stream, 200, "OK", "text/html", &html)
        }
        _ => send_response(&mut stream, 404, "Not Found", "text/plain", "Not Found"),
    }
}

fn send_response(
    stream: &mut TcpStream,
    code: u16,
    status: &str,
    content_type: &str,
    body: &str,
) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: {}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n\
         {}",
        code,
        status,
        content_type,
        body.len(),
        body
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Protocol;
    use chrono::Utc;
    use std::net::TcpStream;
    use std::time::Duration;

    #[test]
    fn test_api_server_routes() {
        let buffer = ApiPacketBuffer::new();
        let pkt = Packet {
            timestamp: Utc::now(),
            src_addr: None,
            dst_addr: None,
            src_port: None,
            dst_port: None,
            protocol: Protocol::Http,
            length: 128,
            summary: "GET / HTTP/1.1".to_string(),
            data: bytes::Bytes::new(),
        };
        buffer.push(pkt);

        let engine = CaptureEngine::new();
        let server = ApiServer::new(19090, buffer, engine);
        let _handle = server.start();

        thread::sleep(Duration::from_millis(100));

        let mut client = TcpStream::connect("127.0.0.1:19090").unwrap();
        let login_body = "{\"username\":\"admin\",\"password\":\"admin123\"}";
        let login_req = format!(
            "POST /api/v1/auth/login HTTP/1.1\r\n\
             Content-Length: {}\r\n\
             Content-Type: application/json\r\n\r\n\
             {}",
            login_body.len(),
            login_body
        );
        client.write_all(login_req.as_bytes()).unwrap();
        let mut resp = String::new();
        client.read_to_string(&mut resp).unwrap();
        assert!(resp.contains("HTTP/1.1 200 OK"));

        let token_line = resp.split("\r\n\r\n").nth(1).unwrap();
        let json_value: serde_json::Value = serde_json::from_str(token_line).unwrap();
        let token = json_value.get("token").unwrap().as_str().unwrap();

        let mut client = TcpStream::connect("127.0.0.1:19090").unwrap();
        let packets_req = format!(
            "GET /api/v1/packets HTTP/1.1\r\n\
             Authorization: Bearer {}\r\n\r\n",
            token
        );
        client.write_all(packets_req.as_bytes()).unwrap();
        let mut resp = String::new();
        client.read_to_string(&mut resp).unwrap();
        assert!(resp.contains("HTTP/1.1 200 OK"));
        assert!(resp.contains("GET / HTTP/1.1"));

        let mut client = TcpStream::connect("127.0.0.1:19090").unwrap();
        let stats_req = format!(
            "GET /api/v1/stats HTTP/1.1\r\n\
             Authorization: Bearer {}\r\n\r\n",
            token
        );
        client.write_all(stats_req.as_bytes()).unwrap();
        let mut resp = String::new();
        client.read_to_string(&mut resp).unwrap();
        assert!(resp.contains("HTTP/1.1 200 OK"));
        assert!(resp.contains("received"));
    }
}
