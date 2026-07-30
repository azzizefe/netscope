// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 azzizefe. All rights reserved.
//! Lightweight, zero-dependency REST API server (ROADMAP §7.1).
//! Listens on a TCP port and exposes packet list, statistics, and control endpoints.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::capture::CaptureEngine;
use crate::models::Packet;
use crate::stats::StatsEngine;
use chrono::Utc;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum UserRole {
    Admin,
    Analyst,
    Viewer,
}

impl From<&str> for UserRole {
    /// Map a stored role string to a role. Anything unrecognized falls back to
    /// the least-privileged `Viewer` — fail closed.
    fn from(s: &str) -> Self {
        match s {
            "Admin" => Self::Admin,
            "Analyst" => Self::Analyst,
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
    stats_engine: Arc<Mutex<StatsEngine>>,
    sessions: Arc<Mutex<HashMap<String, User>>>,
    db: Arc<Mutex<crate::db::Database>>,
}

impl ApiServer {
    pub fn new(
        port: u16,
        packet_buffer: ApiPacketBuffer,
        engine: CaptureEngine,
        stats_engine: StatsEngine,
    ) -> Self {
        let db = crate::db::Database::open().expect("Failed to open SQLite database");

        Self {
            port,
            packet_buffer,
            engine: Arc::new(Mutex::new(engine)),
            stats_engine: Arc::new(Mutex::new(stats_engine)),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            db: Arc::new(Mutex::new(db)),
        }
    }

    pub fn engine(&self) -> Arc<Mutex<CaptureEngine>> {
        self.engine.clone()
    }

    pub fn stats(&self) -> Arc<Mutex<StatsEngine>> {
        self.stats_engine.clone()
    }

    /// Spawn the API server on a background thread.
    pub fn start(self) -> thread::JoinHandle<()> {
        let port = self.port;
        let buffer = self.packet_buffer.clone();
        let engine = self.engine.clone();
        let stats_engine = self.stats_engine.clone();
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
                let stats_engine = stats_engine.clone();
                let sessions = sessions.clone();
                let db = db.clone();
                thread::spawn(move || {
                    let _ = handle_connection(stream, buffer, engine, stats_engine, sessions, db);
                });
            }
        })
    }
}

fn handle_connection(
    mut stream: TcpStream,
    buffer: ApiPacketBuffer,
    engine: Arc<Mutex<CaptureEngine>>,
    stats_engine: Arc<Mutex<StatsEngine>>,
    sessions: Arc<Mutex<HashMap<String, User>>>,
    db: Arc<Mutex<crate::db::Database>>,
) -> std::io::Result<()> {
    let mut request_bytes = [0u8; 4096];
    let read_len = stream.read(&mut request_bytes)?;
    let request_str = String::from_utf8_lossy(&request_bytes[..read_len]);

    let parts: Vec<&str> = request_str.split("\r\n\r\n").collect();
    let header_part = parts.first().copied().unwrap_or("");

    let mut content_length = 0;
    for line in header_part.lines() {
        if line.to_ascii_lowercase().starts_with("content-length:") {
            if let Some(val) = line.split(':').nth(1) {
                content_length = val.trim().parse::<usize>().unwrap_or(0);
            }
        }
    }

    let mut body_bytes = Vec::new();
    let header_bytes_len = header_part.len() + 4; // including \r\n\r\n
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

            let role_opt = db
                .lock()
                .unwrap()
                .authenticate(username, password)
                .unwrap_or(None);

            if let Some(role_str) = role_opt {
                let role = UserRole::from(role_str.as_str());
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
                && !path.starts_with("/api/v1/ai")
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
        // AI Traffic Records
        ("GET", "/api/v1/ai/traffic") => {
            let stats = stats_engine.lock().unwrap();
            let snapshot = stats.snapshot();
            let mut json = String::from("[");
            for (i, rec) in snapshot.ai_records.iter().enumerate() {
                if i > 0 {
                    json.push(',');
                }
                json.push_str(&format!(
                    "{{\"session_id\":{},\"provider\":\"{:?}\",\"model\":\"{}\",\"prompt_tokens\":{},\"completion_tokens\":{},\"total_tokens\":{},\"ttft_ms\":{},\"cost_usd\":{:.6},\"streaming\":{},\"finish_reason\":\"{}\"}}",
                    rec.session_id,
                    rec.provider,
                    rec.model_name,
                    rec.prompt_token_count,
                    rec.completion_tokens,
                    rec.prompt_token_count + rec.completion_tokens,
                    rec.first_token_latency_ms,
                    rec.total_cost_usd,
                    rec.total_stream_duration_ms > 0,
                    rec.finish_reason,
                ));
            }
            json.push(']');
            let _ = db
                .lock()
                .unwrap()
                .log_action(&user.username, "Read AI Traffic", "-");
            send_response(&mut stream, 200, "OK", "application/json", &json)
        }
        // AI Analytics Summary
        ("GET", "/api/v1/ai/stats") => {
            let stats = stats_engine.lock().unwrap();
            let snapshot = stats.snapshot();
            let llm = &snapshot.llm;
            let mut json = format!(
                "{{\"total_requests\":{},\"total_tokens\":{},\"total_cost\":{:.6},\"model_stats\":[",
                llm.total_requests, llm.total_tokens, llm.total_cost
            );
            let mut first = true;
            for (model, ms) in llm.per_model.iter().take(20) {
                if !first {
                    json.push(',');
                }
                first = false;
                let avg_ttft = if ms.ttft_count > 0 {
                    ms.ttft_sum_ms as f64 / ms.ttft_count as f64
                } else {
                    0.0
                };
                let avg_tpot = if ms.tpot_count > 0 {
                    ms.tpot_sum_us as f64 / ms.tpot_count as f64 / 1000.0
                } else {
                    0.0
                };
                let avg_tps = if ms.tokens_per_second_count > 0 {
                    ms.tokens_per_second_sum / ms.tokens_per_second_count as f64
                } else {
                    0.0
                };
                let error_rate = if ms.requests > 0 {
                    (ms.error_4xx + ms.error_5xx) as f64 / ms.requests as f64 * 100.0
                } else {
                    0.0
                };
                let rate_limit_rate = if ms.requests > 0 {
                    ms.rate_limited as f64 / ms.requests as f64 * 100.0
                } else {
                    0.0
                };
                let stream_kesintisi = if ms.total_streams > 0 {
                    ms.incomplete_streams as f64 / ms.total_streams as f64 * 100.0
                } else {
                    0.0
                };
                json.push_str(&format!(
                    "{{\"model\":\"{}\",\"requests\":{},\"prompt_tokens\":{},\"completion_tokens\":{},\"total_tokens\":{},\"cost\":{:.6},\"avg_ttft_ms\":{:.1},\"avg_tpot_ms\":{:.1},\"avg_tokens_per_second\":{:.1},\"errors_4xx\":{},\"errors_5xx\":{},\"rate_limited\":{},\"incomplete_streams\":{},\"total_streams\":{},\"error_rate_pct\":{:.1},\"rate_limit_rate_pct\":{:.1},\"stream_kesintisi_pct\":{:.1}}}",
                    model,
                    ms.requests,
                    ms.prompt_tokens,
                    ms.completion_tokens,
                    ms.total_tokens,
                    ms.cost,
                    avg_ttft,
                    avg_tpot,
                    avg_tps,
                    ms.error_4xx,
                    ms.error_5xx,
                    ms.rate_limited,
                    ms.incomplete_streams,
                    ms.total_streams,
                    error_rate,
                    rate_limit_rate,
                    stream_kesintisi,
                ));
            }
            json.push_str("],\"provider_stats\":[");
            let mut first = true;
            for (provider, ps) in llm.per_provider.iter().take(20) {
                if !first {
                    json.push(',');
                }
                first = false;
                json.push_str(&format!(
                    "{{\"provider\":\"{}\",\"requests\":{},\"tokens\":{},\"cost\":{:.6}}}",
                    provider, ps.requests, ps.total_tokens, ps.cost,
                ));
            }
            json.push_str("]}");
            let _ = db
                .lock()
                .unwrap()
                .log_action(&user.username, "Read AI Stats", "-");
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
            llm: None,
        };
        buffer.push(pkt);

        let engine = CaptureEngine::new();
        let stats_engine = crate::stats::StatsEngine::new();
        let server = ApiServer::new(19090, buffer, engine, stats_engine);
        let _handle = server.start();

        // Use a unique username per test to avoid cross-test credential races
        // when the harness runs tests in parallel and they share the same SQLite DB.
        crate::db::Database::open()
            .unwrap()
            .upsert_user("test_admin_routes", "test-admin-pw", "Admin")
            .unwrap();

        // Retry the initial connect — the server thread may need a moment to
        // bind the port, especially when multiple tests run in parallel and
        // the machine is under I/O pressure from ~4400 assertions.
        let mut client = None;
        for _ in 0..20 {
            thread::sleep(Duration::from_millis(50));
            if let Ok(c) = TcpStream::connect("127.0.0.1:19090") {
                client = Some(c);
                break;
            }
        }
        let mut client = client.expect("API server did not start within 1 s");

        let login_body = "{\"username\":\"test_admin_routes\",\"password\":\"test-admin-pw\"}";
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
        assert!(
            resp.contains("HTTP/1.1 200 OK"),
            "expected 200 OK, got:\n{}",
            resp
        );

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

    #[test]
    fn test_ai_traffic_endpoints() {
        let buffer = ApiPacketBuffer::new();
        let engine = CaptureEngine::new();
        let mut stats_engine = StatsEngine::new();

        let meta = crate::llm_analytics::LlmMetadata {
            provider: "openai".into(),
            model: "gpt-4".into(),
            model_family: "gpt".into(),
            prompt_tokens: Some(50),
            completion_tokens: Some(30),
            total_tokens: Some(80),
            finish_reason: Some("stop".into()),
            request_type: "chat".into(),
            streaming: false,
            error_type: None,
            tool_calls: false,
            cost_usd: Some(0.001),
            latency_ms: Some(200),
        };

        let pkt = Packet {
            timestamp: Utc::now(),
            src_addr: Some("10.0.0.1".parse().unwrap()),
            dst_addr: Some("10.0.0.2".parse().unwrap()),
            src_port: Some(50000),
            dst_port: Some(443),
            protocol: Protocol::Http,
            length: 512,
            summary: "POST /v1/chat/completions".to_string(),
            data: bytes::Bytes::from("{\"model\":\"gpt-4\"}"),
            llm: Some(meta),
        };
        stats_engine.record_packet(&pkt);

        let server = ApiServer::new(19091, buffer, engine, stats_engine);
        let _handle = server.start();

        crate::db::Database::open()
            .unwrap()
            .upsert_user("test_admin_ai", "test-ai-pw", "Admin")
            .unwrap();

        let mut client = None;
        for _ in 0..20 {
            thread::sleep(Duration::from_millis(50));
            if let Ok(c) = TcpStream::connect("127.0.0.1:19091") {
                client = Some(c);
                break;
            }
        }
        let mut client = client.expect("API server did not start within 1 s");

        let login_body = "{\"username\":\"test_admin_ai\",\"password\":\"test-ai-pw\"}";
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
        assert!(
            resp.contains("HTTP/1.1 200 OK"),
            "expected 200 OK, got:\n{}",
            resp
        );
        let token_line = resp.split("\r\n\r\n").nth(1).unwrap();
        let json_value: serde_json::Value = serde_json::from_str(token_line).unwrap();
        let token = json_value.get("token").unwrap().as_str().unwrap();

        let mut client = TcpStream::connect("127.0.0.1:19091").unwrap();
        let ai_traffic_req = format!(
            "GET /api/v1/ai/traffic HTTP/1.1\r\n\
             Authorization: Bearer {}\r\n\r\n",
            token
        );
        client.write_all(ai_traffic_req.as_bytes()).unwrap();
        let mut resp = String::new();
        client.read_to_string(&mut resp).unwrap();
        assert!(resp.contains("gpt-4"));
        assert!(resp.contains("Openai"));
        assert!(resp.contains("stop"));
        assert!(resp.contains("cost_usd"));

        let mut client = TcpStream::connect("127.0.0.1:19091").unwrap();
        let ai_stats_req = format!(
            "GET /api/v1/ai/stats HTTP/1.1\r\n\
             Authorization: Bearer {}\r\n\r\n",
            token
        );
        client.write_all(ai_stats_req.as_bytes()).unwrap();
        let mut resp = String::new();
        client.read_to_string(&mut resp).unwrap();
        assert!(resp.contains("HTTP/1.1 200 OK"));
        assert!(resp.contains("total_requests"));
    }

    #[test]
    fn test_ai_endpoint_requires_auth() {
        let buffer = ApiPacketBuffer::new();
        let engine = CaptureEngine::new();
        let stats_engine = StatsEngine::new();
        let server = ApiServer::new(19092, buffer, engine, stats_engine);
        let _handle = server.start();
        let mut client = None;
        for _ in 0..20 {
            thread::sleep(Duration::from_millis(50));
            if let Ok(c) = TcpStream::connect("127.0.0.1:19092") {
                client = Some(c);
                break;
            }
        }
        let mut client = client.expect("API server did not start within 1 s");

        let req = "GET /api/v1/ai/traffic HTTP/1.1\r\n\r\n";
        client.write_all(req.as_bytes()).unwrap();
        let mut resp = String::new();
        client.read_to_string(&mut resp).unwrap();
        assert!(resp.contains("HTTP/1.1 401"));
        assert!(resp.contains("Unauthorized"));
    }

    #[test]
    fn test_ai_stats_endpoint_requires_auth() {
        let buffer = ApiPacketBuffer::new();
        let engine = CaptureEngine::new();
        let stats_engine = StatsEngine::new();
        let server = ApiServer::new(19093, buffer, engine, stats_engine);
        let _handle = server.start();
        let mut client = None;
        for _ in 0..20 {
            thread::sleep(Duration::from_millis(50));
            if let Ok(c) = TcpStream::connect("127.0.0.1:19093") {
                client = Some(c);
                break;
            }
        }
        let mut client = client.expect("API server did not start within 1 s");

        let req = "GET /api/v1/ai/stats HTTP/1.1\r\n\r\n";
        client.write_all(req.as_bytes()).unwrap();
        let mut resp = String::new();
        client.read_to_string(&mut resp).unwrap();
        assert!(resp.contains("HTTP/1.1 401"));
        assert!(resp.contains("Unauthorized"));
    }
}
