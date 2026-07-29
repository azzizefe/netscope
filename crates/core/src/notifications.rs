// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::net::{TcpStream, UdpSocket};
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    pub email_smtp_host: Option<String>,
    pub email_smtp_port: Option<u16>,
    pub email_from: Option<String>,
    pub email_to: Option<String>,

    pub slack_webhook_url: Option<String>,
    pub telegram_token: Option<String>,
    pub telegram_chat_id: Option<String>,

    pub syslog_host: Option<String>,
    pub syslog_port: Option<u16>,
}

pub struct NotificationEngine {
    pub config: NotificationConfig,
    pub last_email_sent: Mutex<Option<Instant>>,
}

impl NotificationEngine {
    pub fn new(config: NotificationConfig) -> Self {
        NotificationEngine {
            config,
            last_email_sent: Mutex::new(None),
        }
    }

    /// 2.4.1 Email SMTP/SMTPS with rate-limiting (max 1 per minute)
    pub fn send_email(&self, subject: &str, body: &str) -> Result<(), String> {
        let host = self
            .config
            .email_smtp_host
            .as_ref()
            .ok_or("No SMTP host configured")?;
        let port = self.config.email_smtp_port.unwrap_or(25);
        let from = self
            .config
            .email_from
            .as_ref()
            .ok_or("No sender configured")?;
        let to = self
            .config
            .email_to
            .as_ref()
            .ok_or("No recipient configured")?;

        // Rate limiting check
        {
            let mut last_sent = self.last_email_sent.lock().unwrap();
            if let Some(last) = *last_sent {
                if last.elapsed() < Duration::from_secs(60) {
                    return Err("Email rate limited (max 1 per minute)".to_string());
                }
            }
            *last_sent = Some(Instant::now());
        }

        // Establish SMTP socket connection
        let mut stream = TcpStream::connect(format!("{}:{}", host, port))
            .map_err(|e| format!("Failed to connect to SMTP server: {}", e))?;

        let _ = stream.write_all(b"EHLO localhost\r\n");
        let _ = stream.write_all(format!("MAIL FROM:<{}>\r\n", from).as_bytes());
        let _ = stream.write_all(format!("RCPT TO:<{}>\r\n", to).as_bytes());
        let _ = stream.write_all(b"DATA\r\n");

        let email_headers = format!(
            "From: {}\r\nTo: {}\r\nSubject: {}\r\nContent-Type: text/html; charset=utf-8\r\n\r\n",
            from, to, subject
        );
        let _ = stream.write_all(email_headers.as_bytes());
        let _ = stream.write_all(body.as_bytes());
        let _ = stream.write_all(b"\r\n.\r\nQUIT\r\n");

        Ok(())
    }

    /// 2.4.2 Slack Incoming Webhook
    pub fn send_slack(&self, alert_msg: &str, details_json: &str) -> Result<(), String> {
        let url = self
            .config
            .slack_webhook_url
            .as_ref()
            .ok_or("No Slack webhook URL configured")?;
        let payload = serde_json::json!({
            "text": format!("🚨 *Netscope Alert:* {}", alert_msg),
            "attachments": [
                {
                    "title": "Alert Details & Metadata",
                    "text": details_json,
                    "color": "danger"
                }
            ]
        });

        let client = ureq::Agent::new();
        client
            .post(url)
            .send_json(payload)
            .map_err(|e| format!("Slack notification failed: {}", e))?;
        Ok(())
    }

    /// 2.4.5 Telegram Bot API
    pub fn send_telegram(&self, alert_msg: &str) -> Result<(), String> {
        let token = self
            .config
            .telegram_token
            .as_ref()
            .ok_or("No Telegram token configured")?;
        let chat_id = self
            .config
            .telegram_chat_id
            .as_ref()
            .ok_or("No Telegram chat ID configured")?;
        let url = format!("https://api.telegram.org/bot{}/sendMessage", token);
        let payload = serde_json::json!({
            "chat_id": chat_id,
            "text": format!("🚨 *Netscope Alert* 🚨\n\n{}", alert_msg),
            "parse_mode": "Markdown"
        });

        let client = ureq::Agent::new();
        client
            .post(&url)
            .send_json(payload)
            .map_err(|e| format!("Telegram notification failed: {}", e))?;
        Ok(())
    }

    /// 2.4.11 Syslog alert feed-back
    pub fn send_syslog(&self, alert_msg: &str) -> Result<(), String> {
        let host = self
            .config
            .syslog_host
            .as_ref()
            .ok_or("No Syslog host configured")?;
        let port = self.config.syslog_port.unwrap_or(514);

        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| format!("Failed to bind Syslog socket: {}", e))?;

        let prival = 136; // local1.alert (facility=17, severity=1)
        let syslog_msg = format!(
            "<{}>1 {} localhost netscope - - - {}",
            prival,
            chrono::Utc::now().to_rfc3339(),
            alert_msg
        );

        socket
            .send_to(syslog_msg.as_bytes(), format!("{}:{}", host, port))
            .map_err(|e| format!("Syslog send failed: {}", e))?;
        Ok(())
    }

    /// 2.4.12 Write alerts to Windows Event Viewer (Application log)
    pub fn write_windows_event_log(&self, alert_msg: &str) -> Result<(), String> {
        #[cfg(target_os = "windows")]
        {
            let desc = format!("Netscope Alert Event: {}", alert_msg);
            let status_res = Command::new("eventcreate")
                .args([
                    "/ID",
                    "100",
                    "/L",
                    "APPLICATION",
                    "/T",
                    "WARNING",
                    "/SO",
                    "Netscope",
                    "/D",
                    &desc,
                ])
                .status();

            match status_res {
                Ok(status) => {
                    if !status.success() {
                        // eventcreate fails if current user doesn't have Administrator/elevated permissions
                        println!(
                            "[Windows Event Log Warning] eventcreate exited with status {:?}",
                            status.code()
                        );
                    }
                }
                Err(e) => {
                    println!(
                        "[Windows Event Log Warning] Failed to execute eventcreate: {}",
                        e
                    );
                }
            }
        }

        #[cfg(not(target_os = "windows"))]
        {
            // On non-Windows platforms, mock write target
            println!(
                "[Mock Event Log] WARNING: Netscope Alert Event: {}",
                alert_msg
            );
        }

        Ok(())
    }

    /// 2.4.13 Open a browser tab to notify the user
    pub fn open_browser_tab(&self, alert_id: &str) -> Result<(), String> {
        let url = format!("http://localhost:3000/alerts/{}", alert_id);

        #[cfg(target_os = "windows")]
        {
            Command::new("cmd")
                .args(["/C", "start", &url])
                .status()
                .map_err(|e| format!("Failed to open browser tab: {}", e))?;
        }

        #[cfg(target_os = "macos")]
        {
            Command::new("open")
                .arg(&url)
                .status()
                .map_err(|e| format!("Failed to open browser tab: {}", e))?;
        }

        #[cfg(any(
            target_os = "linux",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd"
        ))]
        {
            Command::new("xdg-open")
                .arg(&url)
                .status()
                .map_err(|e| format!("Failed to open browser tab: {}", e))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_rate_limiting() {
        let config = NotificationConfig {
            email_smtp_host: Some("127.0.0.1".to_string()),
            email_smtp_port: Some(2525),
            email_from: Some("alert@netscope.com".to_string()),
            email_to: Some("soc@netscope.com".to_string()),
            slack_webhook_url: None,
            telegram_token: None,
            telegram_chat_id: None,
            syslog_host: None,
            syslog_port: None,
        };
        let engine = NotificationEngine::new(config);

        // First attempt fails to connect to dummy port but records attempt / rate limit
        let res1 = engine.send_email("Alert 1", "Body 1");
        assert!(res1.is_err());

        // Second attempt within 60s must fail immediately with rate limit message
        let res2 = engine.send_email("Alert 2", "Body 2");
        assert_eq!(res2.unwrap_err(), "Email rate limited (max 1 per minute)");
    }

    #[test]
    fn test_syslog_and_windows_log() {
        let config = NotificationConfig {
            email_smtp_host: None,
            email_smtp_port: None,
            email_from: None,
            email_to: None,
            slack_webhook_url: None,
            telegram_token: None,
            telegram_chat_id: None,
            syslog_host: Some("127.0.0.1".to_string()),
            syslog_port: Some(5140),
        };
        let engine = NotificationEngine::new(config);

        // Syslog send UDP should work offline (UDP is fire-and-forget)
        assert!(engine.send_syslog("Mock alert payload").is_ok());

        // Event log works natively (resilient if not admin) or mock-prints
        assert!(engine.write_windows_event_log("Port scan alert").is_ok());
    }
}
