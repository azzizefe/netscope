// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use serde::{Deserialize, Serialize};
use std::net::UdpSocket;
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    pub email_smtp_host: Option<String>,
    pub email_smtp_port: Option<u16>,
    pub email_from: Option<String>,
    pub email_to: Option<String>,
    pub email_username: Option<String>,
    pub email_password: Option<String>,
    /// `"starttls"` (default), `"implicit"` or `"none"`.
    pub email_tls: Option<String>,

    pub slack_webhook_url: Option<String>,
    pub discord_webhook_url: Option<String>,
    pub custom_webhook_url: Option<String>,
    pub telegram_token: Option<String>,
    pub telegram_chat_id: Option<String>,

    pub syslog_host: Option<String>,
    pub syslog_port: Option<u16>,
}

pub struct NotificationEngine {
    pub config: NotificationConfig,
    pub last_email_sent: Mutex<Option<Instant>>,
}

/// This machine's name for the RFC 5424 HOSTNAME field, or `"-"` (NILVALUE).
///
/// Reads the environment rather than taking a dependency: `COMPUTERNAME` on
/// Windows, `HOSTNAME` elsewhere. A shell does not always export `HOSTNAME`, so
/// the NILVALUE fallback is a real path, not a formality — and it is still
/// better than naming a machine wrongly.
fn local_hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty() && !h.contains(' '))
        .unwrap_or_else(|| "-".to_string())
}

impl NotificationEngine {
    pub fn new(config: NotificationConfig) -> Self {
        NotificationEngine {
            config,
            last_email_sent: Mutex::new(None),
        }
    }

    /// Send one alert mail, rate-limited to one per minute.
    ///
    /// This used to be a socket and a sequence of `let _ = write_all(..)`: it
    /// never read a reply, never looked at a status code, and returned `Ok(())`
    /// whenever the TCP connect succeeded. A refused recipient, a 550, an auth
    /// challenge, or a server that hung up were all reported as a sent mail —
    /// and the SOC view showed the channel as working. `lettre` speaks the
    /// actual protocol, so a rejection comes back as a rejection.
    pub fn send_email(&self, subject: &str, body: &str) -> Result<(), String> {
        use lettre::transport::smtp::authentication::Credentials;
        use lettre::{Message, SmtpTransport, Transport};

        let host = self
            .config
            .email_smtp_host
            .as_ref()
            .ok_or("No SMTP host configured")?;
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

        let message = Message::builder()
            .from(from.parse().map_err(|e| format!("Bad email_from: {e}"))?)
            .to(to.parse().map_err(|e| format!("Bad email_to: {e}"))?)
            .subject(subject)
            .header(lettre::message::header::ContentType::TEXT_PLAIN)
            .body(body.to_string())
            .map_err(|e| format!("Could not build the message: {e}"))?;

        let tls = self.config.email_tls.as_deref().unwrap_or("starttls");
        let mut builder = match tls {
            "starttls" => SmtpTransport::starttls_relay(host)
                .map_err(|e| format!("STARTTLS setup failed: {e}"))?,
            "implicit" => {
                SmtpTransport::relay(host).map_err(|e| format!("TLS setup failed: {e}"))?
            }
            // Explicitly asked for, never inferred — see `email_tls`.
            "none" => SmtpTransport::builder_dangerous(host),
            other => {
                return Err(format!(
                    "email_tls must be \"starttls\", \"implicit\" or \"none\", got {other:?}"
                ))
            }
        };

        if let Some(port) = self.config.email_smtp_port {
            builder = builder.port(port);
        }
        match (
            self.config.email_username.as_ref(),
            self.config.email_password.as_ref(),
        ) {
            (Some(u), Some(p)) => {
                if tls == "none" {
                    return Err(
                        "Refusing to send credentials over a plaintext SMTP session \
                         (email_tls = \"none\"); use \"starttls\" or \"implicit\""
                            .to_string(),
                    );
                }
                builder = builder.credentials(Credentials::new(u.clone(), p.clone()));
            }
            (Some(_), None) => return Err("email_username set without email_password".into()),
            (None, Some(_)) => return Err("email_password set without email_username".into()),
            (None, None) => {}
        }

        // Rate-limit only once the message and transport are known to be
        // well-formed: a misconfiguration should be reportable on every
        // attempt, not silenced for a minute by the first one.
        {
            let mut last_sent = self.last_email_sent.lock().unwrap();
            if let Some(last) = *last_sent {
                if last.elapsed() < Duration::from_secs(60) {
                    return Err("Email rate limited (max 1 per minute)".to_string());
                }
            }
            *last_sent = Some(Instant::now());
        }

        builder
            .build()
            .send(&message)
            .map_err(|e| format!("SMTP send failed: {e}"))?;
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
            "text": format!("ğŸš¨ *Netscope Alert:* {}", alert_msg),
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

    /// 2.4.5 Telegram Bot API (Â§4.1.1)
    pub fn send_telegram(&self, alert_msg: &str) -> Result<(), String> {
        let token = self
            .config
            .telegram_token
            .as_ref()
            .ok_or("No Telegram token configured")?;
        let url = format!("https://api.telegram.org/bot{}/sendMessage", token);
        self.send_telegram_to_url(alert_msg, &url)
    }

    /// Send Telegram notification to a specific endpoint URL (used for custom endpoints/testing).
    pub fn send_telegram_to_url(&self, alert_msg: &str, endpoint_url: &str) -> Result<(), String> {
        let chat_id = self
            .config
            .telegram_chat_id
            .as_ref()
            .ok_or("No Telegram chat ID configured")?;
        let payload = serde_json::json!({
            "chat_id": chat_id,
            "text": format!("ğŸš¨ *Netscope Alert* ğŸš¨\n\n{}", alert_msg),
            "parse_mode": "Markdown"
        });

        let client = ureq::Agent::new();
        client
            .post(endpoint_url)
            .send_json(payload)
            .map_err(|e| format!("Telegram notification failed: {}", e))?;
        Ok(())
    }

    /// Discord Webhook Notification (Â§4.1.2)
    pub fn send_discord(&self, alert_msg: &str, details_json: &str) -> Result<(), String> {
        let url = self
            .config
            .discord_webhook_url
            .as_ref()
            .ok_or("No Discord webhook URL configured")?;
        let payload = serde_json::json!({
            "content": format!("ğŸš¨ **Netscope Security Alert** ğŸš¨\n{}", alert_msg),
            "embeds": [
                {
                    "title": "Threat Metadata & Event Details",
                    "description": details_json,
                    "color": 15158332 // Red
                }
            ]
        });

        let client = ureq::Agent::new();
        client
            .post(url)
            .send_json(payload)
            .map_err(|e| format!("Discord notification failed: {}", e))?;
        Ok(())
    }

    /// Custom JSON Webhook Notification (Â§4.1.3)
    pub fn send_custom_webhook(
        &self,
        alert_msg: &str,
        target_url: Option<&str>,
    ) -> Result<(), String> {
        let url = target_url
            .or(self.config.custom_webhook_url.as_deref())
            .ok_or("No custom webhook URL configured")?;

        let payload = serde_json::json!({
            "source": "netscope-threat-engine",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "alert": alert_msg,
            "status": "triggered"
        });

        let client = ureq::Agent::new();
        client
            .post(url)
            .send_json(payload)
            .map_err(|e| format!("Custom webhook notification failed: {}", e))?;
        Ok(())
    }

    /// Dispatch high-severity alert notifications across all configured channels
    /// (Telegram, Discord, Slack, Custom Webhook, Email, Syslog).
    /// Returns a list of tuples containing channel names and their execution results.
    pub fn dispatch_all_configured(
        &self,
        alert_msg: &str,
        details_json: &str,
    ) -> Vec<(&'static str, Result<(), String>)> {
        let mut results = Vec::new();

        if self.config.telegram_token.is_some() && self.config.telegram_chat_id.is_some() {
            results.push(("telegram", self.send_telegram(alert_msg)));
        }
        if self.config.discord_webhook_url.is_some() {
            results.push(("discord", self.send_discord(alert_msg, details_json)));
        }
        if self.config.slack_webhook_url.is_some() {
            results.push(("slack", self.send_slack(alert_msg, details_json)));
        }
        if self.config.custom_webhook_url.is_some() {
            results.push(("custom_webhook", self.send_custom_webhook(alert_msg, None)));
        }
        if self.config.email_smtp_host.is_some() {
            results.push((
                "email",
                self.send_email(&format!("ğŸš¨ Netscope Alert: {}", alert_msg), alert_msg),
            ));
        }
        if self.config.syslog_host.is_some() {
            results.push(("syslog", self.send_syslog(alert_msg)));
        }

        results
    }

    // ---- On-call paging ---------------------------------------------------
    //
    // These three moved here from `escalation::invoke_on_call_api`, which
    // discarded every result with `let _ =`. `ureq` reports a non-2xx as
    // `Err(Error::Status(code, _))`, so `?` on `send_json` is what turns a
    // rejected page back into a failure the caller can show.

    /// PagerDuty Events API v2.
    pub fn send_pagerduty(&self, routing_key: &str, summary: &str) -> Result<(), String> {
        let body = serde_json::json!({
            "routing_key": routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": summary,
                "source": "netscope",
                "severity": "critical"
            }
        });
        ureq::Agent::new()
            .post("https://events.pagerduty.com/v2/enqueue")
            .send_json(body)
            .map_err(|e| format!("PagerDuty page failed: {e}"))?;
        Ok(())
    }

    /// Opsgenie Alert API v2.
    pub fn send_opsgenie(&self, api_key: &str, message: &str) -> Result<(), String> {
        let body = serde_json::json!({
            "message": message,
            "description": "Escalated by netscope",
            "priority": "P1"
        });
        ureq::Agent::new()
            .post("https://api.opsgenie.com/v2/alerts")
            .set("Authorization", &format!("GenieKey {api_key}"))
            .send_json(body)
            .map_err(|e| format!("Opsgenie page failed: {e}"))?;
        Ok(())
    }

    /// VictorOps (Splunk On-Call) generic integration.
    pub fn send_victorops(&self, key: &str, message: &str) -> Result<(), String> {
        let body = serde_json::json!({
            "message_type": "CRITICAL",
            "entity_id": "netscope-alert",
            "state_message": message
        });
        ureq::Agent::new()
            .post(&format!(
                "https://alert.victorops.com/integrations/generic/20131114/alert/{key}"
            ))
            .send_json(body)
            .map_err(|e| format!("VictorOps page failed: {e}"))?;
        Ok(())
    }

    /// Deliver one escalation step over whatever channel its chain names.
    ///
    /// Every channel in [`crate::escalation::EscalationStep::notify_channel`]'s
    /// documented set is handled here. An unrecognised name is an error, not a
    /// no-op — the bug this replaces was a `_ => {}` that swallowed `"Slack"`
    /// and `"Email"`, so the first two rungs of the default chain paged nobody
    /// and reported nothing.
    pub fn send_escalation(
        &self,
        notice: &crate::escalation::EscalationNotice,
    ) -> Result<(), String> {
        let msg = notice.message.as_str();
        // The paging services identify the responder by their integration key;
        // without one there is no way to reach them, and saying so beats
        // returning Ok after doing nothing.
        let key = || -> Result<&str, String> {
            notice
                .on_call
                .as_ref()
                .and_then(|u| u.integration_key.as_deref())
                .ok_or_else(|| {
                    format!(
                        "{} needs an integration_key for the week's on-call \
                         (set it under [[escalation.oncall]])",
                        notice.channel,
                    )
                })
        };

        match notice.channel.as_str() {
            "Slack" => self.send_slack(msg, "{}"),
            "Email" => self.send_email(&format!("netscope escalation: {}", notice.rule_name), msg),
            "PagerDuty" => self.send_pagerduty(key()?, msg),
            "Opsgenie" => self.send_opsgenie(key()?, msg),
            "VictorOps" => self.send_victorops(key()?, msg),
            other => Err(format!("Unknown escalation channel {other:?}")),
        }
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
                          // RFC 5424 HOSTNAME. This was the literal "localhost", which made every
                          // event on the SIEM side claim to come from a machine called localhost.
                          // "-" is the spec's NILVALUE and is the honest answer when the name is
                          // genuinely unknown — unlike a wrong name, it asserts nothing.
        let syslog_msg = format!(
            "<{}>1 {} {} netscope - - - {}",
            prival,
            chrono::Utc::now().to_rfc3339(),
            local_hostname(),
            alert_msg
        );

        socket
            .send_to(syslog_msg.as_bytes(), format!("{}:{}", host, port))
            .map_err(|e| format!("Syslog send failed: {}", e))?;
        Ok(())
    }

    /// 2.4.12 Write alerts to Windows Event Viewer (Application log)
    ///
    /// Reports what actually happened. `eventcreate` needs an elevated process
    /// to write the Application log, and this used to print a warning and
    /// return `Ok(())` anyway — so a caller testing the channel was told it
    /// worked while nothing had been written. The SOC view surfaces this result
    /// to the user, which only means anything if a failure comes back as one.
    pub fn write_windows_event_log(&self, alert_msg: &str) -> Result<(), String> {
        #[cfg(target_os = "windows")]
        {
            let desc = format!("Netscope Alert Event: {}", alert_msg);
            let output = Command::new("eventcreate")
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
                .output()
                .map_err(|e| format!("Could not run eventcreate: {e}"))?;

            if !output.status.success() {
                return Err(match output.status.code() {
                    Some(c) => format!(
                        "eventcreate exited with {c} — writing the Application log needs netscope to run elevated"
                    ),
                    None => "eventcreate was terminated by a signal".to_string(),
                });
            }
            Ok(())
        }

        #[cfg(not(target_os = "windows"))]
        {
            let _ = alert_msg;
            Err("The Windows Event Log channel is only available on Windows".to_string())
        }
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

    /// Nothing configured. Tests set only the fields they exercise.
    fn blank_config() -> NotificationConfig {
        NotificationConfig {
            email_smtp_host: None,
            email_smtp_port: None,
            email_from: None,
            email_to: None,
            email_username: None,
            email_password: None,
            email_tls: None,
            slack_webhook_url: None,
            discord_webhook_url: None,
            custom_webhook_url: None,
            telegram_token: None,
            telegram_chat_id: None,
            syslog_host: None,
            syslog_port: None,
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_email_rate_limiting() {
        let config = NotificationConfig {
            email_smtp_host: Some("127.0.0.1".to_string()),
            email_smtp_port: Some(2525),
            email_from: Some("alert@netscope.com".to_string()),
            email_to: Some("soc@netscope.com".to_string()),
            email_tls: Some("none".to_string()),
            ..blank_config()
        };
        let engine = NotificationEngine::new(config);

        // First attempt fails to connect to dummy port but records attempt / rate limit
        let res1 = engine.send_email("Alert 1", "Body 1");
        assert!(res1.is_err());

        // Second attempt within 60s must fail immediately with rate limit message
        let res2 = engine.send_email("Alert 2", "Body 2");
        assert_eq!(res2.unwrap_err(), "Email rate limited (max 1 per minute)");
    }

    /// A server that rejects the mail must be reported as a failure.
    ///
    /// `send_email` used to write EHLO/MAIL FROM/RCPT TO/DATA with
    /// `let _ = write_all(..)` and never read a byte back, so it returned
    /// `Ok(())` whenever the TCP connect succeeded. A 550, a refused recipient,
    /// an auth demand — all reported as sent, and the SOC view showed the
    /// channel as healthy. This stands up a server that answers the greeting
    /// and then rejects, which the old code could not distinguish from success.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn an_smtp_rejection_is_not_reported_as_sent() {
        use std::io::{BufRead, BufReader, Write as _};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        std::thread::spawn(move || {
            if let Ok((sock, _)) = listener.accept() {
                let mut reader = BufReader::new(sock.try_clone().unwrap());
                let mut out = sock;
                let _ = out.write_all(b"220 test ESMTP\r\n");
                let mut line = String::new();
                // Greet, then refuse whatever it asks for.
                while reader.read_line(&mut line).is_ok() && !line.is_empty() {
                    let _ = out.write_all(b"550 mailbox unavailable\r\n");
                    line.clear();
                }
            }
        });

        let engine = NotificationEngine::new(NotificationConfig {
            email_smtp_host: Some("127.0.0.1".to_string()),
            email_smtp_port: Some(port),
            email_from: Some("alert@example.com".to_string()),
            email_to: Some("soc@example.com".to_string()),
            // Plaintext so the test needs no certificate; the rejection path is
            // what is under test, not the transport.
            email_tls: Some("none".to_string()),
            ..blank_config()
        });

        let err = engine
            .send_email("Alert", "Body")
            .expect_err("a 550 must not be reported as a sent mail");
        assert!(
            err.contains("SMTP send failed"),
            "the error should name the SMTP failure, got {err:?}",
        );
    }

    /// Credentials must never be handed to a plaintext session.
    #[test]
    fn credentials_are_refused_over_plaintext_smtp() {
        let engine = NotificationEngine::new(NotificationConfig {
            email_smtp_host: Some("127.0.0.1".to_string()),
            email_from: Some("alert@example.com".to_string()),
            email_to: Some("soc@example.com".to_string()),
            email_username: Some("user".to_string()),
            email_password: Some("hunter2".to_string()),
            email_tls: Some("none".to_string()),
            ..blank_config()
        });

        let err = engine.send_email("Alert", "Body").unwrap_err();
        assert!(err.contains("Refusing to send credentials"), "got {err:?}",);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_syslog_and_windows_log() {
        let config = NotificationConfig {
            email_smtp_host: None,
            email_smtp_port: None,
            email_from: None,
            email_to: None,
            email_username: None,
            email_password: None,
            email_tls: None,
            slack_webhook_url: None,
            discord_webhook_url: None,
            custom_webhook_url: None,
            telegram_token: None,
            telegram_chat_id: None,
            syslog_host: Some("127.0.0.1".to_string()),
            syslog_port: Some(5140),
        };
        let engine = NotificationEngine::new(config);

        // Syslog send UDP should work offline (UDP is fire-and-forget)
        assert!(engine.send_syslog("Mock alert payload").is_ok());

        // The event log is the one channel whose outcome depends on privilege
        // and platform, so this pins the contract rather than the result: it
        // either writes, or explains why it could not. What it must never do is
        // the old behaviour — report success after printing a warning and
        // writing nothing.
        match engine.write_windows_event_log("Port scan alert") {
            // Success is only reachable on Windows, and only when elevated.
            Ok(()) if cfg!(target_os = "windows") => {}
            Ok(()) => panic!("only Windows can write the Application log"),
            Err(e) => assert!(
                e.contains("elevated")
                    || e.contains("only available on Windows")
                    || e.contains("eventcreate"),
                "unhelpful event-log error: {e}"
            ),
        }
    }

    fn start_mock_http_server() -> (String, std::sync::mpsc::Receiver<String>) {
        use std::io::{BufRead, BufReader, Read, Write};
        use std::net::TcpListener;
        use std::sync::mpsc::channel;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = channel();

        std::thread::spawn(move || {
            while let Ok((sock, _)) = listener.accept() {
                let mut reader = BufReader::new(sock.try_clone().unwrap());
                let mut out = sock;
                let mut content_length: usize = 0;
                let mut line = String::new();

                while reader.read_line(&mut line).is_ok() {
                    if line == "\r\n" || line == "\n" {
                        break;
                    }
                    if line.to_lowercase().starts_with("content-length:") {
                        if let Some(val) = line.split(':').nth(1) {
                            content_length = val.trim().parse().unwrap_or(0);
                        }
                    }
                    line.clear();
                }

                let mut body = vec![0u8; content_length];
                if content_length > 0 {
                    let _ = reader.read_exact(&mut body);
                }

                let body_str = String::from_utf8_lossy(&body).to_string();
                let _ = tx.send(body_str);

                let resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"ok\":true}";
                let _ = out.write_all(resp.as_bytes());
            }
        });

        (format!("http://127.0.0.1:{}", port), rx)
    }

    #[test]
    fn test_telegram_notification() {
        let (url, rx) = start_mock_http_server();
        let config = NotificationConfig {
            telegram_token: Some("123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11".to_string()),
            telegram_chat_id: Some("987654321".to_string()),
            ..blank_config()
        };
        let engine = NotificationEngine::new(config);

        let res = engine.send_telegram_to_url("High severity attack detected", &url);
        assert!(res.is_ok(), "Telegram send failed: {:?}", res);

        let received_payload = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(received_payload.contains("987654321"));
        assert!(received_payload.contains("High severity attack detected"));
        assert!(received_payload.contains("Markdown"));
    }

    #[test]
    fn test_discord_notification() {
        let (url, rx) = start_mock_http_server();
        let config = NotificationConfig {
            discord_webhook_url: Some(url),
            ..blank_config()
        };
        let engine = NotificationEngine::new(config);

        let res = engine.send_discord("Malware activity", "{\"ip\": \"192.168.1.50\"}");
        assert!(res.is_ok(), "Discord send failed: {:?}", res);

        let received_payload = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(received_payload.contains("Netscope Security Alert"));
        assert!(received_payload.contains("Malware activity"));
        assert!(received_payload.contains("192.168.1.50"));
    }

    #[test]
    fn test_slack_notification() {
        let (url, rx) = start_mock_http_server();
        let config = NotificationConfig {
            slack_webhook_url: Some(url),
            ..blank_config()
        };
        let engine = NotificationEngine::new(config);

        let res = engine.send_slack("Exfiltration attempt", "{\"bytes\": 5000000}");
        assert!(res.is_ok(), "Slack send failed: {:?}", res);

        let received_payload = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(received_payload.contains("Netscope Alert"));
        assert!(received_payload.contains("Exfiltration attempt"));
        assert!(received_payload.contains("5000000"));
    }

    #[test]
    fn test_custom_webhook_notification() {
        let (url, rx) = start_mock_http_server();
        let config = NotificationConfig {
            custom_webhook_url: Some(url),
            ..blank_config()
        };
        let engine = NotificationEngine::new(config);

        let res = engine.send_custom_webhook("Port scan detected", None);
        assert!(res.is_ok(), "Custom webhook send failed: {:?}", res);

        let received_payload = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(received_payload.contains("netscope-threat-engine"));
        assert!(received_payload.contains("Port scan detected"));
        assert!(received_payload.contains("triggered"));
    }

    #[test]
    fn test_dispatch_all_configured() {
        let (url1, _rx1) = start_mock_http_server();
        let (url2, _rx2) = start_mock_http_server();

        let config = NotificationConfig {
            discord_webhook_url: Some(url1),
            custom_webhook_url: Some(url2),
            syslog_host: Some("127.0.0.1".to_string()),
            syslog_port: Some(5140),
            ..blank_config()
        };
        let engine = NotificationEngine::new(config);

        let results = engine.dispatch_all_configured("Critical Breach", "{\"src\": \"10.0.0.1\"}");
        assert_eq!(results.len(), 3);
        for (channel, res) in results {
            assert!(res.is_ok(), "Channel {} failed: {:?}", channel, res);
        }
    }
}
