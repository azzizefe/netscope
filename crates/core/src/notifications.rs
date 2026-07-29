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
            let status = Command::new("eventcreate")
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
                .status()
                .map_err(|e| format!("Could not run eventcreate: {e}"))?;

            if !status.success() {
                return Err(match status.code() {
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
}
