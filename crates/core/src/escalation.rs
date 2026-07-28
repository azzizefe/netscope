// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::collections::HashMap;
use chrono::{DateTime, Datelike, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EscalationLevel {
    L1,    // SOC Analyst
    L2,    // Senior Analyst
    L3,    // IR Lead
    Ciso,  // CISO
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationStep {
    pub level: EscalationLevel,
    pub wait_duration_secs: u64,
    pub notify_channel: String, // "Slack", "Email", "PagerDuty", "Opsgenie", "VictorOps"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationPolicy {
    pub rule_name: String,
    pub chain: Vec<EscalationStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnCallUser {
    pub name: String,
    pub email: String,
    pub phone: String,
    pub integration_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShiftRotation {
    pub week_number: u32,
    pub primary_user: OnCallUser,
    pub backup_user: OnCallUser,
}

#[derive(Debug, Clone)]
pub struct ActiveEscalation {
    pub alert_id: String,
    pub rule_name: String,
    pub alert_msg: String,
    pub start_time: DateTime<Utc>,
    pub current_step_index: usize,
    pub last_escalated: DateTime<Utc>,
    pub status: String, // "Acknowledged", "Resolved", "Escalating"
}

pub struct EscalationEngine {
    pub policies: HashMap<String, EscalationPolicy>,
    pub active_escalations: HashMap<String, ActiveEscalation>,
    pub shift_rotations: HashMap<u32, ShiftRotation>,
    pub default_policy: EscalationPolicy,
}

impl EscalationEngine {
    pub fn new(shift_rotations: HashMap<u32, ShiftRotation>) -> Self {
        // Default time-based escalation policy (2.3.1)
        // L1 (SOC Analyst) -> 15 min -> L2 (Senior Analyst) -> 30 min -> L3 (IR Lead) -> 1 hr -> CISO
        let default_policy = EscalationPolicy {
            rule_name: "Default".to_string(),
            chain: vec![
                EscalationStep {
                    level: EscalationLevel::L1,
                    wait_duration_secs: 15 * 60,
                    notify_channel: "Slack".to_string(),
                },
                EscalationStep {
                    level: EscalationLevel::L2,
                    wait_duration_secs: 30 * 60,
                    notify_channel: "Email".to_string(),
                },
                EscalationStep {
                    level: EscalationLevel::L3,
                    wait_duration_secs: 60 * 60,
                    notify_channel: "PagerDuty".to_string(),
                },
                EscalationStep {
                    level: EscalationLevel::Ciso,
                    wait_duration_secs: 24 * 3600, // final level holds indefinitely
                    notify_channel: "Opsgenie".to_string(),
                },
            ],
        };

        EscalationEngine {
            policies: HashMap::new(),
            active_escalations: HashMap::new(),
            shift_rotations,
            default_policy,
        }
    }

    pub fn trigger_alert_escalation(&mut self, alert_id: String, rule_name: String, msg: String) {
        let now = Utc::now();
        let escalation = ActiveEscalation {
            alert_id: alert_id.clone(),
            rule_name,
            alert_msg: msg,
            start_time: now,
            current_step_index: 0,
            last_escalated: now,
            status: "Escalating".to_string(),
        };

        self.active_escalations.insert(alert_id, escalation);
    }

    pub fn acknowledge_escalation(&mut self, alert_id: &str) {
        if let Some(esc) = self.active_escalations.get_mut(alert_id) {
            esc.status = "Acknowledged".to_string();
        }
    }

    pub fn resolve_escalation(&mut self, alert_id: &str) {
        if let Some(esc) = self.active_escalations.get_mut(alert_id) {
            esc.status = "Resolved".to_string();
        }
    }

    pub fn get_on_call_for_time(&self, time: DateTime<Utc>) -> Option<&ShiftRotation> {
        let week = time.iso_week().week();
        self.shift_rotations.get(&week)
    }

    pub fn process_escalations(&mut self, current_time: DateTime<Utc>) -> Vec<String> {
        let mut notifications = Vec::new();
        let mut keys_to_remove = Vec::new();

        let rotations = self.shift_rotations.clone();
        let default_chain = self.default_policy.chain.clone();
        let policies = self.policies.clone();

        for (alert_id, esc) in self.active_escalations.iter_mut() {
            if esc.status == "Resolved" {
                keys_to_remove.push(alert_id.clone());
                continue;
            }
            if esc.status == "Acknowledged" {
                continue;
            }

            // Determine active policy (2.3.2)
            let chain = if let Some(policy) = policies.get(&esc.rule_name) {
                &policy.chain
            } else {
                &default_chain
            };

            if esc.current_step_index < chain.len() {
                let current_step = &chain[esc.current_step_index];
                let duration_since_last = current_time.signed_duration_since(esc.last_escalated);

                if duration_since_last.num_seconds() >= current_step.wait_duration_secs as i64 {
                    // Escalate to next level
                    esc.current_step_index += 1;
                    esc.last_escalated = current_time;

                    if esc.current_step_index < chain.len() {
                        let next_step = &chain[esc.current_step_index];
                        let on_call = rotations.get(&current_time.iso_week().week());

                        let level_notification = format!(
                            "Alert {} escalated to level {:?}. Notifying current week {} on-call (Primary: {}) via {}",
                            esc.alert_id,
                            next_step.level,
                            current_time.iso_week().week(),
                            on_call.map(|o| o.primary_user.name.as_str()).unwrap_or("None"),
                            next_step.notify_channel
                        );
                        notifications.push(level_notification);

                        // Invoke third-party APIs (2.3.3)
                        if let Some(on_call_user) = on_call.map(|o| &o.primary_user) {
                            invoke_on_call_api(on_call_user, &next_step.level, &esc.alert_msg, &next_step.notify_channel);
                        }
                    }
                }
            }
        }

        for key in keys_to_remove {
            self.active_escalations.remove(&key);
        }

        notifications
    }
}

fn invoke_on_call_api(user: &OnCallUser, level: &EscalationLevel, alert_msg: &str, channel: &str) {
    let client = ureq::Agent::new();
    match channel {
        "PagerDuty" => {
            if let Some(ref key) = user.integration_key {
                let body = serde_json::json!({
                    "routing_key": key,
                    "event_action": "trigger",
                    "payload": {
                        "summary": format!("[{:?}] {}", level, alert_msg),
                        "source": "netscope-agent",
                        "severity": "critical"
                    }
                });
                let _ = client.post("https://events.pagerduty.com/v2/enqueue")
                    .send_json(body);
            }
        }
        "Opsgenie" => {
            if let Some(ref key) = user.integration_key {
                let body = serde_json::json!({
                    "message": format!("[{:?}] {}", level, alert_msg),
                    "description": "Escalated from Netscope agent",
                    "priority": "P1"
                });
                let _ = client.post("https://api.opsgenie.com/v2/alerts")
                    .set("Authorization", &format!("GenieKey {}", key))
                    .send_json(body);
            }
        }
        "VictorOps" => {
            if let Some(ref key) = user.integration_key {
                let body = serde_json::json!({
                    "message_type": "CRITICAL",
                    "entity_id": "netscope-alert",
                    "state_message": format!("[{:?}] {}", level, alert_msg)
                });
                let url = format!("https://alert.victorops.com/integrations/generic/20131114/alert/{}", key);
                let _ = client.post(&url).send_json(body);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_alert_escalation_lifecycle() {
        let primary = OnCallUser {
            name: "John SOC Analyst".to_string(),
            email: "john@netscope.com".to_string(),
            phone: "+123456789".to_string(),
            integration_key: Some("dummy-key".to_string()),
        };
        let backup = OnCallUser {
            name: "Jane Senior Analyst".to_string(),
            email: "jane@netscope.com".to_string(),
            phone: "+987654321".to_string(),
            integration_key: None,
        };

        let mut shifts = HashMap::new();
        shifts.insert(1, ShiftRotation {
            week_number: 1,
            primary_user: primary.clone(),
            backup_user: backup.clone(),
        });

        let mut engine = EscalationEngine::new(shifts);

        let start_time = Utc.with_ymd_and_hms(2026, 1, 5, 12, 0, 0).unwrap();
        let week = start_time.iso_week().week();
        
        engine.shift_rotations.insert(week, ShiftRotation {
            week_number: week,
            primary_user: primary.clone(),
            backup_user: backup.clone(),
        });

        // Trigger alert
        engine.trigger_alert_escalation("alert-123".to_string(), "Port scan detection".to_string(), "Threshold exceeded: 50 SYN packets".to_string());
        if let Some(esc) = engine.active_escalations.get_mut("alert-123") {
            esc.start_time = start_time;
            esc.last_escalated = start_time;
        }
        
        assert_eq!(engine.active_escalations.len(), 1);
        assert_eq!(engine.active_escalations["alert-123"].status, "Escalating");

        // 1. Tick time by 16 minutes
        let time_l2 = start_time + chrono::Duration::minutes(16);
        let notifications = engine.process_escalations(time_l2);

        assert_eq!(notifications.len(), 1);
        assert!(notifications[0].contains("escalated to level L2"));
        assert!(notifications[0].contains("John SOC Analyst"));

        // 2. Acknowledge escalation
        engine.acknowledge_escalation("alert-123");
        let time_l3 = time_l2 + chrono::Duration::minutes(35);
        let notifications = engine.process_escalations(time_l3);
        assert!(notifications.is_empty()); // Escalation paused!
    }
}
