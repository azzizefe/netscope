// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use chrono::{DateTime, Datelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EscalationLevel {
    L1,   // SOC Analyst
    L2,   // Senior Analyst
    L3,   // IR Lead
    Ciso, // CISO
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

/// One step of the chain coming due: who should be paged, over what channel.
///
/// `process_escalations` returns these instead of delivering them itself. That
/// split is the whole point: this module used to carry its own `ureq` client
/// alongside the one in [`crate::notifications`], and its `match` on the channel
/// name had no arm for `"Slack"` or `"Email"` — which are exactly the channels
/// of L1 and L2 in the default chain. The first two escalation levels therefore
/// paged nobody, silently, because the fallthrough arm was `_ => {}`.
///
/// With delivery moved out, the engine is pure time-and-state logic (and
/// testable without a socket), and every channel goes through the one delivery
/// path that already reports failures.
#[derive(Debug, Clone, PartialEq)]
pub struct EscalationNotice {
    pub alert_id: String,
    pub rule_name: String,
    pub level: EscalationLevel,
    /// "Slack" | "Email" | "PagerDuty" | "Opsgenie" | "VictorOps".
    pub channel: String,
    /// `None` when no rotation covers this ISO week — there is nobody to page,
    /// and the caller must say so rather than quietly escalating into a void.
    pub on_call: Option<OnCallUser>,
    /// Human-readable line for the UI and the notification body.
    pub message: String,
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

    /// Advance every active escalation and report the steps that came due.
    ///
    /// Returns what *should* be delivered; it sends nothing itself. See
    /// [`EscalationNotice`] for why.
    pub fn process_escalations(&mut self, current_time: DateTime<Utc>) -> Vec<EscalationNotice> {
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
                        let week = current_time.iso_week().week();
                        let on_call = rotations.get(&week).map(|r| r.primary_user.clone());

                        let message = format!(
                            "Alert {} escalated to {:?} — week {} on-call: {} (via {}). {}",
                            esc.alert_id,
                            next_step.level,
                            week,
                            on_call
                                .as_ref()
                                .map(|u| u.name.as_str())
                                .unwrap_or("nobody on the rotation"),
                            next_step.notify_channel,
                            esc.alert_msg,
                        );

                        notifications.push(EscalationNotice {
                            alert_id: esc.alert_id.clone(),
                            rule_name: esc.rule_name.clone(),
                            level: next_step.level,
                            channel: next_step.notify_channel.clone(),
                            on_call,
                            message,
                        });
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

// `invoke_on_call_api` used to live here. It was a second `ureq` client parallel
// to the one in `notifications`, it discarded every HTTP result with `let _ =`
// (so a 401 was indistinguishable from a page), and its `_ => {}` arm silently
// dropped "Slack" and "Email" — the L1 and L2 channels. Delivery now lives in
// `notifications::send_escalation`, which returns a `Result` and handles all
// five channels.

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
        shifts.insert(
            1,
            ShiftRotation {
                week_number: 1,
                primary_user: primary.clone(),
                backup_user: backup.clone(),
            },
        );

        let mut engine = EscalationEngine::new(shifts);

        let start_time = Utc.with_ymd_and_hms(2026, 1, 5, 12, 0, 0).unwrap();
        let week = start_time.iso_week().week();

        engine.shift_rotations.insert(
            week,
            ShiftRotation {
                week_number: week,
                primary_user: primary.clone(),
                backup_user: backup.clone(),
            },
        );

        // Trigger alert
        engine.trigger_alert_escalation(
            "alert-123".to_string(),
            "Port scan detection".to_string(),
            "Threshold exceeded: 50 SYN packets".to_string(),
        );
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
        assert!(notifications[0].message.contains("escalated to L2"));
        assert!(notifications[0].message.contains("John SOC Analyst"));
        assert_eq!(notifications[0].alert_id, "alert-123");
        assert_eq!(
            notifications[0].on_call.as_ref().map(|u| u.name.as_str()),
            Some("John SOC Analyst"),
        );

        // 2. Acknowledge escalation
        engine.acknowledge_escalation("alert-123");
        let time_l3 = time_l2 + chrono::Duration::minutes(35);
        let notifications = engine.process_escalations(time_l3);
        assert!(notifications.is_empty()); // Escalation paused!
    }

    /// Every rung of the default chain must name a channel that can be
    /// delivered.
    ///
    /// The engine used to page people itself, through a `match` whose only arms
    /// were PagerDuty, Opsgenie and VictorOps, with `_ => {}` underneath. L1 and
    /// L2 of this very chain are `"Slack"` and `"Email"` — so the first two
    /// escalation levels hit the fallthrough and notified nobody, without an
    /// error anywhere. Delivery now lives in `notifications::send_escalation`;
    /// this pins that the chain and that dispatcher agree on the channel names.
    #[test]
    fn every_default_chain_step_names_a_deliverable_channel() {
        const DELIVERABLE: &[&str] = &["Slack", "Email", "PagerDuty", "Opsgenie", "VictorOps"];

        let engine = EscalationEngine::new(HashMap::new());
        let chain = &engine.default_policy.chain;
        assert!(!chain.is_empty());

        for step in chain {
            assert!(
                DELIVERABLE.contains(&step.notify_channel.as_str()),
                "{:?} escalates over {:?}, which send_escalation cannot deliver",
                step.level,
                step.notify_channel,
            );
        }

        // Pin the two that used to be silently dropped, by position.
        assert_eq!(chain[0].notify_channel, "Slack");
        assert_eq!(chain[1].notify_channel, "Email");
    }

    /// An escalation with nobody on the rotation must still surface.
    ///
    /// `get_on_call_for_time` returns `None` for an uncovered week, and the old
    /// code turned that into the string "Primary: None" and moved on. The notice
    /// now carries `on_call: None` so the delivery layer can fail loudly for the
    /// paging channels instead of pretending someone was reached.
    #[test]
    fn an_uncovered_week_still_produces_a_notice_with_no_on_call() {
        let mut engine = EscalationEngine::new(HashMap::new()); // no rotations at all
        let start = Utc.with_ymd_and_hms(2026, 3, 2, 9, 0, 0).unwrap();

        engine.trigger_alert_escalation(
            "alert-999".into(),
            "Port scan".into(),
            "50 SYN packets".into(),
        );
        if let Some(e) = engine.active_escalations.get_mut("alert-999") {
            e.start_time = start;
            e.last_escalated = start;
        }

        let notices = engine.process_escalations(start + chrono::Duration::minutes(16));
        assert_eq!(notices.len(), 1);
        assert!(notices[0].on_call.is_none());
        assert!(
            notices[0].message.contains("nobody on the rotation"),
            "the message must say the rotation is empty, got {:?}",
            notices[0].message,
        );
    }
}
