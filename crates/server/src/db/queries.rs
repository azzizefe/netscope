use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use super::models::*;

// ── Users ──

pub async fn get_user_by_username(pool: &PgPool, username: &str) -> Result<Option<User>> {
    Ok(sqlx::query_as::<_, User>(
        "SELECT id, username, email, password_hash, role, is_active, created_at, updated_at
         FROM users WHERE username = $1",
    )
    .bind(username)
    .fetch_optional(pool)
    .await?)
}

pub async fn create_user(pool: &PgPool, user: &CreateUser, hash: &str) -> Result<User> {
    Ok(sqlx::query_as::<_, User>(
        "INSERT INTO users (username, email, password_hash, role)
         VALUES ($1, $2, $3, $4)
         RETURNING id, username, email, password_hash, role, is_active, created_at, updated_at",
    )
    .bind(&user.username)
    .bind(&user.email)
    .bind(hash)
    .bind(&user.role)
    .fetch_one(pool)
    .await?)
}

// ── Sensors ──

pub async fn register_sensor(pool: &PgPool, sensor: &RegisterSensor) -> Result<Sensor> {
    Ok(sqlx::query_as::<_, Sensor>(
        "INSERT INTO sensors (hostname, ip_address, os, version, interfaces, cpu_cores, ram_mb, status, deployment_type, capture_mode, location, last_heartbeat)
         VALUES ($1, $2::inet, $3, $4, $5::jsonb, $6, $7, 'online', $8, $9, $10, now())
         RETURNING id, hostname, ip_address::inet, os, version, interfaces, cpu_cores, ram_mb,
                   status, tags, metadata, deployment_type, capture_mode, location, registered_at, last_heartbeat",
    )
    .bind(&sensor.hostname)
    .bind(sensor.ip_address.to_string())
    .bind(&sensor.os)
    .bind(&sensor.version)
    .bind(serde_json::to_value(&sensor.interfaces)?)
    .bind(sensor.cpu_cores)
    .bind(sensor.ram_mb)
    .bind(&sensor.deployment_type)
    .bind(&sensor.capture_mode)
    .bind(&sensor.location)
    .fetch_one(pool)
    .await?)
}

pub async fn list_sensors(pool: &PgPool) -> Result<Vec<SensorSummary>> {
    Ok(sqlx::query_as::<_, SensorSummary>(
        "SELECT s.id, s.hostname, s.ip_address::inet, s.os, s.version, s.status, s.last_heartbeat,
                sh.uptime_secs, sh.cpu_load_pct, sh.ram_used_mb, s.ram_mb, sh.capture_throughput_bps
         FROM sensors s
         LEFT JOIN LATERAL (
             SELECT uptime_secs, cpu_load_pct, ram_used_mb, capture_throughput_bps
             FROM sensor_heartbeats
             WHERE sensor_id = s.id
             ORDER BY received_at DESC
             LIMIT 1
         ) sh ON true
         ORDER BY s.hostname",
    )
    .fetch_all(pool)
    .await?)
}

pub async fn get_sensor(pool: &PgPool, id: Uuid) -> Result<Option<Sensor>> {
    Ok(sqlx::query_as::<_, Sensor>(
        "SELECT id, hostname, ip_address::inet, os, version, interfaces, cpu_cores, ram_mb,
                status, tags, metadata, registered_at, last_heartbeat
         FROM sensors WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?)
}

pub async fn update_sensor_heartbeat(
    pool: &PgPool,
    sensor_id: Uuid,
    hb: &SensorHeartbeat,
) -> Result<()> {
    sqlx::query("UPDATE sensors SET status = 'online', last_heartbeat = now() WHERE id = $1")
        .bind(sensor_id)
        .execute(pool)
        .await?;

    sqlx::query(
        "INSERT INTO sensor_heartbeats (sensor_id, cpu_load_pct, ram_used_mb, capture_throughput_bps, uptime_secs, disk_free_mb, interface_stats)
         VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)",
    )
    .bind(sensor_id)
    .bind(hb.cpu_load_pct)
    .bind(hb.ram_used_mb)
    .bind(hb.capture_throughput_bps)
    .bind(hb.uptime_secs)
    .bind(hb.disk_free_mb)
    .bind(&hb.interface_stats)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_sensor_throughput_history(
    pool: &PgPool,
    sensor_id: Uuid,
) -> Result<Vec<ThroughputPoint>> {
    Ok(sqlx::query_as::<_, ThroughputPoint>(
        "SELECT date_trunc('minute', received_at) as minute, AVG(capture_throughput_bps)::bigint as throughput \
         FROM sensor_heartbeats \
         WHERE sensor_id = $1 AND received_at > now() - interval '1 hour' \
         GROUP BY minute ORDER BY minute"
    )
    .bind(sensor_id)
    .fetch_all(pool)
    .await?)
}

pub async fn get_sensor_topology(pool: &PgPool, sensor_id: Uuid) -> Result<Vec<TopologyEdge>> {
    Ok(sqlx::query_as::<_, TopologyEdge>(
        "SELECT source_ip::text as source_ip, dest_ip::text as dest_ip, \
                COALESCE(protocol, 'unknown') as protocol, COUNT(*)::bigint as count \
         FROM events \
         WHERE sensor_id = $1 AND source_ip IS NOT NULL AND dest_ip IS NOT NULL \
         GROUP BY source_ip, dest_ip, protocol \
         ORDER BY count DESC \
         LIMIT 100",
    )
    .bind(sensor_id)
    .fetch_all(pool)
    .await?)
}

// ── Events ──

pub async fn insert_event(pool: &PgPool, event: &Event) -> Result<Event> {
    Ok(sqlx::query_as::<_, Event>(
        // `timestamp` is bound rather than left to the column default: the
        // default is `now()`, which is the ingest time, and a batch replayed
        // from a sensor's offline buffer is not from now.
        "INSERT INTO events (sensor_id, event_type, severity, title, description,
                source_ip, dest_ip, protocol, port, raw_data, tags, timestamp)
         VALUES ($1, $2, $3, $4, $5, $6::inet, $7::inet, $8, $9, $10::jsonb, $11::jsonb, $12)
         RETURNING id, sensor_id, event_type, severity, title, description,
                   source_ip::inet, dest_ip::inet, protocol, port, raw_data, tags, timestamp",
    )
    .bind(event.sensor_id)
    .bind(&event.event_type)
    .bind(&event.severity)
    .bind(&event.title)
    .bind(&event.description)
    .bind(event.source_ip.clone().map(|i| i.to_string()))
    .bind(event.dest_ip.clone().map(|i| i.to_string()))
    .bind(&event.protocol)
    .bind(event.port)
    .bind(&event.raw_data)
    .bind(&event.tags)
    .bind(event.timestamp)
    .fetch_one(pool)
    .await?)
}

pub async fn list_events(pool: &PgPool, filter: &EventFilter) -> Result<Vec<Event>> {
    let page = filter.page.unwrap_or(1).max(1);
    let per_page = filter.per_page.unwrap_or(50).clamp(1, 500);
    let offset = (page - 1) * per_page;

    let mut sql = String::from(
        "SELECT id, sensor_id, event_type, severity, title, description,
                source_ip::inet, dest_ip::inet, protocol, port, raw_data, tags, timestamp
         FROM events WHERE 1=1",
    );
    let mut idx = 1u32;

    if filter.severity.is_some() {
        sql.push_str(&format!(" AND severity = ${idx}"));
        idx += 1;
    }
    if filter.sensor_id.is_some() {
        sql.push_str(&format!(" AND sensor_id = ${idx}"));
        idx += 1;
    }
    if filter.timerange_start.is_some() {
        sql.push_str(&format!(" AND timestamp >= ${idx}"));
        idx += 1;
    }
    if filter.timerange_end.is_some() {
        sql.push_str(&format!(" AND timestamp <= ${idx}"));
        idx += 1;
    }
    if filter.event_type.is_some() {
        sql.push_str(&format!(" AND event_type = ${idx}"));
        idx += 1;
    }

    sql.push_str(" ORDER BY timestamp DESC");
    sql.push_str(&format!(" LIMIT ${idx} OFFSET ${}", idx + 1));

    let mut q = sqlx::query_as::<_, Event>(&sql);
    if let Some(ref sev) = filter.severity {
        q = q.bind(sev);
    }
    if let Some(sid) = filter.sensor_id {
        q = q.bind(sid);
    }
    if let Some(ts) = filter.timerange_start {
        q = q.bind(ts);
    }
    if let Some(te) = filter.timerange_end {
        q = q.bind(te);
    }
    if let Some(ref et) = filter.event_type {
        q = q.bind(et);
    }
    q = q.bind(per_page).bind(offset);

    Ok(q.fetch_all(pool).await?)
}

// ── Alerts ──

pub async fn list_alerts(pool: &PgPool, filter: &AlertFilter) -> Result<Vec<Alert>> {
    let page = filter.page.unwrap_or(1).max(1);
    let per_page = filter.per_page.unwrap_or(50).clamp(1, 500);
    let offset = (page - 1) * per_page;

    let mut sql = String::from(
        "SELECT id, rule_id, sensor_id, event_id, status, severity, title, description,
                source_ip::inet, dest_ip::inet, raw_data, assigned_to,
                acknowledged_by, acknowledged_at, resolved_by, resolved_at,
                created_at, updated_at
         FROM alerts WHERE 1=1",
    );
    let mut idx = 1u32;

    if filter.status.is_some() {
        sql.push_str(&format!(" AND status = ${idx}"));
        idx += 1;
    }
    if filter.severity.is_some() {
        sql.push_str(&format!(" AND severity = ${idx}"));
        idx += 1;
    }
    if filter.sensor_id.is_some() {
        sql.push_str(&format!(" AND sensor_id = ${idx}"));
        idx += 1;
    }
    if filter.timerange_start.is_some() {
        sql.push_str(&format!(" AND created_at >= ${idx}"));
        idx += 1;
    }
    if filter.timerange_end.is_some() {
        sql.push_str(&format!(" AND created_at <= ${idx}"));
        idx += 1;
    }

    sql.push_str(" ORDER BY created_at DESC");
    sql.push_str(&format!(" LIMIT ${idx} OFFSET ${}", idx + 1));

    let mut q = sqlx::query_as::<_, Alert>(&sql);
    if let Some(ref s) = filter.status {
        q = q.bind(s);
    }
    if let Some(ref sev) = filter.severity {
        q = q.bind(sev);
    }
    if let Some(sid) = filter.sensor_id {
        q = q.bind(sid);
    }
    if let Some(ts) = filter.timerange_start {
        q = q.bind(ts);
    }
    if let Some(te) = filter.timerange_end {
        q = q.bind(te);
    }
    q = q.bind(per_page).bind(offset);

    Ok(q.fetch_all(pool).await?)
}

pub async fn update_alert_status(
    pool: &PgPool,
    id: Uuid,
    status: &str,
    user_id: Option<Uuid>,
    assigned_to: Option<Uuid>,
    update_assignment: bool,
) -> Result<Option<Alert>> {
    let alert = sqlx::query_as::<_, Alert>(
        "UPDATE alerts 
         SET status = $1,
             assigned_to = CASE WHEN $5 THEN $2 ELSE assigned_to END,
             acknowledged_by = CASE WHEN $1 IN ('acknowledged', 'investigating') AND acknowledged_by IS NULL THEN $3 ELSE acknowledged_by END,
             acknowledged_at = CASE WHEN $1 IN ('acknowledged', 'investigating') AND acknowledged_at IS NULL THEN now() ELSE acknowledged_at END,
             resolved_by = CASE WHEN $1 IN ('resolved', 'dismissed') AND resolved_by IS NULL THEN $3 ELSE resolved_by END,
             resolved_at = CASE WHEN $1 IN ('resolved', 'dismissed') AND resolved_at IS NULL THEN now() ELSE resolved_at END,
             updated_at = now()
         WHERE id = $4
         RETURNING id, rule_id, sensor_id, event_id, status, severity, title, description,
                   source_ip::inet, dest_ip::inet, raw_data, assigned_to,
                   acknowledged_by, acknowledged_at, resolved_by, resolved_at,
                   created_at, updated_at"
    )
    .bind(status)
    .bind(assigned_to)
    .bind(user_id)
    .bind(id)
    .bind(update_assignment)
    .fetch_optional(pool)
    .await?;

    Ok(alert)
}

pub async fn get_alert_detail(pool: &PgPool, id: Uuid) -> Result<Option<AlertDetail>> {
    let alert = sqlx::query_as::<_, Alert>(
        "SELECT id, rule_id, sensor_id, event_id, status, severity, title, description,
                source_ip::inet, dest_ip::inet, raw_data, assigned_to,
                acknowledged_by, acknowledged_at, resolved_by, resolved_at,
                created_at, updated_at
         FROM alerts WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    if let Some(alert) = alert {
        let mut rule_name = None;
        let mut rule_description = None;
        let mut rule_yaml = None;
        if let Some(rid) = alert.rule_id {
            if let Ok(Some(rule)) = get_rule(pool, rid).await {
                rule_name = Some(rule.name.clone());
                rule_description = rule.description.clone();
                let condition_json =
                    serde_json::to_string_pretty(&rule.condition).unwrap_or_default();
                rule_yaml = Some(format!(
                    "name: {}\nseverity: {}\ncooldown_secs: {}\ncondition: |\n  {}",
                    rule.name,
                    rule.severity,
                    rule.cooldown_secs,
                    condition_json.replace('\n', "\n  ")
                ));
            }
        }

        let mut event_details = None;
        if let Some(eid) = alert.event_id {
            let event: Option<Event> = sqlx::query_as(
                "SELECT id, sensor_id, event_type, severity, title, description,
                        source_ip::inet, dest_ip::inet, protocol, port, raw_data, tags, timestamp
                 FROM events WHERE id = $1",
            )
            .bind(eid)
            .fetch_optional(pool)
            .await?;
            if let Some(e) = event {
                event_details = Some(serde_json::to_value(e)?);
            }
        }

        let mut assigned_username = None;
        if let Some(uid) = alert.assigned_to {
            assigned_username = sqlx::query_scalar("SELECT username FROM users WHERE id = $1")
                .bind(uid)
                .fetch_optional(pool)
                .await?;
        }
        let mut acknowledged_username = None;
        if let Some(uid) = alert.acknowledged_by {
            acknowledged_username = sqlx::query_scalar("SELECT username FROM users WHERE id = $1")
                .bind(uid)
                .fetch_optional(pool)
                .await?;
        }
        let mut resolved_username = None;
        if let Some(uid) = alert.resolved_by {
            resolved_username = sqlx::query_scalar("SELECT username FROM users WHERE id = $1")
                .bind(uid)
                .fetch_optional(pool)
                .await?;
        }

        Ok(Some(AlertDetail {
            alert,
            rule_name,
            rule_description,
            rule_yaml,
            event_details,
            assigned_username,
            acknowledged_username,
            resolved_username,
        }))
    } else {
        Ok(None)
    }
}

pub async fn get_rule(pool: &PgPool, id: Uuid) -> Result<Option<AlertRule>> {
    Ok(sqlx::query_as::<_, AlertRule>(
        "SELECT id, name, description, enabled, severity, condition, actions, cooldown_secs,
                created_by, created_at, updated_at
         FROM alert_rules WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?)
}

pub async fn get_alert_notes(pool: &PgPool, alert_id: Uuid) -> Result<Vec<AlertNote>> {
    Ok(sqlx::query_as::<_, AlertNote>(
        "SELECT n.id, n.alert_id, n.user_id, u.username, n.note, n.created_at \
         FROM alert_notes n \
         LEFT JOIN users u ON u.id = n.user_id \
         WHERE n.alert_id = $1 \
         ORDER BY n.created_at ASC",
    )
    .bind(alert_id)
    .fetch_all(pool)
    .await?)
}

pub async fn insert_alert_note(
    pool: &PgPool,
    alert_id: Uuid,
    user_id: Option<Uuid>,
    note: &str,
) -> Result<AlertNote> {
    let row = sqlx::query(
        "INSERT INTO alert_notes (alert_id, user_id, note) VALUES ($1, $2, $3) RETURNING id, created_at"
    )
    .bind(alert_id)
    .bind(user_id)
    .bind(note)
    .fetch_one(pool)
    .await?;

    let id: Uuid = row.get(0);
    let created_at: DateTime<Utc> = row.get(1);

    let username = if let Some(uid) = user_id {
        sqlx::query_scalar("SELECT username FROM users WHERE id = $1")
            .bind(uid)
            .fetch_optional(pool)
            .await?
    } else {
        None
    };

    Ok(AlertNote {
        id,
        alert_id,
        user_id,
        username,
        note: note.to_string(),
        created_at,
    })
}

pub async fn bulk_update_alerts_status(
    pool: &PgPool,
    ids: &[Uuid],
    status: &str,
    user_id: Option<Uuid>,
) -> Result<u64> {
    let mut tx = pool.begin().await?;
    let mut updated_count = 0;

    for id in ids {
        let query_str = match status {
            "acknowledged" | "investigating" => {
                if let Some(uid) = user_id {
                    sqlx::query("UPDATE alerts SET status = $1, acknowledged_by = $2, acknowledged_at = now(), updated_at = now() WHERE id = $3")
                        .bind(status).bind(uid).bind(*id)
                } else {
                    sqlx::query("UPDATE alerts SET status = $1, updated_at = now() WHERE id = $2")
                        .bind(status)
                        .bind(*id)
                }
            }
            "resolved" | "dismissed" => {
                if let Some(uid) = user_id {
                    sqlx::query("UPDATE alerts SET status = $1, resolved_by = $2, resolved_at = now(), updated_at = now() WHERE id = $3")
                        .bind(status).bind(uid).bind(*id)
                } else {
                    sqlx::query("UPDATE alerts SET status = $1, updated_at = now() WHERE id = $2")
                        .bind(status)
                        .bind(*id)
                }
            }
            _ => sqlx::query("UPDATE alerts SET status = $1, updated_at = now() WHERE id = $2")
                .bind(status)
                .bind(*id),
        };

        let res = query_str.execute(&mut *tx).await?;
        updated_count += res.rows_affected();
    }

    tx.commit().await?;
    Ok(updated_count)
}

// ── Rules ──

pub async fn create_rule(
    pool: &PgPool,
    rule: &CreateRule,
    user_id: Option<Uuid>,
) -> Result<AlertRule> {
    Ok(sqlx::query_as::<_, AlertRule>(
        "INSERT INTO alert_rules (name, description, enabled, severity, condition, actions, cooldown_secs, created_by)
         VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7, $8)
         RETURNING id, name, description, enabled, severity, condition, actions, cooldown_secs,
                   created_by, created_at, updated_at",
    )
    .bind(&rule.name)
    .bind(&rule.description)
    .bind(rule.enabled.unwrap_or(true))
    .bind(rule.severity.as_deref().unwrap_or("medium"))
    .bind(&rule.condition)
    .bind(&rule.actions)
    .bind(rule.cooldown_secs.unwrap_or(300))
    .bind(user_id)
    .fetch_one(pool)
    .await?)
}

pub async fn update_rule(pool: &PgPool, id: Uuid, rule: &CreateRule) -> Result<Option<AlertRule>> {
    Ok(sqlx::query_as::<_, AlertRule>(
        "UPDATE alert_rules SET name = $1, description = $2, enabled = $3, severity = $4,
                condition = $5::jsonb, actions = $6::jsonb, cooldown_secs = $7, updated_at = now()
         WHERE id = $8
         RETURNING id, name, description, enabled, severity, condition, actions, cooldown_secs,
                   created_by, created_at, updated_at",
    )
    .bind(&rule.name)
    .bind(&rule.description)
    .bind(rule.enabled.unwrap_or(true))
    .bind(rule.severity.as_deref().unwrap_or("medium"))
    .bind(&rule.condition)
    .bind(&rule.actions)
    .bind(rule.cooldown_secs.unwrap_or(300))
    .bind(id)
    .fetch_optional(pool)
    .await?)
}

pub async fn delete_rule(pool: &PgPool, id: Uuid) -> Result<bool> {
    let r = sqlx::query("DELETE FROM alert_rules WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(r.rows_affected() > 0)
}

pub async fn list_rules(pool: &PgPool) -> Result<Vec<AlertRule>> {
    Ok(sqlx::query_as::<_, AlertRule>(
        "SELECT id, name, description, enabled, severity, condition, actions, cooldown_secs,
                created_by, created_at, updated_at
         FROM alert_rules ORDER BY name",
    )
    .fetch_all(pool)
    .await?)
}

// ── Dashboard ──

pub async fn dashboard_summary(pool: &PgPool) -> Result<DashboardSummary> {
    let active_alerts: (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM alerts WHERE status IN ('open','acknowledged','investigating')",
    )
    .fetch_one(pool)
    .await?;

    let total_sensors: (i64,) = sqlx::query_as("SELECT COUNT(*)::bigint FROM sensors")
        .fetch_one(pool)
        .await?;

    let online_sensors: (i64,) =
        sqlx::query_as("SELECT COUNT(*)::bigint FROM sensors WHERE status = 'online'")
            .fetch_one(pool)
            .await?;

    let events_per_second: (Option<f64>,) = sqlx::query_as(
        "SELECT CASE WHEN COUNT(*) > 0 AND EXTRACT(EPOCH FROM max(timestamp) - min(timestamp)) > 0
                THEN COUNT(*)::float8 / EXTRACT(EPOCH FROM max(timestamp) - min(timestamp))
                ELSE 0 END
         FROM events WHERE timestamp > now() - interval '5 minutes'",
    )
    .fetch_one(pool)
    .await?;

    let alerts_by_severity: Vec<CountBySeverity> = sqlx::query_as::<_, CountBySeverity>(
        "SELECT severity, COUNT(*)::bigint as count
         FROM alerts WHERE created_at > now() - interval '24 hours'
         GROUP BY severity ORDER BY severity",
    )
    .fetch_all(pool)
    .await?;

    let top_threats: Vec<TopThreat> = sqlx::query_as::<_, TopThreat>(
        "SELECT indicator_type, value, confidence, last_seen
         FROM threat_indicators ORDER BY last_seen DESC LIMIT 10",
    )
    .fetch_all(pool)
    .await?;

    // Extended metrics queries
    let total_events_24h: (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM events WHERE timestamp > now() - interval '24 hours'",
    )
    .fetch_one(pool)
    .await?;

    let open_alerts_l1: (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM alerts WHERE status = 'open' AND severity IN ('low','info')",
    )
    .fetch_one(pool)
    .await?;

    let open_alerts_l2: (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM alerts WHERE status = 'open' AND severity = 'medium'",
    )
    .fetch_one(pool)
    .await?;

    let open_alerts_l3: (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM alerts WHERE status = 'open' AND severity IN ('high','critical')",
    )
    .fetch_one(pool)
    .await?;

    let alert_times: Vec<(DateTime<Utc>,)> = sqlx::query_as(
        "SELECT created_at FROM alerts WHERE created_at > now() - interval '1 hour'",
    )
    .fetch_all(pool)
    .await?;

    let mut alert_trend_1h = vec![0i64; 12];
    let now_utc = Utc::now();
    for (t,) in alert_times {
        let diff = now_utc.signed_duration_since(t).num_minutes();
        if (0..60).contains(&diff) {
            let bin = (diff / 5) as usize;
            if bin < 12 {
                alert_trend_1h[11 - bin] += 1;
            }
        }
    }

    let top_attackers_5: Vec<IpCount> = sqlx::query_as(
        "SELECT source_ip::text as ip, COUNT(*)::bigint as count \
         FROM events WHERE source_ip IS NOT NULL AND timestamp > now() - interval '24 hours' \
         GROUP BY source_ip ORDER BY count DESC LIMIT 5",
    )
    .fetch_all(pool)
    .await?;

    let top_targets_5: Vec<IpCount> = sqlx::query_as(
        "SELECT dest_ip::text as ip, COUNT(*)::bigint as count \
         FROM events WHERE dest_ip IS NOT NULL AND timestamp > now() - interval '24 hours' \
         GROUP BY dest_ip ORDER BY count DESC LIMIT 5",
    )
    .fetch_all(pool)
    .await?;

    let protocol_distribution: Vec<ProtocolCount> = sqlx::query_as(
        "SELECT COALESCE(protocol, 'unknown') as protocol, COUNT(*)::bigint as count \
         FROM events WHERE timestamp > now() - interval '24 hours' \
         GROUP BY protocol ORDER BY count DESC",
    )
    .fetch_all(pool)
    .await?;

    let aggregate_throughput_bps: (Option<i64>,) = sqlx::query_as(
        "SELECT SUM(capture_throughput_bps)::bigint \
         FROM ( \
             SELECT DISTINCT ON (sensor_id) capture_throughput_bps \
             FROM sensor_heartbeats \
             ORDER BY sensor_id, received_at DESC \
         ) last_heartbeats",
    )
    .fetch_one(pool)
    .await?;

    let mttr_seconds_7d: (Option<f64>,) = sqlx::query_as(
        "SELECT AVG(EXTRACT(EPOCH FROM (resolved_at - created_at)))::float8 \
         FROM alerts \
         WHERE status = 'resolved' AND resolved_at > now() - interval '7 days'",
    )
    .fetch_one(pool)
    .await?;

    let false_positive_rate_7d: (Option<f64>,) = sqlx::query_as(
        "SELECT \
            CASE WHEN COUNT(*) > 0 \
                 THEN (COUNT(*) FILTER (WHERE status = 'dismissed'))::float8 / COUNT(*)::float8 \
                 ELSE 0.0 END \
         FROM alerts \
         WHERE created_at > now() - interval '7 days'",
    )
    .fetch_one(pool)
    .await?;

    Ok(DashboardSummary {
        active_alerts: active_alerts.0,
        events_per_second: events_per_second.0.unwrap_or(0.0),
        total_sensors: total_sensors.0,
        online_sensors: online_sensors.0,
        top_talkers: Vec::new(),
        top_threats,
        alerts_by_severity,
        total_events_24h: total_events_24h.0,
        open_alerts_l1: open_alerts_l1.0,
        open_alerts_l2: open_alerts_l2.0,
        open_alerts_l3: open_alerts_l3.0,
        alert_trend_1h,
        top_attackers_5,
        top_targets_5,
        protocol_distribution,
        aggregate_throughput_bps: aggregate_throughput_bps.0.unwrap_or(0),
        mttr_seconds_7d: mttr_seconds_7d.0.unwrap_or(0.0),
        false_positive_rate_7d: false_positive_rate_7d.0.unwrap_or(0.0),
    })
}

// ── Sensor Configuration Queries ──

pub async fn get_sensor_config(pool: &PgPool, sensor_id: Uuid) -> Result<Option<SensorConfig>> {
    Ok(sqlx::query_as::<_, SensorConfig>(
        "SELECT sensor_id, config_data, version, updated_at, updated_by
         FROM sensor_configs WHERE sensor_id = $1",
    )
    .bind(sensor_id)
    .fetch_optional(pool)
    .await?)
}

pub async fn update_sensor_config(
    pool: &PgPool,
    sensor_id: Uuid,
    config_data: &str,
    user_id: Option<Uuid>,
) -> Result<SensorConfig> {
    let mut tx = pool.begin().await?;

    let current_version: Option<(i32,)> =
        sqlx::query_as("SELECT version FROM sensor_configs WHERE sensor_id = $1")
            .bind(sensor_id)
            .fetch_optional(&mut *tx)
            .await?;

    let next_version = current_version.map(|v| v.0 + 1).unwrap_or(1);

    let config = sqlx::query_as::<_, SensorConfig>(
        "INSERT INTO sensor_configs (sensor_id, config_data, version, updated_at, updated_by)
         VALUES ($1, $2, $3, now(), $4)
         ON CONFLICT (sensor_id) DO UPDATE
         SET config_data = EXCLUDED.config_data,
             version = EXCLUDED.version,
             updated_at = now(),
             updated_by = EXCLUDED.updated_by
         RETURNING sensor_id, config_data, version, updated_at, updated_by",
    )
    .bind(sensor_id)
    .bind(config_data)
    .bind(next_version)
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;

    sqlx::query(
        "INSERT INTO sensor_config_history (sensor_id, config_data, version, created_at, created_by)
         VALUES ($1, $2, $3, now(), $4)"
    )
    .bind(sensor_id)
    .bind(config_data)
    .bind(next_version)
    .bind(user_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(config)
}

pub async fn get_sensor_config_history(
    pool: &PgPool,
    sensor_id: Uuid,
) -> Result<Vec<SensorConfigHistory>> {
    Ok(sqlx::query_as::<_, SensorConfigHistory>(
        "SELECT id, sensor_id, config_data, version, created_at, created_by
         FROM sensor_config_history WHERE sensor_id = $1 ORDER BY version DESC",
    )
    .bind(sensor_id)
    .fetch_all(pool)
    .await?)
}

pub async fn get_sensor_config_version(
    pool: &PgPool,
    sensor_id: Uuid,
    version: i32,
) -> Result<Option<SensorConfigHistory>> {
    Ok(sqlx::query_as::<_, SensorConfigHistory>(
        "SELECT id, sensor_id, config_data, version, created_at, created_by
         FROM sensor_config_history WHERE sensor_id = $1 AND version = $2",
    )
    .bind(sensor_id)
    .bind(version)
    .fetch_optional(pool)
    .await?)
}

pub async fn insert_audit_log(
    pool: &PgPool,
    user_id: Option<Uuid>,
    action: &str,
    resource_type: &str,
    resource_id: Option<Uuid>,
    details: serde_json::Value,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO audit_log (user_id, action, resource_type, resource_id, details)
         VALUES ($1, $2, $3, $4, $5::jsonb)",
    )
    .bind(user_id)
    .bind(action)
    .bind(resource_type)
    .bind(resource_id)
    .bind(details)
    .execute(pool)
    .await?;
    Ok(())
}

/// The columns of an alert that the caller supplies.
///
/// Grouped rather than passed as ten positional arguments: five of them are
/// `Option`s of two types, so a pair swapped at a call site would still
/// compile and would quietly file alerts against the wrong sensor.
pub struct NewAlert<'a> {
    pub rule_id: Option<Uuid>,
    pub sensor_id: Option<Uuid>,
    pub event_id: Option<Uuid>,
    pub severity: &'a str,
    pub title: &'a str,
    pub description: Option<&'a str>,
    pub source_ip: Option<&'a str>,
    pub dest_ip: Option<&'a str>,
    pub raw_data: Option<&'a serde_json::Value>,
}

pub async fn insert_alert(pool: &PgPool, alert: NewAlert<'_>) -> Result<Alert> {
    let NewAlert {
        rule_id,
        sensor_id,
        event_id,
        severity,
        title,
        description,
        source_ip,
        dest_ip,
        raw_data,
    } = alert;
    Ok(sqlx::query_as::<_, Alert>(
        // The column list carries names only. It used to read
        // `source_ip::inet, dest_ip::inet` here, which Postgres rejects as a
        // syntax error — a cast is not a column name. The casts belong in the
        // VALUES clause, where they already were, and where the neighbouring
        // `events` and `sensors` inserts put theirs.
        "INSERT INTO alerts (rule_id, sensor_id, event_id, status, severity, title, description, source_ip, dest_ip, raw_data)
         VALUES ($1, $2, $3, 'open', $4, $5, $6, $7::inet, $8::inet, $9::jsonb)
         RETURNING id, rule_id, sensor_id, event_id, status, severity, title, description,
                    source_ip::inet, dest_ip::inet, raw_data,
                    acknowledged_by, acknowledged_at, resolved_by, resolved_at,
                    created_at, updated_at",
    )
    .bind(rule_id)
    .bind(sensor_id)
    .bind(event_id)
    .bind(severity)
    .bind(title)
    .bind(description)
    .bind(source_ip)
    .bind(dest_ip)
    .bind(raw_data)
    .fetch_one(pool)
    .await?)
}

// ── Threat Hunting SQL Compiler and Helpers ──

impl HuntRule {
    pub fn to_sql(&self, idx: &mut u32, params: &mut Vec<String>) -> Result<String, String> {
        match self {
            HuntRule::Group { logical, rules } => {
                if rules.is_empty() {
                    return Ok("1=1".to_string());
                }
                let log_op = logical.to_uppercase();
                if log_op == "NOT" {
                    let mut clauses = Vec::new();
                    for rule in rules {
                        clauses.push(rule.to_sql(idx, params)?);
                    }
                    return Ok(format!("(NOT ({}))", clauses.join(" OR ")));
                }
                let op_join = match log_op.as_str() {
                    "AND" => " AND ",
                    "OR" => " OR ",
                    _ => return Err(format!("Invalid logical operator: {}", logical)),
                };
                let mut clauses = Vec::new();
                for rule in rules {
                    clauses.push(rule.to_sql(idx, params)?);
                }
                Ok(format!("(({}))", clauses.join(op_join)))
            }
            HuntRule::Condition {
                field,
                operator,
                value,
            } => {
                let col_name = match field.as_str() {
                    "source_ip" => "source_ip::text",
                    "dest_ip" => "dest_ip::text",
                    "protocol" => "protocol",
                    "port" => "port::text",
                    "event_type" => "event_type",
                    "severity" => "severity",
                    "title" => "title",
                    "description" => "description",
                    _ => return Err(format!("Invalid search field: {}", field)),
                };

                let val_str = match value {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Number(n) => n.to_string(),
                    serde_json::Value::Bool(b) => b.to_string(),
                    serde_json::Value::Null => "null".to_string(),
                    _ => return Err(format!("Invalid value type for field: {}", field)),
                };

                let sql_op = match operator.as_str() {
                    "equals" | "eq" => "=",
                    "not_equals" | "neq" => "!=",
                    "contains" => "LIKE",
                    "not_contains" => "NOT LIKE",
                    "greater_than" | "gt" => ">",
                    "less_than" | "lt" => "<",
                    _ => return Err(format!("Invalid operator: {}", operator)),
                };

                let bind_val = if sql_op.contains("LIKE") {
                    format!("%{}%", val_str)
                } else {
                    val_str
                };

                let param_placeholder = format!("${}", idx);
                *idx += 1;
                params.push(bind_val);

                Ok(format!("({} {} {})", col_name, sql_op, param_placeholder))
            }
        }
    }
}

pub async fn hunt_events(pool: &PgPool, payload: &HuntQueryPayload) -> Result<Vec<Event>> {
    let page = payload.page.unwrap_or(1).max(1);
    let per_page = payload.per_page.unwrap_or(50).clamp(1, 500);
    let offset = (page - 1) * per_page;

    let mut sql = String::from(
        "SELECT id, sensor_id, event_type, severity, title, description,
                source_ip::inet, dest_ip::inet, protocol, port, raw_data, tags, timestamp
         FROM events WHERE 1=1",
    );

    let mut idx = 1u32;
    let mut params = Vec::new();

    if let Some(ts) = payload.timerange_start {
        sql.push_str(&format!(" AND timestamp >= ${}", idx));
        idx += 1;
        params.push(ts.to_rfc3339());
    }

    if let Some(te) = payload.timerange_end {
        sql.push_str(&format!(" AND timestamp <= ${}", idx));
        idx += 1;
        params.push(te.to_rfc3339());
    }

    if let Some(ref filter) = payload.filter {
        if let Ok(filter_sql) = filter.to_sql(&mut idx, &mut params) {
            sql.push_str(&format!(" AND {}", filter_sql));
        }
    }

    sql.push_str(" ORDER BY timestamp DESC");
    sql.push_str(&format!(" LIMIT ${} OFFSET ${}", idx, idx + 1));

    let mut q = sqlx::query_as::<_, Event>(&sql);
    for p in params {
        q = q.bind(p);
    }
    q = q.bind(per_page).bind(offset);

    Ok(q.fetch_all(pool).await?)
}

pub async fn hunt_histogram(
    pool: &PgPool,
    payload: &HistogramPayload,
) -> Result<Vec<HistogramBucket>> {
    let bucket_size = payload.bucket_size_secs.unwrap_or(3600).max(10);

    let mut sql = "SELECT to_timestamp(floor(extract(epoch from timestamp) / $1) * $1) AT TIME ZONE 'UTC' as bucket_time,
                count(*)::bigint as count
         FROM events WHERE 1=1".to_string();

    let mut idx = 2u32;
    let mut params = vec![bucket_size.to_string()];

    if let Some(ts) = payload.timerange_start {
        sql.push_str(&format!(" AND timestamp >= ${}", idx));
        idx += 1;
        params.push(ts.to_rfc3339());
    }
    if let Some(te) = payload.timerange_end {
        sql.push_str(&format!(" AND timestamp <= ${}", idx));
        idx += 1;
        params.push(te.to_rfc3339());
    }

    if let Some(ref filter) = payload.filter {
        if let Ok(filter_sql) = filter.to_sql(&mut idx, &mut params) {
            sql.push_str(&format!(" AND {}", filter_sql));
        }
    }

    sql.push_str(" GROUP BY bucket_time ORDER BY bucket_time ASC");

    let mut q = sqlx::query(&sql);
    let mut first = true;
    for p in params {
        if first {
            q = q.bind(bucket_size);
            first = false;
        } else {
            q = q.bind(p);
        }
    }

    let rows = q.fetch_all(pool).await?;
    let mut buckets = Vec::new();
    for row in rows {
        let bucket_time: DateTime<Utc> = row.try_get("bucket_time")?;
        let count: i64 = row.try_get("count")?;
        buckets.push(HistogramBucket { bucket_time, count });
    }

    Ok(buckets)
}

pub async fn list_saved_searches(pool: &PgPool) -> Result<Vec<SavedSearch>> {
    Ok(sqlx::query_as::<_, SavedSearch>(
        "SELECT id, name, query_json, created_by, created_at, updated_at \
         FROM saved_searches \
         ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await?)
}

pub async fn get_saved_search(pool: &PgPool, id: Uuid) -> Result<Option<SavedSearch>> {
    Ok(sqlx::query_as::<_, SavedSearch>(
        "SELECT id, name, query_json, created_by, created_at, updated_at \
         FROM saved_searches \
         WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?)
}

pub async fn insert_saved_search(
    pool: &PgPool,
    name: &str,
    query_json: &serde_json::Value,
    user_id: Option<Uuid>,
) -> Result<SavedSearch> {
    Ok(sqlx::query_as::<_, SavedSearch>(
        "INSERT INTO saved_searches (name, query_json, created_by) \
         VALUES ($1, $2, $3) \
         RETURNING id, name, query_json, created_by, created_at, updated_at",
    )
    .bind(name)
    .bind(query_json)
    .bind(user_id)
    .fetch_one(pool)
    .await?)
}

// ── Reporting & Compliance Queries ──

pub async fn get_daily_soc_report(pool: &PgPool) -> Result<DailySocReport> {
    let total_events: (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM events WHERE timestamp > now() - interval '24 hours'",
    )
    .fetch_one(pool)
    .await?;
    let total_alerts: (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM alerts WHERE created_at > now() - interval '24 hours'",
    )
    .fetch_one(pool)
    .await?;

    let severities: Vec<CountBySeverity> = sqlx::query_as("SELECT severity, COUNT(*)::bigint as count FROM alerts WHERE created_at > now() - interval '24 hours' GROUP BY severity").fetch_all(pool).await?;
    let mut alerts_by_severity = std::collections::HashMap::new();
    for s in severities {
        alerts_by_severity.insert(s.severity, s.count);
    }

    let resolved: (i64,) = sqlx::query_as("SELECT COUNT(*)::bigint FROM alerts WHERE status = 'resolved' AND resolved_at > now() - interval '24 hours'").fetch_one(pool).await?;
    let dismissed: (i64,) = sqlx::query_as("SELECT COUNT(*)::bigint FROM alerts WHERE status = 'dismissed' AND resolved_at > now() - interval '24 hours'").fetch_one(pool).await?;

    let top_sensors: Vec<CountByEntity> = sqlx::query_as("SELECT COALESCE(s.name, e.sensor_id::text) as name, COUNT(*)::bigint as count FROM events e LEFT JOIN sensors s ON s.id = e.sensor_id WHERE e.timestamp > now() - interval '24 hours' GROUP BY s.name, e.sensor_id ORDER BY count DESC LIMIT 5").fetch_all(pool).await?;
    let top_rules: Vec<CountByEntity> = sqlx::query_as("SELECT COALESCE(r.name, a.rule_id::text) as name, COUNT(*)::bigint as count FROM alerts a LEFT JOIN alert_rules r ON r.id = a.rule_id WHERE a.created_at > now() - interval '24 hours' GROUP BY r.name, a.rule_id ORDER BY count DESC LIMIT 5").fetch_all(pool).await?;

    let mttr: (Option<f64>,) = sqlx::query_as("SELECT AVG(EXTRACT(EPOCH FROM (resolved_at - created_at)))::float8 FROM alerts WHERE status = 'resolved' AND resolved_at > now() - interval '24 hours'").fetch_one(pool).await?;
    let mack: (Option<f64>,) = sqlx::query_as("SELECT AVG(EXTRACT(EPOCH FROM (acknowledged_at - created_at)))::float8 FROM alerts WHERE acknowledged_at > now() - interval '24 hours'").fetch_one(pool).await?;

    let new_ips_rows: Vec<(String,)> = sqlx::query_as("SELECT DISTINCT source_ip::text FROM events WHERE source_ip IS NOT NULL AND timestamp > now() - interval '24 hours' LIMIT 10").fetch_all(pool).await?;
    let new_ips = new_ips_rows.into_iter().map(|(ip,)| ip).collect();

    let new_protos_rows: Vec<(Option<String>,)> = sqlx::query_as("SELECT DISTINCT protocol FROM events WHERE protocol IS NOT NULL AND timestamp > now() - interval '24 hours' LIMIT 5").fetch_all(pool).await?;
    let new_protocols = new_protos_rows.into_iter().filter_map(|(p,)| p).collect();

    Ok(DailySocReport {
        total_events: total_events.0,
        total_alerts: total_alerts.0,
        alerts_by_severity,
        resolved_alerts: resolved.0,
        false_positive_alerts: dismissed.0,
        top_sensors,
        top_rules,
        new_ips,
        new_protocols,
        mttr_seconds: mttr.0.unwrap_or(0.0),
        mean_ack_seconds: mack.0.unwrap_or(0.0),
    })
}

/// Average the scores that were measured, ignoring the ones that were not.
///
/// Two wrong answers this avoids. Counting an unmeasured framework as a number
/// is how `overall_score` used to include the hardcoded 92.0 and 90.0 for GDPR
/// and KVKK — two fifths of the headline figure came from constants. Counting
/// it as zero is equally untrue and reads as a failing grade. Nothing measured
/// at all is `None`, which the dashboard draws as "—" rather than as 0%.
fn mean_of_measured(scores: &[Option<f64>]) -> Option<f64> {
    let measured: Vec<f64> = scores.iter().copied().flatten().collect();
    (!measured.is_empty()).then(|| measured.iter().sum::<f64>() / measured.len() as f64)
}

pub async fn get_compliance_report(pool: &PgPool) -> Result<ComplianceReport> {
    let total_30d: (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM alerts WHERE created_at > now() - interval '30 days'",
    )
    .fetch_one(pool)
    .await?;
    let in_sla_30d: (i64,) = sqlx::query_as("SELECT COUNT(*)::bigint FROM alerts WHERE created_at > now() - interval '30 days' AND (acknowledged_at IS NOT NULL AND EXTRACT(EPOCH FROM (acknowledged_at - created_at)) < 3600)").fetch_one(pool).await?;
    // No alerts in the window is not "94.5% compliant", which is what this
    // returned. It is nothing to measure, and the report says so.
    let iso27001_score =
        (total_30d.0 > 0).then(|| (in_sla_30d.0 as f64) / (total_30d.0 as f64) * 100.0);

    let cleartext_count: (i64,) = sqlx::query_as("SELECT COUNT(*)::bigint FROM events WHERE protocol IN ('http', 'ftp', 'telnet') AND timestamp > now() - interval '30 days'").fetch_one(pool).await?;
    let secure_count: (i64,) = sqlx::query_as("SELECT COUNT(*)::bigint FROM events WHERE protocol IN ('https', 'tls', 'ssh') AND timestamp > now() - interval '30 days'").fetch_one(pool).await?;
    let total_proto = cleartext_count.0 + secure_count.0;
    let pci_dss_score =
        (total_proto > 0).then(|| (secure_count.0 as f64) / (total_proto as f64) * 100.0);

    let online_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*)::bigint FROM sensors WHERE status = 'online'")
            .fetch_one(pool)
            .await?;
    let total_sensors_count: (i64,) = sqlx::query_as("SELECT COUNT(*)::bigint FROM sensors")
        .fetch_one(pool)
        .await?;
    // A fleet with no sensors registered is not 100% online.
    let nis2_score = (total_sensors_count.0 > 0)
        .then(|| (online_count.0 as f64) / (total_sensors_count.0 as f64) * 100.0);

    // GDPR and KVKK were 92.0 and 90.0 — constants, never derived from
    // anything, that the dashboard drew as green progress bars. Whether
    // personal data is processed lawfully is a question about consent,
    // retention and purpose, none of which is in a packet header. netscope has
    // no measurement to offer here, and saying nothing is the honest answer.
    let gdpr_score = None;
    let kvkk_score = None;

    let overall_score = mean_of_measured(&[
        iso27001_score,
        pci_dss_score,
        nis2_score,
        gdpr_score,
        kvkk_score,
    ]);

    let unmeasured = "Not measured — netscope has no network-visible evidence for this framework.";

    Ok(ComplianceReport {
        overall_score,
        gdpr_score,
        gdpr_details: unmeasured.to_string(),
        kvkk_score,
        kvkk_details: unmeasured.to_string(),
        iso27001_score,
        // The sample size travels with the number: 100% of three alerts and
        // 100% of thirty thousand render identically without it.
        iso27001_details: match iso27001_score {
            Some(pct) => format!(
                "Evidence towards A.5.25: {}/{} alerts in the last 30 days were acknowledged within 1h ({pct:.1}%).",
                in_sla_30d.0, total_30d.0
            ),
            None => "No alerts in the last 30 days, so acknowledgement SLA is not measurable."
                .to_string(),
        },
        pci_dss_score,
        pci_dss_details: match pci_dss_score {
            Some(pct) => format!(
                "Evidence towards Req 4: {}/{} observed flows used an encrypted protocol ({pct:.1}%). Counts http/ftp/telnet against https/tls/ssh only.",
                secure_count.0, total_proto
            ),
            None => "No http/ftp/telnet or https/tls/ssh flows in the last 30 days, so transport security is not measurable.".to_string(),
        },
        nis2_score,
        nis2_details: match nis2_score {
            Some(pct) => format!(
                "Evidence towards Art. 21 monitoring: {}/{} sensors online ({pct:.1}%).",
                online_count.0, total_sensors_count.0
            ),
            None => "No sensors are registered, so fleet coverage is not measurable.".to_string(),
        },
        generated_at: Utc::now(),
    })
}

pub async fn list_scheduled_reports(pool: &PgPool) -> Result<Vec<ScheduledReport>> {
    Ok(sqlx::query_as::<_, ScheduledReport>(
        "SELECT id, report_type, recipients, schedule, enabled, created_at FROM scheduled_reports ORDER BY created_at DESC"
    )
    .fetch_all(pool)
    .await?)
}

pub async fn insert_scheduled_report(
    pool: &PgPool,
    report_type: &str,
    recipients: &str,
    schedule: &str,
) -> Result<ScheduledReport> {
    Ok(sqlx::query_as::<_, ScheduledReport>(
        "INSERT INTO scheduled_reports (report_type, recipients, schedule) VALUES ($1, $2, $3) RETURNING id, report_type, recipients, schedule, enabled, created_at"
    )
    .bind(report_type)
    .bind(recipients)
    .bind(schedule)
    .fetch_one(pool)
    .await?)
}

pub async fn delete_scheduled_report(pool: &PgPool, id: Uuid) -> Result<bool> {
    let res = sqlx::query("DELETE FROM scheduled_reports WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected() > 0)
}

// ── SOAR & Incident Response Queries ──

pub async fn list_cases(pool: &PgPool) -> Result<Vec<Case>> {
    Ok(sqlx::query_as::<_, Case>(
        "SELECT id, title, description, status, severity, assigned_to, created_at, updated_at FROM cases ORDER BY created_at DESC"
    )
    .fetch_all(pool)
    .await?)
}

pub async fn get_case_detail(pool: &PgPool, id: Uuid) -> Result<Option<Case>> {
    Ok(sqlx::query_as::<_, Case>(
        "SELECT id, title, description, status, severity, assigned_to, created_at, updated_at FROM cases WHERE id = $1"
    )
    .bind(id)
    .fetch_optional(pool)
    .await?)
}

pub async fn get_case_alerts(pool: &PgPool, case_id: Uuid) -> Result<Vec<Alert>> {
    Ok(sqlx::query_as::<_, Alert>(
        "SELECT a.id, a.rule_id, a.sensor_id, a.event_id, a.status, a.severity, a.title, a.description, \
                a.source_ip::inet, a.dest_ip::inet, a.raw_data, \
                a.acknowledged_by, a.acknowledged_at, a.resolved_by, a.resolved_at, \
                a.created_at, a.updated_at \
         FROM alerts a \
         JOIN case_alerts ca ON ca.alert_id = a.id \
         WHERE ca.case_id = $1"
    )
    .bind(case_id)
    .fetch_all(pool)
    .await?)
}

pub async fn insert_case(
    pool: &PgPool,
    title: &str,
    description: Option<&str>,
    severity: &str,
    assigned_to: Option<Uuid>,
) -> Result<Case> {
    Ok(sqlx::query_as::<_, Case>(
        "INSERT INTO cases (title, description, severity, assigned_to) \
         VALUES ($1, $2, $3, $4) \
         RETURNING id, title, description, status, severity, assigned_to, created_at, updated_at",
    )
    .bind(title)
    .bind(description)
    .bind(severity)
    .bind(assigned_to)
    .fetch_one(pool)
    .await?)
}

pub async fn link_alert_to_case(pool: &PgPool, case_id: Uuid, alert_id: Uuid) -> Result<()> {
    sqlx::query(
        "INSERT INTO case_alerts (case_id, alert_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(case_id)
    .bind(alert_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn update_case_status(pool: &PgPool, id: Uuid, status: &str) -> Result<Option<Case>> {
    Ok(sqlx::query_as::<_, Case>(
        "UPDATE cases SET status = $1, updated_at = now() WHERE id = $2 RETURNING id, title, description, status, severity, assigned_to, created_at, updated_at"
    )
    .bind(status)
    .bind(id)
    .fetch_optional(pool)
    .await?)
}

// ── Evidence Locker Queries ──

pub async fn list_evidence(pool: &PgPool, case_id: Uuid) -> Result<Vec<Evidence>> {
    Ok(sqlx::query_as::<_, Evidence>(
        "SELECT id, case_id, evidence_type, filename, filepath, added_by, added_at, checksum FROM evidence_locker WHERE case_id = $1 ORDER BY added_at DESC"
    )
    .bind(case_id)
    .fetch_all(pool)
    .await?)
}

pub async fn insert_evidence(
    pool: &PgPool,
    case_id: Uuid,
    evidence_type: &str,
    filename: &str,
    filepath: &str,
    added_by: Option<Uuid>,
    checksum: Option<&str>,
) -> Result<Evidence> {
    Ok(sqlx::query_as::<_, Evidence>(
        "INSERT INTO evidence_locker (case_id, evidence_type, filename, filepath, added_by, checksum) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         RETURNING id, case_id, evidence_type, filename, filepath, added_by, added_at, checksum"
    )
    .bind(case_id)
    .bind(evidence_type)
    .bind(filename)
    .bind(filepath)
    .bind(added_by)
    .bind(checksum)
    .fetch_one(pool)
    .await?)
}

// ── Chain of Custody Queries ──

pub async fn list_custody_logs(pool: &PgPool, case_id: Uuid) -> Result<Vec<ChainOfCustody>> {
    Ok(sqlx::query_as::<_, ChainOfCustody>(
        "SELECT coc.id, coc.evidence_id, coc.action, coc.performed_by, coc.performed_at, coc.notes \
         FROM chain_of_custody coc \
         JOIN evidence_locker el ON el.id = coc.evidence_id \
         WHERE el.case_id = $1 ORDER BY coc.performed_at DESC"
    )
    .bind(case_id)
    .fetch_all(pool)
    .await?)
}

pub async fn insert_custody_log(
    pool: &PgPool,
    evidence_id: Uuid,
    action: &str,
    performed_by: Option<Uuid>,
    notes: Option<&str>,
) -> Result<ChainOfCustody> {
    Ok(sqlx::query_as::<_, ChainOfCustody>(
        "INSERT INTO chain_of_custody (evidence_id, action, performed_by, notes) \
         VALUES ($1, $2, $3, $4) \
         RETURNING id, evidence_id, action, performed_by, performed_at, notes",
    )
    .bind(evidence_id)
    .bind(action)
    .bind(performed_by)
    .bind(notes)
    .fetch_one(pool)
    .await?)
}

// ── Incident Timeline Queries ──

pub async fn list_timeline_events(pool: &PgPool, case_id: Uuid) -> Result<Vec<IncidentTimeline>> {
    Ok(sqlx::query_as::<_, IncidentTimeline>(
        "SELECT id, case_id, event_type, description, timestamp, actor FROM incident_timeline WHERE case_id = $1 ORDER BY timestamp ASC"
    )
    .bind(case_id)
    .fetch_all(pool)
    .await?)
}

pub async fn insert_timeline_event(
    pool: &PgPool,
    case_id: Uuid,
    event_type: &str,
    description: &str,
    actor: Option<Uuid>,
) -> Result<IncidentTimeline> {
    Ok(sqlx::query_as::<_, IncidentTimeline>(
        "INSERT INTO incident_timeline (case_id, event_type, description, actor) \
         VALUES ($1, $2, $3, $4) \
         RETURNING id, case_id, event_type, description, timestamp, actor",
    )
    .bind(case_id)
    .bind(event_type)
    .bind(description)
    .bind(actor)
    .fetch_one(pool)
    .await?)
}

// ── Playbook CRUD Queries ──

pub async fn list_playbooks(pool: &PgPool) -> Result<Vec<DbPlaybook>> {
    Ok(sqlx::query_as::<_, DbPlaybook>(
        "SELECT id, name, yaml_content, created_at, updated_at FROM playbooks ORDER BY created_at DESC"
    )
    .fetch_all(pool)
    .await?)
}

pub async fn insert_playbook(pool: &PgPool, name: &str, yaml_content: &str) -> Result<DbPlaybook> {
    Ok(sqlx::query_as::<_, DbPlaybook>(
        "INSERT INTO playbooks (name, yaml_content) VALUES ($1, $2) \
         ON CONFLICT (name) DO UPDATE SET yaml_content = EXCLUDED.yaml_content, updated_at = now() \
         RETURNING id, name, yaml_content, created_at, updated_at",
    )
    .bind(name)
    .bind(yaml_content)
    .fetch_one(pool)
    .await?)
}

// ── Ticketing Integration Queries ──

pub async fn list_ticketing_integrations(pool: &PgPool) -> Result<Vec<TicketingIntegration>> {
    Ok(sqlx::query_as::<_, TicketingIntegration>(
        "SELECT id, provider, url, api_token, project_key, enabled, created_at FROM ticketing_integrations ORDER BY provider"
    )
    .fetch_all(pool)
    .await?)
}

pub async fn insert_ticketing_integration(
    pool: &PgPool,
    provider: &str,
    url: &str,
    api_token: Option<&str>,
    project_key: Option<&str>,
    enabled: bool,
) -> Result<TicketingIntegration> {
    Ok(sqlx::query_as::<_, TicketingIntegration>(
        "INSERT INTO ticketing_integrations (provider, url, api_token, project_key, enabled) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (provider) DO UPDATE SET url = EXCLUDED.url, api_token = EXCLUDED.api_token, project_key = EXCLUDED.project_key, enabled = EXCLUDED.enabled \
         RETURNING id, provider, url, api_token, project_key, enabled, created_at"
    )
    .bind(provider)
    .bind(url)
    .bind(api_token)
    .bind(project_key)
    .bind(enabled)
    .fetch_one(pool)
    .await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A framework netscope cannot measure must not move the headline score.
    ///
    /// `overall_score` used to be the mean of five numbers, two of which —
    /// GDPR and KVKK — were the constants 92.0 and 90.0. Two fifths of the
    /// figure an operator read as their compliance posture came from nowhere,
    /// and it could never drop below 36.4 no matter how badly the three real
    /// measurements scored.
    #[test]
    fn an_unmeasured_framework_does_not_contribute_to_the_average() {
        assert_eq!(
            mean_of_measured(&[Some(50.0), None, Some(100.0), None, None]),
            Some(75.0),
            "only the two measured scores should count"
        );
        assert_eq!(mean_of_measured(&[Some(42.0)]), Some(42.0));
    }

    /// Nothing measured is `None`, not zero.
    ///
    /// Zero is a score, and a bad one: a fresh deployment with no alerts, no
    /// flows and no sensors would have shown a red 0% compliance posture, which
    /// is as false as the 94.5% it used to show instead.
    #[test]
    fn measuring_nothing_is_not_a_score_of_zero() {
        assert_eq!(mean_of_measured(&[None, None, None, None, None]), None);
        assert_eq!(mean_of_measured(&[]), None);
    }
}
