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
        "INSERT INTO sensors (hostname, ip_address, os, version, interfaces, cpu_cores, ram_mb, status, last_heartbeat)
         VALUES ($1, $2::inet, $3, $4, $5::jsonb, $6, $7, 'online', now())
         RETURNING id, hostname, ip_address::inet, os, version, interfaces, cpu_cores, ram_mb,
                   status, tags, metadata, registered_at, last_heartbeat",
    )
    .bind(&sensor.hostname)
    .bind(sensor.ip_address.to_string())
    .bind(&sensor.os)
    .bind(&sensor.version)
    .bind(serde_json::to_value(&sensor.interfaces)?)
    .bind(sensor.cpu_cores)
    .bind(sensor.ram_mb)
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

pub async fn get_sensor_topology(
    pool: &PgPool,
    sensor_id: Uuid,
) -> Result<Vec<TopologyEdge>> {
    Ok(sqlx::query_as::<_, TopologyEdge>(
        "SELECT source_ip::text as source_ip, dest_ip::text as dest_ip, \
                COALESCE(protocol, 'unknown') as protocol, COUNT(*)::bigint as count \
         FROM events \
         WHERE sensor_id = $1 AND source_ip IS NOT NULL AND dest_ip IS NOT NULL \
         GROUP BY source_ip, dest_ip, protocol \
         ORDER BY count DESC \
         LIMIT 100"
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

pub async fn get_alert_detail(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<AlertDetail>> {
    let alert = sqlx::query_as::<_, Alert>(
        "SELECT id, rule_id, sensor_id, event_id, status, severity, title, description,
                source_ip::inet, dest_ip::inet, raw_data, assigned_to,
                acknowledged_by, acknowledged_at, resolved_by, resolved_at,
                created_at, updated_at
         FROM alerts WHERE id = $1"
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
                let condition_json = serde_json::to_string_pretty(&rule.condition).unwrap_or_default();
                rule_yaml = Some(format!(
                    "name: {}\nseverity: {}\ncooldown_secs: {}\ncondition: |\n  {}",
                    rule.name, rule.severity, rule.cooldown_secs, condition_json.replace('\n', "\n  ")
                ));
            }
        }

        let mut event_details = None;
        if let Some(eid) = alert.event_id {
            let event: Option<Event> = sqlx::query_as(
                "SELECT id, sensor_id, event_type, severity, title, description,
                        source_ip::inet, dest_ip::inet, protocol, port, raw_data, tags, timestamp
                 FROM events WHERE id = $1"
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
            assigned_username = sqlx::query_scalar("SELECT username FROM users WHERE id = $1").bind(uid).fetch_optional(pool).await?;
        }
        let mut acknowledged_username = None;
        if let Some(uid) = alert.acknowledged_by {
            acknowledged_username = sqlx::query_scalar("SELECT username FROM users WHERE id = $1").bind(uid).fetch_optional(pool).await?;
        }
        let mut resolved_username = None;
        if let Some(uid) = alert.resolved_by {
            resolved_username = sqlx::query_scalar("SELECT username FROM users WHERE id = $1").bind(uid).fetch_optional(pool).await?;
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
         ORDER BY n.created_at ASC"
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
        sqlx::query_scalar("SELECT username FROM users WHERE id = $1").bind(uid).fetch_optional(pool).await?
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
                        .bind(status).bind(*id)
                }
            }
            "resolved" | "dismissed" => {
                if let Some(uid) = user_id {
                    sqlx::query("UPDATE alerts SET status = $1, resolved_by = $2, resolved_at = now(), updated_at = now() WHERE id = $3")
                        .bind(status).bind(uid).bind(*id)
                } else {
                    sqlx::query("UPDATE alerts SET status = $1, updated_at = now() WHERE id = $2")
                        .bind(status).bind(*id)
                }
            }
            _ => {
                sqlx::query("UPDATE alerts SET status = $1, updated_at = now() WHERE id = $2")
                    .bind(status).bind(*id)
            }
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
