use anyhow::Result;
use sqlx::PgPool;
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
        "SELECT s.id, s.hostname, s.ip_address::inet, s.version, s.status, s.last_heartbeat,
                sh.uptime_secs, sh.cpu_load_pct
         FROM sensors s
         LEFT JOIN LATERAL (
             SELECT uptime_secs, cpu_load_pct
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
                source_ip::inet, dest_ip::inet, raw_data,
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
) -> Result<Option<Alert>> {
    match status {
        "acknowledged" | "investigating" => {
            if let Some(uid) = user_id {
                Ok(sqlx::query_as::<_, Alert>(
                    "UPDATE alerts SET status = $1, acknowledged_by = $2, acknowledged_at = now(), updated_at = now()
                     WHERE id = $3
                     RETURNING id, rule_id, sensor_id, event_id, status, severity, title, description,
                               source_ip::inet, dest_ip::inet, raw_data,
                               acknowledged_by, acknowledged_at, resolved_by, resolved_at,
                               created_at, updated_at",
                )
                .bind(status)
                .bind(uid)
                .bind(id)
                .fetch_optional(pool)
                .await?)
            } else {
                Ok(sqlx::query_as::<_, Alert>(
                    "UPDATE alerts SET status = $1, updated_at = now()
                     WHERE id = $2
                     RETURNING id, rule_id, sensor_id, event_id, status, severity, title, description,
                               source_ip::inet, dest_ip::inet, raw_data,
                               acknowledged_by, acknowledged_at, resolved_by, resolved_at,
                               created_at, updated_at",
                )
                .bind(status)
                .bind(id)
                .fetch_optional(pool)
                .await?)
            }
        }
        "resolved" | "dismissed" => {
            if let Some(uid) = user_id {
                Ok(sqlx::query_as::<_, Alert>(
                    "UPDATE alerts SET status = $1, resolved_by = $2, resolved_at = now(), updated_at = now()
                     WHERE id = $3
                     RETURNING id, rule_id, sensor_id, event_id, status, severity, title, description,
                               source_ip::inet, dest_ip::inet, raw_data,
                               acknowledged_by, acknowledged_at, resolved_by, resolved_at,
                               created_at, updated_at",
                )
                .bind(status)
                .bind(uid)
                .bind(id)
                .fetch_optional(pool)
                .await?)
            } else {
                Ok(sqlx::query_as::<_, Alert>(
                    "UPDATE alerts SET status = $1, updated_at = now()
                     WHERE id = $2
                     RETURNING id, rule_id, sensor_id, event_id, status, severity, title, description,
                               source_ip::inet, dest_ip::inet, raw_data,
                               acknowledged_by, acknowledged_at, resolved_by, resolved_at,
                               created_at, updated_at",
                )
                .bind(status)
                .bind(id)
                .fetch_optional(pool)
                .await?)
            }
        }
        _ => Ok(sqlx::query_as::<_, Alert>(
            "UPDATE alerts SET status = $1, updated_at = now()
                 WHERE id = $2
                 RETURNING id, rule_id, sensor_id, event_id, status, severity, title, description,
                           source_ip::inet, dest_ip::inet, raw_data,
                           acknowledged_by, acknowledged_at, resolved_by, resolved_at,
                           created_at, updated_at",
        )
        .bind(status)
        .bind(id)
        .fetch_optional(pool)
        .await?),
    }
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

    Ok(DashboardSummary {
        active_alerts: active_alerts.0,
        events_per_second: events_per_second.0.unwrap_or(0.0),
        total_sensors: total_sensors.0,
        online_sensors: online_sensors.0,
        top_talkers: Vec::new(),
        top_threats,
        alerts_by_severity,
    })
}
