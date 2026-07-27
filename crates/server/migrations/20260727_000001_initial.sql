-- ═══════════════════════════════════════════════════════════
-- Netscope Central Management Server — Initial Schema
-- ═══════════════════════════════════════════════════════════

-- ── Users & Auth ──
CREATE TABLE IF NOT EXISTS users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username        VARCHAR(64)  NOT NULL UNIQUE,
    email           VARCHAR(255) NOT NULL UNIQUE,
    password_hash   TEXT         NOT NULL,
    role            VARCHAR(32)  NOT NULL DEFAULT 'viewer'
                        CHECK (role IN ('admin', 'operator', 'analyst', 'viewer')),
    is_active       BOOLEAN      NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS roles (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(64)  NOT NULL UNIQUE,
    description     TEXT,
    permissions     JSONB        NOT NULL DEFAULT '[]',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS api_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_hash        TEXT         NOT NULL,
    label           VARCHAR(128) NOT NULL,
    scopes          JSONB        NOT NULL DEFAULT '[]',
    expires_at      TIMESTAMPTZ,
    last_used_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- ── Sensors ──
CREATE TABLE IF NOT EXISTS sensors (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname        VARCHAR(255) NOT NULL,
    ip_address      INET         NOT NULL,
    os              VARCHAR(64),
    version         VARCHAR(32)  NOT NULL,
    interfaces      JSONB        NOT NULL DEFAULT '[]',
    cpu_cores       INT,
    ram_mb          INT,
    status          VARCHAR(32)  NOT NULL DEFAULT 'offline'
                        CHECK (status IN ('online', 'offline', 'degraded', 'disabled')),
    tags            JSONB        NOT NULL DEFAULT '[]',
    metadata        JSONB        NOT NULL DEFAULT '{}',
    registered_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_heartbeat  TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS sensor_heartbeats (
    id              BIGSERIAL PRIMARY KEY,
    sensor_id       UUID         NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    cpu_load_pct    FLOAT4,
    ram_used_mb     INT,
    capture_throughput_bps BIGINT,
    uptime_secs     BIGINT,
    interface_stats JSONB,
    received_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX idx_sensor_heartbeats_sensor_time
    ON sensor_heartbeats (sensor_id, received_at DESC);

-- ── Events ──
CREATE TABLE IF NOT EXISTS events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sensor_id       UUID         REFERENCES sensors(id) ON DELETE SET NULL,
    event_type      VARCHAR(64)  NOT NULL,
    severity        VARCHAR(16)  NOT NULL DEFAULT 'info'
                        CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    title           VARCHAR(255) NOT NULL,
    description     TEXT,
    source_ip       INET,
    dest_ip         INET,
    protocol        VARCHAR(32),
    port            INT,
    raw_data        JSONB,
    tags            JSONB        NOT NULL DEFAULT '[]',
    timestamp       TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX idx_events_severity      ON events (severity, timestamp DESC);
CREATE INDEX idx_events_sensor_time   ON events (sensor_id, timestamp DESC);
CREATE INDEX idx_events_timerange     ON events (timestamp DESC);

-- ── Alerts ──
CREATE TABLE IF NOT EXISTS alerts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id         UUID         REFERENCES alert_rules(id) ON DELETE SET NULL,
    sensor_id       UUID         REFERENCES sensors(id) ON DELETE SET NULL,
    event_id        UUID         REFERENCES events(id) ON DELETE SET NULL,
    status          VARCHAR(16)  NOT NULL DEFAULT 'open'
                        CHECK (status IN ('open', 'acknowledged', 'investigating', 'resolved', 'dismissed')),
    severity        VARCHAR(16)  NOT NULL
                        CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    title           VARCHAR(255) NOT NULL,
    description     TEXT,
    source_ip       INET,
    dest_ip         INET,
    raw_data        JSONB,
    acknowledged_by UUID         REFERENCES users(id),
    acknowledged_at TIMESTAMPTZ,
    resolved_by     UUID         REFERENCES users(id),
    resolved_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX idx_alerts_status        ON alerts (status, created_at DESC);
CREATE INDEX idx_alerts_severity      ON alerts (severity, created_at DESC);
CREATE INDEX idx_alerts_timerange     ON alerts (created_at DESC);

-- ── Alert Rules ──
CREATE TABLE IF NOT EXISTS alert_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    enabled         BOOLEAN      NOT NULL DEFAULT true,
    severity        VARCHAR(16)  NOT NULL DEFAULT 'medium',
    condition       JSONB        NOT NULL,
    actions         JSONB        NOT NULL DEFAULT '[]',
    cooldown_secs   INT          NOT NULL DEFAULT 300,
    created_by      UUID         REFERENCES users(id),
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- ── Threat Indicators ──
CREATE TABLE IF NOT EXISTS threat_indicators (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    indicator_type  VARCHAR(32)  NOT NULL
                        CHECK (indicator_type IN ('ip', 'domain', 'url', 'hash', 'ja3', 'ja3s')),
    value           TEXT         NOT NULL,
    confidence      VARCHAR(16)  NOT NULL DEFAULT 'medium'
                        CHECK (confidence IN ('high', 'medium', 'low')),
    source          VARCHAR(128),
    description     TEXT,
    first_seen      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ
);

CREATE UNIQUE INDEX idx_threat_indicators_type_value
    ON threat_indicators (indicator_type, value);

-- ── Audit Log ──
CREATE TABLE IF NOT EXISTS audit_log (
    id              BIGSERIAL PRIMARY KEY,
    user_id         UUID         REFERENCES users(id),
    action          VARCHAR(64)  NOT NULL,
    resource_type   VARCHAR(64)  NOT NULL,
    resource_id     UUID,
    details         JSONB,
    ip_address      INET,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_log_user    ON audit_log (user_id, created_at DESC);
CREATE INDEX idx_audit_log_action  ON audit_log (action, created_at DESC);
CREATE INDEX idx_audit_log_time    ON audit_log (created_at DESC);

-- ── Seed default admin user (password: admin123 — change on first login) ──
INSERT INTO users (username, email, password_hash, role)
VALUES ('admin', 'admin@netscope.local',
        '$argon2id$v=19$m=65536,t=3,p=4$SEJQQlI1V0tFaGlTNHhLcQ$fQHlBvJx+XnnvnGRmvlVFMzh9jPjKfrVqAv6BX9OESo',
        'admin')
ON CONFLICT (username) DO NOTHING;
