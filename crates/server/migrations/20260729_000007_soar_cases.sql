-- Migration: 20260729_000007_soar_cases.sql

CREATE TABLE IF NOT EXISTS cases (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title         VARCHAR(255) NOT NULL,
    description   TEXT,
    status        VARCHAR(50) NOT NULL DEFAULT 'open', -- 'open', 'investigating', 'resolved', 'closed'
    severity      VARCHAR(50) NOT NULL DEFAULT 'medium', -- 'low', 'medium', 'high', 'critical'
    assigned_to   UUID,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS case_alerts (
    case_id       UUID REFERENCES cases(id) ON DELETE CASCADE,
    alert_id      UUID REFERENCES alerts(id) ON DELETE CASCADE,
    PRIMARY KEY (case_id, alert_id)
);

CREATE TABLE IF NOT EXISTS evidence_locker (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id       UUID REFERENCES cases(id) ON DELETE CASCADE,
    evidence_type VARCHAR(50) NOT NULL, -- 'pcap', 'log', 'screenshot', 'note'
    filename      VARCHAR(255) NOT NULL,
    filepath      TEXT NOT NULL,
    added_by      UUID,
    added_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    checksum      VARCHAR(64) -- SHA-256 Chain of Custody
);

CREATE TABLE IF NOT EXISTS chain_of_custody (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    evidence_id   UUID REFERENCES evidence_locker(id) ON DELETE CASCADE,
    action        VARCHAR(100) NOT NULL, -- 'uploaded', 'downloaded', 'transferred', 'deleted'
    performed_by  UUID,
    performed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    notes         TEXT
);

CREATE TABLE IF NOT EXISTS incident_timeline (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id       UUID REFERENCES cases(id) ON DELETE CASCADE,
    event_type    VARCHAR(100) NOT NULL, -- 'created', 'alert_added', 'playbook_run', 'evidence_added', 'status_changed', 'closed'
    description   TEXT NOT NULL,
    timestamp     TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor         UUID
);

CREATE TABLE IF NOT EXISTS ticketing_integrations (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider       VARCHAR(50) NOT NULL UNIQUE, -- 'jira', 'servicenow', 'thehive', 'github', 'linear'
    url            TEXT NOT NULL,
    api_token      TEXT,
    project_key    VARCHAR(50),
    enabled        BOOLEAN NOT NULL DEFAULT false,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS playbooks (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name          VARCHAR(255) NOT NULL UNIQUE,
    yaml_content  TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
