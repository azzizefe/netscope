-- Migration: 20260729_000006_scheduled_reports.sql
CREATE TABLE IF NOT EXISTS scheduled_reports (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_type VARCHAR(50) NOT NULL,
    recipients  TEXT NOT NULL,
    schedule    VARCHAR(50) NOT NULL,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
