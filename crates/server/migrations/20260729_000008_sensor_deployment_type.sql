-- Migration: 20260729_000008_sensor_deployment_type.sql
-- Adds deployment model type to sensors table for Phase 5.1

ALTER TABLE sensors
    ADD COLUMN IF NOT EXISTS deployment_type VARCHAR(32) NOT NULL DEFAULT 'endpoint'
        CHECK (deployment_type IN (
            'inline',       -- Bridge mode, L2 visibility, can block
            'span',         -- Switch SPAN/mirror port, passive-only
            'tap',          -- Network TAP, full-duplex visibility
            'endpoint',     -- Lightweight per-host agent
            'cloud',        -- AWS VPC Mirror / Azure vTap / GCP Packet Mirror
            'container',    -- Kubernetes DaemonSet pod
            'virtual'       -- VMware/Hyper-V virtual switch mirror
        ));

ALTER TABLE sensors
    ADD COLUMN IF NOT EXISTS capture_mode VARCHAR(32) NOT NULL DEFAULT 'passive'
        CHECK (capture_mode IN ('passive', 'inline_block', 'inline_monitor'));

ALTER TABLE sensors
    ADD COLUMN IF NOT EXISTS location VARCHAR(255);
