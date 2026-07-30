-- SPDX-License-Identifier: LicenseRef-Proprietary
-- Copyright (c) 2026 azzizefe. All rights reserved.

-- Config Store: Active configuration override for each sensor
CREATE TABLE IF NOT EXISTS sensor_configs (
    sensor_id       UUID PRIMARY KEY REFERENCES sensors(id) ON DELETE CASCADE,
    config_data     TEXT NOT NULL,
    version         INT NOT NULL DEFAULT 1,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by      UUID REFERENCES users(id) ON DELETE SET NULL
);

-- Version History: Rollback support and version tracking
CREATE TABLE IF NOT EXISTS sensor_config_history (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sensor_id       UUID NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    config_data     TEXT NOT NULL,
    version         INT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL
);
