-- SPDX-License-Identifier: LicenseRef-Proprietary
-- Copyright (c) 2026 azzizefe. All rights reserved.

-- The agent has always sent `disk_free_mb` in its heartbeat and the server has
-- always parsed it, but there was nowhere to put it, so it was dropped on the
-- floor. A sensor that fills its capture disk stops recording, which is the
-- one failure an operator most needs to see coming.
ALTER TABLE sensor_heartbeats
    ADD COLUMN IF NOT EXISTS disk_free_mb BIGINT;
