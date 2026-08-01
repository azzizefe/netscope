#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 netscope contributors

if [ -f "/usr/local/bin/netscope-agent" ]; then
    VERSION=$(/usr/local/bin/netscope-agent --version 2>/dev/null | awk '{print $2}')
    echo "<result>${VERSION:-Installed}</result>"
else
    echo "<result>Not Installed</result>"
fi
