#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 netscope contributors
set -euo pipefail

VERSION="${1:-0.2.0}"
OUTPUT_DIR="netscope-airgap-v${VERSION}"

echo "[+] Creating Air-gapped Deployment Bundle for Netscope v${VERSION}..."

mkdir -p "${OUTPUT_DIR}"/binaries
mkdir -p "${OUTPUT_DIR}"/docker
mkdir -p "${OUTPUT_DIR}"/manifests

# Copy deployment manifests
cp -r deploy/* "${OUTPUT_DIR}"/manifests/ 2>/dev/null || true

cat <<EOF > "${OUTPUT_DIR}"/install.sh
#!/usr/bin/env bash
set -euo pipefail
echo "[+] Installing Netscope Air-gapped Bundle..."
if command -v systemctl >/dev/null 2>&1; then
    cp manifests/systemd/netscope-agent.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable netscope-agent
    echo "[+] Systemd service installed."
fi
EOF

chmod +x "${OUTPUT_DIR}"/install.sh
tar -czf "${OUTPUT_DIR}.tar.gz" "${OUTPUT_DIR}"
rm -rf "${OUTPUT_DIR}"

echo "[+] Air-gapped deployment bundle created: ${OUTPUT_DIR}.tar.gz"
