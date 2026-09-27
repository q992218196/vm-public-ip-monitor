#!/usr/bin/env bash
set -euo pipefail
[[ ${EUID} -eq 0 ]] || { echo 'Run as root'; exit 1; }
systemctl disable --now vm-monitor-agent || true
rm -f /etc/systemd/system/vm-monitor-agent.service
systemctl daemon-reload
echo 'Service removed. Data, credentials and any operator-created OVS mirror were preserved. Review and remove them separately if needed.'
