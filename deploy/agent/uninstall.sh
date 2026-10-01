#!/usr/bin/env bash
set -euo pipefail
[[ ${EUID} -eq 0 ]] || { echo 'Run as root'; exit 1; }
command -v systemctl >/dev/null || { echo 'systemctl is required by uninstaller'; exit 1; }
command -v flock >/dev/null || { echo 'flock is required by uninstaller'; exit 1; }
mkdir -p /run/lock
exec 9>/run/lock/vm-monitor-agent-install.lock
flock -n 9 || { echo 'Another Agent installation or removal is in progress'; exit 1; }
systemctl disable --now vm-monitor-agent || true
rm -f /etc/systemd/system/vm-monitor-agent.service
systemctl daemon-reload
echo 'Service removed. Data, credentials and any operator-created OVS mirror were preserved. Review and remove them separately if needed.'
