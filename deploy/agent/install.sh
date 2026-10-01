#!/usr/bin/env bash
set -euo pipefail
umask 077
# Usage: install.sh /path/to/agent.json /path/to/vm-agent-linux-amd64
[[ ${EUID} -eq 0 ]] || { echo 'Run as root'; exit 1; }
[[ $# -eq 2 ]] || { echo 'Usage: install.sh CONFIG BINARY'; exit 1; }
config=$(readlink -f "$1"); binary=$(readlink -f "$2")
[[ -f "$config" && -r "$config" && -f "$binary" && -r "$binary" ]] || { echo 'Config and binary must be readable files'; exit 1; }
chmod 700 "$binary"
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
python_bin=$(command -v python3 || command -v python || true)
[[ -n "$python_bin" ]] || { echo 'Python 2.7+ or 3 is required by installer'; exit 1; }
command -v systemctl >/dev/null || { echo 'systemctl is required by installer'; exit 1; }
command -v flock >/dev/null || { echo 'flock is required by installer'; exit 1; }
mkdir -p /run/lock
exec 9>/run/lock/vm-monitor-agent-install.lock
flock -n 9 || { echo 'Another Agent installation is in progress'; exit 1; }
version=$(systemctl --version | awk 'NR==1 {print $2}')
[[ $version =~ ^[0-9]+$ ]] || { echo 'Unable to detect systemd version'; exit 1; }
mapfile -t settings < <("$python_bin" - "$config" <<'PY'
from __future__ import print_function
import json,re,sys
c=json.load(open(sys.argv[1]));p=c.get('data_dir','/home/vm-monitor');h=int(c.get('memory_hard_mib',4096));s=int(c.get('memory_soft_mib',2048))
if not re.match(r'^/[a-zA-Z0-9/_-]+$',p) or p in ['/', '/home', '/etc', '/usr', '/var', '/tmp'] or '..' in p.split('/') or h<s+128 or h>65536:
    raise SystemExit('Invalid directory or memory limits')
print(p);print(h)
PY
)
[[ ${#settings[@]} -eq 2 ]] || exit 1
data=${settings[0]}; hard=${settings[1]}
[[ ! -L "$data" ]] || { echo 'Data directory must not be a symlink'; exit 1; }
mkdir -p "$data"/{config,bin,logs,spool,tmp}
chmod 700 "$data" "$data"/{config,bin,logs,spool,tmp}
"$binary" -config "$config" -check
if systemctl is-active --quiet vm-monitor-agent; then systemctl stop vm-monitor-agent; fi
if [[ -f "$data/config/agent.json" ]]; then
    install -m 600 "$data/config/agent.json" "$data/config/agent.json.previous"
fi
if [[ -f /etc/systemd/system/vm-monitor-agent.service ]]; then
    install -m 600 /etc/systemd/system/vm-monitor-agent.service "$data/config/vm-monitor-agent.service.previous"
fi
if [[ "$config" != "$data/config/agent.json" ]]; then
    install -m 600 "$config" "$data/config/agent.json.new"
    mv -f "$data/config/agent.json.new" "$data/config/agent.json"
fi
if [[ -f "$data/bin/vm-agent" ]]; then cp -p "$data/bin/vm-agent" "$data/bin/vm-agent.previous"; fi
install -m 700 "$binary" "$data/bin/vm-agent.new"
mv -f "$data/bin/vm-agent.new" "$data/bin/vm-agent"
if [[ -f "$script_dir/uninstall.sh" && "$script_dir/uninstall.sh" != "$data/bin/uninstall.sh" ]]; then
    install -m 700 "$script_dir/uninstall.sh" "$data/bin/uninstall.sh"
fi
if (( version >= 231 )); then limit="MemoryMax=${hard}M"; else limit="MemoryLimit=${hard}M"; fi
cat > /etc/systemd/system/vm-monitor-agent.service <<EOF
[Unit]
Description=VM public IP traffic monitor
After=network-online.target
Wants=network-online.target
StartLimitInterval=60
StartLimitBurst=5

[Service]
Type=simple
ExecStart=$data/bin/vm-agent -config $data/config/agent.json
WorkingDirectory=$data
Environment=TMPDIR=$data/tmp
Restart=on-failure
RestartSec=10
TimeoutStopSec=15
$limit
LimitNOFILE=4096
LimitCORE=0
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_RAW
ProtectSystem=full
ProtectHome=false
PrivateTmp=true
UMask=0077
StandardOutput=null
StandardError=append:$data/logs/startup.log

[Install]
WantedBy=multi-user.target
EOF
# append: output is unavailable on old systemd; the application owns bounded logs.
if (( version < 240 )); then sed -i 's|^StandardError=.*|StandardError=null|' /etc/systemd/system/vm-monitor-agent.service; fi
systemctl daemon-reload
systemctl enable vm-monitor-agent
systemctl restart vm-monitor-agent
sleep 2
systemctl --no-pager status vm-monitor-agent
echo "Installed; data=$data; memory hard limit=${hard} MiB. No firewall/bridge/OVS configuration was changed."
if [[ -f "$data/bin/uninstall.sh" ]]; then echo "Uninstall service (keep data): bash $data/bin/uninstall.sh"; fi
