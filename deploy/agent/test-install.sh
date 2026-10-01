#!/usr/bin/env bash
set -euo pipefail
# Run only in a disposable Linux container: mocks replace systemd, never the host.
[[ -f /.dockerenv && ${EUID} -eq 0 ]] || { echo 'Run this test in a disposable Docker container as root'; exit 1; }
root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
fixture=$(mktemp -d)
data=/home/vm-monitor-installer-test
mkdir -p "$fixture/mockbin" /etc/systemd/system
export MOCK_SYSTEMD_VERSION=219 MOCK_STATE="$fixture/active" MOCK_LOG="$fixture/systemctl.log"
cat > "$fixture/mockbin/systemctl" <<'SH'
#!/usr/bin/env bash
set -eu
echo "$*" >> "$MOCK_LOG"
case "$1" in
  --version) echo "systemd $MOCK_SYSTEMD_VERSION" ;;
  is-active) test -f "$MOCK_STATE" ;;
  stop|disable) rm -f "$MOCK_STATE" ;;
  restart) touch "$MOCK_STATE" ;;
esac
SH
chmod 700 "$fixture/mockbin/systemctl"
export PATH="$fixture/mockbin:$PATH"
cp "$root/install.sh" "$root/uninstall.sh" "$fixture/"
printf '#!/usr/bin/env bash\n# first version\nexit 0\n' > "$fixture/agent"
chmod 600 "$fixture/agent"
printf '{"data_dir":"%s","memory_soft_mib":512,"memory_hard_mib":1024,"test_revision":1}\n' "$data" > "$fixture/agent.json"
bash "$fixture/install.sh" "$fixture/agent.json" "$fixture/agent"
test "$(stat -c %a "$data/bin/vm-agent")" = 700
test "$(stat -c %a "$data/config/agent.json")" = 600
test "$(stat -c %a "$data/bin/uninstall.sh")" = 700
grep -q '^MemoryLimit=1024M$' /etc/systemd/system/vm-monitor-agent.service
grep -q '^StandardError=null$' /etc/systemd/system/vm-monitor-agent.service
echo 'retained spool' > "$data/spool/retained"
echo 'retained log' > "$data/logs/retained"
cp "$data/config/agent.json" "$fixture/first-config"
cp "$data/bin/vm-agent" "$fixture/first-agent"
cp /etc/systemd/system/vm-monitor-agent.service "$fixture/first-unit"
export MOCK_SYSTEMD_VERSION=252
printf '#!/usr/bin/env bash\n# second version\nexit 0\n' > "$fixture/agent"
printf '{"data_dir":"%s","memory_soft_mib":512,"memory_hard_mib":2048,"test_revision":2}\n' "$data" > "$fixture/agent.json"
bash "$fixture/install.sh" "$fixture/agent.json" "$fixture/agent"
cmp "$fixture/first-agent" "$data/bin/vm-agent.previous"
cmp "$fixture/first-config" "$data/config/agent.json.previous"
cmp "$fixture/first-unit" "$data/config/vm-monitor-agent.service.previous"
cmp "$fixture/agent" "$data/bin/vm-agent"
cmp "$fixture/agent.json" "$data/config/agent.json"
grep -q '^MemoryMax=2048M$' /etc/systemd/system/vm-monitor-agent.service
grep -q '^stop vm-monitor-agent$' "$MOCK_LOG"
test -f "$data/spool/retained" && test -f "$data/logs/retained"
test "$(stat -c %a "$data/config/agent.json.previous")" = 600
# A failed configuration self-check must leave the running installation untouched.
cp "$data/bin/vm-agent" "$fixture/current-agent"
cp "$data/config/agent.json" "$fixture/current-config"
cp /etc/systemd/system/vm-monitor-agent.service "$fixture/current-unit"
cp "$MOCK_LOG" "$fixture/before-reject"
printf '#!/usr/bin/env bash\nexit 1\n' > "$fixture/agent"
if bash "$fixture/install.sh" "$fixture/agent.json" "$fixture/agent"; then exit 1; fi
cmp "$fixture/current-agent" "$data/bin/vm-agent"
cmp "$fixture/current-config" "$data/config/agent.json"
cmp "$fixture/current-unit" /etc/systemd/system/vm-monitor-agent.service
test -f "$MOCK_STATE"
test "$(grep -c '^stop ' "$MOCK_LOG")" = "$(grep -c '^stop ' "$fixture/before-reject")"
bash "$data/bin/uninstall.sh"
test ! -f /etc/systemd/system/vm-monitor-agent.service
test ! -f "$MOCK_STATE"
test -f "$data/config/agent.json" && test -f "$data/bin/vm-agent"
test -f "$data/spool/retained" && test -f "$data/logs/retained"
echo 'Installer tests passed: permissions, repeat install, backups, rejection, CentOS 7 and modern systemd, uninstall preservation.'
