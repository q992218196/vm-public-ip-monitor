#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
[[ -f .env ]] || cp .env.example .env
umask 077
if ! command -v python3 >/dev/null; then echo 'python3 required'; exit 1; fi
python3 - <<'PY'
import base64,secrets,pathlib
p=pathlib.Path('.env');s=p.read_text()
s=s.replace('APP_KEY=\n','APP_KEY=base64:'+base64.b64encode(secrets.token_bytes(32)).decode()+'\n')
s=s.replace('replace-with-a-long-random-password',secrets.token_hex(32))
s=s.replace('replace-with-at-least-32-random-characters',secrets.token_hex(32))
s=s.replace('replace-with-buildadmin-db-password',secrets.token_hex(32))
s=s.replace('replace-with-buildadmin-token-key',secrets.token_hex(32))
if 'BUILDADMIN_DB_PASSWORD=' not in s:
    s+='\nBUILDADMIN_DB_PASSWORD='+secrets.token_hex(32)+'\n'
if 'BUILDADMIN_TOKEN_KEY=' not in s:
    s+='BUILDADMIN_TOKEN_KEY='+secrets.token_hex(32)+'\n'
p.write_text(s);p.chmod(0o600)
PY
echo 'Secrets initialized without printing. Edit .env: APP_URL and MONITOR_DATA_DIR, then follow docs/DEPLOYMENT.md.'
