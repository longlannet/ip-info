#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

echo "[ip-info] checking syntax"
python3 -m py_compile scripts/query_ip.py

echo "[ip-info] note: this check includes live network smoke tests"

echo "[ip-info] smoke test: default provider chain / IPv4"
python3 scripts/query_ip.py 1.1.1.1 >/tmp/ip-info-check-ip.txt

echo "[ip-info] smoke test: IPv6"
python3 scripts/query_ip.py 2606:4700:4700::1111 >/tmp/ip-info-check-ipv6.txt

echo "[ip-info] smoke test: domain"
python3 scripts/query_ip.py example.com >/tmp/ip-info-check-domain.txt

echo "[ip-info] smoke test: single provider json"
python3 scripts/query_ip.py 8.8.8.8 --provider ip-api --json >/tmp/ip-info-check-json.txt

echo "[ip-info] smoke test: ipinfo json"
python3 scripts/query_ip.py 8.8.8.8 --provider ipinfo --json >/tmp/ip-info-check-ipinfo.json

echo "[ip-info] smoke test: raw output"
python3 scripts/query_ip.py 8.8.8.8 --provider ip-api --raw >/tmp/ip-info-check-raw.json

echo "[ip-info] smoke test: all providers json"
python3 scripts/query_ip.py 8.8.8.8 --all --json >/tmp/ip-info-check-all.json

echo "[ip-info] smoke test: summary output"
python3 scripts/query_ip.py 8.8.8.8 --all --summary --json >/tmp/ip-info-check-summary.json

echo "[ip-info] smoke test: summary text"
python3 scripts/query_ip.py 8.8.8.8 --all --summary >/tmp/ip-info-check-summary.txt

echo "[ip-info] smoke test: summary single provider"
python3 scripts/query_ip.py 8.8.8.8 --provider ipinfo --summary --json >/tmp/ip-info-check-summary-single.json

echo "[ip-info] smoke test: structured json error"
if python3 scripts/query_ip.py not-a-domain.invalid --json >/tmp/ip-info-check-error.json; then
  echo "[ip-info] expected json error path to exit non-zero" >&2
  exit 1
fi
python3 - <<'PY'
import json
with open('/tmp/ip-info-check-error.json', 'r', encoding='utf-8') as f:
    data = json.load(f)
assert data['ok'] is False
assert data['error']['code'] == 'NO_PROVIDER_SUCCESS'
assert isinstance(data['error'].get('providerErrors'), list) and data['error']['providerErrors']
PY

echo "[ip-info] check complete"
