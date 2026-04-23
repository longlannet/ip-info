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
assert data['error']['code'] == 'DOMAIN_UNRESOLVED'
assert data['resolution']['inputKind'] == 'domain'
assert data['resolution']['dnsResolved'] is False
assert isinstance(data['error'].get('providerErrors'), list) and data['error']['providerErrors']
PY

echo "[ip-info] smoke test: invalid target format json error"
if python3 scripts/query_ip.py 'https://example.com' --provider ip-api --json >/tmp/ip-info-check-invalid-format.json; then
  echo "[ip-info] expected invalid-format path to exit non-zero" >&2
  exit 1
fi
python3 - <<'PY'
import json
with open('/tmp/ip-info-check-invalid-format.json', 'r', encoding='utf-8') as f:
    data = json.load(f)
assert data['ok'] is False
assert data['error']['code'] == 'TARGET_INVALID_FORMAT'
assert data['resolution']['invalidFormat'] is True
assert data['provider'] == 'ip-api'
PY

echo "[ip-info] smoke test: provider-scoped json error"
if python3 scripts/query_ip.py not-a-domain.invalid --provider ip-api --json >/tmp/ip-info-check-provider-error.json; then
  echo "[ip-info] expected provider-scoped error path to exit non-zero" >&2
  exit 1
fi
python3 - <<'PY'
import json
with open('/tmp/ip-info-check-provider-error.json', 'r', encoding='utf-8') as f:
    data = json.load(f)
assert data['ok'] is False
assert data['provider'] == 'ip-api'
assert data['error']['code'] == 'DOMAIN_UNRESOLVED'
assert len(data['error'].get('providerErrors', [])) == 1
PY

echo "[ip-info] smoke test: synthetic error classifier"
python3 - <<'PY'
import importlib.util
spec = importlib.util.spec_from_file_location('query_ip', 'scripts/query_ip.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

payload = mod.build_error_payload(
    'example.com',
    ['ipwhois', 'ip-api'],
    attempts=[
        {'provider': 'ipwhois', 'ok': False, 'errorCode': 'TIMEOUT', 'error': 'timeout', 'transient': True},
        {'provider': 'ip-api', 'ok': False, 'errorCode': 'RATE_LIMITED', 'error': 'rate limited', 'transient': True},
    ],
    resolution={'inputKind': 'domain', 'dnsResolved': True, 'resolvedCandidates': ['1.1.1.1'], 'invalidFormat': False},
)
assert payload['error']['code'] == 'UPSTREAM_UNAVAILABLE'

payload = mod.build_error_payload(
    'example.com',
    ['ipwhois', 'ip-api'],
    attempts=[
        {'provider': 'ipwhois', 'ok': False, 'errorCode': 'TIMEOUT', 'error': 'timeout', 'transient': True},
        {'provider': 'ip-api', 'ok': False, 'errorCode': 'INVALID_QUERY', 'error': 'invalid query', 'transient': False},
    ],
    resolution={'inputKind': 'domain', 'dnsResolved': True, 'resolvedCandidates': ['1.1.1.1'], 'invalidFormat': False},
)
assert payload['error']['code'] == 'NO_PROVIDER_SUCCESS'
PY

echo "[ip-info] check complete"
