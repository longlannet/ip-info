# ip-info

Lightweight IP lookup skill for OpenClaw.

It checks:

- IP geolocation
- ISP / organization / ASN info
- domain → IP resolution before lookup

The script now uses a small provider architecture with these sources:

- `ip-api.com`
- `api.ip.sb`
- `ipwho.is`
- `api.ipapi.is`
- `ipinfo.io`

By default it returns the first successful result from the tuned provider order:

- `ipwhois`
- `ipapi-is`
- `ip-api`
- `ipinfo`
- `ip-sb`

`ipinfo.io` works without a token by default. If `IPINFO_TOKEN` is present, the script automatically uses the tokenized path.

## Files

```text
ip-info/
├── SKILL.md
├── README.md
└── scripts/
    ├── check.sh
    ├── install.sh
    └── query_ip.py
```

## Install

This skill has no pip dependencies.

```bash
bash scripts/install.sh
```

No API key is required for the currently integrated providers.
If `IPINFO_TOKEN` is set, `ipinfo.io` is automatically upgraded to its tokenized query path.

## Quick start

```bash
python3 scripts/query_ip.py 8.8.8.8
python3 scripts/query_ip.py 1.1.1.1
python3 scripts/query_ip.py google.com
python3 scripts/query_ip.py 2606:4700:4700::1111
python3 scripts/query_ip.py 8.8.8.8 --json
python3 scripts/query_ip.py 8.8.8.8 --provider ip-api
python3 scripts/query_ip.py 8.8.8.8 --provider ipapi-is --json
python3 scripts/query_ip.py 8.8.8.8 --provider ipinfo --json
python3 scripts/query_ip.py 8.8.8.8 --all --json
python3 scripts/query_ip.py 8.8.8.8 --provider ip-api --raw
python3 scripts/query_ip.py 8.8.8.8 --all --summary
python3 scripts/query_ip.py 8.8.8.8 --all --summary --json
```

## Check

```bash
bash scripts/check.sh
```

This check includes real network smoke tests, not just local syntax validation.

## Notes

- No external Python packages are required.
- The script supports IPv4, IPv6, and normal-domain lookup.
- `--json` emits normalized structured output.
- `--provider <name>` forces one provider.
- `--all` queries all configured providers and returns every successful result.
- `--raw` emits raw provider payloads.
- `--summary` emits a consensus / difference summary across providers.
- summary mode also adds normalized consensus, high-level labels, and a `verdict` / `classification` block.
- `ipinfo.io` works without a token; if `IPINFO_TOKEN` is present, it is used automatically.
- `ip-api.com` free endpoint is HTTP-only.
