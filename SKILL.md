---
name: ip-info
description: Query IP address geolocation and ISP / ASN ownership info using ipinfo.io and ip-api.com. Use when the user asks where an IP is located, who owns an IP, what ISP / ASN it belongs to, or when a domain needs to be resolved and checked as an IP.
homepage: https://github.com/ihmily/ip-info-api
metadata:
  openclaw:
    emoji: "🌍"
requires:
  bins: [python3]
  env: [IPINFO_TOKEN]
primaryEnv: IPINFO_TOKEN
---

# IP Info

Use `scripts/query_ip.py` for one-off IP / domain lookups.

## Command

```bash
python3 {baseDir}/scripts/query_ip.py "<target>"
python3 {baseDir}/scripts/query_ip.py "<target>" --json
python3 {baseDir}/scripts/query_ip.py "<target>" --raw
python3 {baseDir}/scripts/query_ip.py "<target>" --provider ip-api
python3 {baseDir}/scripts/query_ip.py "<target>" --all --json
python3 {baseDir}/scripts/query_ip.py "<target>" --all --summary
```

- `<target>` can be an IPv4 address like `1.1.1.1`
- `<target>` can be an IPv6 address like `2606:4700:4700::1111`
- `<target>` can be a domain like `google.com`
- `--json` emits normalized structured output
- `--raw` emits raw provider payloads
- `--summary` summarizes provider consensus and differences
- summary mode also normalizes obvious aliases, emits high-level labels, and produces a `verdict` / `classification` block
- `--provider` forces one provider from `ip-api`, `ip-sb`, `ipwhois`, `ipapi-is`, `ipinfo`
- `--all` queries all configured providers and returns all successful results
- default provider order is tuned as `ipwhois` → `ipapi-is` → `ip-api` → `ipinfo` → `ip-sb`
- `ipinfo.io` works without a token; if `IPINFO_TOKEN` is set, the script automatically uses the tokenized query path

## Notes

- The script prints human-readable output by default.
- Domain input is resolved with DNS first when possible.
- `ip-api.com` is used over HTTP because that is how its free endpoint works.
- If all configured providers fail, the script exits non-zero.
