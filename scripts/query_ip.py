#!/usr/bin/env python3
import argparse
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import urllib.parse
import urllib.request

USER_AGENT = "OpenClaw/1.0"
REQUEST_TIMEOUT_SECONDS = 12
CTX = ssl.create_default_context()
IPINFO_TOKEN = os.environ.get("IPINFO_TOKEN", "").strip()
DEFAULT_PROVIDER_ORDER = ["ipwhois", "ipapi-is", "ip-api", "ipinfo", "ip-sb"]


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Query IP geolocation / ASN / ISP info for an IPv4, IPv6, or domain"
    )
    parser.add_argument("target", nargs="?", default="", help="IPv4, IPv6, or domain")
    parser.add_argument("--json", action="store_true", dest="json_output", help="emit normalized JSON output")
    parser.add_argument("--raw", action="store_true", help="emit raw provider payloads")
    parser.add_argument("--summary", action="store_true", help="summarize provider consensus and differences")
    parser.add_argument(
        "--provider",
        choices=DEFAULT_PROVIDER_ORDER,
        help="query only one provider",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="query all configured providers and return all successful results",
    )
    args = parser.parse_args(argv)
    if args.json_output and args.raw:
        parser.error("--json cannot be combined with --raw")
    if args.summary and args.raw:
        parser.error("--summary cannot be combined with --raw")
    return args


def safe_request_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json,*/*"})
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS, context=CTX) as resp:
        body = resp.read().decode("utf-8", errors="replace")
        return json.loads(body)


def is_ip_address(target):
    try:
        return ipaddress.ip_address(target)
    except ValueError:
        return None


def resolve_domain(domain):
    try:
        rows = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        return []

    seen = set()
    results = []
    for family, _, _, _, sockaddr in rows:
        ip = sockaddr[0]
        if ip in seen:
            continue
        seen.add(ip)
        version = 6 if family == socket.AF_INET6 else 4 if family == socket.AF_INET else None
        results.append({"ip": ip, "version": version})
    return results


def parse_loc(value):
    if not isinstance(value, str) or "," not in value:
        return None, None
    lat, lon = value.split(",", 1)
    return lat, lon


def normalize_common(*, provider, source_label, original_target, query_value, resolved_from, ip, country, region, city, org, isp, asn, hostname, lat, lon, loc, raw, extra=None):
    ip_version = None
    if ip:
        try:
            ip_version = ipaddress.ip_address(str(ip)).version
        except ValueError:
            ip_version = 6 if ":" in str(ip) else 4 if "." in str(ip) else None
    payload = {
        "ok": True,
        "provider": provider,
        "sourceLabel": source_label,
        "target": original_target,
        "queryValue": query_value,
        "resolvedFrom": resolved_from,
        "ip": ip or "-",
        "ipVersion": ip_version,
        "country": country or "-",
        "region": region or "-",
        "city": city or "-",
        "org": org or "-",
        "isp": isp or "-",
        "asn": asn or "-",
        "hostname": hostname or "-",
        "loc": loc or "-",
        "lat": lat if lat not in [None, ""] else "-",
        "lon": lon if lon not in [None, ""] else "-",
        "raw": raw,
    }
    if extra:
        payload["extra"] = extra
    return payload


def provider_ip_api(query_value, original_target, resolved_from=None):
    url = f"http://ip-api.com/json/{urllib.parse.quote(query_value)}?fields=66842623&lang=zh-CN"
    data = safe_request_json(url)
    if data.get("status") != "success":
        raise RuntimeError(data.get("message") or "ip-api query failed")
    return normalize_common(
        provider="ip-api",
        source_label="ip-api.com",
        original_target=original_target,
        query_value=query_value,
        resolved_from=resolved_from,
        ip=data.get("query"),
        country=data.get("country"),
        region=data.get("regionName") or data.get("region"),
        city=data.get("city"),
        org=data.get("org"),
        isp=data.get("isp"),
        asn=data.get("as"),
        hostname="-",
        lat=data.get("lat"),
        lon=data.get("lon"),
        loc=f"{data.get('lat')},{data.get('lon')}" if data.get("lat") is not None and data.get("lon") is not None else "-",
        raw=data,
        extra={
            "proxy": data.get("proxy"),
            "hosting": data.get("hosting"),
            "mobile": data.get("mobile"),
            "timezone": data.get("timezone"),
            "currency": data.get("currency"),
            "countryCode": data.get("countryCode"),
            "continent": data.get("continent"),
            "continentCode": data.get("continentCode"),
            "district": data.get("district"),
            "zip": data.get("zip"),
            "asname": data.get("asname"),
        },
    )


def provider_ip_sb(query_value, original_target, resolved_from=None):
    url = f"https://api.ip.sb/geoip/{urllib.parse.quote(query_value)}"
    data = safe_request_json(url)
    return normalize_common(
        provider="ip-sb",
        source_label="api.ip.sb",
        original_target=original_target,
        query_value=query_value,
        resolved_from=resolved_from,
        ip=data.get("ip"),
        country=data.get("country"),
        region=data.get("region"),
        city=data.get("city"),
        org=data.get("organization"),
        isp=data.get("isp"),
        asn=(f"AS{data.get('asn')} {data.get('asn_organization')}" if data.get("asn") else data.get("asn_organization")),
        hostname="-",
        lat=data.get("latitude"),
        lon=data.get("longitude"),
        loc=f"{data.get('latitude')},{data.get('longitude')}" if data.get("latitude") is not None and data.get("longitude") is not None else "-",
        raw=data,
        extra={
            "countryCode": data.get("country_code"),
            "continentCode": data.get("continent_code"),
            "timezone": data.get("timezone"),
            "offset": data.get("offset"),
            "asnNumber": data.get("asn"),
            "asnOrganization": data.get("asn_organization"),
        },
    )


def provider_ipwhois(query_value, original_target, resolved_from=None):
    url = f"https://ipwho.is/{urllib.parse.quote(query_value)}"
    data = safe_request_json(url)
    if data.get("success") is False:
        raise RuntimeError(data.get("message") or "ipwho.is query failed")
    connection = data.get("connection") or {}
    return normalize_common(
        provider="ipwhois",
        source_label="ipwho.is",
        original_target=original_target,
        query_value=query_value,
        resolved_from=resolved_from,
        ip=data.get("ip"),
        country=data.get("country"),
        region=data.get("region"),
        city=data.get("city"),
        org=connection.get("org"),
        isp=connection.get("isp"),
        asn=connection.get("asn"),
        hostname="-",
        lat=data.get("latitude"),
        lon=data.get("longitude"),
        loc=f"{data.get('latitude')},{data.get('longitude')}" if data.get("latitude") is not None and data.get("longitude") is not None else "-",
        raw=data,
        extra={
            "type": data.get("type"),
            "continent": data.get("continent"),
            "continentCode": data.get("continent_code"),
            "countryCode": data.get("country_code"),
            "regionCode": data.get("region_code"),
            "postal": data.get("postal"),
            "timezone": data.get("timezone"),
            "callingCode": data.get("calling_code"),
            "capital": data.get("capital"),
            "borders": data.get("borders"),
            "isEu": data.get("is_eu"),
        },
    )


def provider_ipapi_is(query_value, original_target, resolved_from=None):
    url = f"https://api.ipapi.is/?ip={urllib.parse.quote(query_value)}"
    data = safe_request_json(url)
    location = data.get("location") or {}
    company = data.get("company") or {}
    asn_info = data.get("asn") or {}
    hostname = location.get("reverse") or "-"
    return normalize_common(
        provider="ipapi-is",
        source_label="api.ipapi.is",
        original_target=original_target,
        query_value=query_value,
        resolved_from=resolved_from,
        ip=data.get("ip"),
        country=location.get("country"),
        region=location.get("state") or location.get("region"),
        city=location.get("city"),
        org=company.get("name") or asn_info.get("org"),
        isp=company.get("name") or asn_info.get("descr"),
        asn=(f"AS{asn_info.get('asn')} {asn_info.get('descr')}" if asn_info.get("asn") else asn_info.get("descr")),
        hostname=hostname,
        lat=location.get("latitude"),
        lon=location.get("longitude"),
        loc=f"{location.get('latitude')},{location.get('longitude')}" if location.get("latitude") is not None and location.get("longitude") is not None else "-",
        raw=data,
        extra={
            "rir": data.get("rir"),
            "isBogon": data.get("is_bogon"),
            "isMobile": data.get("is_mobile"),
            "isCrawler": data.get("is_crawler"),
            "isDatacenter": data.get("is_datacenter"),
            "isTor": data.get("is_tor"),
            "isProxy": data.get("is_proxy"),
            "isVpn": data.get("is_vpn"),
            "isAbuser": data.get("is_abuser"),
            "countryCode": location.get("country_code"),
            "continent": location.get("continent"),
            "continentCode": location.get("continent_code"),
            "timezone": location.get("timezone"),
            "companyType": company.get("type"),
            "companyDomain": company.get("domain"),
            "network": company.get("network") or asn_info.get("route"),
            "abuse": asn_info.get("abuse"),
        },
    )


def provider_ipinfo(query_value, original_target, resolved_from=None):
    if query_value:
        base = f"https://ipinfo.io/{urllib.parse.quote(query_value)}/json"
    else:
        base = "https://ipinfo.io/json"
    url = f"{base}?token={urllib.parse.quote(IPINFO_TOKEN)}" if IPINFO_TOKEN else base
    data = safe_request_json(url)
    if isinstance(data, dict) and data.get("error"):
        raise RuntimeError(data.get("error", {}).get("title") or "ipinfo query failed")
    lat, lon = parse_loc(data.get("loc"))
    org = data.get("org")
    asn_text = org
    if isinstance(data.get("asn"), dict):
        asn_info = data.get("asn") or {}
        asn_text = asn_info.get("asn") or org
    else:
        asn_info = {}
    return normalize_common(
        provider="ipinfo",
        source_label=("ipinfo.io (token)" if IPINFO_TOKEN else "ipinfo.io"),
        original_target=original_target,
        query_value=query_value,
        resolved_from=resolved_from,
        ip=data.get("ip"),
        country=data.get("country"),
        region=data.get("region"),
        city=data.get("city"),
        org=org,
        isp=org,
        asn=asn_text,
        hostname=data.get("hostname") or "-",
        lat=lat,
        lon=lon,
        loc=data.get("loc") or "-",
        raw=data,
        extra={
            "postal": data.get("postal"),
            "timezone": data.get("timezone"),
            "countryCode": data.get("country"),
            "org": data.get("org"),
            "asnName": asn_info.get("name") if asn_info else None,
            "asnDomain": asn_info.get("domain") if asn_info else None,
            "asnRoute": asn_info.get("route") if asn_info else None,
            "privacy": data.get("privacy"),
            "company": data.get("company"),
        },
    )


PROVIDERS = {
    "ip-api": provider_ip_api,
    "ip-sb": provider_ip_sb,
    "ipwhois": provider_ipwhois,
    "ipapi-is": provider_ipapi_is,
    "ipinfo": provider_ipinfo,
}

COUNTRY_ALIASES = {
    "us": "United States",
    "usa": "United States",
    "united states": "United States",
    "美国": "United States",
}



def normalize_scalar(value):
    if value in [None, "", "-"]:
        return "-"
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value
    text = str(value).strip()
    if not text:
        return "-"
    return text



def normalize_country(value):
    value = normalize_scalar(value)
    if value == "-":
        return value
    return COUNTRY_ALIASES.get(str(value).strip().lower(), value)



def normalize_asn(value):
    value = normalize_scalar(value)
    if value == "-":
        return value
    text = str(value).strip()
    if text.isdigit():
        return f"AS{text}"
    upper = text.upper()
    if upper.startswith("AS"):
        number = upper.split()[0]
        return number
    return text



def normalize_org(value):
    value = normalize_scalar(value)
    if value == "-":
        return value
    text = str(value).strip()
    text = re.sub(r"^AS\d+\s+", "", text, flags=re.I)
    return text.strip() or "-"



def normalize_region(value):
    value = normalize_scalar(value)
    if value == "-":
        return value
    text = str(value).strip()
    aliases = {
        "弗吉尼亚州": "Virginia",
        "加利福尼亚州": "California",
    }
    return aliases.get(text, text)



def values_equal(a, b):
    if a in [None, "", "-"] and b in [None, "", "-"]:
        return True
    return str(a) == str(b)



def derive_labels(results, summary):
    labels = []
    notes = []
    hostname = str(summary.get("consensus", {}).get("hostname", "-")).lower()
    if hostname not in ["-", ""] and any(token in hostname for token in ["dns", "resolver"]):
        labels.append("public-dns")
        notes.append("hostname suggests a public DNS service")

    risk = summary.get("riskSignals", {})
    bool_true = lambda key: any(v is True for v in (risk.get(key) or {}).values())
    bool_false = lambda key: any(v is False for v in (risk.get(key) or {}).values())

    if bool_true("hosting") or bool_true("isDatacenter"):
        labels.append("datacenter")
        notes.append("at least one provider marks this IP as hosting / datacenter")
    if bool_true("isProxy") or bool_true("proxy"):
        labels.append("proxy")
        notes.append("at least one provider marks this IP as proxy")
    if bool_true("isVpn"):
        labels.append("vpn")
        notes.append("at least one provider marks this IP as VPN")
    if bool_true("isTor"):
        labels.append("tor")
        notes.append("at least one provider marks this IP as Tor")
    if bool_true("isAbuser"):
        labels.append("abuse-flagged")
        notes.append("at least one provider marks this IP as abuser / suspicious")

    if not any(label in labels for label in ["datacenter", "proxy", "vpn", "tor"]) and bool_false("proxy"):
        labels.append("non-proxy-signal")
        notes.append("available provider signals lean away from proxy use")

    return labels, notes



def derive_verdict(summary):
    labels = set(summary.get("labels") or [])
    consensus = summary.get("consensus") or {}
    differences = summary.get("differences") or {}

    classification = "unknown"
    confidence = "low"
    reasons = []

    if "tor" in labels:
        classification = "tor-exit"
        confidence = "high"
        reasons.append("provider signals include tor")
    elif "vpn" in labels and "proxy" in labels:
        classification = "vpn-or-proxy"
        confidence = "high"
        reasons.append("provider signals include both vpn and proxy")
    elif "vpn" in labels:
        classification = "vpn"
        confidence = "high"
        reasons.append("provider signals include vpn")
    elif "proxy" in labels:
        classification = "proxy"
        confidence = "high"
        reasons.append("provider signals include proxy")
    elif "public-dns" in labels and "datacenter" in labels:
        classification = "public-dns-datacenter"
        confidence = "high"
        reasons.append("hostname indicates public DNS and provider signals indicate datacenter / hosting")
    elif "datacenter" in labels:
        classification = "datacenter"
        confidence = "medium"
        reasons.append("provider signals indicate datacenter / hosting")
    elif "non-proxy-signal" in labels:
        classification = "likely-direct-network"
        confidence = "low"
        reasons.append("available provider signals lean away from proxy use")

    if "abuse-flagged" in labels:
        reasons.append("at least one provider flags this IP as suspicious / abuser")

    location_confidence = "low"
    if not differences.get("country"):
        location_confidence = "high"
        reasons.append(f"country consensus: {consensus.get('country', '-')}")
    elif consensus.get("country") not in [None, "", "-"]:
        location_confidence = "medium"
        reasons.append(f"country normalized consensus: {consensus.get('country')}")

    if not differences.get("region") and consensus.get("region") not in [None, "", "-"]:
        reasons.append(f"region consensus: {consensus.get('region')}")
    if not differences.get("city") and consensus.get("city") not in [None, "", "-"]:
        reasons.append(f"city consensus: {consensus.get('city')}")

    network_identity = {
        "asn": consensus.get("asn", "-"),
        "org": consensus.get("org", "-") if consensus.get("org", "-") != "-" else consensus.get("isp", "-"),
        "hostname": consensus.get("hostname", "-"),
    }

    return {
        "classification": classification,
        "confidence": confidence,
        "locationConfidence": location_confidence,
        "networkIdentity": network_identity,
        "reasons": reasons,
    }



def summarize_results(results):
    fields = ["ip", "ipVersion", "country", "region", "city", "org", "isp", "asn", "hostname"]
    normalizers = {
        "country": normalize_country,
        "region": normalize_region,
        "org": normalize_org,
        "isp": normalize_org,
        "asn": normalize_asn,
    }

    consensus = {}
    differences = {}
    normalized = {}
    raw_values = {}

    for field in fields:
        provider_values = {r["provider"]: r.get(field) for r in results}
        raw_values[field] = provider_values
        normalizer = normalizers.get(field, normalize_scalar)
        provider_normalized = {provider: normalizer(value) for provider, value in provider_values.items()}
        normalized[field] = provider_normalized
        non_empty = {k: v for k, v in provider_normalized.items() if v not in [None, "", "-"]}
        unique_values = []
        for value in non_empty.values():
            if not any(values_equal(value, existing) for existing in unique_values):
                unique_values.append(value)
        if len(unique_values) <= 1:
            consensus[field] = unique_values[0] if unique_values else "-"
        else:
            differences[field] = provider_normalized

    risk_keys = ["proxy", "hosting", "mobile", "isProxy", "isVpn", "isDatacenter", "isTor", "isAbuser"]
    risk_summary = {}
    for key in risk_keys:
        vals = {}
        for r in results:
            extra = r.get("extra") or {}
            if key in extra and extra[key] not in [None, "", "-"]:
                vals[r["provider"]] = extra[key]
        if vals:
            risk_summary[key] = vals

    summary = {
        "providers": [r["provider"] for r in results],
        "count": len(results),
        "consensus": consensus,
        "differences": differences,
        "normalized": normalized,
        "rawFieldValues": raw_values,
        "riskSignals": risk_summary,
    }
    labels, notes = derive_labels(results, summary)
    summary["labels"] = labels
    summary["notes"] = notes
    summary["verdict"] = derive_verdict(summary)
    return summary


def print_text_result(result):
    print(f"🌍 IP 信息查询 ({result['provider']})")
    print("----------------")
    if result.get("resolvedFrom"):
        print(f"🔍 DNS 解析: {result['resolvedFrom']} -> {result['ip']}")
    print(f"📍 IP 地址: {result.get('ip', '-')}")
    if result.get("ipVersion"):
        print(f"🧬 IP 版本: IPv{result['ipVersion']}")
    print(f"🏳️ 归属地: {result.get('country', '-')} {result.get('region', '-')} {result.get('city', '-')}")
    print(f"🏢 运营商: {result.get('isp', '-')}")
    print(f"🏛️ 组织: {result.get('org', '-')}")
    print(f"🌐 ASN / AS号: {result.get('asn', '-')}")
    print(f"🔗 主机名: {result.get('hostname', '-')}")
    print(f"🧭 坐标: {result.get('loc', '-')}")
    extra = result.get("extra") or {}
    if extra:
        important = []
        for key in [
            "timezone",
            "countryCode",
            "continent",
            "continentCode",
            "asname",
            "proxy",
            "hosting",
            "mobile",
            "isProxy",
            "isVpn",
            "isDatacenter",
            "isTor",
            "isAbuser",
            "network",
        ]:
            if key in extra and extra[key] not in [None, "", "-"]:
                important.append(f"{key}={extra[key]}")
        if important:
            print(f"⚙️ 扩展信息: {' | '.join(important)}")
    print("----------------")
    print(f"📡 数据来源: {result.get('sourceLabel', result.get('provider', '-'))}")


def print_json_result(result):
    payload = {k: v for k, v in result.items() if k != "raw"}
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def print_raw_result(result):
    payload = {
        "ok": result.get("ok", False),
        "provider": result.get("provider"),
        "target": result.get("target"),
        "queryValue": result.get("queryValue"),
        "resolvedFrom": result.get("resolvedFrom"),
        "raw": result.get("raw"),
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def print_multi_text(results):
    print(f"🔎 多源查询结果: 成功 {len(results)} 个 provider")
    print("=" * 40)
    for idx, result in enumerate(results, start=1):
        print(f"[{idx}] {result['provider']}")
        print_text_result(result)
        if idx != len(results):
            print()


def print_multi_json(results, target, query_mode):
    payload = {
        "ok": bool(results),
        "mode": query_mode,
        "target": target,
        "providers": [r["provider"] for r in results],
        "results": [{k: v for k, v in r.items() if k != "raw"} for r in results],
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def print_multi_raw(results, target, query_mode):
    payload = {
        "ok": bool(results),
        "mode": query_mode,
        "target": target,
        "providers": [r["provider"] for r in results],
        "results": [
            {
                "provider": r.get("provider"),
                "target": r.get("target"),
                "queryValue": r.get("queryValue"),
                "resolvedFrom": r.get("resolvedFrom"),
                "raw": r.get("raw"),
            }
            for r in results
        ],
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def print_summary(results, target, json_output=False):
    payload = {
        "ok": bool(results),
        "mode": "summary",
        "target": target,
        "summary": summarize_results(results),
    }
    if json_output:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return
    summary = payload["summary"]
    print(f"🧾 汇总视图: {summary['count']} 个 provider")
    print(f"📦 Providers: {', '.join(summary['providers'])}")
    if summary.get("labels"):
        print(f"🏷️ 标签: {', '.join(summary['labels'])}")
    verdict = summary.get("verdict") or {}
    if verdict:
        print(f"🧠 Classification: {verdict.get('classification', '-')}")
        print(f"📏 Confidence: {verdict.get('confidence', '-')} | Location: {verdict.get('locationConfidence', '-')}")
        network_identity = verdict.get("networkIdentity") or {}
        bits = []
        for key in ["asn", "org", "hostname"]:
            value = network_identity.get(key)
            if value not in [None, "", "-"]:
                bits.append(f"{key}={value}")
        if bits:
            print(f"🪪 Network identity: {' | '.join(bits)}")
        if verdict.get("reasons"):
            print(f"📝 Verdict: {'; '.join(verdict['reasons'])}")
    elif summary.get("notes"):
        print(f"📝 判断: {'; '.join(summary['notes'])}")
    print("-" * 40)
    print("✅ 共识字段:")
    for key, value in summary["consensus"].items():
        if value not in [None, "", "-"]:
            print(f"- {key}: {value}")
    if summary["differences"]:
        print("-" * 40)
        print("⚠️ 差异字段（已做基础归一化后）:")
        for key, provider_values in summary["differences"].items():
            bits = [f"{provider}={value}" for provider, value in provider_values.items() if value not in [None, '', '-']]
            print(f"- {key}: {' | '.join(bits)}")
    if summary["riskSignals"]:
        print("-" * 40)
        print("🚩 风险 / 类型信号:")
        for key, provider_values in summary["riskSignals"].items():
            bits = [f"{provider}={value}" for provider, value in provider_values.items()]
            print(f"- {key}: {' | '.join(bits)}")


def print_error_result(target, provider_names, attempts=None, query_mode="default", selected_provider=None, json_output=False):
    payload = {
        "ok": False,
        "mode": query_mode,
        "target": target,
        "providersTried": provider_names,
        "error": {
            "code": "NO_PROVIDER_SUCCESS",
            "message": "all configured providers failed or the target could not be resolved",
        },
    }
    if selected_provider:
        payload["provider"] = selected_provider
    provider_errors = []
    for attempt in attempts or []:
        provider_errors.append(
            {
                "provider": attempt.get("provider"),
                "queryValue": attempt.get("queryValue"),
                "resolvedFrom": attempt.get("resolvedFrom"),
                "error": attempt.get("error") or "unknown error",
            }
        )
    if provider_errors:
        payload["error"]["providerErrors"] = provider_errors

    if json_output:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print("❌ 查询失败：所有 provider 均无法访问或解析。")


def try_provider(provider_name, query_value, original_target, resolved_from=None):
    fn = PROVIDERS[provider_name]
    try:
        return fn(query_value, original_target, resolved_from=resolved_from)
    except Exception as e:
        return {"ok": False, "provider": provider_name, "error": str(e)}


def run_providers(provider_names, query_value, original_target, resolved_from=None):
    results = []
    attempts = []
    for provider_name in provider_names:
        result = try_provider(provider_name, query_value, original_target, resolved_from=resolved_from)
        attempt = {
            "provider": provider_name,
            "queryValue": query_value,
            "resolvedFrom": resolved_from,
        }
        if result.get("ok"):
            results.append(result)
            attempt["ok"] = True
            attempt["ip"] = result.get("ip")
        else:
            attempt["ok"] = False
            attempt["error"] = result.get("error") or "unknown error"
        attempts.append(attempt)
    return results, attempts


def query_target(provider_names, original_target):
    if not original_target:
        return run_providers(provider_names, "", original_target)

    parsed_ip = is_ip_address(original_target)
    if parsed_ip is not None:
        return run_providers(provider_names, str(parsed_ip), original_target)

    candidates = resolve_domain(original_target)
    if not candidates:
        return run_providers(provider_names, original_target, original_target)

    all_attempts = []
    for candidate in candidates:
        results, attempts = run_providers(provider_names, candidate["ip"], original_target, resolved_from=original_target)
        if results:
            return results, attempts
        all_attempts.extend(attempts)
    return [], all_attempts


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    provider_names = [args.provider] if args.provider else list(DEFAULT_PROVIDER_ORDER)
    target = args.target.strip()
    results, attempts = query_target(provider_names, target)
    query_mode = "provider" if args.provider and not args.all else "all" if args.all else "default"

    if not results:
        print_error_result(
            target,
            provider_names,
            attempts=attempts,
            query_mode=query_mode,
            selected_provider=args.provider,
            json_output=(args.json_output or args.raw),
        )
        return 1

    if args.provider and not args.all:
        result = results[0]
        if args.raw:
            print_raw_result(result)
        elif args.summary:
            print_summary([result], target, json_output=args.json_output)
        elif args.json_output:
            print_json_result(result)
        else:
            print_text_result(result)
        return 0

    if args.all:
        if args.raw:
            print_multi_raw(results, target, "all")
        elif args.summary:
            print_summary(results, target, json_output=args.json_output)
        elif args.json_output:
            print_multi_json(results, target, "all")
        else:
            print_multi_text(results)
        return 0

    result = results[0]
    if args.raw:
        print_raw_result(result)
    elif args.summary:
        print_summary(results, target, json_output=args.json_output)
    elif args.json_output:
        print_json_result(result)
    else:
        print_text_result(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
