# ip-info

面向 OpenClaw 的轻量多源 IP 查询 skill。

它可以查询：

- IP 地理位置
- ISP / 组织 / ASN 信息
- 域名解析后的 IP 信息

当前脚本使用一套小型 provider 架构，集成了这些来源：

- `ip-api.com`
- `api.ip.sb`
- `ipwho.is`
- `api.ipapi.is`
- `ipinfo.io`

默认会按调优后的顺序返回第一个成功结果：

- `ipwhois`
- `ipapi-is`
- `ip-api`
- `ipinfo`
- `ip-sb`

`ipinfo.io` 默认支持无 token 使用；如果检测到 `IPINFO_TOKEN`，脚本会自动切到带 token 的查询路径。

## 文件结构

```text
ip-info/
├── SKILL.md
├── README.md
└── scripts/
    ├── check.sh
    ├── install.sh
    └── query_ip.py
```

## 安装

这个 skill 没有额外 pip 依赖。

```bash
bash scripts/install.sh
```

当前集成的 provider 默认都不强制要求 API key。  
如果设置了 `IPINFO_TOKEN`，`ipinfo.io` 会自动升级到 token 模式。

## 快速开始

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

## 校验

```bash
bash scripts/check.sh
```

这个检查会包含真实联网 smoke test，不只是本地语法检查。

## 说明

- 不需要外部 Python 包。
- 支持 IPv4、IPv6 和普通域名查询。
- `--provider <name>` 可强制指定单个 provider。
- `--all` 会查询所有已配置 provider，并返回全部成功结果。
- `--raw` 输出 provider 原始 payload。
- `--summary` 会输出多源共识 / 差异汇总，并附带 labels 与 `verdict` / `classification`。
- `ip-api.com` 免费接口是 HTTP-only。
