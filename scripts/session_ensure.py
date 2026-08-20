#!/usr/bin/env python3
"""
会话验活 — 独立于 auth-diff 体系。

给 sqlmap / http_fuzz 等需认证的工具提供有效 Cookie。
不做越权对比、不做 auth_diff —— 只确认 cookie 能用。

原理:
  - discover (auth_token_discovery.py) 从 Burp 代理历史做频率分析，自动发现心跳端点 + 提取令牌。
    验活端点 = discover 发现的那个心跳 URL，不写死。
  - 验活 = urllib HTTP GET。cookie 有效 → 缓存到 .session.json。
  - 下次调用先读缓存验活，过期才输出 MCP 搜索指令。

用法:
  python session_ensure.py <workspace> [--target HOST]

  首次 (无缓存):
    → exit 1，输出 3 步 MCP 指令:
      1. proxy_history(host=target, max_results=1) → 取 total_filtered
      2. proxy_history(host=target, start_index=total_filtered-50) → 取最新 50 条
      3. session_ensure.py --ingest=... → discover → HTTP验活 → 缓存
    → exit 0，输出有效 cookie

  后续 (有缓存):
    → 读缓存 → HTTP验活 → 有效直接返回 → exit 0
    → 过期 → 输出 MCP 搜索指令 → exit 1

输出 (exit 0):
  {"status":"valid","cookie":"...","session_tag":"...","target":"...","verified_endpoint":"..."}

缓存: <workspace>/.session.json
"""

import json
import os
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta

TZ_SHANGHAI = timezone(timedelta(hours=8))
CACHE_FILE = ".session.json"

# 复用 auth_token_discovery 的频率分析 (纯计算，不依赖 Burp/auth-diff)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)


def load_cache(ws: str) -> dict | None:
    p = os.path.join(ws, CACHE_FILE)
    if not os.path.exists(p):
        return None
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


def write_cache(ws: str, target: str, cookie: str, stag: str | None,
                endpoint: str, source_index: int = 0):
    with open(os.path.join(ws, CACHE_FILE), "w", encoding="utf-8") as f:
        json.dump({
            "target": target,
            "cookie": cookie,
            "session_tag": stag,
            "endpoint": endpoint,
            "source_index": source_index,
            "last_verified": datetime.now(TZ_SHANGHAI).isoformat(),
        }, f, indent=2, ensure_ascii=False)


def http_verify(target: str, endpoint: str, cookie: str,
                session_tag: str | None, timeout: int = 8) -> tuple[bool, int]:
    """urllib GET → (有效?, HTTP状态码)。"""
    url = f"http://{target}{endpoint}"
    headers = {"Cookie": cookie, "Accept": "*/*", "Connection": "close"}
    if session_tag:
        headers["SessionTag"] = session_tag
    try:
        req = urllib.request.Request(url, headers=headers, method="GET")
        resp = urllib.request.urlopen(req, timeout=timeout)
        return (resp.status in (200, 204), resp.status)
    except urllib.error.HTTPError as e:
        return (False, e.code)
    except Exception:
        return (False, 0)


def proxy_history_mcp_calls(target: str, ws: str, lookback: int = 50) -> list[dict]:
    """生成两步 MCP proxy_history 调用指令，拿最新 N 条记录。

    原理 (感谢 BurpMCP-Ultra 支持 start_index):
      Step 1: proxy_history(host=target, max_results=1) → 只取 total_filtered
      Step 2: proxy_history(host=target, start_index=total_filtered-N, max_results=N) → 最新 N 条

    注意: proxy_history_search 搜索的是 HTTP 内容，不是 Burp 元数据。
    HTTP 内容里不会出现 ISO 8601 时间戳，所以不能用时间 pattern 搜。
    但 proxy_history 返回的每条记录都有 time 元数据字段。
    """
    return [
        {
            "step": 1,
            "action": "mcp__burp__proxy_history",
            "params": {"host": target, "max_results": 1},
            "save_to": f"{ws}/proxy_count.json",
            "note": "取 total_filtered (不在乎返回的具体条目)",
        },
        {
            "step": 2,
            "action": "mcp__burp__proxy_history",
            "params": {
                "host": target,
                "start_index": f"{{total_filtered - {lookback}}}",
                "max_results": lookback,
            },
            "save_to": f"{ws}/polling_search.json",
            "note": f"取最新 {lookback} 条 (需先从 step1 结果计算 start_index)",
        },
        {
            "step": 3,
            "action": "shell",
            "command": f'python "{__file__}" {ws} --target={target} --ingest={ws}/polling_search.json',
            "note": "内部: 频率分析→提取令牌→HTTP验活→缓存",
        },
    ]


def _pick_auth_endpoint(items: list[dict], fallback: str) -> str:
    """从 proxy_history 条目中找一个需认证的端点。

    判断依据: 同一路径同时出现 200 (带 cookie) 和 401/403 (不带 cookie)
    → 该端点需认证，适合做验活。
    找不到则退回 discover 发现的心跳端点 (可能公开)。
    """
    # 按标准化路径分组，统计状态码分布
    from collections import defaultdict
    path_statuses: dict[str, set[int]] = defaultdict(set)
    path_latest: dict[str, dict] = {}

    for item in items:
        p = item.get("path", "")
        if not p:
            continue
        base = p.split("?")[0].rstrip("/") or "/"
        sc = item.get("status_code", 0)
        path_statuses[base].add(sc)
        idx = item.get("index", 0)
        if base not in path_latest or idx > path_latest[base].get("index", 0):
            path_latest[base] = item

    # 优先: 同时有 200 和 401/403 的路径 → 确认需认证
    auth_paths = []
    for base, statuses in path_statuses.items():
        has_ok = 200 in statuses
        has_deny = bool({401, 403} & statuses)
        if has_ok and has_deny:
            latest = path_latest[base]
            auth_paths.append((latest.get("index", 0), base))

    if auth_paths:
        auth_paths.sort(reverse=True)
        return auth_paths[0][1]

    # 次选: 有 401/403 但无 200 (设备可能重启后 session 全过期)
    deny_only = []
    for base, statuses in path_statuses.items():
        if {401, 403} & statuses:
            deny_only.append((path_latest[base].get("index", 0), base))
    if deny_only:
        deny_only.sort(reverse=True)
        return deny_only[0][1]

    # 兜底
    return fallback


def main():
    args = sys.argv[1:]

    ws = ""
    target = ""
    ingest = ""
    for a in args:
        if a.startswith("--target="):
            target = a.split("=", 1)[1]
        elif a.startswith("--ingest="):
            ingest = a.split("=", 1)[1]
        elif not a.startswith("--"):
            ws = a

    if not ws:
        print("用法: python session_ensure.py <workspace> [--target HOST] [--ingest SEARCH.json]", file=sys.stderr)
        sys.exit(2)

    # ── 模式: --ingest 注入 ──
    if ingest:
        if not target:
            print(json.dumps({"status": "error", "detail": "--ingest 需 --target=IP"}, ensure_ascii=False))
            sys.exit(2)
        if not os.path.exists(ingest):
            print(json.dumps({"status": "error", "detail": f"文件不存在: {ingest}"}, ensure_ascii=False))
            sys.exit(1)

        import auth_token_discovery as td
        with open(ingest, "r", encoding="utf-8") as f:
            raw = f.read()
        items = td.parse_proxy_history(raw)
        disc = td.find_best_token(items)

        if disc["status"] != "ok":
            print(json.dumps({"status": "error", "detail": "令牌发现失败", "discovery": disc}, ensure_ascii=False))
            sys.exit(1)

        cookie = disc["tokens"]["cookie"]
        stag = disc["tokens"]["session_tag"]
        heartbeat_ep = disc["source"]["path"] or "/"

        if not cookie:
            print(json.dumps({"status": "error", "detail": "未提取到 Cookie"}, ensure_ascii=False))
            sys.exit(1)

        # 找认证端点: 在搜索结果中，同一路径同时出现 200 和 401 → 需认证
        verify_ep = _pick_auth_endpoint(items, heartbeat_ep)
        ok, code = http_verify(target, verify_ep, cookie, stag)

        if ok:
            write_cache(ws, target, cookie, stag, verify_ep, disc["source"].get("index", 0))
            print(json.dumps({
                "status": "valid",
                "cookie": cookie,
                "session_tag": stag,
                "target": target,
                "verified_endpoint": verify_ep,
                "http_status": code,
            }, ensure_ascii=False))
            sys.exit(0)
        else:
            print(json.dumps({
                "status": "expired",
                "http_status": code,
                "detail": f"令牌验活失败 (HTTP {code})。请在浏览器刷新设备页面后重试。",
                "tried_endpoint": verify_ep,
            }, ensure_ascii=False))
            sys.exit(1)

    # ── 模式: 验活 ──
    cache = load_cache(ws)
    if cache:
        cookie = cache.get("cookie", "")
        stag = cache.get("session_tag", "")
        tgt = target or cache.get("target", "")
        ep = cache.get("endpoint", "")

        if tgt and cookie and ep:
            ok, code = http_verify(tgt, ep, cookie, stag)
            if ok:
                write_cache(ws, tgt, cookie, stag, ep, cache.get("source_index", 0))
                print(json.dumps({
                    "status": "valid",
                    "cookie": cookie,
                    "session_tag": stag,
                    "target": tgt,
                    "verified_endpoint": ep,
                    "http_status": code,
                }, ensure_ascii=False))
                sys.exit(0)

    # ── 过期 / 无缓存 → MCP 搜索指令 ──
    if not target:
        print(json.dumps({
            "status": "need_target",
            "detail": "无 target。请在浏览器 (经 Burp 代理) 访问设备后，传 --target=IP 重试。",
        }, ensure_ascii=False))
        sys.exit(1)

    steps = proxy_history_mcp_calls(target, ws)
    print(json.dumps({
        "status": "expired",
        "detail": "会话过期。执行 3 步: MCP 取总数 → MCP 取最新 N 条 → 本脚本 --ingest。",
        "refresh": steps,
    }, indent=2, ensure_ascii=False))
    sys.exit(1)


if __name__ == "__main__":
    main()
