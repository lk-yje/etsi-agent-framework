#!/usr/bin/env python3
"""
Auth 越权检测编排器。

子命令:
  endpoints   从 sitemap 输出中提取 API 端点列表 → 去重/过滤/分批
  verdict     对 auth_diff 结果做批量裁决

用法:
  python auth_orchestrator.py endpoints <sitemap.json> [--max N]
  python auth_orchestrator.py verdict <results.json>
"""

import json
import os
import re
import sys
from typing import Optional

# -- 常驻: 静态资源排除 --------------------------------------------
STATIC_EXTS = {".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
               ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp", ".mp4", ".webm"}
STATIC_MIMES = ("IMAGE_", "SCRIPT", "CSS", "FONT", "VIDEO", "AUDIO")
EXCLUDE_PATH_KW = ("sessionLogin", "sessionLogout", "sessionHeartbeat",
                   "captcha", "challenge", "nonce", "getSecurityQuestion")
EXCLUDE_EXTS = (".exe", ".dll", ".so", ".bin", ".dav", ".zip", ".tar", ".gz")

# -- 高风险路径关键词 (优先不采样) ----------------------------------
HIGH_RISK_KW = ("admin", "config", "system", "security", "management",
                "user", "device", "network", "video", "stream", "record",
                "firmware", "upgrade", "update", "reset", "reboot", "factory")


def is_static(url: str, mime: str = "") -> bool:
    """排除静态资源和可执行文件。"""
    url_lower = url.lower()
    for ext in STATIC_EXTS:
        if url_lower.endswith(ext) or f"{ext}?" in url_lower:
            return True
    for ext in EXCLUDE_EXTS:
        if url_lower.endswith(ext):
            return True
    for prefix in STATIC_MIMES:
        if (mime or "").upper().startswith(prefix):
            return True
    return False


def is_preauth(url: str) -> bool:
    """排除预认证端点。"""
    url_lower = url.lower()
    return any(kw.lower() in url_lower for kw in EXCLUDE_PATH_KW)


def extract_path(url: str) -> str:
    """从完整 URL 或路径中提取标准化路径。"""
    # 如果是完整 URL: http://host/path?query → /path
    if "://" in url:
        path = url.split("://", 1)[1].split("/", 1)
        path = "/" + path[1] if len(path) > 1 else "/"
    else:
        path = url
    # 去 query string
    path = path.split("?")[0]
    # 去尾 / (保留根路径 /)
    if len(path) > 1:
        path = path.rstrip("/")
    return path


def is_high_risk(path: str) -> bool:
    """高风险路径 (GET 采样时不丢弃)。"""
    return any(kw in path.lower() for kw in HIGH_RISK_KW)


def cmd_endpoints(args: list[str]) -> int:
    """子命令: endpoints — 从 sitemap 输出中提取 API 端点列表。"""
    if len(args) < 1:
        print("用法: python auth_orchestrator.py endpoints <sitemap.json> [--max N]", file=sys.stderr)
        return 2

    path = args[0]
    max_endpoints = 50
    for a in args[1:]:
        if a.startswith("--max="):
            max_endpoints = int(a.split("=", 1)[1])

    if not os.path.exists(path):
        print(json.dumps({"error": f"文件不存在: {path}"}, ensure_ascii=False))
        return 1

    with open(path, "r", encoding="utf-8") as f:
        sitemap = json.load(f)

    # Step 1: 过滤
    candidates = []
    for entry in sitemap:
        url = entry.get("url", "")
        method = entry.get("method", "GET")
        status = entry.get("status_code", 0)
        mime = entry.get("mime_type", "")

        # 跳过静态资源
        if is_static(url, mime):
            continue
        # 跳过预认证端点
        if is_preauth(url):
            continue
        # 跳过未成功访问过的 (status=0 且 no content)
        if status == 0 and entry.get("content_length", 0) == 0:
            continue
        # 跳过 404
        if status == 404:
            continue

        norm = extract_path(url)
        candidates.append({
            "method": method,
            "path": norm,
            "full_url": url,
            "status": status,
            "mime": mime,
            "high_risk": is_high_risk(norm),
        })

    # Step 2: 去重 (同 path + method 只保留一个)
    seen = set()
    unique = []
    for c in candidates:
        key = (c["method"], c["path"])
        if key not in seen:
            seen.add(key)
            unique.append(c)

    # Step 3: 优先级排序
    # POST/PUT/DELETE 在前 (写越权风险最高)
    write_methods = [c for c in unique if c["method"] in ("POST", "PUT", "DELETE", "PATCH")]
    get_high = [c for c in unique if c["method"] == "GET" and c["high_risk"]]
    get_rest = [c for c in unique if c["method"] == "GET" and not c["high_risk"]]
    other = [c for c in unique if c["method"] not in ("GET", "POST", "PUT", "DELETE", "PATCH")]

    prioritized = write_methods + get_high + get_rest + other

    # Step 4: 采样 (如果超过 max_endpoints)
    total = len(prioritized)
    if total > max_endpoints:
        sampled = prioritized[:max_endpoints]
        dropped = total - max_endpoints
        drop_note = (f"端点总数 {total} 超过上限 {max_endpoints}，"
                     f"丢弃 {dropped} 个低风险 GET 端点。"
                     f"所有 POST/PUT/DELETE ({len(write_methods)}) 均已保留。")
    else:
        sampled = prioritized
        drop_note = None

    # Step 5: 输出
    result = {
        "total_endpoints": total,
        "after_filter": len(sampled),
        "write_methods_count": len(write_methods),
        "dropped": total - len(sampled) if total > max_endpoints else 0,
        "drop_note": drop_note,
        "endpoints": [
            {
                "seq": i + 1,
                "method": ep["method"],
                "path": ep["path"],
                "full_url": ep["full_url"],
                "status": ep["status"],
                "high_risk": ep["high_risk"],
            }
            for i, ep in enumerate(sampled)
        ],
    }

    print(json.dumps(result, indent=2, ensure_ascii=False))

    # agent 下一步指引
    if result["endpoints"]:
        print(f"\n# --- agent: 对以上 {len(sampled)} 个端点逐条调用 auth_diff ---")
        print(f"# 每条: 使用 discover 步骤输出的 auth_levels + 替换 path")
        print(f"# 结果追加写入: <workspace>/auth_diff_results.jsonl (每行一条 JSON)")
        if write_count := len(write_methods):
            print(f"# ⚠️ 其中 {write_count} 个 POST/PUT/DELETE 端点, CSRF token 可能导致 admin 也 403")
        if drop_note:
            print(f"# ⚠️ {drop_note}")

    return 0


def cmd_verdict(args: list[str]) -> int:
    """子命令: verdict — 批量裁决 auth_diff 结果。"""
    from auth_verdict_decider import decide_single

    if len(args) < 1:
        print("用法: python auth_orchestrator.py verdict <results.json>", file=sys.stderr)
        return 2

    path = args[0]
    if not os.path.exists(path):
        print(json.dumps({"error": f"文件不存在: {path}"}, ensure_ascii=False))
        return 1

    with open(path, "r", encoding="utf-8") as f:
        results_data = json.load(f)

    # 支持两种格式: 数组 [ep1, ep2, ...] 或对象 {results: [...]}
    if isinstance(results_data, list):
        entries = results_data
    elif isinstance(results_data, dict) and "results" in results_data:
        entries = results_data["results"]
    else:
        entries = [results_data]

    verdicts = []
    stats = {"PASS": 0, "FAIL": 0, "SUSPICIOUS": 0, "SKIP": 0, "INCONCLUSIVE": 0, "ERROR": 0}

    for entry in entries:
        ep = entry.get("endpoint", entry.get("path", "?"))
        method = entry.get("method", "GET")
        try:
            raw = json.dumps(entry.get("auth_diff_result", entry))
            v = decide_single(raw)
        except Exception as e:
            v = {"verdict": "ERROR", "confidence": "NONE", "reason": str(e)}

        v["endpoint"] = ep
        v["method"] = method
        verdicts.append(v)
        stats[v["verdict"]] = stats.get(v["verdict"], 0) + 1

    total = len(verdicts)
    failed = stats["FAIL"]
    suspicious = stats["SUSPICIOUS"]
    effective = total - stats["SKIP"] - stats["ERROR"]

    if failed > 0:
        overall = "FAIL"
        summary = f"{effective} 个有效端点中 {failed} 个存在未认证访问"
    elif suspicious > 0:
        overall = "INCONCLUSIVE"
        summary = f"{suspicious} 个端点需人工确认"
    elif stats["PASS"] == 0:
        overall = "INCONCLUSIVE"
        summary = "无有效端点完成测试"
    else:
        overall = "PASS"
        summary = f"{effective} 个端点全部通过越权检测"

    output = {
        "overall_verdict": overall,
        "summary": summary,
        "stats": stats,
        "total": total,
        "effective": effective,
        "results": [
            {"seq": i + 1, "method": v["method"], "endpoint": v["endpoint"],
             "verdict": v["verdict"], "confidence": v.get("confidence", ""),
             "reason": v.get("reason", "")[:120]}
            for i, v in enumerate(verdicts)
        ],
    }

    # FAIL 详情
    failed_eps = [v for v in verdicts if v["verdict"] == "FAIL"]
    if failed_eps:
        output["fail_details"] = [
            {"method": v["method"], "endpoint": v["endpoint"], "reason": v.get("reason", "")}
            for v in failed_eps
        ]

    print(json.dumps(output, indent=2, ensure_ascii=False))
    return 1 if failed > 0 else 0


def main():
    if len(sys.argv) < 2:
        print("用法: python auth_orchestrator.py <endpoints|verdict> [args...]", file=sys.stderr)
        print("  endpoints <sitemap.json> [--max N]", file=sys.stderr)
        print("  verdict   <results.json>", file=sys.stderr)
        sys.exit(2)

    cmd = sys.argv[1]
    rest = sys.argv[2:]

    if cmd == "endpoints":
        sys.exit(cmd_endpoints(rest))
    elif cmd == "verdict":
        sys.exit(cmd_verdict(rest))
    else:
        print(f"未知子命令: {cmd}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
