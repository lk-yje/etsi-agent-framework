#!/usr/bin/env python3
"""
从 Burp proxy_history 输出中提取最新有效认证令牌。

用法:
  python auth_token_discovery.py <proxy_history_output.json>
  cat result.json | python auth_token_discovery.py --stdin

输出 (JSON):
  {
    "status": "ok" | "no_auth" | "no_traffic",
    "tokens": {"cookie": "...", "session_tag": "...", "authorization": null},
    "source": {"index": 4707, "timestamp": "...", "status_code": 200, "path": "..."}
  }

注意: proxy_history 正序排列 (最旧在前)。调用方应先用 start_index 两步法取最新条目:
  1. proxy_history(host=DUT, max_results=1) → total_filtered
  2. proxy_history(host=DUT, start_index=total_filtered-50, max_results=50) → 最新 50 条
"""

import json
import os
import sys
from typing import Optional


def parse_proxy_history(raw: str) -> list[dict]:
    """解析 proxy_history 原始输出，返回扁平条目列表。"""
    data = json.loads(raw)
    if isinstance(data, list) and len(data) == 1 and "text" in data[0]:
        inner = json.loads(data[0]["text"])
    elif isinstance(data, list):
        return data
    else:
        inner = data
    if isinstance(inner, dict) and "items" in inner:
        return inner["items"]
    if isinstance(inner, list):
        return inner
    return []


def extract_auth_headers(item: dict) -> dict[str, Optional[str]]:
    """从单个条目提取所有认证相关 header。"""
    headers = item.get("request_headers", [])
    result = {"cookie": None, "session_tag": None, "authorization": None}
    for h in headers:
        name = h.get("name", "")
        value = h.get("value", "")
        nl = name.lower()
        if nl == "cookie":
            result["cookie"] = value
        elif nl == "sessiontag":
            result["session_tag"] = value
        elif nl == "authorization":
            result["authorization"] = value
    return result


def has_any_auth(item: dict) -> bool:
    auth = extract_auth_headers(item)
    return bool(auth["cookie"] or auth["session_tag"] or auth["authorization"])


def find_best_token(items: list[dict]) -> dict:
    """取 index 最大 (最新) 且带认证头的条目。"""
    if not items:
        return {"status": "no_traffic", "error": "proxy_history 中无条目"}

    best = None
    best_idx = -1
    for item in items:
        if not has_any_auth(item):
            continue
        idx = item.get("index", 0)
        if idx > best_idx:
            best_idx = idx
            best = item

    if not best:
        return {"status": "no_auth", "error": "无携带认证头的条目"}

    auth = extract_auth_headers(best)
    return {
        "status": "ok",
        "tokens": {
            "cookie": auth["cookie"],
            "session_tag": auth["session_tag"],
            "authorization": auth["authorization"],
        },
        "source": {
            "index": best.get("index", 0),
            "timestamp": best.get("time", ""),
            "status_code": best.get("status_code", 0),
            "path": best.get("path", ""),
        },
    }


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]

    if len(args) < 1 and "--stdin" not in sys.argv:
        print("用法: python auth_token_discovery.py <proxy_history.json>", file=sys.stderr)
        print("      cat result.json | python auth_token_discovery.py --stdin", file=sys.stderr)
        sys.exit(2)

    if "--stdin" in sys.argv:
        raw = sys.stdin.read()
    else:
        path = args[0]
        if not os.path.exists(path):
            print(json.dumps({"status": "error", "error": f"文件不存在: {path}"}, ensure_ascii=False))
            sys.exit(1)
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()

    try:
        items = parse_proxy_history(raw)
    except Exception as e:
        print(json.dumps({"status": "error", "error": f"解析失败: {e}"}, ensure_ascii=False))
        sys.exit(1)

    result = find_best_token(items)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    sys.exit(0 if result["status"] == "ok" else 1)


if __name__ == "__main__":
    main()
