#!/usr/bin/env python3
"""
登录爆破锁定探测 (条款 5.1-5) — 确认爆破锁定机制存在 + 锁定阈值。

纯确定性脚本：用 http_fuzz 的 FUZZ 模式把登录口令位置替换为 N 个错误口令，
顺序重放 (sniper 模式天然逐条发送)，观察状态码/body 变化锁定阈值。
不自持 MCP 连接 —— 输出 mcp_call 供 agent 执行，--ingest 处理执行结果。

约束 (per persona): 只做 1-2 次失败探针确认机制存在，完整锁定测试标手工，
不要触发认证锁定导致设备不可用。N 建议 3-5。

用法:
  # 生成 http_fuzz MCP 指令 (exit 1)
  python login_lockout_probe.py <workspace> --target=IP --endpoint=/login --username=admin [--attempts=5] [--prefix=https]

  # 处理 http_fuzz 结果 (exit 0)，检测锁定阈值
  python login_lockout_probe.py <workspace> --target=IP --ingest=fuzz_result.json

输出 (生成模式):
  {"status":"ready", "mcp_calls":[{...http_fuzz...}], "ingest":"..."}

输出 (处理模式):
  {"status":"ok", "attempts":N, "lockout_detected":bool, "lockout_after":K,
   "response_sequence":[{attempt,status_code,...}], "verdict_hint":"..."}
"""

import json
import os
import sys

# 锁定信号状态码 + body 关键词
LOCKOUT_STATUS = {429, 403, 423}
LOCKOUT_KEYWORDS = ("locked", "too many", "rate limit", "throttle", "account lock",
                    "锁定", "过多", "频繁", "超限", "ban")


def build_fuzz_call(target: str, endpoint: str, username: str, attempts: int, prefix: str) -> dict:
    """构造登录爆破 http_fuzz 调用：password=FUZZ，payload 为 N 个错误口令。"""
    payloads = [f"wrong{i}" for i in range(1, attempts + 1)]
    req = (
        f"POST {endpoint} HTTP/1.1\r\n"
        f"Host: {target}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Connection: close\r\n\r\n"
        f"username={username}&password=FUZZ"
    )
    return {
        "step": 1,
        "action": "mcp__burp__http_fuzz",
        "params": {
            "request": req,
            "host": target,
            "port": 443 if prefix == "https" else 80,
            "use_tls": prefix == "https",
            "payloads": payloads,
        },
        "note": f"对 {endpoint} 用 {attempts} 个错误口令顺序重放，观察锁定阈值",
    }


def parse_fuzz_result(raw: str) -> list[dict]:
    try:
        data = json.loads(raw)
    except Exception:
        return []
    if isinstance(data, list) and len(data) == 1 and isinstance(data[0], dict) and "text" in data[0]:
        try:
            data = json.loads(data[0]["text"])
        except Exception:
            return []
    if isinstance(data, dict):
        for key in ("responses", "results", "items"):
            if isinstance(data.get(key), list):
                return data[key]
    if isinstance(data, list):
        return data
    return []


def detect_lockout(items: list[dict]) -> dict:
    """顺序分析响应序列，检测锁定阈值。"""
    seq = []
    lockout_after = None
    for i, it in enumerate(items, start=1):
        if not isinstance(it, dict):
            continue
        sc = it.get("status_code", it.get("status", 0))
        if isinstance(sc, str):
            try:
                sc = int(sc)
            except Exception:
                sc = 0
        body = json.dumps(it.get("body", it.get("body_preview", "")), ensure_ascii=False).lower()
        locked = sc in LOCKOUT_STATUS or any(kw in body for kw in LOCKOUT_KEYWORDS)
        seq.append({"attempt": i, "status_code": sc, "locked": locked})
        if locked and lockout_after is None:
            lockout_after = i

    return {
        "attempts": len(seq),
        "lockout_detected": lockout_after is not None,
        "lockout_after": lockout_after,
        "response_sequence": seq,
    }


def main():
    ws = ""
    target = ""
    endpoint = "/login"
    username = "admin"
    attempts = 5
    ingest = ""
    prefix = "http"

    for a in sys.argv[1:]:
        if a.startswith("--target="):
            target = a.split("=", 1)[1]
        elif a.startswith("--endpoint="):
            endpoint = a.split("=", 1)[1]
        elif a.startswith("--username="):
            username = a.split("=", 1)[1]
        elif a.startswith("--attempts="):
            attempts = int(a.split("=", 1)[1])
        elif a.startswith("--prefix="):
            prefix = a.split("=", 1)[1]
        elif a.startswith("--ingest="):
            ingest = a.split("=", 1)[1]
        elif not a.startswith("--"):
            ws = a

    if not ws:
        print("用法: python login_lockout_probe.py <workspace> --target=IP [--endpoint=/login] [--username=admin] [--attempts=5] [--ingest=FILE]", file=sys.stderr)
        sys.exit(2)

    # ── 处理模式 ──
    if ingest:
        if not os.path.exists(ingest):
            print(json.dumps({"status": "error", "error": f"文件不存在: {ingest}"}, ensure_ascii=False))
            sys.exit(1)
        with open(ingest, "r", encoding="utf-8") as f:
            raw = f.read()
        result = detect_lockout(parse_fuzz_result(raw))
        result["status"] = "ok"
        if result["lockout_detected"]:
            result["verdict_hint"] = (
                f"第 {result['lockout_after']} 次失败后触发锁定，机制存在。"
                f"对照 IXIT 声明的锁定阈值/时长。"
            )
        else:
            result["verdict_hint"] = (
                f"{result['attempts']} 次失败均未锁定 → 可能无爆破防护 (潜在 FAIL)。"
                f"谨慎评估，勿继续大量爆破导致设备锁定。"
            )
        print(json.dumps(result, indent=2, ensure_ascii=False))
        sys.exit(0)

    # ── 生成模式 ──
    if not target:
        print(json.dumps({"status": "error", "error": "生成模式需 --target=IP"}, ensure_ascii=False))
        sys.exit(2)

    fc = build_fuzz_call(target, endpoint, username, attempts, prefix)
    save_to = os.path.join(ws, "fuzz_lockout_result.json")
    fc["save_to"] = save_to
    result = {
        "status": "ready",
        "detail": f"登录爆破锁定探测 {target}{endpoint} (user={username}, {attempts} 次)",
        "mcp_calls": [fc],
        "ingest": f"python login_lockout_probe.py {ws} --target={target} --ingest={save_to}",
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))
    sys.exit(1)


if __name__ == "__main__":
    main()
