#!/usr/bin/env python3
"""
篡改固件上传流量核验 (条款 5.3-9) — 验证设备拒绝篡改固件。

固件更新已在 TrafficCollectStage 手动触发并抓取，本脚本只做「事后读流量 + 裁决」：
  1. proxy_history 拉取固件相关请求 (host 过滤 + 本地按路径关键词筛)
  2. websocket_list 找固件更新的 WS 连接
  3. websocket_get_messages 读服务端状态帧 (server_to_client)
  4. 本地裁决：服务端拒绝 (reject/error/deny) → PASS；接受 (success/ok) → FAIL

不自持 MCP 连接 —— 输出 mcp_calls 供 agent 执行，--ingest 处理执行结果。

用法:
  # 生成 MCP 指令序列 (exit 1)
  python firmware_traffic_verify.py <workspace> --target=IP

  # 处理结果 (exit 0)
  python firmware_traffic_verify.py <workspace> --target=IP --ingest=collected.json
"""

import json
import os
import re
import sys

# 固件相关路径关键词 (本地筛 proxy_history 用)
FIRMWARE_PATH_KW = ("firmware", "update", "upgrade", "upload", "flash", "fw", "upgrade")
# 服务端拒绝信号
REJECT_KW = ("reject", "deny", "fail", "error", "invalid", "signature", "verify",
             "拒绝", "失败", "无效", "签名", "校验")
# 服务端接受信号
ACCEPT_KW = ("success", "ok", "accepted", "complete", "成功", "接受", "完成")


def build_mcp_sequence(target: str, ws: str) -> list[dict]:
    return [
        {
            "step": 1,
            "action": "mcp__burp__proxy_history",
            "params": {"host": target, "include_request": True, "max_results": 200},
            "save_to": os.path.join(ws, "firmware_proxy_history.json"),
            "note": f"拉取 {target} 的代理历史 (含请求)，下一步本地筛固件上传请求",
        },
        {
            "step": 2,
            "action": "mcp__burp__proxy_websocket_history",
            "params": {"host": target, "direction": "server_to_client", "count": 20},
            "save_to": os.path.join(ws, "firmware_ws_history.json"),
            "note": "查 WS 升级历史。⚠️ proxy_websocket_history 只认 start_index/count（不读 max_results），direction=server_to_client + count≤20 防超时",
        },
        {
            "step": 3,
            "action": "mcp__burp__websocket_list",
            "params": {},
            "save_to": os.path.join(ws, "firmware_ws_list.json"),
            "note": "列出 WS 连接，找固件更新用的 connection_id",
        },
        {
            "step": 4,
            "action": "mcp__burp__websocket_get_messages",
            "params": {
                "connection_id": "{{从 step3 结果的固件相关 connection_id 填入}}",
                "direction": "server_to_client",
                "max_results": 20,
            },
            "save_to": os.path.join(ws, "firmware_ws_messages.json"),
            "note": "读服务端状态帧 (⚠️ max_results≤20 防超时)。把 proxy_history + ws_history + ws_messages 合并成 collected.json 再 ingest",
        },
    ]


def load_json_file(path: str) -> dict | list:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def unwrap(data) -> list:
    """兼容 MCP wrapper，返回扁平条目列表。"""
    if isinstance(data, list) and len(data) == 1 and isinstance(data[0], dict) and "text" in data[0]:
        try:
            data = json.loads(data[0]["text"])
        except Exception:
            return []
    if isinstance(data, dict):
        for key in ("items", "entries", "responses", "messages", "results"):
            if isinstance(data.get(key), list):
                return data[key]
    if isinstance(data, list):
        return data
    return []


def find_firmware_requests(proxy_items: list[dict]) -> list[dict]:
    out = []
    for it in proxy_items:
        if not isinstance(it, dict):
            continue
        url = it.get("url") or it.get("path") or ""
        if any(kw in url.lower() for kw in FIRMWARE_PATH_KW):
            out.append(it)
    return out


def judge(firmware_reqs: list[dict], ws_messages: list[dict]) -> dict:
    """裁决：服务端是否拒绝篡改固件。"""
    verdict = "INCONCLUSIVE"
    reasons = []

    if not firmware_reqs:
        reasons.append("未在 proxy_history 中发现固件相关请求")
    else:
        # 从请求状态码看上传是否被拒
        for r in firmware_reqs:
            sc = r.get("status_code", r.get("status", 0))
            if isinstance(sc, str):
                try:
                    sc = int(sc)
                except Exception:
                    sc = 0
            if sc in (400, 401, 403, 406, 415, 422, 500):
                reasons.append(f"上传请求 {r.get('url', r.get('path', '?'))} 返回 {sc} (拒绝)")

    # 从 WS 状态帧看服务端态度
    ws_text = " ".join(
        str(m.get("message", m.get("data", m.get("text", "")))).lower()
        for m in ws_messages if isinstance(m, dict)
    )
    # 实测拒绝帧核心信号: statusCode=4 + fileError (clause-reference.md 5.3-2 坑注)
    file_error = "fileerror" in ws_text
    status_4 = ("statuscode" in ws_text) and re.search(r"statuscode[\"':=\s]*4\b", ws_text) is not None
    has_reject = file_error or status_4 or any(kw in ws_text for kw in REJECT_KW)
    has_accept = any(kw in ws_text for kw in ACCEPT_KW)
    if file_error:
        reasons.append("WS 状态帧含 fileError 字段 (固件被拒)")
    if status_4:
        reasons.append("WS 状态帧含 statusCode=4 (错误状态码)")

    if has_reject and not has_accept:
        verdict = "PASS"
    elif has_accept and not has_reject:
        verdict = "FAIL"
    elif firmware_reqs and not ws_messages:
        verdict = "INCONCLUSIVE"
        reasons.append("有固件请求但无 WS 状态帧，需人工确认")

    return {
        "verdict": verdict,
        "reasons": reasons,
        "firmware_requests": len(firmware_reqs),
        "ws_message_count": len(ws_messages),
        "clause": "5.3-9",
    }


def main():
    ws = ""
    target = ""
    ingest = ""

    for a in sys.argv[1:]:
        if a.startswith("--target="):
            target = a.split("=", 1)[1]
        elif a.startswith("--ingest="):
            ingest = a.split("=", 1)[1]
        elif not a.startswith("--"):
            ws = a

    if not ws:
        print("用法: python firmware_traffic_verify.py <workspace> --target=IP [--ingest=collected.json]", file=sys.stderr)
        sys.exit(2)

    # ── 处理模式 ──
    if ingest:
        if not os.path.exists(ingest):
            print(json.dumps({"status": "error", "error": f"文件不存在: {ingest}"}, ensure_ascii=False))
            sys.exit(1)
        data = load_json_file(ingest)
        # collected.json 结构: {"proxy_history": [...], "ws_messages": [...]}
        if isinstance(data, dict):
            proxy_items = unwrap(data.get("proxy_history", []))
            ws_messages = unwrap(data.get("ws_messages", []))
        else:
            proxy_items = unwrap(data)
            ws_messages = []
        firmware_reqs = find_firmware_requests(proxy_items)
        result = judge(firmware_reqs, ws_messages)
        result["status"] = "ok"
        print(json.dumps(result, indent=2, ensure_ascii=False))
        sys.exit(0 if result["verdict"] == "PASS" else 1)

    # ── 生成模式 ──
    if not target:
        print(json.dumps({"status": "error", "error": "生成模式需 --target=IP"}, ensure_ascii=False))
        sys.exit(2)

    seq = build_mcp_sequence(target, ws)
    result = {
        "status": "ready",
        "detail": f"固件上传流量核验 {target} (4 步 MCP)",
        "mcp_calls": seq,
        "ingest": f"python firmware_traffic_verify.py {ws} --target={target} --ingest={os.path.join(ws, 'collected.json')}",
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))
    sys.exit(1)


if __name__ == "__main__":
    main()
