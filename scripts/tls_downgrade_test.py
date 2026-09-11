#!/usr/bin/env python3
"""
TLS 降级 MITM + 固件篡改 + WS 状态帧 (条款 5.3-2)。

固件更新已在 TrafficCollectStage 手动触发并抓取，本脚本生成「降级配置 + 读流量 + 裁决」的
MCP 指令序列。裁决两个维度:
  1. 弱 TLS 降级: 设备是否在 TLS1.0/1.1 降级下仍接受固件更新 → 接受 = FAIL
  2. 固件篡改: 篡改固件是否被拒绝 → 拒绝 = PASS

注意: burp_import_project_config 的 config_json 是 Burp 版本相关的 schema，
本脚本给出模板，第一步先 burp_export_project_config 拿到实际字段再改。

用法:
  # 生成 MCP 指令序列 (exit 1)
  python tls_downgrade_test.py <workspace> --target=IP

  # 处理结果 (exit 0)
  python tls_downgrade_test.py <workspace> --target=IP --ingest=collected.json
"""

import json
import os
import re
import sys

# 降级 TLS 配置模板 (字段名来自 burp_export_project_config 的 proxy.request_listeners 结构；
# 真实字段是 custom_tls_protocols / use_custom_tls_protocols / enable_http2，
# 不存在顶层 tls_protocols/http2 —— 用错字段 import 会被静默丢弃 (no-op)，同 config_upstream_proxy_set)
TLS_DOWNGRADE_CONFIG = {
    "proxy": {
        "request_listeners": [
            {
                "listener_port": 8080,
                "use_custom_tls_protocols": True,
                "custom_tls_protocols": ["TLSv1", "TLSv1.1"],
                "enable_http2": False,
            }
        ]
    }
}

# 弱 TLS 信号 (从 proxy_history 里固件更新请求的 TLS 版本字段判断)
WEAK_TLS_KW = ("TLSv1.0", "TLSv1.1", "TLS1.0", "TLS1.1", "tlsv1")
REJECT_KW = ("reject", "deny", "fail", "error", "invalid", "signature", "verify",
             "拒绝", "失败", "无效", "签名", "校验")
FIRMWARE_PATH_KW = ("firmware", "update", "upgrade", "upload", "flash", "fw")


def build_mcp_sequence(target: str, ws: str) -> list[dict]:
    return [
        {
            "step": 1,
            "action": "mcp__burp__burp_export_project_config",
            "params": {"paths": ["proxy"]},
            "save_to": os.path.join(ws, "tls_config_export.json"),
            "note": "导出当前 proxy 配置，核对 tls_protocols 字段名后改降级配置",
        },
        {
            "step": 2,
            "action": "mcp__burp__burp_import_project_config",
            "params": {"config_json": json.dumps(TLS_DOWNGRADE_CONFIG)},
            "save_to": os.path.join(ws, "tls_config_import_result.json"),
            "note": "导入降级 TLS 配置 (只允许 TLS1.0/1.1，关 http2)。若字段名不符，先按 step1 结果改 config_json",
        },
        {
            "step": 3,
            "action": "mcp__burp__proxy_history",
            "params": {"host": target, "include_request": True, "max_results": 200},
            "save_to": os.path.join(ws, "tls_proxy_history.json"),
            "note": f"拉取 {target} 代理历史，本地筛固件更新请求并看 TLS 版本",
        },
        {
            "step": 4,
            "action": "mcp__burp__proxy_websocket_history",
            "params": {"host": target, "direction": "server_to_client", "count": 20},
            "save_to": os.path.join(ws, "tls_ws_history.json"),
            "note": "查 WS 升级记录 (status 101)。⚠️ proxy_websocket_history 只认 start_index/count（不读 max_results），count≤20 防超时",
        },
        {
            "step": 5,
            "action": "mcp__burp__websocket_list",
            "params": {},
            "save_to": os.path.join(ws, "tls_ws_list.json"),
            "note": "列出 WS 连接，找固件更新的 connection_id",
        },
        {
            "step": 6,
            "action": "mcp__burp__websocket_get_messages",
            "params": {
                "connection_id": "{{从 step5 结果的固件相关 connection_id 填入}}",
                "direction": "server_to_client",
                "max_results": 20,
            },
            "save_to": os.path.join(ws, "tls_ws_messages.json"),
            "note": "读服务端状态帧，判断篡改固件是否被拒",
        },
    ]


def unwrap(data) -> list:
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
        url = str(it.get("url") or it.get("path") or "")
        if any(kw in url.lower() for kw in FIRMWARE_PATH_KW):
            out.append(it)
    return out


def judge(proxy_items: list[dict], ws_messages: list[dict]) -> dict:
    """裁决 5.3-2: 弱 TLS 是否被接受 + 篡改固件是否被拒。"""
    firmware_reqs = find_firmware_requests(proxy_items)
    weak_tls_seen = False
    weak_tls_evidence = []

    for r in firmware_reqs:
        blob = json.dumps(r, ensure_ascii=False).lower()
        if any(kw.lower() in blob for kw in WEAK_TLS_KW):
            weak_tls_seen = True
            weak_tls_evidence.append({
                "url": r.get("url", r.get("path", "?")),
                "status_code": r.get("status_code", r.get("status", 0)),
            })

    ws_text = " ".join(
        str(m.get("message", m.get("data", m.get("text", "")))).lower()
        for m in ws_messages if isinstance(m, dict)
    )
    # 实测拒绝帧核心信号: statusCode=4 + fileError
    file_error = "fileerror" in ws_text
    status_4 = ("statuscode" in ws_text) and re.search(r"statuscode[\"':=\s]*4\b", ws_text) is not None
    has_reject = file_error or status_4 or any(kw in ws_text for kw in REJECT_KW)

    findings = []
    # 维度 1: 弱 TLS 降级
    if weak_tls_seen:
        findings.append({
            "dimension": "tls_downgrade",
            "verdict": "FAIL",
            "detail": f"固件更新请求走弱 TLS (TLS1.0/1.1)，设备接受降级连接",
        })
    else:
        findings.append({
            "dimension": "tls_downgrade",
            "verdict": "PASS" if firmware_reqs else "INCONCLUSIVE",
            "detail": "未发现固件更新走弱 TLS" if firmware_reqs else "未发现固件更新请求",
        })

    # 维度 2: 固件篡改
    if has_reject:
        findings.append({
            "dimension": "firmware_tamper",
            "verdict": "PASS",
            "detail": "WS 状态帧含拒绝/签名校验信号，篡改固件被拒",
        })
    elif ws_messages:
        findings.append({
            "dimension": "firmware_tamper",
            "verdict": "FAIL",
            "detail": "WS 状态帧无拒绝信号，篡改固件可能被接受",
        })
    else:
        findings.append({
            "dimension": "firmware_tamper",
            "verdict": "INCONCLUSIVE",
            "detail": "无 WS 状态帧",
        })

    overall = "INCONCLUSIVE"
    if any(f["verdict"] == "FAIL" for f in findings):
        overall = "FAIL"
    elif all(f["verdict"] in ("PASS", "INCONCLUSIVE") for f in findings) and any(f["verdict"] == "PASS" for f in findings):
        overall = "PASS" if all(f["verdict"] == "PASS" for f in findings) else "INCONCLUSIVE"

    return {
        "verdict": overall,
        "findings": findings,
        "firmware_requests": len(firmware_reqs),
        "weak_tls_evidence": weak_tls_evidence,
        "ws_message_count": len(ws_messages),
        "clause": "5.3-2",
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
        print("用法: python tls_downgrade_test.py <workspace> --target=IP [--ingest=collected.json]", file=sys.stderr)
        sys.exit(2)

    if ingest:
        if not os.path.exists(ingest):
            print(json.dumps({"status": "error", "error": f"文件不存在: {ingest}"}, ensure_ascii=False))
            sys.exit(1)
        with open(ingest, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            proxy_items = unwrap(data.get("proxy_history", []))
            ws_messages = unwrap(data.get("ws_messages", []))
        else:
            proxy_items = unwrap(data)
            ws_messages = []
        result = judge(proxy_items, ws_messages)
        result["status"] = "ok"
        print(json.dumps(result, indent=2, ensure_ascii=False))
        sys.exit(0 if result["verdict"] == "PASS" else 1)

    if not target:
        print(json.dumps({"status": "error", "error": "生成模式需 --target=IP"}, ensure_ascii=False))
        sys.exit(2)

    seq = build_mcp_sequence(target, ws)
    result = {
        "status": "ready",
        "detail": f"TLS 降级 + 固件篡改核验 {target} (6 步 MCP)",
        "mcp_calls": seq,
        "ingest": f"python tls_downgrade_test.py {ws} --target={target} --ingest={os.path.join(ws, 'collected.json')}",
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))
    sys.exit(1)


if __name__ == "__main__":
    main()
