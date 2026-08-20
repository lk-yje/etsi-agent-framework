#!/usr/bin/env python3
"""
Auth Step 3a: auth_diff 请求构造强制门禁。

在每次调用 mcp__burp__auth_diff 之前执行，验证请求的协议合规性。
三项硬检查 + 一项设备适配建议。任何一项 FAIL → exit 1，禁止发送请求。

检查项:
  1. CRLF 强制: 行尾必须是 \\r\\n，禁止裸 \\n (HTTP/1.1 RFC 要求)
  2. 认证头隔离: base request 禁止携带 Cookie / Authorization / SessionTag
  3. 双头结构: ISAPI 设备强制 SessionTag 在 base request, Cookie 在 auth_levels
  4. 基础结构: method + path + HTTP version + Host header

用法:
  python auth_request_lint.py <request_json_file>
  echo '{"request":"...","auth_levels":[...]}' | python auth_request_lint.py --stdin

request_json 格式:
  {
    "request": "GET /path HTTP/1.1\\r\\nHost: DUT\\r\\nSessionTag: abc\\r\\n\\r\\n",
    "auth_levels": [
      {"name":"admin","header_name":"Cookie","header_value":"session=xyz"},
      {"name":"none"}
    ],
    "device_hint": "isapi"   // 可选: "isapi" | "generic" | null
  }

退出码:
  0 = 所有检查通过，可以发送
  1 = 发现 WARN (建议修复但允许继续) — 仍然 exit 0
  2 = 发现 FAIL (硬阻断) — 禁止发送，必须修复后重新 lint
"""

import json
import os
import re
import sys


def check_crlf(request: str) -> list[dict]:
    """检查行尾是否为 CRLF (\\r\\n) 而非裸 \\n。"""
    findings = []
    # 检测裸 \\n (前面没有 \\r)
    bare_lf_pattern = re.compile(r'(?<!\r)\n')
    matches = list(bare_lf_pattern.finditer(request))
    if matches:
        # 排除请求体中的换行 (header 之后的部分)
        header_end = request.find("\r\n\r\n")
        header_part = request[:header_end] if header_end > 0 else request
        header_bare = list(bare_lf_pattern.finditer(header_part))
        if header_bare:
            findings.append({
                "level": "FAIL",
                "check": "crlf",
                "message": (
                    f"请求头中发现 {len(header_bare)} 处裸 \\n (非 \\r\\n)。"
                    f"HTTP/1.1 协议要求行尾为 CRLF。裸 \\n 会导致服务器无法正确解析 → 连接挂起 ~8s 超时。"
                ),
                "fix": "将请求中所有 \\n 替换为 \\r\\n。注意: Claude Code tool call 参数中直接写成 \\r\\n 即可。",
                "ref": "tool-error-kb.json → AUTH_DIFF_CRLF_TIMEOUT",
            })
        elif matches:
            findings.append({
                "level": "WARN",
                "check": "crlf",
                "message": (
                    f"请求体中发现 {len(matches)} 处裸 \\n。header 部分正常。"
                    f"若 body 是 JSON/XML 且 \\n 仅作格式化，通常不影响解析。"
                ),
                "fix": "如果不确定，将 body 也改用 \\r\\n。"
            })
    if not matches:
        findings.append({
            "level": "OK",
            "check": "crlf",
            "message": "行尾 CRLF 正确"
        })
    return findings


def check_auth_isolation(request: str, auth_levels: list[dict], device_hint: str = "generic") -> list[dict]:
    """检查 base request 是否泄漏认证头。

    ISAPI 双头模式例外: SessionTag 是辅助头 (单独不足以认证)，允许放在 base request。
    但 Cookie 和 Authorization 绝对不能在 base request — 它们是主凭据，泄漏 = 漏报。
    """
    findings = []
    # 提取 header 部分
    header_end = request.find("\r\n\r\n")
    if header_end < 0:
        header_end = request.find("\n\n")
    header_part = request[:header_end] if header_end > 0 else request

    has_cookie = bool(re.search(r'^(cookie|Cookie):', header_part, re.MULTILINE))
    has_auth = bool(re.search(r'^(authorization|Authorization):', header_part, re.MULTILINE))
    has_stag = bool(re.search(r'^(sessiontag|Sessiontag|SessionTag):', header_part, re.MULTILINE))
    has_cookie_in_levels = any(
        lv.get("header_name", "").lower() == "cookie" for lv in auth_levels
    )

    # Cookie 在主凭据位置 → 总是 FAIL
    # Authorization → 总是 FAIL
    hard_leaks = []
    if has_cookie:
        hard_leaks.append("Cookie")
    if has_auth:
        hard_leaks.append("Authorization")

    # SessionTag 在 ISAPI 双头模式下允许，否则也报
    stag_allowed = (device_hint == "isapi" and has_stag and has_cookie_in_levels)
    if has_stag and not stag_allowed:
        hard_leaks.append("SessionTag")

    if hard_leaks:
        findings.append({
            "level": "FAIL",
            "check": "auth_isolation",
            "message": (
                f"base request 中包含主认证头: {hard_leaks}。"
                f"auth_diff 不会自动剥离原请求中的认证头 → none 级别实际也携带认证 → 漏报。"
            ),
            "fix": (
                f"从 request 参数中删除 {hard_leaks} header。"
                f"认证凭据通过 auth_levels 的 header_name + header_value 注入。"
            ),
            "ref": "tool-error-kb.json → AUTH_DIFF_LEAKS_ORIGINAL_AUTH",
        })
    elif stag_allowed:
        findings.append({
            "level": "OK",
            "check": "auth_isolation",
            "message": "ISAPI 双头模式: SessionTag 在 base request (辅助头，单独不足以认证) + Cookie 在 auth_levels (主凭据)。结构正确。"
        })
    else:
        findings.append({
            "level": "OK",
            "check": "auth_isolation",
            "message": "base request 中无主认证头泄漏"
        })
    return findings


def check_dual_header_structure(request: str, auth_levels: list[dict], device_hint: str) -> list[dict]:
    """检查 ISAPI 双头认证结构: SessionTag in base request + Cookie in auth_levels。"""
    findings = []

    has_stag_in_request = bool(re.search(
        r'^(sessiontag|Sessiontag|SessionTag):', request, re.MULTILINE
    ))
    has_cookie_in_levels = any(
        lv.get("header_name", "").lower() == "cookie"
        for lv in auth_levels
    )

    if device_hint == "isapi" or (has_stag_in_request and has_cookie_in_levels):
        if has_stag_in_request and has_cookie_in_levels:
            findings.append({
                "level": "OK",
                "check": "dual_header",
                "message": "ISAPI 双头结构正确: SessionTag 在 base request (固定携带) + Cookie 在 auth_levels (区分 admin/none)"
            })
        elif has_stag_in_request and not has_cookie_in_levels:
            findings.append({
                "level": "FAIL",
                "check": "dual_header",
                "message": "ISAPI 设备: base request 含 SessionTag 但 auth_levels 中无 Cookie。none 级别仅 SessionTag 不足以认证，但 admin 级别也缺少主凭据 Cookie。",
                "fix": "在 auth_levels 中添加: {name:'admin', header_name:'Cookie', header_value:'WebSession_xxx=...'}",
                "ref": "tool-error-kb.json → AUTH_DUAL_HEADER_REQUIRED",
            })
        elif not has_stag_in_request and has_cookie_in_levels:
            findings.append({
                "level": "OK",
                "check": "dual_header",
                "message": "单头设备模式: Cookie 在 auth_levels，base request 无辅助头。若实际需要双头 → 加 --device-hint isapi"
            })
    else:
        findings.append({
            "level": "OK",
            "check": "dual_header",
            "message": "单头设备模式 (未检测到 ISAPI 双头结构)"
        })

    return findings


def check_basic_structure(request: str) -> list[dict]:
    """检查 HTTP 请求的基本结构完整性。"""
    findings = []
    lines = request.split("\r\n")

    # Request line
    if len(lines) < 1:
        findings.append({
            "level": "FAIL",
            "check": "structure",
            "message": "请求为空",
            "fix": "提供完整的 HTTP 请求: METHOD /path HTTP/1.1\\r\\nHost: ...\\r\\n\\r\\n"
        })
        return findings

    req_line = lines[0]
    req_match = re.match(r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+HTTP/1\.[01]', req_line)
    if not req_match:
        findings.append({
            "level": "FAIL",
            "check": "structure",
            "message": f"请求行格式错误: '{req_line[:60]}'。预期: METHOD /path HTTP/1.1",
            "fix": "确保第一行格式为: GET /ISAPI/Security/capabilities HTTP/1.1\\r\\n"
        })
    else:
        findings.append({
            "level": "OK",
            "check": "structure",
            "message": f"请求行: {req_match.group(1)} {req_match.group(2)} {req_match.group(0).split()[-1]}"
        })

    # Host header
    has_host = any(
        re.match(r'^Host:\s+\S+', line, re.IGNORECASE) for line in lines[1:]
    )
    if not has_host:
        findings.append({
            "level": "FAIL",
            "check": "structure",
            "message": "缺少 Host header。HTTP/1.1 要求 Host header。",
            "fix": "在请求头中添加: Host: <dut_ip>\\r\\n"
        })

    # 必须以 \\r\\n\\r\\n 结束
    if not request.endswith("\r\n\r\n"):
        findings.append({
            "level": "WARN",
            "check": "structure",
            "message": "请求未以 \\r\\n\\r\\n 结束 (缺少空行标记 header/body 边界)",
            "fix": "请求末尾加 \\r\\n\\r\\n"
        })

    return findings


def lint(request_json: dict) -> dict:
    """执行所有检查，返回汇总结果。"""
    request = request_json.get("request", "")
    auth_levels = request_json.get("auth_levels", [])
    device_hint = request_json.get("device_hint", "generic")

    all_findings = []
    all_findings.extend(check_crlf(request))
    all_findings.extend(check_auth_isolation(request, auth_levels, device_hint))
    all_findings.extend(check_dual_header_structure(request, auth_levels, device_hint))
    all_findings.extend(check_basic_structure(request))

    fails = [f for f in all_findings if f["level"] == "FAIL"]
    warns = [f for f in all_findings if f["level"] == "WARN"]
    oks = [f for f in all_findings if f["level"] == "OK"]

    summary = (
        f"{len(oks)} OK, {len(warns)} WARN, {len(fails)} FAIL"
    )

    return {
        "result": "PASS" if not fails else "FAIL",
        "summary": summary,
        "checks_passed": len(oks),
        "checks_warn": len(warns),
        "checks_failed": len(fails),
        "findings": all_findings,
    }


def main():
    if len(sys.argv) < 2 and "--stdin" not in sys.argv:
        print("用法: python auth_request_lint.py <request.json>", file=sys.stderr)
        print("      echo '{...}' | python auth_request_lint.py --stdin", file=sys.stderr)
        sys.exit(2)

    if "--stdin" in sys.argv:
        raw = sys.stdin.read()
    else:
        path = sys.argv[1]
        if not os.path.exists(path):
            print(json.dumps({"result": "ERROR", "error": f"文件不存在: {path}"}, ensure_ascii=False))
            sys.exit(2)
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        print(json.dumps({"result": "ERROR", "error": f"JSON 解析失败: {e}"}, ensure_ascii=False))
        sys.exit(2)

    result = lint(data)
    print(json.dumps(result, indent=2, ensure_ascii=False))

    if result["result"] == "PASS":
        sys.exit(0)
    else:
        sys.exit(2)


if __name__ == "__main__":
    main()
