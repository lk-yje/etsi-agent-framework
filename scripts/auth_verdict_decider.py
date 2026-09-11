#!/usr/bin/env python3
"""
Auth Step 4: auth_diff 响应 → 裁决矩阵 → 机械化判定。

将 auth_diff 的 JSON 输出按决策矩阵 (auth-diff-workflow.md Step 4) 逐端点判定，
消除 agent 主观判断。支持单端点模式和批量模式。

裁决矩阵:
  admin=200 + none=401/403           → PASS   (标准认证保护)
  admin=200 + none=302→/login        → PASS   (重定向到登录页)
  admin=200 + none=200 + sim<50%     → PASS   (同为200但body实质不同)
  admin=200 + none=200 + sim>80%     → FAIL   (Missing Auth)
  admin=200 + none=200 + sim 50-80%  → SUSPICIOUS (需人工确认)
  admin≠200                          → SKIP   (端点异常)
  admin=401/403 + none=401/403       → INCONCLUSIVE (令牌可能过期)
  Burp 标记 "identical responses"    → FAIL   (IDOR级别)

用法:
  # 单端点
  python auth_verdict_decider.py <auth_diff_output.json>

  # 批量 (含多个端点的汇总 JSON)
  python auth_verdict_decider.py --batch <batch_results.json>

输入格式 (单端点):
  auth_diff 的原始 JSON 输出

输出 (JSON):
  {
    "verdict": "PASS",
    "reason": "admin=200, none=401 → 标准认证保护",
    "details": { "admin_status": 200, "none_status": 401, "similarity": 0, ... }
  }

退出码:
  0 = 判定完成
  1 = 输入解析失败
"""

import json
import os
import sys
from typing import Optional


# -- 裁决矩阵 -------------------------------------------------------
def apply_matrix(
    admin_status: int,
    none_status: int,
    body_similarity: float,
    none_body_preview: str = "",
    burp_findings: list[str] = None,
) -> dict:
    """按 auth-diff-workflow.md Step 4 的决策矩阵判定单个端点。"""

    burp_findings = burp_findings or []

    # admin 非 200 → 端点异常 (先于 identical 检查，避免双403误判为FAIL)
    if admin_status not in (200, 201, 204):
        return {
            "verdict": "SKIP",
            "confidence": "HIGH",
            "reason": f"admin 返回 {admin_status}，端点异常或不存在，不计入统计",
            "matrix_rule": f"admin={admin_status} → SKIP",
        }

    # admin=200, none=401/403 → 标准认证保护
    if none_status in (401, 403):
        return {
            "verdict": "PASS",
            "confidence": "HIGH",
            "reason": f"admin={admin_status}, none={none_status} → 标准认证保护。未认证请求被正确拒绝。",
            "matrix_rule": f"admin=200 + none={none_status} → PASS",
        }

    # admin=200, none=302 → 重定向登录页
    if none_status == 302:
        is_login_redirect = any(
            kw in none_body_preview.lower()
            for kw in ("login", "signin", "auth", "unauthorized")
        )
        if is_login_redirect:
            return {
                "verdict": "PASS",
                "confidence": "HIGH",
                "reason": f"admin=200, none=302 → /login → 重定向到登录页，有认证保护",
                "matrix_rule": "admin=200 + none=302 → /login → PASS",
            }
        else:
            return {
                "verdict": "SUSPICIOUS",
                "confidence": "LOW",
                "reason": f"admin=200, none=302 但 Location 不明确指向登录页。需人工确认。",
                "matrix_rule": "admin=200 + none=302 + ambiguous redirect → SUSPICIOUS",
            }

    # admin=200, none=200 → 同为200，看 body 相似度
    if none_status == 200:
        # Burp "identical responses" + 同为200 → 确认 IDOR
        if any("identical" in f.lower() for f in burp_findings):
            return {
                "verdict": "FAIL",
                "confidence": "HIGH",
                "reason": "admin=200 + none=200 且 Burp 判定为 identical responses (IDOR 级别)",
                "matrix_rule": "admin=200 + none=200 + Burp identical → FAIL",
            }
        if body_similarity < 50.0:
            return {
                "verdict": "PASS",
                "confidence": "MEDIUM",
                "reason": (
                    f"admin=200, none=200 但 body 相似度={body_similarity:.1f}% (< 50%)。"
                    f"同为 200 但响应内容实质不同 (none 可能返回登录页 HTML 或通用错误 JSON)。"
                ),
                "matrix_rule": f"admin=200 + none=200 + sim={body_similarity:.1f}% < 50% → PASS",
            }
        elif body_similarity > 80.0:
            return {
                "verdict": "FAIL",
                "confidence": "HIGH",
                "reason": (
                    f"admin=200, none=200 且 body 相似度={body_similarity:.1f}% (> 80%)。"
                    f"未认证请求返回了与认证请求高度一致的响应 → Missing Auth / IDOR。"
                ),
                "matrix_rule": f"admin=200 + none=200 + sim={body_similarity:.1f}% > 80% → FAIL",
            }
        else:
            return {
                "verdict": "SUSPICIOUS",
                "confidence": "LOW",
                "reason": (
                    f"admin=200, none=200 且 body 相似度={body_similarity:.1f}% (50%-80%)。"
                    f"可能是不同数据视图或部分越权，需人工确认。"
                ),
                "matrix_rule": f"admin=200 + none=200 + sim={body_similarity:.1f}% 50-80% → SUSPICIOUS",
            }

    # admin=200, none=其他状态码
    return {
        "verdict": "SUSPICIOUS",
        "confidence": "LOW",
        "reason": (
            f"admin=200, none={none_status}。未预期组合，需人工确认。"
        ),
        "matrix_rule": f"admin=200 + none={none_status} (unexpected) → SUSPICIOUS",
    }


def parse_auth_diff_output(raw: str) -> dict:
    """解析 auth_diff 的 JSON 输出，提取判定所需字段。"""
    data = json.loads(raw) if isinstance(raw, str) else raw

    # 处理 MCP wrapper
    if isinstance(data, list) and len(data) == 1 and "text" in data[0]:
        inner = json.loads(data[0]["text"])
    else:
        inner = data

    responses = inner.get("responses", [])
    admin_resp = None
    none_resp = None
    for r in responses:
        if r.get("level") == "admin":
            admin_resp = r
        elif r.get("level") == "none":
            none_resp = r

    if not admin_resp or not none_resp:
        raise ValueError("auth_diff 输出中缺少 admin 或 none 级别的响应")

    # 相似度从 differences 中提取
    similarity = 0.0
    differences = inner.get("differences", [])
    for diff in differences:
        for d in diff.get("differences", []):
            if d.get("field") == "body_content":
                similarity = d.get("similarity_percent", 0.0)
                break

    return {
        "admin_status": admin_resp.get("status_code", 0),
        "none_status": none_resp.get("status_code", 0),
        "body_similarity": similarity,
        "none_body_preview": none_resp.get("body_preview", ""),
        "burp_findings": inner.get("findings", []),
        "all_same_status": inner.get("all_same_status", False),
        "all_same_body": inner.get("all_same_body", False),
        "admin_body_length": admin_resp.get("body_length", 0),
        "none_body_length": none_resp.get("body_length", 0),
    }


def decide_single(auth_diff_output: str) -> dict:
    """判定单个端点。"""
    try:
        parsed = parse_auth_diff_output(auth_diff_output)
    except Exception as e:
        return {
            "verdict": "ERROR",
            "confidence": "NONE",
            "reason": f"解析 auth_diff 输出失败: {e}",
            "matrix_rule": "PARSE_ERROR → ERROR",
        }

    result = apply_matrix(
        admin_status=parsed["admin_status"],
        none_status=parsed["none_status"],
        body_similarity=parsed["body_similarity"],
        none_body_preview=parsed["none_body_preview"],
        burp_findings=parsed["burp_findings"],
    )

    result["details"] = parsed
    return result


def decide_batch(batch_data: list[dict]) -> dict:
    """批量判定多个端点，输出统计汇总。"""
    results = []
    stats = {"PASS": 0, "FAIL": 0, "SUSPICIOUS": 0, "SKIP": 0, "INCONCLUSIVE": 0, "ERROR": 0}

    for item in batch_data:
        endpoint = item.get("endpoint", item.get("path", "?"))
        method = item.get("method", "GET")
        try:
            parsed = parse_auth_diff_output(json.dumps(item.get("auth_diff_result", {})))
            result = apply_matrix(
                admin_status=parsed["admin_status"],
                none_status=parsed["none_status"],
                body_similarity=parsed["body_similarity"],
                none_body_preview=parsed["none_body_preview"],
                burp_findings=parsed["burp_findings"],
            )
        except Exception as e:
            result = {"verdict": "ERROR", "confidence": "NONE", "reason": str(e)}

        result["endpoint"] = endpoint
        result["method"] = method
        result["details"] = parsed if "parsed" in dir() else {}
        results.append(result)
        stats[result["verdict"]] = stats.get(result["verdict"], 0) + 1

    total = len(results)
    passed = stats["PASS"]
    failed = stats["FAIL"]
    suspicious = stats["SUSPICIOUS"]
    skipped = stats["SKIP"] + stats["ERROR"]

    # 5.5-5-2 综合裁决
    if failed > 0:
        overall = "FAIL"
        overall_reason = f"{total} 个端点中 {failed} 个存在未认证访问 (越权/IDOR)"
    elif suspicious > 0:
        overall = "INCONCLUSIVE"
        overall_reason = f"{suspicious} 个端点需人工确认 (相似度 50-80%)"
    elif passed == 0:
        overall = "INCONCLUSIVE"
        overall_reason = "无有效端点完成测试"
    else:
        overall = "PASS"
        overall_reason = f"{total} 个端点全部通过越权检测"

    return {
        "verdict": overall,
        "reason": overall_reason,
        "stats": stats,
        "total_endpoints": total,
        "effective_total": total - skipped,
        "results": results,
    }


def main():
    if len(sys.argv) < 2:
        print("用法: python auth_verdict_decider.py <auth_diff_output.json>", file=sys.stderr)
        print("      python auth_verdict_decider.py --batch <batch_results.json>", file=sys.stderr)
        sys.exit(2)

    if sys.argv[1] == "--batch":
        path = sys.argv[2] if len(sys.argv) > 2 else None
        if not path or not os.path.exists(path):
            print(json.dumps({"verdict": "ERROR", "reason": f"文件不存在: {path}"}, ensure_ascii=False))
            sys.exit(1)
        with open(path, "r", encoding="utf-8") as f:
            batch = json.load(f)
        result = decide_batch(batch)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        path = sys.argv[1]
        if not os.path.exists(path):
            print(json.dumps({"verdict": "ERROR", "reason": f"文件不存在: {path}"}, ensure_ascii=False))
            sys.exit(1)
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
        result = decide_single(raw)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        if result["verdict"] == "FAIL":
            sys.exit(1)


if __name__ == "__main__":
    main()
