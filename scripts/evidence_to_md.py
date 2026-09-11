#!/usr/bin/env python3
"""
Evidence JSON → Markdown 确定性生成器。

用法:
  python evidence_to_md.py <evidence_Mx_*.json> [--out <output.md>]

审计 ACCEPT 后由主线程调用。不靠 LLM — 纯数据转换，格式统一、无遗漏、不编造。
输出文件名默认与 JSON 同名 (换 .md 后缀)。
"""

import json
import os
import sys
from datetime import datetime


VERDICT_ICON = {
    "PASS": "[OK] PASS",
    "FAIL": "[FAIL] FAIL",
    "NA": "[N/A] N/A",
    "INCONCLUSIVE": "[INFO] INCONCLUSIVE",
    "PENDING_MANUAL": "[WARN] 待手工测试",
}

LEVEL_LABEL = {
    "L1": "L1-原始数据",
    "L2": "L2-处理后数据",
    "L3": "L3-间接证据",
    "L4": "L4-无证据",
    "L5": "L5-证据矛盾",
}

EVIDENCE_TYPE_LABEL = {
    "nmap": "Nmap",
    "tshark": "tshark/pcap",
    "burp": "Burp Suite",
    "curl": "curl",
    "sqlmap": "sqlmap",
    "xray": "xray",
    "playwright": "Playwright",
    "ixit": "IXIT 文档",
    "netstat": "netstat",
    "other": "其他",
}


def generate_md(data: dict) -> str:
    meta = data["meta"]
    trace = data.get("executionTrace", {})
    clauses = data["clauses"]
    sc = data.get("selfCheck", {})

    lines: list[str] = []

    # -- 标题 ---------------------------------------------------
    lines.append(f"# {meta['moduleId']} {meta.get('moduleName', '')} — ETSI TS 103 701 检测证据")
    lines.append("")
    lines.append(f"> 结构化数据见 `evidence_{meta['moduleId']}_{_slug(meta.get('moduleName', ''))}.json`")
    lines.append(f"> 生成时间: {meta.get('generatedAt', '?')} | 重试次数: {meta.get('retryCount', 0)} | 状态: {meta.get('status', '?')}")
    lines.append("")

    # -- 检测环境 -----------------------------------------------
    lines.append("## 检测环境")
    lines.append("")
    lines.append(f"| 项目 | 内容 |")
    lines.append(f"|------|------|")
    lines.append(f"| DUT IP | {meta.get('dutIp', '?')} |")
    lines.append(f"| IXIT | `{meta.get('ixitJsonPath', '?')}` |")
    lines.append(f"| 模块条款数 | {meta.get('clauseCount', '?')} |")
    lines.append("")

    # -- 执行轨迹摘要 -------------------------------------------
    if trace:
        lines.append("## 执行轨迹")
        lines.append("")
        steps = trace.get("steps", [])
        lines.append(f"| # | 阶段 | 摘要 | 工具 | 涉及条款 | 耗时 |")
        lines.append(f"|---|------|------|------|---------|------|")
        for s in steps:
            tool = s.get("tool", "-")
            cids = ",".join(s.get("clauseIds", [])) or "-"
            dur = f"{s.get('durationSec', '?')}s"
            lines.append(
                f"| {s['seq']} | {s.get('phase', '?')} | {s.get('summary', '?')} | {tool} | {cids} | {dur} |"
            )
        lines.append("")

        warnings = trace.get("warnings", [])
        if warnings:
            lines.append("### 执行警告")
            lines.append("")
            for w in warnings:
                lines.append(f"- [WARN] {w}")
            lines.append("")

    # -- 逐条款证据 ---------------------------------------------
    lines.append("## 逐条款检测记录")
    lines.append("")

    for c in clauses:
        cid = c["clauseId"]
        v = c.get("verdict", "?")
        icon = VERDICT_ICON.get(v, v)

        lines.append(f"### {cid} — {c.get('provisionText', '?')}")
        lines.append("")

        # 信息表
        lines.append(f"| 项目 | 内容 |")
        lines.append(f"|------|------|")
        lines.append(f"| **裁决** | {icon} |")
        lines.append(f"| **ICS Status** | {c.get('icsStatus', '?')} |")
        lines.append(f"| **ICS Support** | {c.get('icsSupport', '?')} |")
        if c.get("icsDetail"):
            lines.append(f"| **IXIT 声明** | {c['icsDetail']} |")
        if c.get("ixitReferences"):
            refs = ", ".join(c["ixitReferences"])
            lines.append(f"| **IXIT 引用** | {refs} |")
        tags = c.get("tags", [])
        if tags:
            lines.append(f"| **标签** | {', '.join(tags)} |")
        lines.append("")

        # 推理链
        lines.append(f"**裁决理由:** {c.get('reason', '?')}")
        lines.append("")

        # FAIL 对照
        if v == "FAIL":
            if c.get("expectedBehavior"):
                lines.append(f"**预期行为:** {c['expectedBehavior']}")
                lines.append("")
            if c.get("actualBehavior"):
                lines.append(f"**实际行为:** {c['actualBehavior']}")
                lines.append("")

        # 证据
        ev_list = c.get("evidence", [])
        if ev_list:
            lines.append("**证据:**")
            lines.append("")
            for j, ev in enumerate(ev_list):
                etype = EVIDENCE_TYPE_LABEL.get(ev.get("type", ""), ev.get("type", "?"))
                lvl = LEVEL_LABEL.get(ev.get("level", ""), ev.get("level", "?"))
                path = ev.get("path") or "(纯 IXIT 引用)"
                lines.append(f"{j+1}. **[{etype}]** {lvl} — {ev.get('description', '?')}")
                lines.append(f"   - 路径: `{path}`")
                if ev.get("expectedVsActual"):
                    lines.append(f"   - 预期 vs 实际: {ev['expectedVsActual']}")
            lines.append("")

        # 手工步骤
        ms = c.get("manualSteps")
        if ms and str(ms).strip():
            lines.append("**手工测试步骤:**")
            lines.append("")
            lines.append(str(ms))
            lines.append("")

        # 警告
        warns = c.get("warnings", [])
        if warns:
            lines.append("**注意事项:**")
            for w in warns:
                lines.append(f"- [WARN] {w}")
            lines.append("")

        # 重测历史
        rh = c.get("retryHistory", [])
        if rh:
            lines.append("**重测历史:**")
            lines.append("")
            for h in rh:
                lines.append(f"- 第 {h['retryCount']} 次重测: {h.get('changesMade', '?')}")
            lines.append("")

        lines.append("---")
        lines.append("")

    # -- 自检表 -------------------------------------------------
    lines.append("## 自检清单")
    lines.append("")
    lines.append(f"| 项目 | 值 |")
    lines.append(f"|------|------|")
    lines.append(f"| 预期条款数 | {sc.get('totalExpected', '?')} |")
    lines.append(f"| JSON 实际条目数 | {sc.get('actualInJson', '?')} |")
    lines.append(f"| FAIL 条款数 | {sc.get('failCount', '?')} |")
    lines.append(f"| 待手工测试条款数 | {sc.get('pendingManual', '?')} |")
    lines.append(f"| 缺失条款 | {sc.get('missingClauses', []) or '无'} |")
    lines.append(f"| 不确定条款 | {sc.get('uncertainClauses', []) or '无'} |")
    lines.append(f"| 自检错误 | {'是' if sc.get('hasErrors') else '否'} |")
    lines.append("")
    lines.append(f"> 结构化数据见 `evidence_{meta['moduleId']}_{_slug(meta.get('moduleName', ''))}.json`")

    return "\n".join(lines)


def _slug(name: str) -> str:
    """中文名 → 英文 slug"""
    mapping = {
        "攻击面与端口": "attack_surface",
        "认证与口令": "auth_password",
        "通信加密": "comm_crypto",
        "更新与完整性": "update_integrity",
        "输入验证与数据保护": "input_dataprotection",
        "ICS 逻辑验证": "ics_validation",
    }
    return mapping.get(name, name.replace(" ", "_").lower())


def main() -> int:
    if len(sys.argv) < 2:
        print("用法: python evidence_to_md.py <evidence_Mx_*.json> [--out <output.md>]", file=sys.stderr)
        return 2

    json_path = sys.argv[1]
    out_path = None

    args = sys.argv[2:]
    for i, arg in enumerate(args):
        if arg == "--out" and i + 1 < len(args):
            out_path = args[i + 1]

    if not os.path.exists(json_path):
        print(f"[FAIL] JSON 文件不存在: {json_path}", file=sys.stderr)
        return 1

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # 检查 status
    status = data.get("meta", {}).get("status")
    if status != "accepted":
        print(f"[WARN] meta.status={status}，非 `accepted`。仅在审计 ACCEPT 后生成 MD。", file=sys.stderr)
        # 仍然生成，但加上警告

    md = generate_md(data)

    if not out_path:
        out_path = json_path.replace(".json", ".md")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(md)

    print(f"[OK] MD 已生成: {out_path}")
    print(f"   模块: {data['meta']['moduleId']} | {data['meta'].get('moduleName', '')}")
    print(f"   条款: {data['selfCheck'].get('actualInJson', '?')} 条 | {data['selfCheck'].get('failCount', 0)} FAIL | {data['selfCheck'].get('pendingManual', 0)} 手工")
    return 0


if __name__ == "__main__":
    sys.exit(main())
