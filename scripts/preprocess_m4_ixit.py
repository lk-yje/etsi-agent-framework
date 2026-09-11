#!/usr/bin/env python3
"""
M4 模块 IXIT 预处理脚本。

从 ixit.json 提取 M4 所需的 4 张 sheet，预计算所有 escape_clause 条件，
输出紧凑的 m4_preprocessed.json (~5-15KB vs 原始 8MB+)。

M4 agent 加载此文件即可完成全部概念性测试，不再需要反复提取 ixit.json。

用法:
  python preprocess_m4_ixit.py <ixit.json> [输出路径]

  默认输出到 ixit.json 同目录下的 m4_preprocessed.json
"""

import json
import os
import sys
from typing import Any

# M4 需要的 IXIT sheet
M4_SHEETS = ["6-SoftComp", "7-UpdMech", "8-UpdProc", "10-SecParam"]

# M4 覆盖条款的 escape_clause 条件定义
# 格式: { clauseId: { "condition": "人类可读条件", "check": "要检查的 IXIT 字段" } }
ESCAPE_CLAUSES = {
    "5.3-4": {
        "description": "自动更新机制 — DUT 不支持自动更新时条款不适用",
        "trigger": "IXIT 7-UpdMech 中未声明自动更新能力",
    },
    "5.3-5": {
        "description": "检查安全更新 — DUT 不支持检查更新时条款不适用",
        "trigger": "IXIT 7-UpdMech 中未声明更新检查能力",
    },
    "5.3-6": {
        "description": "自动更新可配置 (5.3-6A + 5.3-6B) — 前提不满足时直接 PASS",
        "escape_5_3_6A": "DUT 不支持自动更新 → 5.3-6A PASS (escape)",
        "escape_5_3_6B": "DUT 不支持更新通知 → 5.3-6B PASS (escape)",
        "trigger_A": "IXIT 7-UpdMech 中无 Automatic Update 相关描述",
        "trigger_B": "IXIT 7-UpdMech 中无 Update Notification 相关描述",
    },
    "5.3-11": {
        "description": "通知用户安全更新 — DUT 不支持自动检查更新时条款 N/A",
        "trigger": "IXIT 7-UpdMech 中未声明自动检查更新能力",
    },
    "5.3-14": {
        "description": "不可更新说明文档 — DUT 可更新时条款 N/A",
        "trigger": "IXIT 6-SoftComp 中所有组件均有更新机制 → N/A",
    },
    "5.3-15": {
        "description": "不可更新设备隔离 — DUT 可更新 或 非受限设备时 N/A",
        "trigger": "DUT 可更新 或 非受限设备 → N/A",
    },
    "5.4-2": {
        "description": "安全参数唯设备硬编码 — 条件性 R-should，适用于硬编码场景",
        "trigger": "IXIT 10-SecParam 中无唯设备硬编码项 → N/A",
    },
    "5.7-2": {
        "description": "软件完整性告警 — N/A 循环论证风险 (没有发生过 ≠ 不需要机制)",
        "trigger": "IXIT 6-SoftComp 或 8-UpdProc 中无完整性检测描述 → 概念 FAIL (有检测无告警)",
        "warning": "[WARN] 若 IXIT 声称 'N/A — 没有发生过通知事件'，这是循环论证，应判 FAIL",
    },
}

# ICS dependency: 5.7-2 依赖的安全启动/完整性检测字段关键词
INTEGRITY_KEYWORDS = [
    "secure boot", "安全启动", "integrity check", "完整性检查",
    "signature verification", "签名验证", "firmware verification", "固件校验",
    "software attestation", "measured boot",
]


def extract_sheet(ixit: dict, sheet_name: str) -> dict | None:
    """从 ixit JSON 提取指定 sheet，剔除冗余字段保留关键内容."""
    sheets = ixit.get("ixit_tables", {})
    sheet = sheets.get(sheet_name)
    if not sheet:
        return None

    result: dict[str, Any] = {
        "meta": sheet.get("meta", {}),
        "row_count": len(sheet.get("rows", [])),
        "rows": [],
    }

    for row in sheet.get("rows", []):
        # 只保留非空值，压缩体积
        compact = {k: v for k, v in row.items() if v and v != "N/A" and v != "-"}
        if compact:
            result["rows"].append(compact)

    return result


def _find_constrained_device(dut_identification: dict) -> str:
    """在 DUT Identification 嵌套结构 {section: {field: value}} 中查找受限设备声明。

    跨 section 防御性搜索：字段名含 constrain/constraint 即命中，返回其值。
    """
    if not isinstance(dut_identification, dict):
        return ""
    for fields in dut_identification.values():
        if not isinstance(fields, dict):
            continue
        for field, value in fields.items():
            low = str(field).lower()
            if "constrain" in low or "constraint" in low:
                if value:
                    return str(value)
    return ""


def check_escape_clauses(sheets: dict, ics_declarations: list[dict], dut_identification: dict) -> dict:
    """基于 IXIT sheet 内容预计算所有 escape_clause 条件."""

    escape_results: dict[str, Any] = {}

    # 从 sheet 中提取关键事实
    upd_mech_rows = [r for r in sheets.get("7-UpdMech", {}).get("rows", [])]
    soft_comp_rows = [r for r in sheets.get("6-SoftComp", {}).get("rows", [])]
    upd_sec_rows = [r for r in sheets.get("8-UpdProc", {}).get("rows", [])]
    sec_param_rows = [r for r in sheets.get("10-SecParam", {}).get("rows", [])]

    # 拼接所有文本做关键词匹配
    upd_text = " ".join(str(r).lower() for r in upd_mech_rows)
    comp_text = " ".join(str(r).lower() for r in soft_comp_rows)
    sec_text = " ".join(str(r).lower() for r in upd_sec_rows)
    param_text = " ".join(str(r).lower() for r in sec_param_rows)

    # ---- 自动更新能力 ----
    has_auto_update = any(
        kw in upd_text
        for kw in [
            "automatic update", "自动更新", "auto update",
            "auto-update", "automatically update",
        ]
    )
    has_update_check = any(
        kw in upd_text
        for kw in [
            "check for update", "检查更新", "update check",
            "polling", "轮询更新",
        ]
    )
    has_update_notify = any(
        kw in upd_text
        for kw in [
            "notification", "通知", "notify user",
            "alert", "user notification",
        ]
    )

    # ---- 可更新性 ----
    all_updatable = all(
        any(
            kw in str(r).lower()
            for kw in ["updatable", "可更新", "update mechanism", "ota", "firmware update"]
        )
        for r in soft_comp_rows
    ) if soft_comp_rows else False

    any_updatable = any(
        any(
            kw in str(r).lower()
            for kw in ["updatable", "可更新", "update mechanism", "ota", "firmware update"]
        )
        for r in soft_comp_rows
    )

    # ---- 受限设备 ----
    constrained_field = _find_constrained_device(dut_identification)
    cf_lower = str(constrained_field).lower()
    # 排除模板占位符 "Yes/No" / "是/否"（未填写），仅当明确选择 Yes/是 时才判为受限设备
    is_constrained = (
        ("yes" in cf_lower and "no" not in cf_lower)
        or ("是" in constrained_field and "否" not in constrained_field)
    )

    # ---- 完整性检测 ----
    has_integrity_check = any(
        kw in comp_text or kw in sec_text
        for kw in INTEGRITY_KEYWORDS
    )

    # ---- 硬编码参数 ----
    has_hardcoded_params = any(
        kw in param_text
        for kw in ["hardcoded", "硬编码", "hard-coded", "fixed key", "固定密钥"]
    )

    # ===== 逐 escape_clause 判定 =====

    # 5.3-4: 自动更新机制 (条件性 R-should)
    escape_results["5.3-4"] = {
        "escape_applies": not has_auto_update,
        "verdict_if_escape": "NA",
        "reason": f"DUT {'不支持' if not has_auto_update else '支持'}自动更新 — "
                  f"{'条款不适用' if not has_auto_update else '需测试自动更新能力'}",
        "source": "IXIT 7-UpdMech",
    }

    # 5.3-5: 检查安全更新 (条件性 R-should)
    escape_results["5.3-5"] = {
        "escape_applies": not has_update_check,
        "verdict_if_escape": "NA",
        "reason": f"DUT {'不支持' if not has_update_check else '支持'}检查更新 — "
                  f"{'条款不适用' if not has_update_check else '需测试更新检查能力'}",
        "source": "IXIT 7-UpdMech",
    }

    # 5.3-6A: 自动更新可配置
    escape_results["5.3-6A"] = {
        "escape_applies": not has_auto_update,
        "verdict_if_escape": "PASS",
        "reason": f"DUT 不支持自动更新功能 → 5.3-6A 前提不满足，条款直接 PASS",
        "source": "IXIT 7-UpdMech",
    }

    # 5.3-6B: 更新通知可配置
    escape_results["5.3-6B"] = {
        "escape_applies": not has_update_notify,
        "verdict_if_escape": "PASS",
        "reason": f"DUT 不支持更新通知功能 → 5.3-6B 前提不满足，条款直接 PASS",
        "source": "IXIT 7-UpdMech",
    }

    # 5.3-11: 通知用户安全更新
    escape_results["5.3-11"] = {
        "escape_applies": not has_auto_update and not has_update_check,
        "verdict_if_escape": "NA",
        "reason": f"DUT 不支持自动检查更新 → 条款 N/A",
        "source": "IXIT 7-UpdMech",
    }

    # 5.3-14: 不可更新说明文档
    escape_results["5.3-14"] = {
        "escape_applies": any_updatable,
        "verdict_if_escape": "NA",
        "reason": f"DUT 可更新 (有更新机制) → 条款 N/A (这是给不可更新设备的条款)",
        "source": "IXIT 6-SoftComp",
    }

    # 5.3-15: 不可更新设备隔离
    escape_results["5.3-15"] = {
        "escape_applies": any_updatable or not is_constrained,
        "verdict_if_escape": "NA",
        "reason": f"{'DUT 可更新' if any_updatable else 'DUT 非受限设备'} → 条款 N/A",
        "source": "IXIT 6-SoftComp + DUT Constrained Device 声明",
    }

    # 5.4-2: 唯设备硬编码
    escape_results["5.4-2"] = {
        "escape_applies": not has_hardcoded_params,
        "verdict_if_escape": "NA",
        "reason": f"DUT 无唯设备硬编码参数 → 条款 N/A",
        "source": "IXIT 10-SecParam",
    }

    # 5.7-2: 软件完整性告警
    escape_results["5.7-2"] = {
        "escape_applies": not has_integrity_check,
        "verdict_if_escape": "NA",
        "reason": f"DUT 无安全启动/完整性检测能力 → 条款 N/A",
        "caution": "若 IXIT 声称无完整性检测但实际设备有 (如 secure boot 已启用), "
                   "则告知段落 N/A 理由不成立，需改为 FAIL",
        "source": "IXIT 6-SoftComp + 8-UpdProc",
    }

    # 汇总
    escape_results["_summary"] = {
        "has_auto_update": has_auto_update,
        "has_update_check": has_update_check,
        "has_update_notify": has_update_notify,
        "all_updatable": all_updatable,
        "any_updatable": any_updatable,
        "is_constrained_device": is_constrained,
        "has_integrity_check": has_integrity_check,
        "has_hardcoded_params": has_hardcoded_params,
    }

    return escape_results


def check_ics_status(ics_declarations: list[dict]) -> dict:
    """从 ICS 声明中提取 M4 条款的 Support 状态."""
    m4_prefixes = ("5.3-", "5.4-", "5.7-")
    result = {}
    for item in ics_declarations:
        ref = item.get("reference", "")
        # reference 形如 "Provision 5.3-1 ..."，clause id 为第 2 个 token
        clause_id = ref.split()[1] if len(ref.split()) >= 2 else ref
        # 匹配 5.3-x, 5.4-x, 5.7-x 格式
        if any(clause_id.startswith(p) for p in m4_prefixes):
            result[clause_id] = {
                "status": item.get("status", "?"),
                "support": item.get("support", "?"),
                "detail": item.get("detail_justification", ""),
            }
    return result


def preprocess(ixit_path: str) -> dict:
    """主预处理逻辑."""
    with open(ixit_path, "r", encoding="utf-8") as f:
        ixit = json.load(f)

    # 1. 提取 M4 需要的 sheet
    sheets = {}
    for name in M4_SHEETS:
        extracted = extract_sheet(ixit, name)
        if extracted:
            sheets[name] = extracted

    # 2. 读取 ICS 声明
    ics = ixit.get("ics", [])

    # 3. 预计算 escape_clause
    dut_identification = ixit.get("meta", {}).get("dut_identification", {})
    escapes = check_escape_clauses(sheets, ics, dut_identification)

    # 4. 提取 M4 条款 ICS 状态
    ics_status = check_ics_status(ics)

    # 5. 组装输出
    result = {
        "meta": {
            "description": "M4 模块 IXIT 预处理结果 — 概念性测试可直接基于此文件裁决",
            "generated_from": ixit_path,
            "sheets_extracted": list(sheets.keys()),
            "sheet_names": M4_SHEETS,
        },
        "sheets": sheets,
        "escape_clauses": escapes,
        "ics_status": ics_status,
    }

    return result


def main() -> int:
    if len(sys.argv) < 2:
        print("用法: python preprocess_m4_ixit.py <ixit.json> [输出路径]", file=sys.stderr)
        return 2

    ixit_path = sys.argv[1]
    if not os.path.exists(ixit_path):
        print(f"ixit.json 不存在: {ixit_path}", file=sys.stderr)
        return 1

    output_path = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
        os.path.dirname(ixit_path), "m4_preprocessed.json"
    )

    try:
        result = preprocess(ixit_path)
    except Exception as e:
        print(f"预处理失败: {e}", file=sys.stderr)
        return 1

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    # 统计
    input_size = os.path.getsize(ixit_path)
    output_size = os.path.getsize(output_path)
    compression = (1 - output_size / input_size) * 100 if input_size > 0 else 0

    print(f"M4 预处理完成:")
    print(f"  ixit.json:    {input_size / 1024:.0f} KB → m4_preprocessed.json: {output_size / 1024:.0f} KB ({compression:.0f}% 压缩)")
    print(f"  Sheet 提取:   {', '.join(result['meta']['sheets_extracted'])}")
    print(f"  escape_clause 预计算: {len(result['escape_clauses']) - 1} 条")  # -1 for _summary

    # 打印关键结论供 Agent 直接使用
    s = result["escape_clauses"]["_summary"]
    print(f"\n  关键事实:")
    print(f"    自动更新:     {'是' if s['has_auto_update'] else '否'}")
    print(f"    检查更新:     {'是' if s['has_update_check'] else '否'}")
    print(f"    更新通知:     {'是' if s['has_update_notify'] else '否'}")
    print(f"    所有组件可更新: {'是' if s['all_updatable'] else '否'}")
    print(f"    受限设备:     {'是' if s['is_constrained_device'] else '否'}")
    print(f"    完整性检测:   {'是' if s['has_integrity_check'] else '否'}")
    print(f"    硬编码参数:   {'是' if s['has_hardcoded_params'] else '否'}")

    # 列出生效的 escape
    active_escapes = [
        (k, v) for k, v in result["escape_clauses"].items()
        if not k.startswith("_") and v.get("escape_applies")
    ]
    if active_escapes:
        print(f"\n  生效的 escape_clause ({len(active_escapes)} 条):")
        for clause_id, info in active_escapes:
            print(f"    {clause_id}: → {info['verdict_if_escape']} | {info['reason']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
