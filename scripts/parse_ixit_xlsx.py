#!/usr/bin/env python3
"""
IXIT Excel 解析脚本 — 同时支持「标准布局」和「扁平布局」两种 sheet。

标准布局: Row 1 有 >=2 个非空表头 → 按列解析（与 xlsx 技能行为一致）。
扁平布局: Row 1 仅 1 个非空表头 "Go to ICS" → 按 [描述, 字段名, 值] 块解析。

用法:
  python parse_ixit_xlsx.py <input.xlsx> [output.json]

  默认输出到 xlsx 同目录下的 ixit.json。

输出格式与原 xlsx 技能生成的 ixit.json 兼容 (顶级 key: meta, ics, ixit_tables)。
"""

import json
import os
import sys
from typing import Any

import openpyxl
from openpyxl.worksheet.formula import ArrayFormula


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def cell_text(cell) -> str:
    """提取单元格的文本值，处理 ArrayFormula 等特殊对象。"""
    val = cell.value
    if val is None:
        return ""
    if isinstance(val, ArrayFormula):
        # data_only=True 下 ArrayFormula 可能残留，尝试取 .text
        try:
            return str(val.text) if hasattr(val, "text") and val.text else ""
        except Exception:
            return ""
    s = str(val).strip()
    # openpyxl 有时将 ArrayFormula 转为字符串残留（已知 bug），标记为空
    if s.startswith("<openpyxl.worksheet.formula.ArrayFormula"):
        return ""
    return s


def detect_layout(ws) -> str:
    """检测 sheet 布局类型。

    Returns:
        "standard" — Row 1 有 >=2 个非空表头
        "flat"     — Row 1 仅 "Go to ICS"
    """
    row1_values = [cell_text(ws.cell(1, j)) for j in range(1, ws.max_column + 1)]
    non_empty = [v for v in row1_values if v]
    if len(non_empty) >= 2:
        return "standard"
    return "flat"


# ---------------------------------------------------------------------------
# Standard layout parser
# ---------------------------------------------------------------------------

def parse_standard(ws) -> dict:
    """解析标准布局 sheet（表头行 + 数据行）。"""
    # Row 1 = headers (去掉末尾冒号以保持兼容)
    raw_headers = []  # 原始表头（带冒号）
    headers = []      # 清理后表头
    for j in range(1, ws.max_column + 1):
        h = cell_text(ws.cell(1, j))
        if h:
            raw_headers.append(h)
            headers.append(h.rstrip(":").strip())
        else:
            raw_headers.append("")
            headers.append(f"Column_{j}")

    rows = []
    skip_next = False  # 用于跳过子表头后的适用性模板行
    for i in range(2, ws.max_row + 1):
        c1 = cell_text(ws.cell(i, 1))
        c2 = cell_text(ws.cell(i, 2))

        # 跳过 sheet title 行（Col 1 以 "IXIT" 开头且其他列全空）
        if c1 and c1.startswith("IXIT"):
            other_cols = [cell_text(ws.cell(i, j)) for j in range(2, ws.max_column + 1)]
            if not any(other_cols):
                continue

        # 跳过模板描述行（Col 2 以 "Unique per IXIT identifier" 开头）
        if c2 and c2.startswith("Unique per IXIT identifier"):
            continue

        # 跳过子表头行（Col 2+ 值与原始表头匹配，如 "ID:", "Description:" 等）
        # 同时标记下一行也要跳过（适用性模板行）
        if c2 and c2 in raw_headers:
            col_vals = [cell_text(ws.cell(i, j)) for j in range(2, ws.max_column + 1)]
            header_match = sum(1 for v, h in zip(col_vals, raw_headers[1:]) if v == h)
            if header_match >= 2:
                skip_next = True
                continue

        # 跳过子表头紧跟的适用性模板行
        if skip_next:
            skip_next = False
            continue

        # 跳过适用性说明行（Col 1 = "Applicability"）
        if c1 == "Applicability":
            continue

        row = {}
        any_val = False
        for j, h in enumerate(headers, start=1):
            val = cell_text(ws.cell(i, j))
            row[h] = val
            if val:
                any_val = True
        if any_val:
            rows.append(row)

    return {
        "meta": {"columns": headers, "layout": "standard", "row_count": len(rows)},
        "rows": rows,
    }


# ---------------------------------------------------------------------------
# Flat layout parser
# ---------------------------------------------------------------------------

def _is_field_name_line(text: str) -> bool:
    """判断是否为字段名行（以冒号结尾或包含特定模式）。"""
    if not text:
        return False
    t = text.strip()
    # 以冒号结尾
    if t.endswith(":"):
        return True
    # 以 (Yes/No): 结尾
    if t.endswith("(Yes/No):"):
        return True
    return False


def _extract_field_name(text: str) -> str:
    """从字段名行提取字段名（去掉末尾冒号）。"""
    t = text.strip()
    if t.endswith(":"):
        t = t[:-1].strip()
    return t


def parse_flat(ws) -> dict:
    """解析扁平布局 sheet（描述 + 字段名 + 值 三行一组）。

    布局模式:
      Row N:   Col 2 = "Description of how..."     ← 描述 / 提示
      Row N+1: Col 2 = "Field Name:"               ← 字段名（以冒号结尾）
               [Col 1 可能有 "Mandatory" / "Compulsory" 等标记]
      Row N+2: Col 1 = "Not applicable" / etc      ← ICS 适用性
               Col 2 = "实际值"                     ← 值
      Row N+3: (空行分隔)

    但也有变体:
      - 描述行可能跨多行（连续多行 Col 2 有内容且不以冒号结尾）
      - 字段名行和描述行可能合并（单行既有描述又以冒号结尾）
    """
    rows = []
    i = 2  # 跳过 Row 1 (Go to ICS)

    # 跳过 Row 2 (sheet title, e.g. "IXIT 2-UserInfo: User Information")
    if i <= ws.max_row:
        r2_c1 = cell_text(ws.cell(i, 1))
        if r2_c1 and r2_c1.startswith("IXIT"):
            i += 1

    while i <= ws.max_row:
        # 跳过空行
        row_vals = [cell_text(ws.cell(i, j)) for j in range(1, ws.max_column + 1)]
        if not any(row_vals):
            i += 1
            continue

        # 跳过 NOTE 行 (e.g. R11 of 9-ReplSup)
        c1_val = cell_text(ws.cell(i, 1))
        c2_val = cell_text(ws.cell(i, 2))
        if c1_val and c1_val.startswith("NOTE:") and not c2_val:
            i += 1
            continue

        # --- 尝试识别一个字段块 ---
        # 收集连续非空行（直到遇到空行或文件末尾）
        block_start = i
        block_lines = []
        while i <= ws.max_row:
            line_c1 = cell_text(ws.cell(i, 1))
            line_c2 = cell_text(ws.cell(i, 2))
            # 空行 = 块结束
            if not line_c1 and not line_c2:
                break
            block_lines.append((i, line_c1, line_c2))
            i += 1

        if not block_lines:
            i += 1
            continue

        # 解析块: 找字段名行（以冒号结尾的 Col 2）
        field_name = ""
        description_parts = []
        ics_status = ""
        value = ""
        mandatory_flag = ""

        # 策略: 从块中找第一个 "字段名:" 行
        field_name_idx = -1
        for idx, (row_num, c1, c2) in enumerate(block_lines):
            if _is_field_name_line(c2):
                field_name_idx = idx
                break

        if field_name_idx >= 0:
            # 字段名行之前的行 = 描述
            for idx in range(field_name_idx):
                _, c1, c2 = block_lines[idx]
                if c2:
                    description_parts.append(c2)

            # 字段名行
            fn_row_num, fn_c1, fn_c2 = block_lines[field_name_idx]
            field_name = _extract_field_name(fn_c2)
            if fn_c1 and fn_c1 not in ("Go to ICS", ""):
                mandatory_flag = fn_c1

            # 字段名行之后的行 = 值行
            for idx in range(field_name_idx + 1, len(block_lines)):
                _, c1, c2 = block_lines[idx]
                if c1 and c1 not in ("Go to ICS",):
                    ics_status = c1
                if c2:
                    value = c2  # 取最后一个非空值
        else:
            # 没找到字段名行 — 整个块当描述处理
            for _, c1, c2 in block_lines:
                if c2:
                    description_parts.append(c2)
                if c1 and c1 not in ("Go to ICS", ""):
                    ics_status = c1

        description = " ".join(description_parts)

        if field_name or value:
            row_data: dict[str, Any] = {
                "Go to ICS": ics_status,
                "Field": field_name,
                "Description": description,
                "Value": value,
            }
            if mandatory_flag:
                row_data["Requirement"] = mandatory_flag
            rows.append(row_data)

    columns = ["Go to ICS", "Field", "Description", "Value"]
    return {
        "meta": {"columns": columns, "layout": "flat", "row_count": len(rows)},
        "rows": rows,
    }


# ---------------------------------------------------------------------------
# ICS sheet parser
# ---------------------------------------------------------------------------

def parse_ics_sheet(ws):
    """解析 ICS (Implementation Conformance Statement) sheet。

    Sheet 结构:
      Row 1-10: 标题与说明
      Row 11:   表头 (Applicability, Reference, Status, 18031-1, 18031-2, 18031-3,
               Support, Detail /Justification, Required IXIT entries)
      Row 12+:  数据行 — 含两种行类型:
        - Section header: 仅 C2 有内容，不以 "Provision" 开头（分组标题，跳过）
        - Provision data:  C1=Applicability, C2=Provision..., C3=Status, C4-C6=EN18031,
                           C7=Support, C8=Detail/Justification, C9=Required IXIT entries

    Returns:
        list[dict] — 每个 dict 对应一条 Provision 记录。
    """
    rows = []
    # 定位表头行（找 "Applicability" 在 C1 的行）
    header_row = 0
    for i in range(1, min(20, ws.max_row + 1)):
        if cell_text(ws.cell(i, 1)) == "Applicability":
            header_row = i
            break
    if header_row == 0:
        return rows  # 未找到表头

    for i in range(header_row + 1, ws.max_row + 1):
        c1 = cell_text(ws.cell(i, 1))
        c2 = cell_text(ws.cell(i, 2))
        c3 = cell_text(ws.cell(i, 3))

        # 跳过空行
        if not c1 and not c2:
            continue

        # 跳过 section header（仅 C2 有内容，不以 "Provision" 开头）
        if c2 and not c1 and not c2.startswith("Provision"):
            continue

        # Provision 数据行: C2 以 "Provision" 开头
        if c2 and c2.startswith("Provision"):
            # EN18031: 合并 C4/C5/C6，按单条目去重保序
            en_items = []
            seen = set()
            for j in (4, 5, 6):
                v = cell_text(ws.cell(i, j))
                if v:
                    for item in v.split("\n"):
                        item = item.strip()
                        if item and item not in seen:
                            seen.add(item)
                            en_items.append(item)
            en18031 = "\n".join(en_items)

            # C7 Support / C8 Detail / C9 Required IXIT entries
            support = cell_text(ws.cell(i, 7))
            detail_justification = cell_text(ws.cell(i, 8))

            required_items = []
            req_seen = set()
            req_raw = cell_text(ws.cell(i, 9))
            if req_raw:
                for item in req_raw.split("\n"):
                    item = item.strip()
                    if item and item not in req_seen:
                        req_seen.add(item)
                        required_items.append(item)

            rows.append({
                "applicability": c1,
                "reference": c2,
                "status": c3,
                "en18031": en18031,
                "support": support,
                "detail_justification": detail_justification,
                "required_ixit_entries": required_items,
                "group": "Implementation Conformance Statement (ICS)",
            })

    return rows


# ---------------------------------------------------------------------------
# DUT Identification nested parser
# ---------------------------------------------------------------------------

def parse_dut_identification(ws):
    """解析 DUT Identification sheet，输出嵌套结构。

    Sheet 结构:
      - Section header: C1 有内容，C2 空 → 新建一个 section
      - Field name:     C2 以 ":" 结尾 → 字段名
      - Value:          紧跟字段名行之后的 C2 内容（不以 ":" 结尾、非描述文本）→ 字段值
      - Description:    C2 有内容但不以 ":" 结尾、且不是紧跟字段名的值行 → 描述/注释（跳过）

    判断"值行" vs "描述行"的启发式:
      - 紧跟字段名行的第一个非空 C2 内容 → 值
      - 字段名之后第二个及以后的非空 C2 内容（不以 ":" 结尾） → 描述/注释

    Returns:
        dict — {section_name: {field_name: value, ...}, ...}
        特殊: "Date of the statement" 等无子字段结构的 section 保留为 {}
    """
    result = {}
    current_section = None
    current_field = None
    awaiting_value = False

    for i in range(1, ws.max_row + 1):
        c1 = cell_text(ws.cell(i, 1))
        c2 = cell_text(ws.cell(i, 2))

        # Section header: C1 有内容
        if c1:
            current_section = c1
            if current_section not in result:
                result[current_section] = {}
            current_field = None
            awaiting_value = False
            continue

        # 无 section 则跳过
        if current_section is None:
            continue

        # C2 有内容
        if c2:
            if c2.endswith(":"):
                # 字段名行
                current_field = c2.rstrip(":").strip()
                result[current_section][current_field] = ""
                awaiting_value = True
            elif awaiting_value and current_field:
                # 紧跟字段名的值行
                result[current_section][current_field] = c2
                awaiting_value = False
            # else: 描述/注释行，跳过

        # 空行: 重置 awaiting_value（字段名后跟空行 = 值为空）
        if not c2 and awaiting_value:
            awaiting_value = False

    return result


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------

def _is_ixit_sheet(name: str) -> bool:
    """判断 sheet 名是否为 IXIT 表（以 数字- 开头，如 "1-AuthMech"）。"""
    if not name:
        return False
    return name[0].isdigit() and "-" in name


def _parse_meta_sheet(ws) -> dict:
    """解析元数据 sheet（DUT Identification / Security Context / Conditions 等）。

    返回 key-value dict。对只有 Col 2 有内容的 sheet（如 Security Context），
    以行号作为 key 保留所有非空内容。
    """
    result = {}
    all_c2_values = []
    for i in range(1, ws.max_row + 1):
        c1 = cell_text(ws.cell(i, 1))
        c2 = cell_text(ws.cell(i, 2))
        if c1 and c2:
            result[c1] = c2
        elif c1 and not c2:
            result[c1] = ""
        elif c2:
            # C2-only 行（如 Security Context）
            all_c2_values.append(c2)
    # 如果有 C2-only 内容，保存为列表
    if all_c2_values and not result:
        result["_content"] = "\n".join(all_c2_values)
    elif all_c2_values:
        result["_extra_content"] = "\n".join(all_c2_values)
    return result


def parse_ixit_xlsx(xlsx_path: str) -> dict:
    """解析 IXIT Excel 文件，输出与 xlsx 技能兼容的 JSON。"""
    wb = openpyxl.load_workbook(xlsx_path, data_only=True)

    ixit_tables: dict[str, Any] = {}
    meta_sections: dict[str, Any] = {}
    summary = {"standard": [], "flat": [], "meta": [], "skipped": []}

    ics_data = []  # ICS 表单独解析
    dut_identification = {}  # DUT Identification 嵌套解析

    for ws_name in wb.sheetnames:
        ws = wb[ws_name]

        # 跳过空 sheet
        if ws.max_row is None or ws.max_row < 1:
            summary["skipped"].append(ws_name)
            continue

        # ICS sheet — 专用解析器
        if ws_name == "ICS":
            ics_data = parse_ics_sheet(ws)
            summary["meta"].append(ws_name)
            continue

        # DUT Identification — 嵌套结构解析器
        if ws_name == "DUT Identification":
            dut_identification = parse_dut_identification(ws)
            summary["meta"].append(ws_name)
            continue

        # IXIT 表（以数字开头，如 "1-AuthMech"）
        if _is_ixit_sheet(ws_name):
            layout = detect_layout(ws)
            if layout == "standard":
                ixit_tables[ws_name] = parse_standard(ws)
                summary["standard"].append(ws_name)
            else:
                ixit_tables[ws_name] = parse_flat(ws)
                summary["flat"].append(ws_name)
        else:
            # 元数据 sheet（Security Context, Conditions 等）
            meta_sections[ws_name] = _parse_meta_sheet(ws)
            summary["meta"].append(ws_name)

    wb.close()

    # 组装 meta
    sec_ctx_raw = meta_sections.get("Security Context", {})
    conditions_raw = meta_sections.get("Conditions", {})

    # Security Context: 优先取 _content（C2-only 行拼接），否则取所有 values
    security_context = sec_ctx_raw.get("_content", "")
    if not security_context:
        sec_ctx_parts = [v for v in sec_ctx_raw.values() if v]
        security_context = "\n".join(sec_ctx_parts)

    result = {
        "meta": {
            "dut_identification": dut_identification,
            "security_context": security_context,
            "conditions": [v for v in conditions_raw.values() if v],
            "source": os.path.basename(xlsx_path),
            "parser": "parse_ixit_xlsx.py",
        },
        "ics": ics_data,
        "ixit_tables": ixit_tables,
    }

    return result, summary


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    if len(sys.argv) < 2:
        print("用法: python parse_ixit_xlsx.py <input.xlsx> [output.json]",
              file=sys.stderr)
        return 2

    xlsx_path = sys.argv[1]
    if not os.path.exists(xlsx_path):
        print(f"文件不存在: {xlsx_path}", file=sys.stderr)
        return 1

    output_path = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
        os.path.dirname(xlsx_path), "ixit.json"
    )

    result, summary = parse_ixit_xlsx(xlsx_path)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    # 打印统计
    out = sys.stdout
    out.write("IXIT Excel 解析完成:\n")
    out.write(f"  输入: {xlsx_path}\n")
    out.write(f"  输出: {output_path} ({os.path.getsize(output_path) / 1024:.0f} KB)\n")
    out.write(f"  ICS 条目: {len(result['ics'])} 条 Provision\n")
    out.write(f"  标准布局 ({len(summary['standard'])} sheets): {', '.join(summary['standard'])}\n")
    out.write(f"  扁平布局 ({len(summary['flat'])} sheets): {', '.join(summary['flat'])}\n")
    out.write(f"  元数据   ({len(summary['meta'])} sheets): {', '.join(summary['meta'])}\n")
    if summary["skipped"]:
        out.write(f"  跳过     ({len(summary['skipped'])} sheets): {', '.join(summary['skipped'])}\n")

    # DUT Identification 嵌套结构
    dut_id = result["meta"]["dut_identification"]
    out.write(f"\n  DUT Identification ({len(dut_id)} sections):\n")
    for sec_name, sec_fields in dut_id.items():
        if isinstance(sec_fields, dict):
            filled = sum(1 for v in sec_fields.values() if v)
            out.write(f"    {sec_name}: {len(sec_fields)} fields ({filled} filled)\n")
        else:
            out.write(f"    {sec_name}: {repr(sec_fields)[:60]}\n")

    # 验证扁平布局 sheet 的字段数
    out.write("\n  扁平布局字段统计:\n")
    for name in summary["flat"]:
        sheet = result["ixit_tables"][name]
        row_count = sheet["meta"]["row_count"]
        fields = [r.get("Field", "?") for r in sheet["rows"]]
        out.write(f"    {name}: {row_count} 个字段\n")
        for f_name in fields:
            out.write(f"      - {f_name}\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
