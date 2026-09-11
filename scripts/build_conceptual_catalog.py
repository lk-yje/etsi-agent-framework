#!/usr/bin/env python3
"""从 ETSI skill 的 qbfw_parsed.json 构建 M0 概念性用例目录。

这不是测试执行器。它只把权威用例表中 ``case_type == 概念性`` 的 62 条
用例规范化为 M0 的受限运行目录，避免人工维护第二份、会漂移的条款清单。
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
QBFW_PATH = ROOT / "skills" / "etsi-ts103701-report" / "references" / "qbfw_parsed.json"
OUTPUT_PATH = ROOT / "framework" / "conceptual_clause_catalog.json"
_TABLE_PATTERN = re.compile(r"\bIXIT\s+(\d+-[A-Za-z0-9]+)\b", re.IGNORECASE)
_CANONICAL_ALIASES = {"5.10-1": "5.10"}


def _canonical_clause_id(source_clause_id: str) -> str:
    return _CANONICAL_ALIASES.get(source_clause_id, source_clause_id)


def _origin_module(clause_id: str) -> str:
    """返回功能性测试组原属模块；仅作报告追溯，不控制 M0 执行。"""
    if clause_id == "4-1":
        return "M0"
    if clause_id.startswith("5.1-"):
        return "M2"
    if clause_id.startswith(("5.3-", "5.4-", "5.7-")):
        return "M4"
    if clause_id.startswith(("5.5-", "5.8-")):
        return "M3"
    if clause_id.startswith("5.6-"):
        return "M1"
    return "M5"


def _table_names(*texts: str) -> list[str]:
    seen: set[str] = set()
    tables: list[str] = []
    for text in texts:
        for match in _TABLE_PATTERN.finditer(text or ""):
            table = match.group(1)
            if table not in seen:
                seen.add(table)
                tables.append(table)
    return tables


def build_catalog(qbfw: list[dict[str, Any]], existing: dict[str, Any] | None = None) -> dict[str, Any]:
    """生成目录，并保留旧目录中已经验证过的补充跨表读取要求。"""
    existing_by_case = {
        str(item.get("test_case_id")): item
        for item in (existing or {}).get("clauses", [])
    }
    clauses: list[dict[str, Any]] = []
    seen: set[str] = set()
    for group in qbfw:
        cases = list(group.get("test_cases") or [])
        conceptual = [case for case in cases if case.get("case_type") == "概念性"]
        if len(conceptual) > 1:
            raise ValueError(f"{group.get('clause_id')}: expected at most one conceptual case")
        if not conceptual:
            continue
        case = conceptual[0]
        source_clause_id = str(group["clause_id"])
        clause_id = _canonical_clause_id(source_clause_id)
        if clause_id in seen:
            raise ValueError(f"duplicate canonical conceptual clause: {clause_id}")
        seen.add(clause_id)
        previous = existing_by_case.get(str(case["case_id"]), {})
        tables = _table_names(case.get("test_units", ""), case.get("conclusion", ""))
        for table in previous.get("ixit_tables", []):
            if table not in tables:
                tables.append(table)
        functional_case_ids = [
            str(item["case_id"])
            for item in cases
            if "功能性" in str(item.get("case_type", ""))
        ]
        clauses.append({
            "clause_id": clause_id,
            "source_clause_id": source_clause_id,
            "test_case_id": str(case["case_id"]),
            "origin_module": _origin_module(clause_id),
            "origin_phase": "m0_concept",
            "ixit_tables": tables,
            "test_purpose": str(case.get("test_purpose", "")).strip(),
            "test_units": str(case.get("test_units", "")).strip(),
            "pass_criteria": str(case.get("conclusion", "")).strip(),
            "functional_case_ids": functional_case_ids,
        })
    if len(clauses) != 62:
        raise ValueError(f"expected 62 conceptual cases, got {len(clauses)}")
    return {
        "version": "2.0",
        "purpose": "M0 概念性测试的权威运行目录；条目由 skills/etsi-ts103701-report/references/qbfw_parsed.json 自动生成。",
        "authority": "qbfw_parsed.json case_type == 概念性",
        "source": "skills/etsi-ts103701-report/references/qbfw_parsed.json",
        "execution_lane": "m0_concept",
        "retry_limit": 2,
        "audit_batch_size": 8,
        "clauses": clauses,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build M0 conceptual catalog from qbfw_parsed.json")
    parser.add_argument("--check", action="store_true", help="只校验当前目录是否与权威用例表一致")
    parser.add_argument("--out", type=Path, default=OUTPUT_PATH)
    args = parser.parse_args()
    qbfw = json.loads(QBFW_PATH.read_text(encoding="utf-8"))
    existing = json.loads(args.out.read_text(encoding="utf-8")) if args.out.exists() else None
    generated = build_catalog(qbfw, existing)
    rendered = json.dumps(generated, ensure_ascii=False, indent=2) + "\n"
    if args.check:
        current = args.out.read_text(encoding="utf-8") if args.out.exists() else ""
        if current != rendered:
            print("catalog is stale; run scripts/build_conceptual_catalog.py")
            return 1
        print("catalog is current: 62 conceptual cases")
        return 0
    args.out.write_text(rendered, encoding="utf-8")
    print(f"wrote {args.out}: 62 conceptual cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
