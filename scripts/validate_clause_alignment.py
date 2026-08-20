#!/usr/bin/env python3
"""校验 ETSI 条款到知识、工具、Phase 的基础对齐关系。

本脚本不执行任何 DUT 测试，也不产生 PASS/FAIL。它回答的是更前置的问题：
某条款是否已经被模块编排、是否有 recipe、是否能在条款/裁决资料中找到，以及
标为 ``full`` 时是否至少声明了一类可调用工具。默认只输出 JSON 报告；使用
``--strict`` 时，发现任一缺口返回非零退出码，供 Catalog 完整后接入 CI。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pipelines.etsi.modules import build_etsi_modules
from framework.conceptual_catalog import load_conceptual_catalog
from framework.phase_engine import PhaseDefinitionLoader


SKILLS_ROOT = ROOT / "skills"
CLAUSE_MAP_PATH = ROOT / "framework" / "clause_tool_map.json"
PHASE_DEFINITIONS_PATH = ROOT / "framework" / "phase_definitions.json"
CLAUSE_REFERENCE_PATH = SKILLS_ROOT / "etsi-ts103701-report" / "references" / "clause-reference.md"
VERDICT_CRITERIA_PATH = SKILLS_ROOT / "etsi-ts103701-report" / "references" / "verdict-criteria.md"
QBFW_PATH = SKILLS_ROOT / "etsi-ts103701-report" / "references" / "qbfw_parsed.json"
CLAUSE_ID_PATTERN = re.compile(r"(?<![\d.])(?:4-1|5\.\d{1,2}-\d{1,2}|6-\d)(?![\d.])")
# 当前 ModuleDef / clause_tool_map 用 "5.10" 作为条款键，而 Skill 中使用
# "5.10-1" 的 provision 写法。两者是同一测试单元，校验时统一为前者，
# 不能把命名粒度差异误报成知识缺失。
CLAUSE_ID_ALIASES = {"5.10-1": "5.10"}


def _clause_ids_in_text(path: Path) -> set[str]:
    return {
        CLAUSE_ID_ALIASES.get(clause_id, clause_id)
        for clause_id in CLAUSE_ID_PATTERN.findall(path.read_text(encoding="utf-8"))
    }


def _conceptual_ids_in_qbfw(path: Path) -> set[str]:
    """只以权威测试用例表中 case_type=概念性 的用例作为 M0 范围。"""
    groups = json.loads(path.read_text(encoding="utf-8"))
    return {
        CLAUSE_ID_ALIASES.get(str(group["clause_id"]), str(group["clause_id"]))
        for group in groups
        if any(case.get("case_type") == "概念性" for case in group.get("test_cases", []))
    }


def _functional_ids_in_qbfw(path: Path) -> set[str]:
    """功能或混合用例仍由 M1–M5 功能执行面负责，不进入 M0。"""
    groups = json.loads(path.read_text(encoding="utf-8"))
    return {
        CLAUSE_ID_ALIASES.get(str(group["clause_id"]), str(group["clause_id"]))
        for group in groups
        if any("功能性" in str(case.get("case_type", "")) for case in group.get("test_cases", []))
    }


def build_alignment_report(root: Path = ROOT) -> dict[str, Any]:
    """生成纯数据的对齐报告，供 CLI、测试与未来 Web API 共用。"""
    skills_root = root / "skills"
    modules = tuple(module for module in build_etsi_modules(skills_root) if module.id != "M0")
    conceptual_ids = {item.clause_id for item in load_conceptual_catalog().clauses}
    qbfw_conceptual_ids = _conceptual_ids_in_qbfw(
        root / "skills" / "etsi-ts103701-report" / "references" / "qbfw_parsed.json"
    )
    qbfw_functional_ids = _functional_ids_in_qbfw(
        root / "skills" / "etsi-ts103701-report" / "references" / "qbfw_parsed.json"
    )
    module_clauses = {
        module.id: set(module.clauses)
        for module in modules
    }
    functional_module_clauses = set().union(*module_clauses.values())
    # 纯概念条款已从功能 Module/Phase 前置到 M0 概念执行面；它们仍是
    # 67 条规范条款的一部分，不能因不再归属 M1-M5 而从对齐校验中消失。
    module_clauses["M0_CONCEPT"] = conceptual_ids
    all_module_clauses = set().union(*module_clauses.values())

    clause_map = json.loads((root / "framework" / "clause_tool_map.json").read_text(encoding="utf-8"))
    catalog_clauses = set(clause_map)

    phase_defs, _ = PhaseDefinitionLoader.load(root / "framework" / "phase_definitions.json")
    phase_clauses = {
        module_id: {clause for phase in definition.phases for clause in phase.clauses}
        for module_id, definition in phase_defs.items()
    }
    phase_clauses["M0_CONCEPT"] = conceptual_ids

    clause_reference_ids = _clause_ids_in_text(
        skills_root / "etsi-ts103701-report" / "references" / "clause-reference.md"
    )
    verdict_ids = _clause_ids_in_text(
        skills_root / "etsi-ts103701-report" / "references" / "verdict-criteria.md"
    )

    full_without_tools = []
    for clause_id, recipe in sorted(clause_map.items()):
        if recipe.get("automation") != "full":
            continue
        tool_groups = recipe.get("tools", {})
        if not any(tool_groups.get(group) for group in ("bash", "burp_mcp", "playwright_mcp")):
            full_without_tools.append(clause_id)

    # 4-1 的概念性判据在 qbfw 测试单元中，而非旧版 clause-reference / verdict 表。
    # 它仍被 recipe 与 M0 catalog 明确覆盖，不能将这种资料分工误报成知识缺失。
    legacy_knowledge_required = all_module_clauses - {"4-1"}

    return {
        "summary": {
            "module_clause_count": len(all_module_clauses),
            "catalog_clause_count": len(catalog_clauses),
            "phase_clause_count": len(set().union(*phase_clauses.values())),
            "qbfw_conceptual_case_count": len(qbfw_conceptual_ids),
            "m0_concept_clause_count": len(conceptual_ids),
            "qbfw_functional_or_mixed_case_count": len(qbfw_functional_ids),
            "m1_m5_functional_clause_count": len(functional_module_clauses),
            "full_recipe_count": sum(
                recipe.get("automation") == "full" for recipe in clause_map.values()
            ),
        },
        "missing": {
            "catalog": sorted(all_module_clauses - catalog_clauses),
            "qbfw_conceptual": sorted(qbfw_conceptual_ids - conceptual_ids),
            "qbfw_functional_or_mixed": sorted(qbfw_functional_ids - functional_module_clauses),
            "phase": {
                module_id: sorted(clauses - phase_clauses.get(module_id, set()))
                for module_id, clauses in module_clauses.items()
                if clauses - phase_clauses.get(module_id, set())
            },
            "clause_reference": sorted(legacy_knowledge_required - clause_reference_ids),
            "verdict_criteria": sorted(legacy_knowledge_required - verdict_ids),
        },
        "unexpected": {
            "catalog": sorted(catalog_clauses - all_module_clauses),
            "m0_conceptual": sorted(conceptual_ids - qbfw_conceptual_ids),
            "m1_m5_functional": sorted(functional_module_clauses - qbfw_functional_ids),
            "phase": {
                module_id: sorted(clauses - module_clauses.get(module_id, set()))
                for module_id, clauses in phase_clauses.items()
                if clauses - module_clauses.get(module_id, set())
            },
        },
        "quality_warnings": {
            "full_without_declared_tools": full_without_tools,
        },
    }


def has_gaps(report: dict[str, Any]) -> bool:
    """判断报告是否存在需要补齐的目录/编排/知识/工具声明缺口。"""
    missing = report["missing"]
    unexpected = report["unexpected"]
    warnings = report["quality_warnings"]
    return any((
        missing["catalog"],
        missing["qbfw_conceptual"],
        missing["qbfw_functional_or_mixed"],
        missing["phase"],
        missing["clause_reference"],
        missing["verdict_criteria"],
        unexpected["catalog"],
        unexpected["m0_conceptual"],
        unexpected["m1_m5_functional"],
        unexpected["phase"],
        warnings["full_without_declared_tools"],
    ))


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate ETSI clause alignment")
    parser.add_argument("--strict", action="store_true", help="发现对齐缺口时返回 1")
    parser.add_argument("--out", type=Path, help="可选：写入 JSON 报告")
    args = parser.parse_args()

    report = build_alignment_report()
    output = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        args.out.write_text(output + "\n", encoding="utf-8")
    print(output)
    return 1 if args.strict and has_gaps(report) else 0


if __name__ == "__main__":
    raise SystemExit(main())
