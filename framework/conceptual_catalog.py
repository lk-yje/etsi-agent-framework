"""纯概念性条款的受控目录。

目录只选择哪些条款可在 M0 的离线概念执行面运行；具体测试方法和
PASS/FAIL/UNCERTAIN 标准仍来自 ETSI skill 的条款速查与裁决表。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


DEFAULT_CATALOG_PATH = Path(__file__).with_name("conceptual_clause_catalog.json")


@dataclass(frozen=True)
class ConceptualClause:
    clause_id: str
    source_clause_id: str
    test_case_id: str
    origin_module: str
    origin_phase: str
    ixit_tables: tuple[str, ...]
    test_purpose: str
    test_units: str
    pass_criteria: str
    functional_case_ids: tuple[str, ...]


@dataclass(frozen=True)
class ConceptualCatalog:
    version: str
    execution_lane: str
    retry_limit: int
    audit_batch_size: int
    clauses: tuple[ConceptualClause, ...]


def load_conceptual_catalog(path: Path | None = None) -> ConceptualCatalog:
    """加载并严格校验 M0 纯概念条款目录。"""
    catalog_path = path or DEFAULT_CATALOG_PATH
    raw = json.loads(catalog_path.read_text(encoding="utf-8"))
    if raw.get("execution_lane") != "m0_concept":
        raise ValueError("Conceptual catalog execution_lane must be 'm0_concept'")

    retry_limit = raw.get("retry_limit")
    if not isinstance(retry_limit, int) or retry_limit < 0:
        raise ValueError("Conceptual catalog retry_limit must be a non-negative integer")

    audit_batch_size = raw.get("audit_batch_size", 8)
    if not isinstance(audit_batch_size, int) or not 1 <= audit_batch_size <= 8:
        raise ValueError("Conceptual catalog audit_batch_size must be 1..8")

    clauses: list[ConceptualClause] = []
    seen: set[str] = set()
    for item in raw.get("clauses", []):
        clause_id = str(item.get("clause_id", "")).strip()
        test_case_id = str(item.get("test_case_id", "")).strip()
        tables = tuple(str(table).strip() for table in item.get("ixit_tables", []) if str(table).strip())
        test_purpose = str(item.get("test_purpose", "")).strip()
        test_units = str(item.get("test_units", "")).strip()
        pass_criteria = str(item.get("pass_criteria", "")).strip()
        if not clause_id or not test_case_id or not test_purpose or not test_units or not pass_criteria:
            raise ValueError(f"Invalid conceptual clause entry: {item!r}")
        if clause_id in seen:
            raise ValueError(f"Duplicate conceptual clause_id: {clause_id}")
        seen.add(clause_id)
        clauses.append(ConceptualClause(
            clause_id=clause_id,
            source_clause_id=str(item.get("source_clause_id", clause_id)).strip(),
            test_case_id=test_case_id,
            origin_module=str(item.get("origin_module", "")).strip(),
            origin_phase=str(item.get("origin_phase", "")).strip(),
            ixit_tables=tables,
            test_purpose=test_purpose,
            test_units=test_units,
            pass_criteria=pass_criteria,
            functional_case_ids=tuple(str(case).strip() for case in item.get("functional_case_ids", []) if str(case).strip()),
        ))

    if not clauses:
        raise ValueError("Conceptual catalog must not be empty")
    version = str(raw.get("version", "")).strip()
    if not version:
        raise ValueError("Conceptual catalog version must be present")
    return ConceptualCatalog(version, "m0_concept", retry_limit, audit_batch_size, tuple(clauses))
