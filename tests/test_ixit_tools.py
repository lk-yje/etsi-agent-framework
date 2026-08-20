import asyncio
import json
from pathlib import Path

from framework.conceptual_catalog import load_conceptual_catalog
from framework.ixit_tools import IXIT_READONLY_CATEGORY, build_ixit_readonly_registry
from framework.tools import ToolRegistry


def _workspace(tmp_path):
    (tmp_path / "ixit.json").write_text(json.dumps({
        "ics": [{"reference": "Provision 5.6-6", "status": "R", "support": "Y"}],
        "ixit_tables": {"16-CodeMin": [{"id": "CodeMin-1", "detail": "no unused code"}]},
    }), encoding="utf-8")
    return tmp_path


def test_ixit_readonly_tools_are_bounded_and_category_is_not_standard(tmp_path):
    ws = _workspace(tmp_path)
    registry = ToolRegistry()
    build_ixit_readonly_registry(registry, ws)

    names = registry.resolve_categories((IXIT_READONLY_CATEGORY,))
    assert names == ["read_ixit_table", "read_ics_clause", "search_ixit"]
    assert "write_file" not in names
    assert "bash" not in names

    context = {"workspace": str(ws), "agent_id": "work_M1_phase_C_v1"}
    table = asyncio.run(registry.execute("read_ixit_table", {"table_name": "16-CodeMin"}, context))
    ics = asyncio.run(registry.execute("read_ics_clause", {"clause_id": "5.6-6"}, context))
    search = asyncio.run(registry.execute("search_ixit", {"query": "unused", "scope": "tables"}, context))

    assert not table.is_error and "ixit.json#/ixit_tables/16-CodeMin" in table.content
    assert not ics.is_error and "Provision 5.6-6" in ics.content
    assert not search.is_error and "16-CodeMin" in search.content


def test_pure_conceptual_clauses_are_not_reopened_by_m1_functional_phases():
    """纯概念-only 条款已前置 M0，功能 Phase 不得重新执行它们。"""
    root = Path(__file__).resolve().parents[1]
    definitions = json.loads((root / "framework" / "phase_definitions.json").read_text(encoding="utf-8"))
    phase_clauses = {
        clause
        for module in definitions["modules"].values()
        for phase in module["phases"]
        for clause in phase["clauses"]
    }
    catalog = load_conceptual_catalog()
    concept_only = {item.clause_id for item in catalog.clauses if not item.functional_case_ids}

    assert not (concept_only & phase_clauses)
    assert catalog.execution_lane == "m0_concept"


def test_m1_m5_keeps_exactly_the_qbfw_functional_or_mixed_groups():
    """概念前置不能误删功能/混合用例，也不能把概念-only 重新混入。"""
    root = Path(__file__).resolve().parents[1]
    qbfw = json.loads((root / "skills" / "etsi-ts103701-report" / "references" / "qbfw_parsed.json").read_text(encoding="utf-8"))
    expected = {
        "5.10" if group["clause_id"] == "5.10-1" else group["clause_id"]
        for group in qbfw
        if any("功能性" in str(case.get("case_type", "")) for case in group.get("test_cases", []))
    }
    from pipelines.etsi.modules import build_etsi_modules
    actual = {
        clause
        for module in build_etsi_modules(root / "skills")
        if module.id != "M0"
        for clause in module.clauses
    }

    assert actual == expected
