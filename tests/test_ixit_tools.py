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
    assert names == ["read_ixit_table", "read_ics_clause", "read_ics_list", "search_ixit"]
    assert "write_file" not in names
    assert "bash" not in names

    context = {"workspace": str(ws), "agent_id": "work_M1_phase_C_v1"}
    table = asyncio.run(registry.execute("read_ixit_table", {"table_name": "16-CodeMin"}, context))
    ics = asyncio.run(registry.execute("read_ics_clause", {"clause_id": "5.6-6"}, context))
    search = asyncio.run(registry.execute("search_ixit", {"query": "unused", "scope": "tables"}, context))

    assert not table.is_error and "ixit.json#/ixit_tables/16-CodeMin" in table.content
    assert not ics.is_error and "Provision 5.6-6" in ics.content
    assert not search.is_error and "16-CodeMin" in search.content


def test_every_catalog_clause_is_scheduled_by_m1_m5_phases():
    """M0 保留概念裁决，但每条 recipe 也必须进入 M1–M5 正式执行调度。"""
    root = Path(__file__).resolve().parents[1]
    definitions = json.loads((root / "framework" / "phase_definitions.json").read_text(encoding="utf-8"))
    phase_clauses = {
        clause
        for module in definitions["modules"].values()
        for phase in module["phases"]
        for clause in phase["clauses"]
    }
    clause_map = json.loads((root / "framework" / "clause_tool_map.json").read_text(encoding="utf-8"))
    assert phase_clauses == set(clause_map)


def test_m1_m5_modules_schedule_every_catalog_clause():
    """模块范围和 recipe catalog 必须一一对齐，防止显示与执行范围缩水。"""
    root = Path(__file__).resolve().parents[1]
    expected = set(json.loads((root / "framework" / "clause_tool_map.json").read_text(encoding="utf-8")))
    from pipelines.etsi.modules import build_etsi_modules
    actual = {
        clause
        for module in build_etsi_modules(root / "skills")
        if module.id != "M0"
        for clause in module.clauses
    }

    assert actual == expected
