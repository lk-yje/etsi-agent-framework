import json
from pathlib import Path

from framework.conceptual_catalog import load_conceptual_catalog


def test_pure_conceptual_catalog_is_complete_and_bounded():
    catalog = load_conceptual_catalog()
    root = Path(__file__).resolve().parents[1]
    qbfw = json.loads((root / "skills" / "etsi-ts103701-report" / "references" / "qbfw_parsed.json").read_text(encoding="utf-8"))
    expected = {
        "5.10" if group["clause_id"] == "5.10-1" else group["clause_id"]
        for group in qbfw
        if any(case.get("case_type") == "概念性" for case in group.get("test_cases", []))
    }

    assert catalog.execution_lane == "m0_concept"
    assert catalog.retry_limit == 2
    assert catalog.audit_batch_size == 8
    assert {item.clause_id for item in catalog.clauses} == expected
    assert len(catalog.clauses) == 62
    assert {item.clause_id for item in catalog.clauses if not item.ixit_tables} == {"4-1"}
    assert len([item for item in catalog.clauses if not item.functional_case_ids]) == 21
    assert all(item.test_purpose and item.test_units and item.pass_criteria for item in catalog.clauses)


def test_pure_conceptual_catalog_uses_existing_recipe_ids():
    root = Path(__file__).resolve().parents[1]
    recipe_ids = set(json.loads(
        (root / "framework" / "clause_tool_map.json").read_text(encoding="utf-8")
    ))

    assert {item.clause_id for item in load_conceptual_catalog().clauses} <= recipe_ids
