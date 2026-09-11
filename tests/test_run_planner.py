import pytest
from pathlib import Path

from contracts.run_plan import RunProfile
from framework.run_planner import build_run_plan
from framework.run_workspace import create_isolated_run_workspace


def test_functional_smoke_skips_certification_gates_without_faking_them():
    plan = build_run_plan(RunProfile.FUNCTIONAL_SMOKE)
    assert plan.certification_claim is False
    assert plan.selected_modules == ["M1", "M2", "M3", "M4", "M5"]
    assert plan.nodes[0].id == "traffic"
    assert "M0 L1/L2 认证 gate" in plan.skipped_gates


def test_functional_module_expands_real_module_dependency():
    plan = build_run_plan("functional-module", ["M3"])
    assert plan.selected_modules == ["M2", "M3"]
    assert next(node for node in plan.nodes if node.id == "m3").depends_on == ["traffic", "m2"]


def test_functional_module_requires_a_target():
    with pytest.raises(ValueError, match="必须指定"):
        build_run_plan("functional-module")


def test_functional_run_workspace_isolated_from_parent(tmp_path):
    parent = tmp_path / "certification"
    parent.mkdir()
    (parent / "ixit.json").write_text('{"ixit": true}', encoding="utf-8")
    (parent / "run_config.json").write_text('{"dut_ip": "192.0.2.1"}', encoding="utf-8")
    run = create_isolated_run_workspace(parent, build_run_plan("functional-module", ["M3"]))
    assert run.parent == parent / "runs"
    assert (run / "ixit.json").read_text(encoding="utf-8") == '{"ixit": true}'
    assert (run / "run_plan.json").is_file()
    assert not (parent / "pipeline_state.json").exists()


def test_resume_traffic_clears_only_resolved_traffic_review_state(tmp_path):
    import json
    from contracts.pipeline import PipelineSnapshot, PipelineState, StageStatus
    from run_pipeline import _resume_traffic

    snapshot = PipelineSnapshot(
        pipeline_id="test", pipeline_name="etsi", current_state=PipelineState.NEEDS_REVIEW,
        workspace_path=str(tmp_path), review_required=True,
        review_reasons=["Traffic BLOCKED: tshark unavailable", "M0 needs manual review"],
        errors=["Traffic retry requested after preflight remediation.", "M0 independent error"],
        stage_statuses={PipelineState.TRAFFIC_COLLECT.value: StageStatus.FAILED},
    )
    (tmp_path / "pipeline_state.json").write_text(
        snapshot.model_dump_json(indent=2), encoding="utf-8"
    )

    _resume_traffic(tmp_path)
    restored = json.loads((tmp_path / "pipeline_state.json").read_text(encoding="utf-8"))

    assert restored["current_state"] == "traffic"
    assert restored["review_required"] is True
    assert restored["review_reasons"] == ["M0 needs manual review"]
    assert restored["errors"] == ["M0 independent error"]
