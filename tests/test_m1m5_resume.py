import json

from contracts.pipeline import PipelineSnapshot, PipelineState, StageStatus
from run_pipeline import _resume_m1m5_via_traffic


def test_m1m5_resume_returns_to_traffic_and_keeps_snapshots(tmp_path):
    (tmp_path / "tokens").mkdir()
    (tmp_path / "tokens" / ".cancel_requested").touch()
    (tmp_path / "snapshots").mkdir()
    (tmp_path / "snapshots" / "phase__M1__phase_A.json").write_text("{}", encoding="utf-8")
    state = PipelineSnapshot(
        pipeline_id="x", pipeline_name="etsi-ts103701", current_state=PipelineState.CANCELLED,
        workspace_path=str(tmp_path), stage_statuses={PipelineState.M1_M5_PARALLEL.value: StageStatus.FAILED},
        failed_stages=[PipelineState.M1_M5_PARALLEL.value],
    )
    (tmp_path / "pipeline_state.json").write_text(state.model_dump_json(indent=2), encoding="utf-8")
    _resume_m1m5_via_traffic(tmp_path)
    updated = PipelineSnapshot.model_validate_json((tmp_path / "pipeline_state.json").read_text(encoding="utf-8"))
    assert updated.current_state == PipelineState.TRAFFIC_COLLECT
    assert updated.stage_statuses[PipelineState.M1_M5_PARALLEL.value] == StageStatus.PENDING
    assert not (tmp_path / "tokens" / ".cancel_requested").exists()
    assert (tmp_path / "snapshots" / "phase__M1__phase_A.json").exists()


def test_m1m5_resume_accepts_reboot_interruption_after_safe_stop(tmp_path):
    (tmp_path / "tokens").mkdir()
    (tmp_path / "tokens" / ".cancel_requested").touch()
    state = PipelineSnapshot(
        pipeline_id="x", pipeline_name="etsi-ts103701", current_state=PipelineState.M1_M5_PARALLEL,
        workspace_path=str(tmp_path), stage_statuses={PipelineState.M1_M5_PARALLEL.value: StageStatus.IN_PROGRESS},
    )
    (tmp_path / "pipeline_state.json").write_text(state.model_dump_json(indent=2), encoding="utf-8")

    _resume_m1m5_via_traffic(tmp_path)

    updated = PipelineSnapshot.model_validate_json((tmp_path / "pipeline_state.json").read_text(encoding="utf-8"))
    assert updated.current_state == PipelineState.TRAFFIC_COLLECT
    assert not (tmp_path / "tokens" / ".cancel_requested").exists()
