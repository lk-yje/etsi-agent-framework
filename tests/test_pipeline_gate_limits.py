"""阶段闸门重试上限与 needs_review 终态测试。"""

import asyncio
from pathlib import Path

from contracts.pipeline import PipelineState
from framework.gate_checker import GateChecker, GateResult
from framework.pipeline import Pipeline, Stage, StageTransition


class _NoopStage(Stage):
    def __init__(self):
        self.calls = 0

    async def execute(self, workspace, registry, pipeline):
        self.calls += 1

    def describe(self):
        return "test noop"


class _FailGate(GateChecker):
    async def check(self, workspace):
        return GateResult.FAIL

    def describe(self):
        return "test failing gate"


class _GateLimitPipeline(Pipeline):
    def __init__(self, workspace: Path, review_on_exhaustion: bool):
        super().__init__(workspace, registry=None)
        self.start = _NoopStage()
        self.report = _NoopStage()
        self.review_on_exhaustion = review_on_exhaustion

    @property
    def pipeline_name(self):
        return "gate-limit-test"

    @property
    def stages(self):
        return {
            PipelineState.INIT: self.start,
            PipelineState.REPORT_GENERATION: self.report,
        }

    @property
    def transitions(self):
        return [
            StageTransition(
                PipelineState.INIT,
                PipelineState.REPORT_GENERATION,
                gate=_FailGate(),
                on_failure=PipelineState.INIT,
                max_gate_failures=1,
                on_exhaustion=(
                    PipelineState.REPORT_GENERATION
                    if self.review_on_exhaustion
                    else PipelineState.FAILED
                ),
                review_on_exhaustion=self.review_on_exhaustion,
            ),
            StageTransition(PipelineState.REPORT_GENERATION, PipelineState.DONE),
        ]


def test_gate_limit_generates_partial_report_then_needs_review(tmp_path):
    pipeline = _GateLimitPipeline(tmp_path, review_on_exhaustion=True)
    result = asyncio.run(pipeline.run())

    assert pipeline.start.calls == 2  # 初次 + 允许的一次阶段级重进
    assert pipeline.report.calls == 1
    assert result.current_state == PipelineState.NEEDS_REVIEW
    assert result.review_required is True
    assert result.gate_failures["init->report"] == 2
    assert result.review_reasons
    assert "init" in result.failed_stages


def test_gate_limit_fails_without_report_when_review_is_not_allowed(tmp_path):
    pipeline = _GateLimitPipeline(tmp_path, review_on_exhaustion=False)
    result = asyncio.run(pipeline.run())

    assert pipeline.start.calls == 2
    assert pipeline.report.calls == 0
    assert result.current_state == PipelineState.FAILED
    assert result.review_required is False


def test_cancellation_token_stops_before_next_stage(tmp_path):
    (tmp_path / "tokens").mkdir()
    (tmp_path / "tokens" / ".cancel_requested").touch()
    pipeline = _GateLimitPipeline(tmp_path, review_on_exhaustion=False)

    result = asyncio.run(pipeline.run())

    assert pipeline.start.calls == 0
    assert result.current_state == PipelineState.CANCELLED
    assert result.errors[-1] == "取消请求在阶段启动前被确认"
