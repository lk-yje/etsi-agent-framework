"""管线状态合约 — PipelineState, StageStatus, PipelineSnapshot"""

from __future__ import annotations
from typing import Dict, List
from pydantic import BaseModel, Field
from enum import Enum
from datetime import datetime


class StageStatus(str, Enum):
    """管线阶段状态"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    AWAITING_GATE = "awaiting_gate"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"


class ModuleVerdict(str, Enum):
    """审计裁决"""
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    FLAGGED = "FLAGGED"


class PipelineState(str, Enum):
    """管线顶层状态"""
    INIT = "init"
    ENV_CHECK = "env_check"
    ICS_PARSE = "ics_parse"
    M0_ICS_VALIDATION = "m0"
    M0_CONCEPT = "m0_concept"
    M0_L1 = "m0_l1"
    M0_AUDIT = "m0_audit"
    TRAFFIC_COLLECT = "traffic"
    M1_M5_PARALLEL = "m1_m5"
    AUDIT_QUEUE = "audit"
    CROSS_MODULE_AUDIT = "cross"
    REPORT_GENERATION = "report"
    DONE = "done"
    NEEDS_REVIEW = "needs_review"
    CANCELLED = "cancelled"
    FAILED = "failed"


class PipelineSnapshot(BaseModel):
    """管线状态快照（持久化到 pipeline_state.json，支持断点续跑）"""
    pipeline_id: str
    pipeline_name: str
    current_state: PipelineState
    stage_statuses: Dict[str, StageStatus] = Field(default_factory=dict)
    started_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
    workspace_path: str
    completed_stages: List[str] = Field(default_factory=list)
    failed_stages: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    gate_failures: Dict[str, int] = Field(default_factory=dict)
    review_required: bool = False
    review_reasons: List[str] = Field(default_factory=list)

    def is_terminal(self) -> bool:
        return self.current_state in (
            PipelineState.DONE,
            PipelineState.NEEDS_REVIEW,
            PipelineState.CANCELLED,
            PipelineState.FAILED,
        )

    def is_stage_completed(self, stage: PipelineState) -> bool:
        return self.stage_statuses.get(stage.value) == StageStatus.PASSED
