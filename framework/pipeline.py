"""管线状态机 — 阶段跃迁、闸门调度、断点续跑。

框架层：不包含 ETSI 业务逻辑。具体管线通过继承 Pipeline 基类定义。
"""

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from contracts.pipeline import PipelineState, PipelineSnapshot, StageStatus
from framework.gate_checker import GateChecker, GateResult


@dataclass
class StageTransition:
    """阶段跃迁规则"""
    from_state: PipelineState
    to_state: PipelineState
    gate: Optional[GateChecker] = None
    on_failure: PipelineState = PipelineState.FAILED
    # Gate 失败后允许重新进入 on_failure 的次数。None 保持原有无限重试语义；
    # 仅自循环/回退 transition 应显式配置，避免持久失败烧尽资源。
    max_gate_failures: Optional[int] = None
    # 超过 gate 上限后的去向；例如 M1-M5 生成部分报告后 needs_review，
    # M0 在尚未进入检测前则直接 failed。
    on_exhaustion: PipelineState = PipelineState.FAILED
    review_on_exhaustion: bool = False


class Stage(ABC):
    """管线阶段基类"""

    @abstractmethod
    async def execute(self, workspace: Path, registry: "AgentRegistry", pipeline: "Pipeline") -> None:  # noqa: F821
        ...

    @abstractmethod
    def describe(self) -> str:
        ...


class Pipeline(ABC):
    """管线基类。

    子类必须定义:
    - stages: 阶段集合
    - transitions: 阶段跃迁规则

    提供:
    - run(): 驱动管线到完成
    - 状态持久化（pipeline_state.json）
    - 断点续跑（_load_or_init_state）
    """

    def __init__(self, workspace: Path, registry: "AgentRegistry"):  # noqa: F821
        self.workspace = Path(workspace)
        self.registry = registry
        self.state_file = self.workspace / "pipeline_state.json"
        self._state: Optional[PipelineSnapshot] = None

    @property
    def initial_state(self) -> PipelineState:
        """计划型管线可覆盖起点；认证默认仍从 INIT 开始。"""
        return PipelineState.INIT

    @property
    def run_profile_name(self) -> str:
        return "certification-full"

    @property
    def certification_claim(self) -> bool:
        return True

    # ===== 子类必须实现的抽象属性 =====

    @property
    @abstractmethod
    def pipeline_name(self) -> str:
        ...

    @property
    @abstractmethod
    def stages(self) -> Dict[PipelineState, Stage]:
        ...

    @property
    @abstractmethod
    def transitions(self) -> List[StageTransition]:
        ...

    # ===== 管线驱动 =====

    async def run(self) -> PipelineSnapshot:
        """驱动管线到完成。返回最终状态快照。"""
        self._load_or_init_state()

        while not self._state.is_terminal():
            await self._advance_one_stage()
            self._save_state()

        return self._state

    async def _advance_one_stage(self) -> None:
        """推进一个阶段：执行 → 闸门 → 跃迁"""
        current = self._state.current_state

        if self._cancellation_requested():
            self._mark_cancelled(current, "取消请求在阶段启动前被确认")
            return

        # 边界：当前阶段无定义
        if current not in self.stages:
            self._state.errors.append(f"未知阶段: {current.value}")
            self._state.current_state = PipelineState.FAILED
            return

        stage = self.stages[current]

        # 1. 标记为执行中并持久化
        self._state.stage_statuses[current.value] = StageStatus.IN_PROGRESS
        self._save_state()

        # 2. 执行阶段
        try:
            await stage.execute(self.workspace, self.registry, self)
            if self._cancellation_requested():
                self._mark_cancelled(current, "取消请求在阶段安全点被确认")
                return
            # 阶段可以在已知无法安全继续时请求一个受控终态（例如 L2 已给出
            # 有证据的分歧，但重做预算耗尽）。不要再把它送进通用闸门回流。
            if self._state.current_state != current:
                self._save_state()
                return
            self._state.stage_statuses[current.value] = StageStatus.AWAITING_GATE
        except Exception as e:
            self._state.errors.append(f"{current.value}: {type(e).__name__}: {e}")
            self._state.stage_statuses[current.value] = StageStatus.FAILED
            # 跳转到失败状态，避免无限循环
            transition = self._find_transition(current)
            self._state.current_state = transition.on_failure if transition else PipelineState.FAILED
            self._save_state()
            return

        # 3. 跑闸门
        transition = self._find_transition(current)
        if transition is None:
            # 无跃迁定义 → 管线结束
            self._state.completed_stages.append(current.value)
            self._state.stage_statuses[current.value] = StageStatus.PASSED
            self._state.current_state = PipelineState.DONE
        elif transition.gate is None:
            # 无闸门，直接跃迁
            self._state.completed_stages.append(current.value)
            self._state.stage_statuses[current.value] = StageStatus.PASSED
            # 部分报告生成完毕后不伪装为成功：以 needs_review 作为独立终态，
            # CLI/Web 可据此显示“已交付报告但不能认证通过”。
            if (
                transition.to_state == PipelineState.DONE
                and self._state.review_required
            ):
                self._state.current_state = PipelineState.NEEDS_REVIEW
            else:
                self._state.current_state = transition.to_state
        else:
            # 有闸门，检查
            gate_result = await transition.gate.check(self.workspace)
            if gate_result == GateResult.PASS:
                self._state.completed_stages.append(current.value)
                self._state.stage_statuses[current.value] = StageStatus.PASSED
                self._state.current_state = transition.to_state
            else:
                self._state.stage_statuses[current.value] = StageStatus.FAILED
                key = f"{current.value}->{transition.to_state.value}"
                failures = self._state.gate_failures.get(key, 0) + 1
                self._state.gate_failures[key] = failures

                if (
                    transition.max_gate_failures is not None
                    and failures > transition.max_gate_failures
                ):
                    reason = (
                        f"{key} gate failed {failures} times "
                        f"(limit {transition.max_gate_failures})"
                    )
                    self._state.errors.append(reason)
                    if current.value not in self._state.failed_stages:
                        self._state.failed_stages.append(current.value)
                    if transition.review_on_exhaustion:
                        self._state.review_required = True
                        self._state.review_reasons.append(reason)
                    self._state.current_state = transition.on_exhaustion
                else:
                    self._state.current_state = transition.on_failure

        self._save_state()

    def _find_transition(self, state: PipelineState) -> Optional[StageTransition]:
        for t in self.transitions:
            if t.from_state == state:
                return t
        return None

    def _cancellation_requested(self) -> bool:
        return (self.workspace / "tokens" / ".cancel_requested").exists()

    def _mark_cancelled(self, current: PipelineState, reason: str) -> None:
        self._state.stage_statuses[current.value] = StageStatus.FAILED
        if current.value not in self._state.failed_stages:
            self._state.failed_stages.append(current.value)
        self._state.errors.append(reason)
        self._state.current_state = PipelineState.CANCELLED
        self._save_state()

    def request_needs_review(self, current: PipelineState, reason: str) -> None:
        """由阶段显式结束为 needs_review，保留失败原因但不伪装为认证通过。"""
        self._state.stage_statuses[current.value] = StageStatus.FAILED
        if current.value not in self._state.failed_stages:
            self._state.failed_stages.append(current.value)
        self._state.review_required = True
        self._state.review_reasons.append(reason)
        self._state.current_state = PipelineState.NEEDS_REVIEW

    # ===== 状态持久化 =====

    def _save_state(self) -> None:
        """持久化管线状态到 JSON"""
        if self._state is None:
            return
        self._state.updated_at = datetime.now()
        self.state_file.write_text(
            self._state.model_dump_json(indent=2), encoding="utf-8"
        )

    def _load_or_init_state(self) -> None:
        """从文件恢复管线状态，或创建新状态"""
        if self.state_file.exists():
            self._state = PipelineSnapshot.model_validate_json(
                self.state_file.read_text(encoding="utf-8")
            )
            # 恢复执行时由本次 RunPlan 重新声明 profile。旧快照可能来自早期
            # 默认的 certification-full 状态模型；不能让该遗留字段把一个
            # functional-smoke 恢复会话在前端误标成认证模式。
            self._state.run_profile = self.run_profile_name
            self._state.certification_claim = self.certification_claim
        else:
            self._state = PipelineSnapshot(
                pipeline_id=str(uuid.uuid4())[:8],
                pipeline_name=self.pipeline_name,
                current_state=self.initial_state,
                stage_statuses={},
                started_at=datetime.now(),
                updated_at=datetime.now(),
                workspace_path=str(self.workspace),
                runProfile=self.run_profile_name,
                certificationClaim=self.certification_claim,
            )

    @property
    def state(self) -> Optional[PipelineSnapshot]:
        return self._state
