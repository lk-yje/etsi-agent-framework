"""闸门系统 — L1 确定性检验 + L2 AI 审计 + Phase 整体闸门。

L1: 使用 Pydantic 模型内置验证器，确定性计算，毫秒级，可阻塞管线
L2: AI 审计 Agent，离线运行，不阻塞管线
Phase: 使用 FileBus 令牌检查（存在即通过）
"""

import json
import os
from abc import ABC, abstractmethod
from enum import Enum
from pathlib import Path
from typing import List

from contracts.evidence import EvidenceManifest


class GateResult(Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"


class GateChecker(ABC):
    """闸门检查器基类"""

    @abstractmethod
    async def check(self, workspace: Path) -> GateResult:
        ...

    @abstractmethod
    def describe(self) -> str:
        ...


class L1StructuralGate(GateChecker):
    """L1 确定性结构闸门 — 使用 Pydantic 模型验证。

    检查项 (确定性，非 AI):
    - JSON 可解析为 EvidenceManifest
    - execution_trace 非空
    - 条款数对账 (self_check.total_expected vs actual)
    - FAIL 缺少 expected_behavior
    - PENDING_MANUAL 缺少 manual_steps
    - L4/L5 证据检测
    - ICS=N/A 缺少 reason
    """

    def __init__(self, evidence_relative_path: str):
        self.evidence_path = evidence_relative_path

    async def check(self, workspace: Path) -> GateResult:
        evidence_file = workspace / self.evidence_path

        if not evidence_file.exists():
            return GateResult.FAIL

        try:
            raw = json.loads(evidence_file.read_text(encoding="utf-8"))
            evidence = EvidenceManifest(**raw)
        except Exception as e:
            err_file = workspace / f"l1_errors_{evidence_file.stem}.txt"
            err_file.write_text(f"L1 验证异常: {e}", encoding="utf-8")
            return GateResult.FAIL

        errors: List[str] = []

        # 检查 L4/L5 证据
        if evidence.has_l4_l5_evidence():
            errors.append("检测到 L4/L5 级别证据 — L4=无证据, L5=证据矛盾")

        # 检查 FAIL 缺 expected vs actual
        fail_violations = evidence.fail_clauses_without_expected_vs_actual()
        if fail_violations:
            errors.append(f"FAIL 条款缺少 expected_behavior: {fail_violations}")

        # 检查 PENDING_MANUAL 缺 manualSteps
        pm_violations = evidence.pending_manual_without_steps()
        if pm_violations:
            errors.append(f"PENDING_MANUAL 缺少 manual_steps: {pm_violations}")

        # 检查条款数对账
        sc = evidence.self_check
        if sc.total_expected != len(evidence.clauses):
            errors.append(
                f"条款数不对: self_check.total_expected={sc.total_expected}, "
                f"clauses 实际={len(evidence.clauses)}"
            )

        # 检查 ICS=N/A 缺 reason
        for c in evidence.clauses:
            if c.ics_support == "N/A" and c.verdict == "NA" and not c.reason.strip():
                errors.append(f"{c.clause_id}: ICS=N/A 但 reason 为空")

        if errors:
            # 写入人类可读的错误文件
            err_file = workspace / f"l1_errors_{evidence_file.stem}.txt"
            err_file.write_text("\n".join(errors), encoding="utf-8")
            # 同时写入结构化错误 JSON（供程序化消费）
            err_json = workspace / f"l1_errors_{evidence_file.stem}.json"
            import json as _json
            err_json.write_text(
                _json.dumps({
                    "evidence_file": str(evidence_file),
                    "error_count": len(errors),
                    "errors": errors,
                    "module_id": evidence_file.stem.replace("pre-", "").replace("-evidence", ""),
                }, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            return GateResult.FAIL

        return GateResult.PASS

    @staticmethod
    def check_pool_consistency(pool, module_id: str) -> GateResult:
        """检查 pool 中该模块的 MODULE-scope 数据是否已被消费。

        Warning-only, 不阻断管线。
        """
        unconsumed = pool.get_unconsumed(module_id)
        if unconsumed:
            return GateResult.WARN
        return GateResult.PASS

    def describe(self) -> str:
        return f"L1 结构校验: {self.evidence_path}"


class L2AuditGate(GateChecker):
    """L2 AI 审计闸门 — 调度 Audit Agent 进行语义级审计。

    check() 不阻塞管线 (总是 PASS)。
    真正的审计逻辑通过 run_audit() 异步执行，结果写入 audit-results/。
    """

    def __init__(self, module_id: str):
        self.module_id = module_id

    async def check(self, workspace: Path) -> GateResult:
        """L2 审计不阻塞管线 — 总是返回 PASS。"""
        return GateResult.PASS

    async def run_audit(
        self,
        workspace: Path,
        runner: "AgentRunner",  # noqa: F821
        pipe_def: "PipelineDef",  # noqa: F821
        *,
        evidence_path: str | None = None,
        output_path: str | None = None,
        audit_label: str | None = None,
    ) -> "AuditResult":  # noqa: F821
        """异步运行审计 Agent 并返回结构化审计结果。

        由管线阶段 (AuditQueue / M1M5Parallel) 在后台调用。
        审计 Agent 只读文件，无工具权限。

        Returns:
            AuditResult: 包含 verdict (ACCEPT/REJECT/FLAGGED) 和 findings
        """
        from contracts.audit import AuditResult
        from framework.agent_runner import AgentConfig
        from framework.audit_tools import (
            AUDIT_READONLY_CATEGORY,
            build_audit_readonly_registry,
        )
        from framework.file_bus import FileBus

        evidence_path = evidence_path or f"evidence/pre-{self.module_id}-evidence.json"
        output_path = output_path or f"audit-results/audit-result_{self.module_id}.json"
        audit_inputs = [evidence_path, "ixit.json"]

        config = AgentConfig(
            agent_id=f"audit_{self.module_id}_{audit_label}_v1" if audit_label else f"audit_{self.module_id}_v1",
            agent_type="audit",
            persona_path=pipe_def.audit_agent_persona,
            knowledge_paths=(
                pipe_def.shared_knowledge + pipe_def.audit_only_knowledge
            ),
            tool_manifest=(AUDIT_READONLY_CATEGORY,),
            forbidden_patterns=(),
            # 与 Work Agent / PhaseEngine 一致：允许私有运行环境选择
            # Anthropic 兼容网关的模型名，避免审计链路仍硬编码默认模型。
            model=os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5"),
            # 私有兼容网关可为审计设置较小的工具轮次预算，避免模型在大
            # evidence 上无限扩展检索而耗尽最终 JSON 输出预算。默认值保持
            # 原有行为；仅离线 Flash 验证会设置该环境变量。
            max_tool_turns=max(1, int(os.environ.get("ANTHROPIC_AUDIT_MAX_TOOL_TURNS", "30"))),
        )

        task_ctx = {
            "task": (
                f"审计模块 {self.module_id} 的 evidence JSON。\n"
                f"文件路径: {evidence_path}\n"
                "如果 meta.scope=conceptual_audit_batch：这是一份受限审计切片；"
                "只审计其中 clauses 和 meta.conceptualCaseSource 明示的测试单元/判据，"
                "不得因未看到其他切片而推断缺失。\n"
                f"按三角对照法 (Standard-IXIT-Evidence) 逐条款审计。\n"
                "使用受限只读工具按需检索 IXIT 表和 evidence 字段；不得臆测未读取的内容。\n"
                f"按 audit-output-schema.json 格式输出 AuditResult JSON。\n"
            ),
            "workspace": str(workspace),
            "inputs": audit_inputs,
            "output_file": output_path,
            # audit-output-schema.json 是编排契约而非全文 Prompt 资产；
            # 在实际调用处从 Pydantic 合约生成 schema，避免只写“按 schema
            # 输出”却未向模型提供必填嵌套字段，导致有效审计降级为 FLAGGED。
            "output_schema": json.dumps(
                AuditResult.model_json_schema(by_alias=True),
                ensure_ascii=False,
            ),
        }

        result = await runner.run(
            config,
            task_ctx,
            tools=build_audit_readonly_registry(workspace, audit_inputs),
            output_schema=AuditResult,
        )

        if result.raw_text:
            import json as _json
            try:
                text = result.raw_text
                if "```json" in text:
                    text = text.split("```json")[1].split("```")[0]
                elif "```" in text:
                    text = text.split("```")[1].split("```")[0]
                audit_data = _json.loads(text.strip())
                audit_result = AuditResult(**audit_data)
                bus = FileBus(workspace)
                bus.write_json(output_path, audit_result.model_dump(mode="json"))
                return audit_result
            except Exception as e:
                import logging
                logging.getLogger("agent_framework").warning(
                    "L2 audit parse failed for %s: %s", self.module_id, e
                )
                # Preserve only the unparsed model final answer inside this
                # workspace.  It is diagnostic material, never a valid audit
                # result and never issues an ACCEPT token.
                bus = FileBus(workspace)
                bus.write_atomic(
                    bus.audit_dir / f"audit-result_{self.module_id}.unparsed.txt",
                    result.raw_text,
                )

        # 审计失败 → 返回默认 FLAGGED 结果
        from contracts.audit import AuditMeta
        fallback = AuditResult(
            audit=AuditMeta(
                moduleId=self.module_id,
                round=1,
                retryCount=0,
                verdict="FLAGGED",
                summary="审计 Agent 未产出有效结构化输出，标记为 FLAGGED 供人工审查",
            ),
            findings=[],
        )
        FileBus(workspace).write_json(output_path, fallback.model_dump(mode="json"))
        return fallback

    def describe(self) -> str:
        return f"L2 AI 审计: {self.module_id}"


class PhaseGate(GateChecker):
    """阶段闸门 — 检查 FileBus 令牌是否全部就绪。"""

    def __init__(self, phase: str, required_tokens: List[str]):
        self.phase = phase
        self.required_tokens = required_tokens

    async def check(self, workspace: Path) -> GateResult:
        token_dir = workspace / "tokens"
        missing = []
        for token in self.required_tokens:
            if not (token_dir / token).exists():
                missing.append(token)

        if missing:
            return GateResult.FAIL

        return GateResult.PASS

    def describe(self) -> str:
        tokens_str = ", ".join(self.required_tokens)
        return f"阶段闸门 [{self.phase}]: 令牌({tokens_str})"
