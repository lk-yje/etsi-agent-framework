"""ETSI TS 103 701 管线定义 — 含完整 Stage 实现。

继承 Pipeline 基类，定义 ETSI 认证检测的完整 9 阶段流程。

设计变更 (2026-08-07):
- 审计改为触发式: 每个 Mx 模块完成后立即触发 round-1 审计
- 全部 round-1 ACCEPT 后进入 round-2 跨模块审计
- AUDIT_QUEUE 阶段不再独立存在，审计逻辑嵌入 M1M5ParallelStage
"""

import asyncio
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlsplit

from contracts.pipeline import PipelineState, StageStatus
from contracts.module import PipelineDef
from contracts.audit import AuditMeta, AuditResult, HarnessReport, RetryInstruction
from contracts.evidence import ClauseResult, EvidenceManifest, ExecutionStep
from framework.pipeline import Pipeline, Stage, StageTransition
from framework.gate_checker import PhaseGate, L1StructuralGate, L2AuditGate
from framework.audit_tokens import record_audit_outcome
from framework.conceptual_catalog import load_conceptual_catalog
from framework.m0_concept import execute_conceptual_clause
from framework.model_config import get_configured_model
from framework.functional_evidence import (
    conceptual_verdict_markers,
    functional_knowledge_paths,
)

from pipelines.etsi.modules import ETSI_MODULES, M0_ICS_VALIDATION
from pipelines.etsi.agents import WORK_AGENT_FORBIDDEN
from pipelines.etsi.traffic_checklist import load_traffic_checklist
from framework.traffic_state import TrafficStateStore


# ============================================================
# Stage 实现
# ============================================================

class InitStage(Stage):
    """初始化 — 创建工作区目录结构"""

    async def execute(self, workspace, registry, pipeline):
        workspace.mkdir(parents=True, exist_ok=True)
        (workspace / "evidence").mkdir(exist_ok=True)
        (workspace / "audit-results").mkdir(exist_ok=True)
        (workspace / "tokens").mkdir(exist_ok=True)
        (workspace / "logs").mkdir(exist_ok=True)
        (workspace / "context").mkdir(exist_ok=True)

    def describe(self) -> str:
        return "初始化工作区"


class EnvCheckStage(Stage):
    """环境检查 — 验证 ixit.json 存在，必要时从 fixture 复制"""

    async def execute(self, workspace, registry, pipeline):
        bus = pipeline.bus
        ixit_path = workspace / "ixit.json"

        if not ixit_path.exists():
            fixture = Path("tests/fixtures/mini_ixit.json")
            if fixture.exists():
                bus.write_json("ixit.json", json.loads(fixture.read_text(encoding="utf-8")))
                pipeline.telemetry.log_stage_event(
                    pipeline._state.pipeline_id if pipeline._state else "?",
                    "ENV_CHECK", "fixture_copied",
                    source=str(fixture),
                )
            else:
                raise FileNotFoundError(
                    "ixit.json 不存在且无 fixture。请将 ICS/IXIT 文档放入工作区。"
                )

    def describe(self) -> str:
        return "环境检查"


class IcsParseStage(Stage):
    """ICS/IXIT 解析 — 验证 ixit.json 结构"""

    async def execute(self, workspace, registry, pipeline):
        bus = pipeline.bus
        try:
            data = bus.read_json("ixit.json")
            assert "ics" in data, "ixit.json 缺少 'ics' 字段"
            assert "ixit_tables" in data, "ixit.json 缺少 'ixit_tables' 字段"
            ics_count = len(data["ics"])
            ixit_tables = list(data["ixit_tables"].keys())
            pipeline.telemetry.log_stage_event(
                pipeline._state.pipeline_id if pipeline._state else "?",
                "ICS_PARSE", "ok",
                ics_entries=ics_count,
                ixit_tables=len(ixit_tables),
            )
        except Exception as e:
            pipeline.telemetry.log_stage_failed(
                pipeline._state.pipeline_id if pipeline._state else "?",
                "ICS_PARSE", str(e),
            )
            raise

    def describe(self) -> str:
        return "ICS/IXIT 文档解析"


class M0Stage(Stage):
    """M0 ICS 逻辑验证 — 纯文档分析，无需 DUT 连接"""

    async def execute(self, workspace, registry, pipeline):
        bus = pipeline.bus
        ixit_data = bus.read_json("ixit.json")
        ics_list = ixit_data.get("ics", [])
        violations: List[str] = []

        def is_conditional_status(status: str) -> bool:
            # 本 XLSX 的 ICS 用 "M F (x)" 表示带条件的 functional
            # provision，并不总是写成 "M C(...)"。M0 只能做确定性的
            # support 形态检查，不能把条件性条款的 N/A 擅自判为 FAIL。
            return "C(" in status or bool(re.search(r"\bF\s*\(", status))

        for item in ics_list:
            status = item.get("status", "")
            support = item.get("support", "")
            ref = item.get("reference", "")[:40]

            # M 条款必须是 Y
            if "M" in status and not is_conditional_status(status) and support != "Y":
                violations.append(f"{ref}: M 条款 support={support} (应为 Y)")
            # C/F 条件条款: Y 或 N/A 的适用性由概念评估/L2 对照 IXIT 处理。
            # R 条款: 可 N

        m0_clauses = []
        for index, item in enumerate(ics_list):
            status = item.get("status", "")
            ref = item.get("reference", "")[:40]
            failed = any(ref in violation for violation in violations)
            expected = (
                "条件性条款的 ICS support 需与适用性理由一致，由概念评估/L2 复核"
                if is_conditional_status(status)
                else "非条件性 M 条款的 ICS support 应为 Y"
            )
            m0_clauses.append({
                "clause_id": f"M0_{index}",
                "provision_text": item.get("reference", ""),
                "ics_status": status,
                "ics_support": item.get("support", ""),
                "ics_detail": item.get("detail_justification", ""),
                "verdict": "FAIL" if failed else "PASS",
                "reason": item.get("detail_justification", ""),
                "expected_behavior": expected,
                "actual_behavior": f"ICS support={item.get('support', '')}",
            })

        evidence = EvidenceManifest(
            meta={"moduleId": "M0", "status": "pending_audit", "retryCount": 0},
            self_check={
                "total_expected": len(ics_list),
                "actual_in_json": len(ics_list),
                "missing_clauses": [],
                "fail_count": len(violations),
                "fail_clauses": [
                    {"clause_id": item["clause_id"], "has_expected_vs_actual": True}
                    for item in m0_clauses if item["verdict"] == "FAIL"
                ],
                "ics_na_clauses": [
                    item["clause_id"] for item in m0_clauses if item["ics_support"] == "N/A"
                ],
                "has_errors": bool(violations), "error_details": violations,
            },
            execution_trace=[{
                "phase": "preflight", "round_number": 1,
                "clause_ids": [item["clause_id"] for item in m0_clauses],
                "action": "ICS logic validation — M status vs Support cross-check for all ICS entries",
                "tool": "python",
                "outcome": f"{len(violations)} violations found" if violations else "all clear",
            }],
            clauses=m0_clauses,
        )

        bus.write_evidence("M0", evidence)

    def describe(self) -> str:
        return "M0 ICS 逻辑验证"


class M0ConceptStage(Stage):
    """Traffic 前的纯概念性测试：只读 IXIT，按 revision 定点重做。"""

    _RETRY_DIR = "rework/M0"

    @staticmethod
    def _manifest_hash(data: dict) -> str:
        payload = json.dumps(data, ensure_ascii=False, sort_keys=True).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    @staticmethod
    def _self_check(clauses) -> dict:
        fails = [clause for clause in clauses if clause.verdict == "FAIL"]
        uncertain = [clause.clause_id for clause in clauses if clause.verdict == "INCONCLUSIVE"]
        pending = [clause.clause_id for clause in clauses if clause.verdict == "PENDING_MANUAL"]
        ics_na = [clause.clause_id for clause in clauses if clause.ics_support == "N/A"]
        return {
            "total_expected": len(clauses),
            "actual_in_json": len(clauses),
            "missing_clauses": [],
            "uncertain_clauses": uncertain,
            "fail_count": len(fails),
            "fail_clauses": [{
                "clause_id": clause.clause_id,
                "has_expected_vs_actual": bool(clause.expected_behavior and clause.actual_behavior),
            } for clause in fails],
            "pending_manual": len(pending),
            "pending_manual_clauses": pending,
            "ics_na_clauses": ics_na,
            "has_errors": False,
            "error_details": [],
        }

    @staticmethod
    def _checkpoint_dir(workspace: Path) -> Path:
        return workspace / "evidence" / "checkpoints" / "M0" / "concepts"

    @staticmethod
    def _write_checkpoint(workspace: Path, clause, trace) -> None:
        """单条概念条款通过范围校验后，原子落盘为独立 checkpoint（含该条 trace）。"""
        path = M0ConceptStage._checkpoint_dir(workspace) / f"{clause.clause_id}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({
            "clause_id": clause.clause_id,
            "saved_at": datetime.now().isoformat(),
            "clause": clause.model_dump(mode="json"),
            "trace": [s.model_dump(mode="json") for s in trace],
        }, ensure_ascii=False, indent=2)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(payload, encoding="utf-8")
        tmp.replace(path)

    @staticmethod
    def _load_checkpoints(workspace: Path, catalog_by_id: dict):
        """校验并读取既有 checkpoint；返回 (clause_id->ClauseResult, clause_id->[ExecutionStep])。

        校验点：clauseId 一致、ClauseResult schema 合法、IXIT 引用非空、trace 非空。
        任一不满足则视为无效，该条会被当作缺失重跑，绝不把不完整输出当 PASS。
        """
        ckpt_dir = M0ConceptStage._checkpoint_dir(workspace)
        clauses: dict = {}
        traces: dict = {}
        if not ckpt_dir.is_dir():
            return clauses, traces
        for clause_id in catalog_by_id:
            path = ckpt_dir / f"{clause_id}.json"
            if not path.is_file():
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if data.get("clause_id") != clause_id:
                    continue
                clause = ClauseResult(**data["clause"])
                trace = [ExecutionStep(**s) for s in data.get("trace", [])]
                if clause.clause_id != clause_id:
                    continue
                if not clause.ixit_references:
                    continue
                if not trace:
                    continue
                clauses[clause_id] = clause
                traces[clause_id] = trace
            except Exception:
                continue
        return clauses, traces

    async def execute(self, workspace, registry, pipeline):
        bus = pipeline.bus
        telemetry = pipeline.telemetry
        pipeline_id = pipeline._state.pipeline_id if pipeline._state else "?"
        catalog = load_conceptual_catalog()
        catalog_by_id = {item.clause_id: item for item in catalog.clauses}
        evidence = bus.read_evidence("M0")
        retry_path = workspace / self._RETRY_DIR / "pending.json"
        retry_data = json.loads(retry_path.read_text(encoding="utf-8")) if retry_path.exists() else None

        # 复用有效 checkpoint：读证据后，用 checkpoint 补齐缺失/无效的概念条款。
        ckpt_clauses, ckpt_traces = self._load_checkpoints(workspace, catalog_by_id)
        existing = {item.clause_id: item for item in evidence.clauses}
        for clause_id, clause in ckpt_clauses.items():
            existing.setdefault(clause_id, clause)

        if retry_data:
            target_ids = retry_data["target_clause_ids"]
            retry_count = int(retry_data["retry_count"])
            rework_notes = retry_data.get("rework_notes", {})
        else:
            target_ids = [item.clause_id for item in catalog.clauses if item.clause_id not in existing]
            retry_count = int(evidence.meta.get("retryCount", 0))
            rework_notes = {}

        invalid = sorted(set(target_ids) - set(catalog_by_id))
        if invalid:
            raise ValueError(f"M0 概念重做包含非纯概念条款: {invalid}")

        traces = list(evidence.execution_trace)
        # 复用（不在重跑清单）的 checkpoint 其 trace 一并保留。
        for clause_id, ckpt_trace in ckpt_traces.items():
            if clause_id not in target_ids:
                traces.extend(ckpt_trace)

        for clause_id in target_ids:
            clause, clause_trace = await execute_conceptual_clause(
                catalog_by_id[clause_id], workspace, pipeline,
                rework_context=rework_notes.get(clause_id, ""),
            )
            old = existing.get(clause_id)
            if old is not None and retry_data:
                history = list(old.retry_history)
                history.append({
                    "retry_count": retry_count,
                    "reason": "L2 要求重新评估；已向 Agent 注入该条的可复核审计意见",
                    "previous_clause_hash": hashlib.sha256(
                        json.dumps(old.model_dump(mode="json"), ensure_ascii=False, sort_keys=True).encode("utf-8")
                    ).hexdigest(),
                })
                clause = clause.model_copy(update={"retry_history": history})
            existing[clause_id] = clause
            traces.extend(clause_trace)
            # 通过单条范围校验后，原子落 checkpoint（保留该条 trace）。
            self._write_checkpoint(workspace, clause, clause_trace)

        # 保留 M0 ICS evidence 的原有顺序，再按目录顺序追加/替换概念条款。
        ics_clauses = [item for item in evidence.clauses if item.clause_id not in catalog_by_id]
        concept_clauses = [existing[item.clause_id] for item in catalog.clauses if item.clause_id in existing]
        merged = EvidenceManifest(
            meta={
                **evidence.meta,
                "moduleId": "M0",
                "status": "pending_l1",
                "retryCount": retry_count,
                "conceptualClauseCount": len(concept_clauses),
                "conceptualCatalogVersion": catalog.version,
            },
            execution_trace=traces,
            clauses=ics_clauses + concept_clauses,
            self_check=self._self_check(ics_clauses + concept_clauses),
        )
        bus.write_evidence("M0", merged)

        if retry_data:
            retry_data["consumed_at"] = datetime.now().isoformat()
            bus.write_json(f"{self._RETRY_DIR}/round_{retry_count}.json", retry_data)
            retry_path.unlink(missing_ok=True)

        telemetry.log_stage_event(
            pipeline_id, "M0_CONCEPT", "concept_evidence_ready",
            module="M0", clause_count=len(concept_clauses), retry_count=retry_count,
            target_clauses=target_ids,
        )

    def describe(self) -> str:
        return "M0 纯概念性条款评估（IXIT 只读）"


class M0L1Stage(Stage):
    """M0 的确定性结构闸门；通过后才允许进入 L2 Auditor。"""

    async def execute(self, workspace, registry, pipeline):
        bus = pipeline.bus
        telemetry = pipeline.telemetry
        pipeline_id = pipeline._state.pipeline_id if pipeline._state else "?"
        result = await L1StructuralGate("evidence/pre-M0-evidence.json").check(workspace)
        l1_token = bus.token_dir / ".l1_M0_PASSED"
        evidence_token = bus.token_dir / ".evidence_M0_complete"
        if result.value == "pass":
            bus.touch_token(".l1_M0_PASSED")
            bus.touch_token(".evidence_M0_complete")
            telemetry.log_stage_event(pipeline_id, "M0_L1", "l1_pass", module="M0")
        else:
            l1_token.unlink(missing_ok=True)
            evidence_token.unlink(missing_ok=True)
            telemetry.log_stage_event(pipeline_id, "M0_L1", "l1_failed", module="M0")

    def describe(self) -> str:
        return "M0 概念 evidence L1 结构校验"


class M0AuditStage(Stage):
    """M0 审计：只有 ACCEPT 才获得 `.audit_M0_ACCEPTED`。

    62 条概念 evidence 会被按受限切片（每批最多 8 条）交给 L2；切片结果
    汇总成唯一的 M0 裁决。这样既保留每条的可追溯 recipe，又不会把全量
    M0 evidence 反复塞进一次模型调用。
    """

    @staticmethod
    def _build_batch_evidence(evidence, clauses, *, batch_index, batch_count, retry_count):
        clause_ids = {item.clause_id for item in clauses}
        results = [item for item in evidence.clauses if item.clause_id in clause_ids]
        traces = [step for step in evidence.execution_trace if clause_ids.intersection(step.clause_ids)]
        if not traces:
            traces = [ExecutionStep(
                seq=1, phase="preflight",
                summary="M0 conceptual audit slice prepared by orchestrator",
                clauseIds=sorted(clause_ids),
            )]
        return EvidenceManifest(
            meta={
                "moduleId": "M0", "scope": "conceptual_audit_batch",
                "batchIndex": batch_index, "batchCount": batch_count,
                "retryCount": retry_count,
                "conceptualCaseSource": [{
                    "clauseId": item.clause_id,
                    "sourceClauseId": item.source_clause_id,
                    "testCaseId": item.test_case_id,
                    "testPurpose": item.test_purpose,
                    "testUnits": item.test_units,
                    "passCriteria": item.pass_criteria,
                } for item in clauses],
            },
            executionTrace=traces,
            clauses=results,
            selfCheck=M0ConceptStage._self_check(results),
        )

    @staticmethod
    def _aggregate_batch_results(results, *, retry_count, expected_count):
        """ACCEPT 必须表示所有切片均有有效、可审计的 ACCEPT。"""
        verdicts = [item.verdict for item in results]
        if len(results) != expected_count or "FLAGGED" in verdicts:
            verdict = "FLAGGED"
        elif "REJECT" in verdicts:
            verdict = "REJECT"
        elif verdicts and all(item == "ACCEPT" for item in verdicts):
            verdict = "ACCEPT"
        else:
            verdict = "FLAGGED"

        findings = [finding for result in results for finding in result.findings]
        targets = []
        for result in results:
            if result.retry_instruction:
                for clause_id in result.retry_instruction.target_clause_ids:
                    if clause_id not in targets:
                        targets.append(clause_id)
        processed = len(results)
        if verdict == "ACCEPT":
            summary = f"M0 概念性 L2 审计通过：{processed}/{expected_count} 个受限切片均 ACCEPT。"
        elif verdict == "REJECT":
            summary = f"M0 概念性 L2 审计拒绝：{processed}/{expected_count} 个切片完成，需定点重做。"
        else:
            summary = f"M0 概念性 L2 审计待人工复核：仅 {processed}/{expected_count} 个切片有有效结果。"
        issues = [] if verdict != "FLAGGED" else ["一个或多个概念审计切片未返回有效 ACCEPT/REJECT 输出。"]
        return AuditResult(
            audit=AuditMeta(moduleId="M0", round=retry_count + 1, retryCount=retry_count,
                            verdict=verdict, summary=summary),
            findings=findings,
            retryInstruction=(RetryInstruction(
                targetClauseIds=targets,
                memo="仅重新评估列出的概念性条款；其他 M0 evidence 保持不变。",
            ) if verdict == "REJECT" and targets else None),
            harnessReport=HarnessReport(
                executionTraceComplete=not issues, totalRoundsOk=True,
                preflightStepsPresent=True, allClausesTraced=not issues,
                roundsWithinBudget=retry_count <= 2, issues=issues,
            ),
        )

    async def execute(self, workspace, registry, pipeline):
        runner = pipeline.runner
        bus = pipeline.bus
        telemetry = pipeline.telemetry
        pipe_def = pipeline.pipe_def
        pipeline_id = pipeline._state.pipeline_id if pipeline._state else "?"
        evidence_data = bus.read_json("evidence/pre-M0-evidence.json")
        evidence = EvidenceManifest(**evidence_data)
        retry_count = int(evidence_data.get("meta", {}).get("retryCount", 0))
        catalog = load_conceptual_catalog()
        present = {item.clause_id for item in evidence.clauses}
        missing = [item.clause_id for item in catalog.clauses if item.clause_id not in present]
        if missing:
            telemetry.log_stage_event(pipeline_id, "M0_AUDIT", "audit_input_incomplete",
                                      module="M0", missing_conceptual_clauses=missing)
            record_audit_outcome(bus, "M0", "ERROR")
            return

        batches = [catalog.clauses[index:index + catalog.audit_batch_size]
                   for index in range(0, len(catalog.clauses), catalog.audit_batch_size)]
        l2_gate = L2AuditGate("M0")
        results = []
        try:
            for index, batch in enumerate(batches, start=1):
                input_path = f"audit-inputs/M0/round-{retry_count + 1}/batch-{index:02d}.json"
                output_path = f"audit-results/batches/M0/round-{retry_count + 1}/batch-{index:02d}.json"
                bus.write_json(input_path, self._build_batch_evidence(
                    evidence, batch, batch_index=index, batch_count=len(batches),
                    retry_count=retry_count,
                ).model_dump(mode="json"))
                telemetry.log_stage_event(pipeline_id, "M0_AUDIT", "audit_batch_start", module="M0",
                                          batch_index=index, batch_count=len(batches),
                                          clause_ids=[item.clause_id for item in batch])
                result = await l2_gate.run_audit(
                    workspace, runner, pipe_def, evidence_path=input_path,
                    output_path=output_path, audit_label=f"batch_{index:02d}",
                )
                results.append(result)
                telemetry.log_stage_event(pipeline_id, "M0_AUDIT", "audit_batch_complete", module="M0",
                                          batch_index=index, verdict=result.verdict)
                # 无效结构化输出不能伪装成正常 REJECT；停止余下调用以保护额度。
                if result.verdict == "FLAGGED":
                    break
        except Exception as e:
            telemetry.log_stage_event(pipeline_id, "M0_AUDIT", "audit_error", module="M0", error=str(e))
            record_audit_outcome(bus, "M0", "ERROR")
            return

        audit_result = self._aggregate_batch_results(
            results, retry_count=retry_count, expected_count=len(batches),
        )
        verdict = audit_result.verdict
        telemetry.log_stage_event(pipeline_id, "M0_AUDIT", f"audit_{verdict.lower()}",
                                  module="M0", verdict=verdict, batches_processed=len(results),
                                  batch_count=len(batches))
        bus.write_audit_result("M0", audit_result)
        bus.write_json(f"audit-results/revisions/M0/round-{retry_count + 1}.json",
                       audit_result.model_dump(mode="json"))

        outcome = verdict if verdict in ("ACCEPT", "FLAGGED", "REJECT") else "ERROR"
        record_audit_outcome(bus, "M0", outcome)
        if verdict == "REJECT":
            allowed = {item.clause_id for item in catalog.clauses}
            instruction = audit_result.retry_instruction
            requested = instruction.target_clause_ids if instruction else []
            targets = [clause_id for clause_id in requested if clause_id in allowed]
            if targets and retry_count < catalog.retry_limit:
                previous_hash = M0ConceptStage._manifest_hash(evidence_data)
                bus.write_json(f"evidence/revisions/M0/revision-{retry_count}.json", evidence_data)
                bus.write_json("rework/M0/pending.json", {
                    "module_id": "M0", "retry_count": retry_count + 1,
                    "target_clause_ids": targets,
                    "audit_result_path": "audit-results/audit-result_M0.json",
                    "rework_notes": self._rework_notes(audit_result, targets),
                    "previous_manifest_hash": previous_hash,
                    "orchestrator_note": "重新评估指定概念条款并输出完整 EvidenceManifest。",
                    "created_at": datetime.now().isoformat(),
                })
                telemetry.log_stage_event(pipeline_id, "M0_AUDIT", "audit_reject_retry_prepared",
                                          module="M0", retry_count=retry_count + 1, target_clauses=targets)
                (bus.token_dir / ".l1_M0_PASSED").unlink(missing_ok=True)
                (bus.token_dir / ".evidence_M0_complete").unlink(missing_ok=True)
            else:
                adjudications = self._apply_supported_fail_adjudications(
                    evidence, audit_result, retry_count=retry_count + 1,
                )
                if adjudications:
                    evidence.self_check = type(evidence.self_check)(
                        **M0ConceptStage._self_check(evidence.clauses)
                    )
                    bus.write_evidence("M0", evidence)
                    # checkpoint 也必须反映最终裁决，否则下次续跑会把旧 Work
                    # 结论重新覆盖回来。
                    for clause in evidence.clauses:
                        if clause.clause_id in adjudications:
                            traces = [step for step in evidence.execution_trace
                                      if clause.clause_id in step.clause_ids]
                            M0ConceptStage._write_checkpoint(workspace, clause, traces)
                bus.write_json("audit-results/M0-needs-review.json", {
                    "module_id": "M0",
                    "verdict": "REJECT",
                    "retry_count": retry_count,
                    "target_clause_ids": targets,
                    "applied_adjudications": adjudications,
                    "unresolved_findings": [
                        finding.model_dump(mode="json", by_alias=True)
                        for finding in audit_result.findings
                        if finding.clause_id in targets
                    ],
                    "note": "重做预算已耗尽。仅应用具备明确建议和可复核证据路径的保守 FAIL 裁决；其余保持人工复核。",
                })
                telemetry.log_stage_event(pipeline_id, "M0_AUDIT", "audit_reject_not_retryable",
                                          module="M0", retry_count=retry_count, target_clauses=targets,
                                          applied_adjudications=sorted(adjudications))
                pipeline.request_needs_review(
                    PipelineState.M0_AUDIT,
                    "M0 L2 审计仍 REJECT，定点重做预算已耗尽；已输出 M0-needs-review.json，"
                    "不得继续进入功能性测试或重复空转。",
                )
        elif verdict == "FLAGGED":
            bus.write_json("audit-results/audit-result_M0_FLAGGED_note.json", {
                "module_id": "M0", "verdict": "FLAGGED",
                "note": "已标记为 FLAGGED，未发放 ACCEPTED，需人工审查",
                "audit_result": audit_result.model_dump(mode="json"),
            })

    def describe(self) -> str:
        return "M0 概念性 L2 审计（受限切片）"

    @staticmethod
    def _rework_notes(audit_result, targets: list[str]) -> dict[str, str]:
        """只注入与该条相关的审计事实，避免把其他条款的上下文污染重做。"""
        notes: dict[str, list[str]] = {clause_id: [] for clause_id in targets}
        for finding in audit_result.findings:
            if finding.clause_id not in notes:
                continue
            paths = ", ".join(finding.evidence_paths) or "（审计未给出结构化 evidencePaths）"
            notes[finding.clause_id].append(
                f"类别: {finding.category}\n问题: {finding.description}\n"
                f"修正建议: {finding.fix}\n建议裁决: {finding.recommended_verdict or '未指定'}\n"
                f"可复核路径: {paths}"
            )
        return {key: "\n\n".join(value) for key, value in notes.items() if value}

    @staticmethod
    def _apply_supported_fail_adjudications(evidence, audit_result, *, retry_count: int) -> dict[str, dict]:
        """仅把有直接、结构化依据的审计 FAIL 记为保守最终裁决。

        这不是用审计文本盲覆盖 Work Agent：每次应用均保留 work_verdict、证据
        路径和审计 finding，且必然标记 review_required。
        """
        clauses = {item.clause_id: item for item in evidence.clauses}
        applied: dict[str, dict] = {}
        for finding in audit_result.findings:
            if not (
                finding.category == "verdict_wrong"
                and finding.recommended_verdict == "FAIL"
                and finding.override_eligible
                and finding.evidence_paths
                and finding.clause_id in clauses
            ):
                continue
            current = clauses[finding.clause_id]
            if current.verdict not in ("PASS", "INCONCLUSIVE"):
                continue
            # FAIL 合约要求有 expected/actual；缺失时不能生成形式正确但不可用的假结果。
            if not current.expected_behavior or not current.actual_behavior:
                continue
            record = {
                "source": "L2_AUDIT",
                "retry_count": retry_count,
                "work_verdict": current.verdict,
                "recommended_verdict": "FAIL",
                "review_required": True,
                "evidence_paths": finding.evidence_paths,
                "finding": finding.description,
                "applied_at": datetime.now().isoformat(),
            }
            clauses[finding.clause_id] = current.model_copy(update={
                "verdict": "FAIL",
                "reason": current.reason + "\n\n[L2 审计保守裁决，需人工复核] " + finding.description,
                "warnings": list(dict.fromkeys([
                    *current.warnings,
                    "L2 审计与 Work 结论不一致；最终以有证据的 FAIL 保守标记，需人工复核。",
                ])),
                "adjudications": [*current.adjudications, record],
            })
            applied[finding.clause_id] = record
        evidence.clauses = [clauses.get(item.clause_id, item) for item in evidence.clauses]
        return applied


class TrafficCollectStage(Stage):
    """流量采集 — 交互式阶段。

    流程:
    1. 检测 tshark / xray 可用性
    2. 确定抓包网卡
    3. 启动 tshark 后台抓包 + xray 被动扫描
    4. 配置 Burp 上游代理 → xray
    5. 打开连续操作窗口，等待用户从头到尾完成全部操作
    6. 停止 tshark + xray
    7. 生成 Traffic Intelligence 主 Bundle
    8. 最佳努力生成迁移期 pcap_analysis 兼容输出
    """

    # 用户只控制连续窗口的开始和结束，不逐步标记或给流量打人工标签。
    async def execute(self, workspace, registry, pipeline):
        bus = pipeline.bus
        telemetry = pipeline.telemetry
        pipeline_id = pipeline._state.pipeline_id if pipeline._state else "?"
        control_mode = getattr(pipeline, "control_mode", "terminal") if pipeline else "terminal"

        # 从 ixit.json 读取 DUT IP
        dut_ip = self._get_dut_ip(workspace)
        checklist_version, checklist = load_traffic_checklist()
        traffic_state = TrafficStateStore(workspace)
        traffic_state.initialize(
            checklist_version=checklist_version,
            checklist=checklist,
            dut_ip=dut_ip,
            capture_pcap=workspace / "capture.pcap",
            control_mode=control_mode,
        )

        # 1. 工具可用性检测 (优先查 path-mapping.json, 再查 PATH)
        resolver = getattr(pipeline, 'path_resolver', None)
        if resolver:
            tshark_ok = resolver.check_tool("tshark")
            xray_ok = resolver.check_tool("xray")
        else:
            tshark_ok = self._check_tool("tshark")
            xray_ok = self._check_tool("xray")

        # 2. 固定本次 Pipeline 的工具解析结果。运行准备层可为一次 run 注入临时
        # PATH_MAPPING；后续启动、网卡枚举必须使用同一个 resolver，不能重新从
        # 环境构造 PathResolver，否则会意外回退到默认/历史映射。
        tshark_path = self._tool_path(resolver, "tshark")
        xray_path = self._tool_path(resolver, "xray")

        # 3. 确定网卡 + 启动采集
        capture_pcap = workspace / "capture.pcap"
        tshark_proc = None
        xray_proc = None
        outcome = "FAILED"
        outcome_reason = "Traffic 阶段未完成"
        receipt_context = {
            "workspace": str(workspace),
            "agent_id": "system_traffic_stage",
            "agent_type": "system",
            "module_id": "TRAFFIC",
            "phase_id": "3.1",
            "clause_ids": [],  # 流量窗口跨条款；不得擅自归属到某一子条款。
            "attempt": traffic_state.read().get("attempt_id"),
        }

        try:
            if not tshark_ok and not xray_ok:
                outcome = "BLOCKED"
                outcome_reason = "tshark 和 xray 均不可用，无法执行双通道流量采集"
                telemetry.log_stage_event(pipeline_id, "TRAFFIC", "tools_unavailable", reason=outcome_reason)
                self._print_skip_message()
                return

            mcp_mgr = getattr(pipeline, "mcp_manager", None)
            burp_mcp_ok = bool(mcp_mgr and getattr(mcp_mgr, "burp_connected", False))
            playwright_mcp_ok = bool(mcp_mgr and getattr(mcp_mgr, "playwright_connected", False))
            if not (burp_mcp_ok and playwright_mcp_ok):
                missing = []
                if not burp_mcp_ok:
                    missing.append("Burp MCP")
                if not playwright_mcp_ok:
                    missing.append("Playwright MCP")
                traffic_state.transition(
                    "CHANNELS_READY", "mcp_preflight_failed",
                    channels={
                        "tshark": {"status": "not_started"},
                        "xray": {"status": "not_started"},
                        "burp_mcp": {"status": "connected" if burp_mcp_ok else "unavailable"},
                        "playwright_mcp": {"status": "connected" if playwright_mcp_ok else "unavailable"},
                        "burp_upstream": {"status": "not_configured"},
                    },
                )
                outcome = "BLOCKED"
                outcome_reason = "MCP 前置连接未就绪：" + "、".join(missing)
                telemetry.log_stage_event(pipeline_id, "TRAFFIC", "mcp_preflight_failed", reason=outcome_reason)
                return

            if tshark_ok:
                # 控制台允许填写 URL，但网卡路由解析只接受主机/IP。
                capture_host = self._capture_host(dut_ip) if dut_ip else None
                iface = self._detect_interface(capture_host, tshark_path) if capture_host else None
                tshark_proc = await self._start_tshark(
                    capture_pcap, dut_ip, iface,
                    {**receipt_context, "artifact_refs": ["capture.pcap"]},
                    tshark_path=tshark_path,
                )
                if tshark_proc:
                    telemetry.log_stage_event(pipeline_id, "TRAFFIC", "tshark_started", capture=str(capture_pcap), dut_ip=dut_ip or "?")

            if xray_ok:
                xray_proc = await self._start_xray(
                    workspace, {**receipt_context, "artifact_refs": ["xray_run.log"]},
                    xray_path=xray_path,
                )
                if xray_proc:
                    telemetry.log_stage_event(pipeline_id, "TRAFFIC", "xray_started")
                    xray_listener_ready = await self._wait_for_tcp_listener("127.0.0.1", 7778, timeout=15)
                    if xray_listener_ready:
                        burp_upstream_ok = await self._configure_burp_upstream(
                            telemetry, pipeline_id, mcp_mgr, workspace / "burp_upstream_backup.json",
                        )
                    else:
                        burp_upstream_ok = False
                        telemetry.log_stage_event(
                            pipeline_id, "TRAFFIC", "xray_listener_not_ready",
                            reason="xray 未在 15 秒内监听 127.0.0.1:7778",
                        )
                else:
                    burp_upstream_ok = False
            else:
                burp_upstream_ok = False

            traffic_state.transition(
                "CHANNELS_READY", "channels_start_attempted",
                channels={
                    "tshark": {"status": "running" if tshark_proc else "unavailable"},
                    "xray": {"status": "running" if xray_proc else "unavailable"},
                    "burp_mcp": {"status": "connected"},
                    "playwright_mcp": {"status": "connected"},
                    "burp_upstream": {"status": "configured" if burp_upstream_ok else "not_configured"},
                },
            )
            if not tshark_proc or not xray_proc or not burp_upstream_ok:
                outcome = "BLOCKED"
                outcome_reason = "Traffic 链路未完整就绪（tshark、xray、Burp→xray 必须全部可用）"
                telemetry.log_stage_event(pipeline_id, "TRAFFIC", "channels_not_ready", reason=outcome_reason)
                return

            # 启动后核验两端进程仍存活。pcap 通常要等用户流量到来才会创建，
            # 因此不得在用户操作窗口前要求它存在，但也不能把“曾启动”当作“仍运行”。
            tshark_alive = bool(tshark_proc and tshark_proc.returncode is None)
            xray_alive = bool(xray_proc and xray_proc.returncode is None)
            if not (tshark_alive and xray_alive):
                dead = "、".join(name for name, alive in (("tshark", tshark_alive), ("xray", xray_alive)) if not alive)
                outcome = "BLOCKED"
                outcome_reason = f"{dead} 启动后进程已退出（网卡、权限或 xray 运行目录问题）；不打开操作窗口"
                telemetry.log_stage_event(
                    pipeline_id, "TRAFFIC", "channel_liveness_verify_failed",
                    reason=outcome_reason,
                )
                return
            telemetry.log_stage_event(
                pipeline_id, "TRAFFIC", "channels_liveness_verified",
            )
            self._print_operation_checklist(dut_ip, capture_pcap, True, True, checklist)
            (workspace / "traffic_collection_window.md").write_text(
                self._build_checklist_md(dut_ip, capture_pcap, True, True, checklist), encoding="utf-8",
            )

            if pipeline and getattr(pipeline, "non_interactive", False) and control_mode != "web":
                outcome = "SKIPPED"
                outcome_reason = "terminal 非交互运行未执行用户操作"
                TrafficCollectStage._safe_print("  [SKIP] Non-interactive mode -- auto-skipping user confirmation.")
            else:
                if control_mode == "web":
                    traffic_state.transition("WAITING_START", "waiting_for_user_start")
                else:
                    traffic_state.transition("COLLECTING", "terminal_operator_window_opened")
                completed = await self._wait_for_user_confirmation(workspace, control_mode, traffic_state)
                if completed is None:
                    outcome = "CANCELLED"
                    outcome_reason = "用户请求取消本次 Pipeline 运行"
                elif not completed:
                    outcome = "SKIPPED"
                    outcome_reason = "用户选择跳过流量分析"
                else:
                    traffic_state.transition("STOPPING", "user_finished_operation")
                    if xray_proc:
                        await self._stop_process(xray_proc, "xray", receipt_context)
                        xray_proc = None
                        telemetry.log_stage_event(pipeline_id, "TRAFFIC", "xray_stopped")
                    if tshark_proc:
                        await self._stop_process(tshark_proc, "tshark", receipt_context)
                        tshark_proc = None
                        telemetry.log_stage_event(pipeline_id, "TRAFFIC", "tshark_stopped")

                    if not capture_pcap.exists():
                        outcome = "BLOCKED"
                        outcome_reason = "capture.pcap 未生成，无法提供流量证据"
                    else:
                        pcap_size_kb = capture_pcap.stat().st_size / 1024
                        telemetry.log_stage_event(pipeline_id, "TRAFFIC", "pcap_verified", size_kb=round(pcap_size_kb, 1))
                        if pcap_size_kb < 1:
                            outcome = "BLOCKED"
                            outcome_reason = "capture.pcap < 1KB，可能没有有效用户操作流量"
                            telemetry.log_stage_event(pipeline_id, "TRAFFIC", "pcap_too_small", warning=outcome_reason)
                        else:
                            traffic_state.transition(
                                "ANALYZING",
                                "traffic_intelligence_started",
                                pcap_size_kb=round(pcap_size_kb, 1),
                            )
                            resolved_tools = {"tshark": tshark_path} if tshark_path else {}
                            if resolver:
                                try:
                                    easytshark_path = resolver.get_tool_path(
                                        "easytshark_analyzer"
                                    )
                                except AttributeError:
                                    easytshark_path = None
                            else:
                                easytshark_path = shutil.which("easytshark-analyzer")
                            if easytshark_path:
                                resolved_tools["easytshark_analyzer"] = easytshark_path
                            intelligence_ok = await self._run_traffic_intelligence(
                                workspace,
                                capture_pcap,
                                dut_ip,
                                {
                                    **receipt_context,
                                    "artifact_refs": ["traffic-intelligence"],
                                    "resolved_tools": resolved_tools,
                                },
                            )
                            if not intelligence_ok:
                                outcome = "FAILED"
                                outcome_reason = "Traffic Intelligence 执行失败"
                                telemetry.log_stage_event(
                                    pipeline_id,
                                    "TRAFFIC",
                                    "traffic_intelligence_failed",
                                    reason=outcome_reason,
                                )
                            else:
                                telemetry.log_stage_event(
                                    pipeline_id,
                                    "TRAFFIC",
                                    "traffic_intelligence_done",
                                    output=str(workspace / "traffic-intelligence"),
                                )

                                # 旧 pcap_analysis 仅保留为迁移期兼容产物。它不能再阻断
                                # Traffic Intelligence 主流程，也不能成为 Agent 首要入口。
                                pcap_output = workspace / "pcap_analysis"
                                legacy_analysis_ok = await self._run_pcap_analyzer(
                                    capture_pcap, pcap_output, dut_ip,
                                    {
                                        **receipt_context,
                                        "artifact_refs": ["pcap_analysis"],
                                        "resolved_tools": (
                                            {"tshark": tshark_path} if tshark_path else {}
                                        ),
                                    },
                                )
                                if legacy_analysis_ok:
                                    telemetry.log_stage_event(
                                        pipeline_id,
                                        "TRAFFIC",
                                        "pcap_analyzer_compat_done",
                                        output=str(pcap_output),
                                    )
                                    outcome_reason = (
                                        "双通道采集、Traffic Intelligence 分析与兼容输出完成"
                                    )
                                else:
                                    # 不留下可能被误认为完整结果的空目录或半成品。
                                    if pcap_output.is_dir():
                                        shutil.rmtree(pcap_output, ignore_errors=True)
                                    telemetry.log_stage_event(
                                        pipeline_id,
                                        "TRAFFIC",
                                        "pcap_analyzer_compat_failed",
                                        reason="迁移期兼容输出失败；不影响主 Bundle",
                                    )
                                    outcome_reason = (
                                        "双通道采集与 Traffic Intelligence 分析完成；"
                                        "迁移期 pcap_analysis 兼容输出不可用"
                                    )
                                outcome = "COMPLETE"
        except Exception as exc:
            outcome = "FAILED"
            outcome_reason = f"Traffic 阶段异常: {type(exc).__name__}: {exc}"
            telemetry.log_stage_event(pipeline_id, "TRAFFIC", "failed", reason=outcome_reason)
        finally:
            traffic_state.transition("STOPPING", "cleanup_started")
            if xray_proc:
                await self._stop_process(xray_proc, "xray", receipt_context)
                telemetry.log_stage_event(pipeline_id, "TRAFFIC", "xray_stopped")
            if tshark_proc:
                await self._stop_process(tshark_proc, "tshark", receipt_context)
                telemetry.log_stage_event(pipeline_id, "TRAFFIC", "tshark_stopped")
            traffic_state.transition("RESTORING_PROXY", "burp_restore_started")
            mcp_mgr = getattr(pipeline, "mcp_manager", None)
            await self._remove_burp_upstream(
                telemetry, pipeline_id, mcp_mgr, workspace / "burp_upstream_backup.json",
            )
            terminal_fields = (
                {"completed_reason": outcome_reason}
                if outcome == "COMPLETE"
                else {"review_reason": outcome_reason}
            )
            traffic_state.transition(outcome, "traffic_finished", **terminal_fields)
            if outcome not in {"COMPLETE", "CANCELLED"}:
                reason = f"Traffic {outcome}: {outcome_reason}"
                # Traffic 是功能性执行的证据前置条件，不是一个可以静默跳过的
                # "提示"阶段。以前这里只标记 review_required，通用状态机随后仍会
                # 将 traffic 记为 passed 并推进 M1–M5，形成未取证的降级运行。
                # 对实际 Pipeline 显式收敛为 needs_review；run() 会识别状态改变，
                # 不再进入通用 transition。保留旧测试/独立调用的兼容回退。
                if hasattr(pipeline, "request_needs_review"):
                    pipeline.request_needs_review(PipelineState.TRAFFIC_COLLECT, reason)
                else:
                    self._mark_review(pipeline, reason)

        telemetry.log_stage_event(
            pipeline_id, "TRAFFIC", "complete",
            outcome=outcome, tshark=tshark_ok, xray=xray_ok, dut_ip=dut_ip or "unknown",
        )

    def describe(self) -> str:
        return "流量采集 (tshark + xray)"

    # ===== 内部方法 =====

    @staticmethod
    def _get_dut_ip(workspace: Path) -> str | None:
        """读取 DUT IP：运行时覆盖优先，且绝不修改原始 IXIT。"""
        run_config = workspace / "run_config.json"
        if run_config.exists():
            try:
                configured = json.loads(run_config.read_text(encoding="utf-8")).get("dut_ip")
                if configured:
                    return str(configured)
            except (json.JSONDecodeError, OSError):
                pass

        # 向后兼容旧 workspace：运行时覆盖缺失时再读取 IXIT 声明。
        ixit_path = workspace / "ixit.json"
        if not ixit_path.exists():
            return None
        try:
            data = json.loads(ixit_path.read_text(encoding="utf-8"))
            # 新 schema: meta.dut_identification 为 {section: {field: value}}，防御性搜索 IP 字段
            dut_id = data.get("meta", {}).get("dut_identification", {})
            if isinstance(dut_id, dict):
                for fields in dut_id.values():
                    if isinstance(fields, dict):
                        for field, value in fields.items():
                            if "ip" in str(field).lower() and value:
                                return str(value)
            return data.get("dutIp")
        except (json.JSONDecodeError, KeyError):
            return None

    @staticmethod
    def _check_tool(name: str) -> bool:
        """检查工具是否在 PATH 中可用"""
        return shutil.which(name) is not None

    @staticmethod
    def _tool_path(resolver, name: str) -> str:
        """获取已冻结 resolver 的工具路径；仅无 resolver 时回退当前 PATH。"""
        if resolver:
            try:
                mapped = resolver.get_tool_path(name)
                if mapped:
                    return mapped
            except AttributeError:
                # 兼容只提供 check_tool 的旧测试/调用方。
                pass
        return shutil.which(name) or shutil.which(f"{name}.exe") or name

    @staticmethod
    def _tshark_binary() -> str:
        """兼容独立调用：从当前环境 resolver 解析 tshark。"""
        try:
            from framework.path_resolver import PathResolver
            return TrafficCollectStage._tool_path(PathResolver(), "tshark")
        except Exception:
            return TrafficCollectStage._tool_path(None, "tshark")

    @staticmethod
    def _local_route_ip(dut_ip: str) -> str | None:
        """到达 DUT 的本机出口 IP。UDP connect 只选路由不发包，断网/DUT 不在线也能得到。"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect((dut_ip, 9))
                return s.getsockname()[0]
            finally:
                s.close()
        except OSError:
            return None

    @staticmethod
    def _detect_interface(dut_ip: str, tshark_path: str | None = None) -> str | None:
        """自动检测到达 DUT 的抓包网卡，返回 tshark -i 可用的接口名。

        Windows 之前解析 route print 的最后一列，实际是跃点数而非网卡，
        且 tshark 需要的是 \\Device\\NPF_{...} 设备名。现在三步走：
        出口 IP → 网卡别名（Get-NetIPAddress）→ tshark -D 中匹配别名的设备名。
        """
        # 手动指定优先（如 TSHARK_IFACE=5 或 TSHARK_IFACE=\Device\NPF_{...}）
        override = os.environ.get("TSHARK_IFACE")
        if override:
            return override

        if os.name != "nt":
            # Linux: ip route get 输出 "... dev <name> ..."，dev 名可直接用于 tshark -i
            try:
                result = subprocess.run(
                    ["ip", "route", "get", dut_ip],
                    capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10,
                )
                tokens = result.stdout.split()
                for i, tok in enumerate(tokens):
                    if tok == "dev" and i + 1 < len(tokens):
                        return tokens[i + 1]
            except Exception:
                return None
            return None

        local_ip = TrafficCollectStage._local_route_ip(dut_ip)
        if not local_ip:
            return None
        try:
            ps = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-NetIPAddress -AddressFamily IPv4 | "
                 f"Where-Object {{$_.IPAddress -eq '{local_ip}'}} | "
                "Select-Object -First 1).InterfaceAlias"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15,
            )
            alias = (ps.stdout or "").strip()
        except Exception:
            alias = ""
        if not alias:
            return None

        # tshark -D 行形如 "5. \Device\NPF_{...} (WLAN)"；括号里就是 InterfaceAlias
        try:
            listing = subprocess.run(
                [tshark_path or TrafficCollectStage._tshark_binary(), "-D"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15,
            )
            for line in listing.stdout.splitlines():
                m = re.match(r"^\s*\d+\.\s+(\S+)\s+\((.+)\)\s*$", line)
                if m and m.group(2).strip() == alias:
                    return m.group(1)
        except Exception:
            return None
        return None

    @staticmethod
    async def _start_tshark(
        capture_pcap: Path, dut_ip: str | None, iface: str | None,
        receipt_context: dict | None = None,
        tshark_path: str | None = None,
    ) -> asyncio.subprocess.Process | None:
        """启动 tshark 后台抓包"""
        tshark_path = tshark_path or TrafficCollectStage._tshark_binary()

        cmd = [tshark_path]
        if iface:
            cmd.extend(["-i", iface])
        if dut_ip:
            # BPF 的 host 只接受主机名/IP。Web 控制台传入的 DUT 值可以是
            # http(s) URL；直接拼入会令 tshark 因非法过滤器立即退出。
            capture_host = TrafficCollectStage._capture_host(dut_ip)
            if capture_host:
                cmd.extend(["-f", f"host {capture_host}"])
        cmd.extend(["-w", str(capture_pcap)])

        started_at = datetime.now()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            from framework.tool_receipts import record_tool_receipt
            record_tool_receipt(receipt_context, "tshark", {"operation": "start", "argv": cmd}, f"pid={proc.pid}", False, started_at, datetime.now())
            return proc
        except Exception as e:
            from framework.tool_receipts import record_tool_receipt
            record_tool_receipt(receipt_context, "tshark", {"operation": "start", "argv": cmd}, str(e), True, started_at, datetime.now())
            TrafficCollectStage._safe_print(f"  [WARN] Failed to start tshark: {e}")
            return None

    @staticmethod
    def _capture_host(dut_ip: str) -> str | None:
        """将控制台的 DUT 地址规整为可供 tshark BPF 使用的 host 值。"""
        value = str(dut_ip or "").strip()
        if not value:
            return None
        parsed = urlsplit(value if "://" in value else f"//{value}")
        return parsed.hostname

    @staticmethod
    async def _wait_for_tcp_listener(host: str, port: int, timeout: float) -> bool:
        """轮询本地监听端口；只在真正可接受连接后才开放操作窗口。"""
        deadline = asyncio.get_running_loop().time() + timeout
        while asyncio.get_running_loop().time() < deadline:
            try:
                with socket.create_connection((host, port), timeout=0.3):
                    return True
            except OSError:
                await asyncio.sleep(0.25)
        return False

    @staticmethod
    async def _start_xray(
        workspace: Path, receipt_context: dict | None = None, xray_path: str | None = None,
    ) -> asyncio.subprocess.Process | None:
        """启动 xray 被动扫描"""
        xray_path = xray_path or shutil.which("xray") or shutil.which("xray_windows_amd64") or "xray"

        xray_log = workspace / "xray_run.log"

        cmd = [
            xray_path, "webscan",
            "--listen", "127.0.0.1:7778",
            "--html-output", str(workspace / "xray_report.html"),
        ]
        started_at = datetime.now()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(Path(xray_path).resolve().parent),
            )
            from framework.tool_receipts import record_tool_receipt
            record_tool_receipt(receipt_context, "xray", {"operation": "start", "argv": cmd}, f"pid={proc.pid}", False, started_at, datetime.now())
            return proc
        except Exception as e:
            from framework.tool_receipts import record_tool_receipt
            record_tool_receipt(receipt_context, "xray", {"operation": "start", "argv": cmd}, str(e), True, started_at, datetime.now())
            TrafficCollectStage._safe_print(f"  [WARN] Failed to start xray: {e}")
            return None

    @staticmethod
    async def _configure_burp_upstream(
        telemetry, pipeline_id: str, mcp_manager=None, backup_path: Optional[Path] = None,
    ) -> bool:
        """配置 Burp 上游代理 → xray:7778。

        ⚠️ 扩展 2.0.1 的 config_upstream_proxy_set 是 no-op（实测）：它导入的是顶层
        `upstream_proxy` 键，而 Burp 真实路径是 `project_options.connections.upstream_proxy.servers`，
        importProjectOptionsFromJson 按精确键合并 → 顶层键无对应 → 静默丢弃，servers 恒为 []。
        因此改用 burp_import_project_config 走正确路径。配置前先导出当前上游配置备份到
        backup_path，供 _remove_burp_upstream 恢复。MCP 不可用或配置失败时返回 False，
        调用方不得打开操作窗口。
        """
        # xray 上游条目 (destination_host='*' = 全部流量过 xray；'.*' 是 glob 不匹配任何主机)
        xray_servers = [{
            "proxy_host": "127.0.0.1",
            "proxy_port": 7778,
            "proxy_type": "HTTP",
            "destination_host": "*",
            "enabled": True,
        }]

        def _upstream_config(servers: list) -> str:
            return json.dumps({
                "project_options": {
                    "connections": {
                        "upstream_proxy": {"servers": servers},
                    },
                },
            })

        # 优先: MCP SDK
        if mcp_manager and mcp_manager.burp_connected:
            try:
                # 1) 备份当前上游配置
                orig_raw = await mcp_manager.call_tool(
                    "burp_export_project_config",
                    {"paths": ["project_options.connections.upstream_proxy"]},
                )
                if backup_path is not None:
                    backup_path.parent.mkdir(parents=True, exist_ok=True)
                    backup_path.write_text(orig_raw, encoding="utf-8")
                # 2) 用正确路径导入 xray 上游
                await mcp_manager.call_tool(
                    "burp_import_project_config",
                    {"config_json": _upstream_config(xray_servers)},
                )
                telemetry.log_stage_event(
                    pipeline_id, "TRAFFIC", "burp_upstream_configured",
                    target="127.0.0.1:7778", method="mcp_sdk",
                )
                return True
            except Exception as e:
                telemetry.log_stage_event(
                    pipeline_id, "TRAFFIC", "burp_upstream_mcp_failed",
                    reason=str(e),
                )
                # fall through to raw HTTP

        telemetry.log_stage_event(
            pipeline_id, "TRAFFIC", "burp_upstream_failed",
            reason="Burp MCP 未连接或配置调用失败",
        )
        return False

    @staticmethod
    async def _remove_burp_upstream(
        telemetry, pipeline_id: str, mcp_manager=None, backup_path: Optional[Path] = None,
    ) -> None:
        """恢复 Burp 上游代理配置（移除 xray 上游）。

        优先恢复 _configure_burp_upstream 备份的原配置 (backup_path)；
        无备份则清空 servers。同样走正确路径，恢复失败不影响管线。
        """
        restore_servers: list = []

        # 优先: 读取备份的原上游配置
        if backup_path is not None and backup_path.exists():
            try:
                backup = json.loads(backup_path.read_text(encoding="utf-8"))
                stored = (
                    backup.get("project_options", {})
                    .get("connections", {})
                    .get("upstream_proxy", {})
                )
                if isinstance(stored.get("servers"), list):
                    restore_servers = stored["servers"]
            except Exception:
                pass

        config_json = json.dumps({
            "project_options": {
                "connections": {
                    "upstream_proxy": {"servers": restore_servers},
                },
            },
        })

        # 优先: MCP SDK
        if mcp_manager and mcp_manager.burp_connected:
            try:
                await mcp_manager.call_tool(
                    "burp_import_project_config", {"config_json": config_json},
                )
                telemetry.log_stage_event(
                    pipeline_id, "TRAFFIC", "burp_upstream_removed",
                    method="mcp_sdk",
                )
                return
            except Exception:
                pass  # fall through to raw HTTP

        # 回退: 原始 HTTP
        import urllib.request
        burp_host = os.environ.get("BURP_MCP_HOST", "127.0.0.1")
        burp_port = os.environ.get("BURP_MCP_PORT", "9877")

        try:
            url = f"http://{burp_host}:{burp_port}/tools/call"
            payload = json.dumps({
                "name": "burp_import_project_config",
                "arguments": {"config_json": config_json},
            }).encode("utf-8")
            req = urllib.request.Request(
                url, data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                telemetry.log_stage_event(
                    pipeline_id, "TRAFFIC", "burp_upstream_removed",
                    method="http_fallback",
                )
        except Exception:
            pass  # 上游代理恢复失败不影响管线

    @staticmethod
    async def _stop_process(
        proc: asyncio.subprocess.Process, name: str, receipt_context: dict | None = None,
    ) -> None:
        """优雅停止子进程"""
        started_at = datetime.now()
        error = None
        try:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=10)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
        except Exception as exc:
            error = str(exc)
        from framework.tool_receipts import record_tool_receipt
        record_tool_receipt(
            receipt_context, name, {"operation": "stop", "pid": proc.pid},
            error or "process stopped", error is not None, started_at, datetime.now(),
        )

    @staticmethod
    async def _run_pcap_analyzer(
        capture_pcap: Path, output_dir: Path, dut_ip: str | None,
        receipt_context: dict | None = None,
    ) -> bool | None:
        """运行 pcap_analyzer.py 批量分析，并返回真实执行结果。"""
        started_at = datetime.now()
        cmd: list[str] = []
        try:
            cmd = [
                sys.executable, "scripts/pcap_analyzer.py",
                str(capture_pcap),
                "--out-dir", str(output_dir),
            ]
            if dut_ip:
                cmd.extend(["--dut-ip", dut_ip])

            # 仅对这个分析子进程临时继承本次 run 的工具解析结果；不修改
            # 系统 PATH、也不写回 PATH_MAPPING。
            child_env = os.environ.copy()
            resolved_tools = (receipt_context or {}).get("resolved_tools", {})
            tshark_path = resolved_tools.get("tshark")
            if tshark_path:
                child_env["TSHARK_PATH"] = str(tshark_path)

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=child_env,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
            success = proc.returncode == 0
            from framework.tool_receipts import record_tool_receipt
            output = stdout.decode("utf-8", errors="replace") + "\n[stderr]\n" + stderr.decode("utf-8", errors="replace")
            record_tool_receipt(receipt_context, "pcap_analyzer", {"operation": "run", "argv": cmd}, output, not success, started_at, datetime.now())
            return success
        except asyncio.TimeoutError:
            from framework.tool_receipts import record_tool_receipt
            record_tool_receipt(receipt_context, "pcap_analyzer", {"operation": "run", "argv": cmd}, "timeout after 300s", True, started_at, datetime.now())
            return False
        except Exception as exc:
            from framework.tool_receipts import record_tool_receipt
            record_tool_receipt(receipt_context, "pcap_analyzer", {"operation": "run", "argv": cmd}, str(exc), True, started_at, datetime.now())
            return False

    @staticmethod
    async def _run_traffic_intelligence(
        workspace: Path,
        capture_pcap: Path,
        dut_ip: str | None,
        receipt_context: dict | None = None,
    ) -> bool:
        """生成统一 Traffic Intelligence Bundle，并记录阶段级收据。"""
        from dataclasses import replace

        from framework.tool_receipts import record_tool_receipt
        from framework.traffic_intelligence.pipeline import (
            TrafficIntelligencePipeline,
            TrafficIntelligenceSettings,
        )

        started_at = datetime.now()
        resolved_tools = (receipt_context or {}).get("resolved_tools", {})
        tshark_path = str(resolved_tools.get("tshark") or "tshark")
        settings = TrafficIntelligenceSettings.from_environment()
        easytshark_path = resolved_tools.get("easytshark_analyzer")
        if easytshark_path and not settings.easytshark_path:
            settings = replace(settings, easytshark_path=str(easytshark_path))
        capture_host = TrafficCollectStage._capture_host(dut_ip) if dut_ip else None
        params = {
            "operation": "analyze",
            "capture": str(capture_pcap),
            "requested_backend": settings.backend,
            "payload_policy": settings.payload_policy,
        }
        try:
            result = await asyncio.to_thread(
                TrafficIntelligencePipeline(settings).run,
                workspace,
                capture_path=capture_pcap,
                dut_addresses=[capture_host] if capture_host else [],
                tshark_path=tshark_path,
            )
            summary = json.dumps({
                "status": "complete",
                "backend": result.manifest.analysis_backend,
                "fallback_reason": result.manifest.fallback_reason,
                "frame_count": result.frame_count,
                "flow_count": result.flow_count,
                "capture_sha256": result.manifest.capture_sha256,
            }, ensure_ascii=False)
            record_tool_receipt(
                receipt_context,
                "traffic_intelligence",
                params,
                summary,
                False,
                started_at,
                datetime.now(),
            )
            return True
        except Exception as exc:
            record_tool_receipt(
                receipt_context,
                "traffic_intelligence",
                params,
                f"{type(exc).__name__}: {exc}",
                True,
                started_at,
                datetime.now(),
            )
            return False

    @classmethod
    def _print_operation_checklist(
        cls, dut_ip: str | None, capture_pcap: Path, tshark_ok: bool, xray_ok: bool,
        checklist: list[dict],
    ) -> None:
        """打印连续操作窗口说明，不要求逐项确认或打标签。"""
        cls._safe_print()
        cls._safe_print("=" * 60)
        cls._safe_print("  [Traffic Capture] Please operate the DUT to generate traffic")
        cls._safe_print("=" * 60)
        if dut_ip:
            cls._safe_print(f"  DUT IP: {dut_ip}")
        cls._safe_print(f"  PCAP:   {capture_pcap}")
        cls._safe_print(f"  tshark: {'[RUNNING]' if tshark_ok else '[UNAVAILABLE]'}")
        cls._safe_print(f"  xray:   {'[RUNNING] (127.0.0.1:7778)' if xray_ok else '[UNAVAILABLE]'}")
        cls._safe_print()
        cls._safe_print("  Operate the DUT continuously from start to finish via Burp proxy")
        cls._safe_print("  (127.0.0.1:8080). No per-step labels or confirmations are required.")
        cls._safe_print()
        cls._safe_print("  " + "=" * 50)
        cls._safe_print("  When done, type 'done' and press Enter.")
        cls._safe_print("  Type 'skip' to stop capture and skip pcap analysis.")
        cls._safe_print("  " + "=" * 50)
        cls._safe_print()

    @staticmethod
    def _build_checklist_md(
        dut_ip: str | None, capture_pcap: Path, tshark_ok: bool, xray_ok: bool,
        checklist: list[dict],
    ) -> str:
        """生成操作指引 Markdown（写入工作区，供审计追溯）"""
        lines = [
            "# 流量采集操作指引",
            "",
            f"- DUT IP: {dut_ip or '未知'}",
            f"- PCAP 路径: {capture_pcap}",
            f"- tshark: {'运行中' if tshark_ok else '不可用'}",
            f"- xray: {'运行中 (127.0.0.1:7778)' if xray_ok else '不可用'}",
            "",
            "## 连续操作窗口",
            "",
            "从开始到结束连续完成本次需要的全部设备操作；中途不分步骤、不打标签、",
            "不逐项确认。完成全部操作后只需点击一次“完成采集”。",
        ]
        lines.append("")
        lines.append("## Burp 代理配置")
        lines.append("")
        lines.append("- 浏览器 → Burp:8080 → xray:7778 → DUT")
        lines.append("- 确保登录请求经过 Burp 代理，proxy_history 中有完整的认证流量")
        return "\n".join(lines)

    @staticmethod
    async def _wait_for_user_confirmation(
        workspace: Path | None = None,
        control_mode: str = "terminal",
        traffic_state: TrafficStateStore | None = None,
    ) -> bool:
        """等待用户确认「流量采集完成」。

        control_mode:
          - "terminal": 终端 input() 等待（默认，CLI 兼容）
          - "web": 先等待 tokens/traffic_user_start，再等待 done|skip；令牌只负责
            唤醒独立进程，真实状态由 traffic_state.json 记录。
        """
        if control_mode == "web":
            token_dir = (workspace or Path(".")) / "tokens"
            token_dir.mkdir(parents=True, exist_ok=True)
            # 清残留控制信号，避免上一次运行的信号误触发
            for name in ("traffic_user_start", "traffic_user_done", "traffic_user_skip"):
                (token_dir / name).unlink(missing_ok=True)
            TrafficCollectStage._safe_print(
                "  [WEB] Waiting for frontend start "
                "(tokens/traffic_user_start) ..."
            )
            started = False
            while True:
                if (token_dir / ".cancel_requested").exists():
                    TrafficCollectStage._safe_print("  [CANCELLED] Frontend requested pipeline cancellation.\n")
                    return None
                if (token_dir / "traffic_user_skip").exists():
                    TrafficCollectStage._safe_print("  [SKIP] Frontend chose to skip - stopping capture.\n")
                    return False
                if not started and (token_dir / "traffic_user_start").exists():
                    started = True
                    # start 前出现的 done 是无效顺序信号；只接受正式操作窗口内的完成动作。
                    (token_dir / "traffic_user_done").unlink(missing_ok=True)
                    if traffic_state:
                        traffic_state.transition("COLLECTING", "user_started_operation")
                        traffic_state.transition("WAITING_FINISH", "waiting_for_user_finish")
                    TrafficCollectStage._safe_print(
                        "  [OK] Frontend started operator window; waiting for finish.\n"
                    )
                if started and (token_dir / "traffic_user_done").exists():
                    TrafficCollectStage._safe_print(
                        "  [OK] Frontend confirmed - stopping capture, entering analysis phase.\n"
                    )
                    return True
                await asyncio.sleep(1)

        # terminal 模式 — 原有 input() 逻辑
        import concurrent.futures
        loop = asyncio.get_event_loop()

        while True:
            try:
                if workspace and (workspace / "tokens" / ".cancel_requested").exists():
                    TrafficCollectStage._safe_print("\n  [CANCELLED] Cancellation requested.")
                    return None
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    user_input = await loop.run_in_executor(
                        pool,
                        lambda: input("  >>> ").strip(),
                    )
            except (EOFError, KeyboardInterrupt):
                TrafficCollectStage._safe_print("\n  [WARN] Input interrupted, skipping traffic capture by default.")
                return False

            if user_input in ("完成", "done", "ok", "y", "yes"):
                if traffic_state:
                    traffic_state.transition("WAITING_FINISH", "terminal_user_finished_operation")
                TrafficCollectStage._safe_print("  [OK] User confirmed - stopping capture, entering analysis phase.\n")
                return True
            elif user_input in ("跳过", "skip", "n", "no"):
                TrafficCollectStage._safe_print("  [SKIP] User chose to skip - stopping capture.\n")
                return False
            else:
                TrafficCollectStage._safe_print(f"  Unrecognized input: '{user_input}'. Type 'done' or 'skip'.")

    @staticmethod
    def _mark_review(pipeline, reason: str) -> None:
        """Traffic 未完整取证时保留部分报告，但绝不伪装为正式通过。"""
        state = getattr(pipeline, "_state", None)
        if state is None:
            return
        state.review_required = True
        if reason not in state.review_reasons:
            state.review_reasons.append(reason)
        pipeline._save_state()

    @staticmethod
    def _print_skip_message() -> None:
        """工具不可用时的跳过提示"""
        TrafficCollectStage._safe_print()
        TrafficCollectStage._safe_print("=" * 60)
        TrafficCollectStage._safe_print("  [Traffic Capture] - SKIPPED")
        TrafficCollectStage._safe_print("=" * 60)
        TrafficCollectStage._safe_print("  tshark and xray are unavailable.")
        TrafficCollectStage._safe_print("  Install Wireshark (tshark) or xray to enable traffic capture.")
        TrafficCollectStage._safe_print("  Pipeline will proceed to M1-M5 detection phase.")
        TrafficCollectStage._safe_print("=" * 60)
        TrafficCollectStage._safe_print()

    @staticmethod
    def _safe_print(*args, **kwargs):
        """Windows-safe print — suppresses UnicodeEncodeError from emoji on GBK terminals."""
        try:
            print(*args, **kwargs)
        except UnicodeEncodeError:
            # Fallback: strip non-ASCII characters
            ascii_args = []
            for a in args:
                if isinstance(a, str):
                    ascii_args.append(a.encode("ascii", errors="replace").decode("ascii"))
                else:
                    ascii_args.append(a)
            try:
                print(*ascii_args, **kwargs)
            except Exception:
                pass  # Last resort: silent


class M1M5ParallelStage(Stage):
    """M1-M5 Work Agent 调度 + 触发式 Round-1 审计。

    设计变更 (2026-08-07):
    - 每个模块 Work Agent 完成 → L1 闸门 → 立即触发 Round-1 审计
    - 审计 REJECT → 构建 retry task → 新 Work Agent (不知审计) → 重新审计
    - 审计 FLAGGED → 写 REVIEW_REQUIRED，进入部分报告/人工裁定路径
    - 全部 round-1 ACCEPT → 发令牌，管线进入 Round-2 跨模块审计

    依赖处理: 拓扑分批保证 M2 在 M3 之前完成；M3 的 task_ctx.inputs
    包含 M2 的 evidence 文件（通过 upstream_inputs 声明）。
    """

    # 最大重试次数
    MAX_WORK_RETRIES = 2       # Work Agent 失败重试
    MAX_AUDIT_RETRIES = 2      # 审计 REJECT → 重新检测的循环次数

    async def execute(self, workspace, registry, pipeline):
        runner = pipeline.runner
        bus = pipeline.bus
        telemetry = pipeline.telemetry
        pipe_def = pipeline.pipe_def
        pipeline_id = pipeline._state.pipeline_id if pipeline._state else "?"

        # ── 初始化 ContextPool + PhaseEngine ──
        from framework.context_pool import ContextPool
        from framework.phase_engine import PhaseExecutionEngine

        pool = ContextPool(workspace)
        engine = PhaseExecutionEngine(
            workspace, pool, runner, bus, telemetry, pipe_def,
        )

        # 加载 phase_definitions.json (如果存在)
        config_path = Path(__file__).resolve().parent.parent.parent / "framework" / "phase_definitions.json"
        if config_path.exists():
            engine.load_definitions(config_path)
            telemetry.log_stage_event(
                pipeline_id, "M1_M5", "phase_engine_loaded",
                config=str(config_path),
                modules_with_phases=str([m for m in engine._modules.keys()]),
            )

        # 存储到实例, 供 _run_module_with_audit 使用
        self._phase_engine = engine
        self._context_pool = pool

        # 只取 M1-M5，排除 M0
        selected = getattr(getattr(pipeline, "run_plan", None), "selected_modules", None)
        modules = [m for m in pipe_def.modules if m.id in ("M1", "M2", "M3", "M4", "M5")
                   and (not selected or m.id in selected)]

        # 按依赖关系拓扑分批
        batches = self._topological_batches(modules)
        telemetry.log_stage_event(
            pipeline_id, "M1_M5", "batches",
            batches=str([[m.id for m in b] for b in batches]),
        )

        for batch_idx, batch in enumerate(batches):
            telemetry.log_stage_event(
                pipeline_id, "M1_M5", f"batch_{batch_idx + 1}_start",
                modules=str([m.id for m in batch]),
            )

            # 同一拓扑批次没有模块级依赖：Work → L1 → Round-1 audit
            # 可以并发；批次之间仍由外层循环严格保持依赖顺序。
            async def run_module(module) -> None:
                try:
                    await self._run_module_with_audit(
                        module, workspace, pipeline, pipe_def,
                    )
                except Exception as e:
                    telemetry.log_stage_event(
                        pipeline_id, "M1_M5", "module_failed",
                        module=module.id, error=str(e),
                    )
                    # 单模块失败不阻断其他模块

            await asyncio.gather(*(run_module(module) for module in batch))

        telemetry.log_stage_event(pipeline_id, "M1_M5", "all_modules_complete")

    async def _run_module_with_audit(
        self, module, workspace, pipeline, pipe_def,
    ) -> None:
        """执行单个模块: Work Agent → L1 → Round-1 Audit → (retry if REJECT)。

        成功路径:
          Work Agent → L1 PASS → touch .evidence_Mx_complete
          → Audit Agent → ACCEPT → touch .audit_Mx_ACCEPTED

        失败路径:
          Work Agent 失败 → 重试 (MAX_WORK_RETRIES)
          L1 FAIL → 重试 Work Agent
          Audit REJECT → 新 Work Agent (clean task) → 重新审计 (MAX_AUDIT_RETRIES)
          Audit FLAGGED → 记录 REVIEW_REQUIRED，不发 ACCEPTED
        """
        bus = pipeline.bus
        telemetry = pipeline.telemetry
        pipeline_id = pipeline._state.pipeline_id if pipeline._state else "?"

        # ── Phase 1: Work Agent + L1 闸门 ──
        # 如果有 Phase 定义, 委托给 PhaseEngine; 否则走原始路径
        engine = getattr(self, "_phase_engine", None)
        if engine and engine.has_phases(module.id):
            evidence_data = await engine.execute_module(
                module, workspace, pipeline, pipe_def,
            )
        else:
            evidence_data = await self._run_work_with_retry(
                module, workspace, pipeline, pipe_def,
            )
        if evidence_data is None:
            telemetry.log_stage_event(
                pipeline_id, "M1_M5", "work_exhausted",
                module=module.id,
            )
            return

        # L1 闸门
        gate = L1StructuralGate(f"evidence/pre-{module.id}-evidence.json")
        gate_result = await gate.check(workspace)
        if gate_result.value != "pass":
            l1_error_path = workspace / f"l1_errors_pre-{module.id}-evidence.json"
            l1_error_json = l1_error_path.with_suffix(".json")
            telemetry.log_stage_event(
                pipeline_id, "M1_M5", "l1_failed",
                module=module.id,
                reason="L1 结构校验未通过；Audit 未入队",
                error_index=(
                    l1_error_json.relative_to(workspace).as_posix()
                    if l1_error_json.exists() else None
                ),
            )
            telemetry.log_stage_event(
                pipeline_id, "M1_M5", "audit_not_queued",
                module=module.id,
                reason="L1 structural gate failed",
                error_index=(
                    l1_error_json.relative_to(workspace).as_posix()
                    if l1_error_json.exists() else None
                ),
            )
            return

        bus.touch_token(f".evidence_{module.id}_complete")
        telemetry.log_stage_event(
            pipeline_id, "M1_M5", "module_l1_pass",
            module=module.id,
        )

        # ── Phase 2: Round-1 审计 (触发式，立即执行) ──
        telemetry.log_stage_event(
            pipeline_id, "M1_M5", "audit_queued",
            module=module.id, reason="L1 structural gate passed",
        )
        audit_result = await self._run_audit_with_retry(
            module, workspace, pipeline, pipe_def,
        )

        if audit_result is None:
            telemetry.log_stage_event(
                pipeline_id, "M1_M5", "audit_exhausted",
                module=module.id,
            )
            record_audit_outcome(bus, module.id, "ERROR")
            return

        verdict = audit_result.get("verdict", "UNKNOWN")
        telemetry.log_stage_event(
            pipeline_id, "M1_M5", f"audit_{verdict.lower()}",
            module=module.id, verdict=verdict,
        )

        outcome = verdict if verdict in ("ACCEPT", "FLAGGED", "REJECT") else "ERROR"
        record_audit_outcome(bus, module.id, outcome)
        if verdict == "FLAGGED":
            bus.write_json(
                f"audit-results/audit-result_{module.id}_FLAGGED_note.json",
                {
                    "module_id": module.id,
                    "verdict": "FLAGGED",
                    "note": "已标记为 FLAGGED，未发放 ACCEPTED，需人工审查",
                    "audit_result": audit_result,
                },
            )
        # REJECT 已在 _run_audit_with_retry 中重试；结束后保留 REJECTED token。

    async def _run_work_with_retry(
        self, module, workspace, pipeline, pipe_def,
    ) -> dict | None:
        """运行 Work Agent (含重试)，返回 evidence dict 或 None。

        ARCHITECTURE.md §8.4: Retry 的 Work Agent 与首次配置完全一致，
        不知道审计发生过，不知道哪些条款之前没通过。
        """
        from framework.agent_runner import AgentConfig

        runner = pipeline.runner
        bus = pipeline.bus
        telemetry = pipeline.telemetry
        pipeline_id = pipeline._state.pipeline_id if pipeline._state else "?"

        for attempt in range(self.MAX_WORK_RETRIES + 1):
            config = AgentConfig(
                agent_id=f"work_{module.id}_v1",
                agent_type="work",
                persona_path=pipe_def.work_agent_persona,
                knowledge_paths=(
                    functional_knowledge_paths(pipe_def.shared_knowledge)
                    + module.ammo_paths
                ),
                tool_manifest=module.tools,
                forbidden_patterns=WORK_AGENT_FORBIDDEN,
                model=get_configured_model(),
            )

            # 构建 task_ctx — 含上游依赖数据
            task_inputs = ["ixit.json"]
            if module.upstream_inputs:
                task_inputs.extend(module.upstream_inputs)

            all_clauses = ", ".join(module.clauses)
            from pipelines.etsi.agents import build_clause_recipe_text
            recipe = build_clause_recipe_text(module.clauses)
            task_text = (
                f"执行 {module.name} ({module.id}) 模块检测。\n"
                f"条款范围: {all_clauses}\n"
                f"按 evidence-schema.json 格式输出 pre-{module.id}-evidence.json\n"
                "\n【执行边界】M1–M5 仅做功能性验证；概念性测试只属于 M0。"
                "IXIT/ICS 只能作为本次实测的预期行为或适用性对照，不能独立构成裁决。\n"
            )
            if recipe:
                task_text += recipe + "\n"
            task_ctx = {
                "task": task_text,
                "workspace": str(workspace),
                "inputs": task_inputs,
                "output_file": f"evidence/pre-{module.id}-evidence.json",
            }

            try:
                result = await runner.run(
                    config, task_ctx,
                    tools=pipeline.tool_registry,
                )

                if result.raw_text:
                    try:
                        evidence_data = json.loads(
                            self._extract_json(result.raw_text)
                        )
                        markers = conceptual_verdict_markers(evidence_data)
                        if markers:
                            telemetry.log_stage_event(
                                pipeline_id, "M1_M5", "functional_evidence_rejected",
                                module=module.id, markers="; ".join(markers[:5]),
                            )
                            continue
                        bus.write_json(
                            f"evidence/pre-{module.id}-evidence.json",
                            evidence_data,
                        )
                        return evidence_data
                    except json.JSONDecodeError as e:
                        # 响亮失败: Work Agent 未产出合法 evidence，绝不静默回退到
                        # sample fixture 冒充真实证据。记录错误并让重试循环处理。
                        telemetry.log_stage_event(
                            pipeline_id, "M1_M5", "json_parse_error",
                            module=module.id, attempt=attempt + 1,
                            error=str(e),
                        )

            except Exception as e:
                telemetry.log_stage_event(
                    pipeline_id, "M1_M5", "work_agent_error",
                    module=module.id, attempt=attempt + 1, error=str(e),
                )

            if attempt < self.MAX_WORK_RETRIES:
                await asyncio.sleep(2 * (attempt + 1))  # 退避

        return None

    async def _run_audit_with_retry(
        self, module, workspace, pipeline, pipe_def,
    ) -> dict | None:
        """运行 Round-1 Audit Agent (含 REJECT→重测循环)。

        审计 REJECT 时:
        1. 解析 retry_instruction.target_clause_ids
        2. 构建干净的 retry task（不含审计信息）
        3. 新 Work Agent 重新检测指定条款
        4. 重新审计
        5. 最多 MAX_AUDIT_RETRIES 轮
        """
        runner = pipeline.runner
        bus = pipeline.bus
        telemetry = pipeline.telemetry
        pipeline_id = pipeline._state.pipeline_id if pipeline._state else "?"

        for retry_round in range(self.MAX_AUDIT_RETRIES + 1):
            # 运行 L2 审计
            l2_gate = L2AuditGate(module.id)
            try:
                audit_result = await l2_gate.run_audit(
                    workspace, runner, pipe_def,
                )
                audit_dict = audit_result.model_dump()
            except Exception as e:
                telemetry.log_stage_event(
                    pipeline_id, "M1_M5", "audit_error",
                    module=module.id, error=str(e),
                )
                return None

            # AuditResult.verdict 是 @property (返回 audit.verdict)，model_dump()
            # 只序列化字段、不序列化 property → 顶层无 "verdict" 键。
            # 补回顶层 verdict，供本函数闸门判断与调用方 _run_module_with_audit 读取。
            verdict = audit_result.verdict
            audit_dict["verdict"] = verdict

            if verdict == "ACCEPT":
                return audit_dict

            if verdict == "REJECT" and retry_round < self.MAX_AUDIT_RETRIES:
                # 解析 retry_instruction
                retry_inst = audit_dict.get("retry_instruction") or {}
                target_clauses = retry_inst.get("target_clause_ids", [])

                if not target_clauses:
                    telemetry.log_stage_event(
                        pipeline_id, "M1_M5", "reject_no_targets",
                        module=module.id,
                    )
                    break

                telemetry.log_stage_event(
                    pipeline_id, "M1_M5", "audit_reject_retry",
                    module=module.id,
                    retry_round=retry_round + 1,
                    target_clauses=",".join(target_clauses),
                )

                # 构建干净的 retry task (ARCHITECTURE.md §8.4)
                await self._retry_work_for_clauses(
                    module, target_clauses, workspace, pipeline, pipe_def,
                )
                continue  # 重新审计

            # FLAGGED 或其他非 REJECT 状态 → 停止
            break

        return audit_dict if 'audit_dict' in dir() else None

    async def _retry_work_for_clauses(
        self, module, target_clause_ids: list, workspace, pipeline, pipe_def,
    ) -> None:
        """为指定条款发起干净的 Work Agent 重测。

        ARCHITECTURE.md §8.4 约束:
        - task 格式与首次 Work Agent 完全相同
        - 不出现"修正"、"审计发现"、"打回"字样
        - Agent 不知道审计发生过
        """
        from framework.agent_runner import AgentConfig

        runner = pipeline.runner
        bus = pipeline.bus

        clauses_str = ", ".join(target_clause_ids)
        task_inputs = ["ixit.json"]
        if module.upstream_inputs:
            task_inputs.extend(module.upstream_inputs)

        config = AgentConfig(
            agent_id=f"work_{module.id}_v1",
            agent_type="work",
            persona_path=pipe_def.work_agent_persona,
            knowledge_paths=(
                functional_knowledge_paths(pipe_def.shared_knowledge)
                + module.ammo_paths
            ),
            tool_manifest=module.tools,
            forbidden_patterns=WORK_AGENT_FORBIDDEN,
            model=get_configured_model(),
        )

        from pipelines.etsi.agents import build_clause_recipe_text
        recipe = build_clause_recipe_text(target_clause_ids)
        task_text = (
            f"请测试 {module.id} 模块以下条款：{clauses_str}\n"
            "【执行边界】M1–M5 仅做功能性验证；概念性测试只属于 M0。"
            "IXIT/ICS 只能作为本次实测的预期行为或适用性对照，不能独立构成裁决。"
        )
        if recipe:
            task_text += "\n" + recipe

        task_ctx = {
            "task": task_text,
            "workspace": str(workspace),
            "inputs": task_inputs,
            "output_file": f"evidence/pre-{module.id}-evidence.json",
        }

        try:
            result = await runner.run(
                config, task_ctx,
                tools=pipeline.tool_registry,
            )
            if result.raw_text:
                try:
                    evidence_data = json.loads(
                        self._extract_json(result.raw_text)
                    )
                    markers = conceptual_verdict_markers(evidence_data)
                    if markers:
                        telemetry = pipeline.telemetry
                        pipeline_id = pipeline._state.pipeline_id if pipeline._state else "?"
                        telemetry.log_stage_event(
                            pipeline_id, "M1_M5", "functional_evidence_rejected",
                            module=module.id, markers="; ".join(markers[:5]),
                        )
                        return
                    bus.write_json(
                        f"evidence/pre-{module.id}-evidence.json",
                        evidence_data,
                    )
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass  # retry 失败由外层审计再捕捉

    @staticmethod
    def _extract_json(text: str) -> str:
        """从 Agent 输出中提取 JSON（处理 markdown 代码块包裹）。"""
        if "```json" in text:
            return text.split("```json")[1].split("```")[0]
        elif "```" in text:
            return text.split("```")[1].split("```")[0]
        return text

    @staticmethod
    def _topological_batches(modules):
        """将模块按依赖关系拓扑分批。

        无依赖的模块 → 批次 1
        依赖已完成的模块 → 后续批次
          同批次内可并发安全执行。
        """
        module_map = {m.id: m for m in modules}
        batches: list[list] = []
        remaining = set(module_map.keys())
        completed: set[str] = set()

        while remaining:
            batch = []
            for mid in sorted(remaining):
                m = module_map[mid]
                dep = m.depends_on
                if dep is None or dep in completed:
                    batch.append(module_map[mid])

            if not batch:
                batch = [module_map[mid] for mid in sorted(remaining)]

            batches.append(batch)
            for m in batch:
                remaining.discard(m.id)
                completed.add(m.id)

        return batches

    def describe(self) -> str:
        return "M1-M5 检测 + Round-1 审计 (触发式)"


class CrossModuleAuditStage(Stage):
    """跨模块一致性审计 — Round 2。

    在所有 round-1 审计 ACCEPT 后执行。检查:
    1. 继承链一致性 — 父条款 PASS 但子条款 FAIL 的矛盾
    2. 跨模块矛盾 — M2 声称 HTTPS 但 M3 发现明文 HTTP
    3. Escape clause 一致性 — 同一条款在不同模块中引用不一致
    4. 证据外推检测 — 某模块的证据被不恰当地引用到其他模块

    如果 Audit Agent 可用，委托给 AI 审计；否则执行确定性检查。
    """

    async def execute(self, workspace, registry, pipeline):
        runner = pipeline.runner
        bus = pipeline.bus
        telemetry = pipeline.telemetry
        pipe_def = pipeline.pipe_def
        pipeline_id = pipeline._state.pipeline_id if pipeline._state else "?"

        # 从 pipe_def 获取 M1-M5 模块列表
        active_modules = [
            m.id for m in pipe_def.modules
            if m.id in ("M1", "M2", "M3", "M4", "M5")
        ]

        # 1. 检查前置条件: 全部 round-1 审计令牌就绪
        required_tokens = [f".audit_{mid}_ACCEPTED" for mid in active_modules]
        missing = bus.missing_tokens(required_tokens)
        if missing:
            telemetry.log_stage_event(
                pipeline_id, "CROSS_AUDIT", "prerequisites_missing",
                missing=",".join(missing),
            )
            raise RuntimeError(
                f"跨模块审计前置条件不满足。缺失令牌: {missing}"
            )

        # 2. 加载所有 round-1 审计结果
        cross_issues: list[dict] = []
        all_evidence: dict[str, dict] = {}
        all_audits: dict[str, dict] = {}

        for module_id in active_modules:
            try:
                ev = bus.read_json(f"evidence/pre-{module_id}-evidence.json")
                all_evidence[module_id] = ev
            except Exception:
                pass
            try:
                au = bus.read_json(f"audit-results/audit-result_{module_id}.json")
                all_audits[module_id] = au
            except Exception:
                pass

        # 3. 确定性跨模块一致性检查
        cross_issues.extend(
            self._check_inheritance_chain(all_evidence)
        )
        cross_issues.extend(
            self._check_cross_module_contradictions(all_evidence)
        )
        cross_issues.extend(
            self._check_escape_clause_consistency(all_evidence)
        )

        # 4. 写跨模块问题报告
        bus.write_json(
            "audit-results/cross-module-issues.json",
            {
                "round": 2,
                "checked_at": datetime.now().isoformat(),
                "modules_audited": list(all_audits.keys()),
                "issues": cross_issues,
                "issue_count": len(cross_issues),
            },
        )

        # 5. 如果有 AI 审计可用，委托给跨模块审计 Agent
        #    只有 schema 合法的 ACCEPT 且不存在确定性 HIGH/CRITICAL 矛盾，
        #    才能签发 ROUND2_ACCEPTED。任何解析/调用错误都是 ERROR，不能放行。
        round2_verdict = "ERROR"
        try:
            from framework.agent_runner import AgentConfig
            from framework.audit_tools import (
                AUDIT_READONLY_CATEGORY,
                build_audit_readonly_registry,
            )
            from contracts.audit import AuditResult

            evidence_list = "\n".join(
                f"- evidence/pre-{mid}-evidence.json" for mid in all_evidence
            )
            audit_list = "\n".join(
                f"- audit-results/audit-result_{mid}.json" for mid in all_audits
            )

            audit_inputs = (
                [f"evidence/pre-{mid}-evidence.json" for mid in all_evidence]
                + [f"audit-results/audit-result_{mid}.json" for mid in all_audits]
                + ["ixit.json"]
            )

            config = AgentConfig(
                agent_id="cross_audit_v1",
                agent_type="audit",
                persona_path=pipe_def.audit_agent_persona,
                knowledge_paths=(
                    pipe_def.shared_knowledge + pipe_def.audit_only_knowledge
                ),
                tool_manifest=(AUDIT_READONLY_CATEGORY,),
                forbidden_patterns=(),
            )

            task_ctx = {
                "task": (
                    "执行 Round 2 跨模块一致性审计。\n"
                    "检查继承链、跨模块矛盾、escape clause 一致性。\n"
                    f"可用的 evidence 文件:\n{evidence_list}\n"
                    f"可用的 round-1 审计结果:\n{audit_list}\n"
                    f"已有的确定性检查发现: {json.dumps(cross_issues, ensure_ascii=False)}\n"
                    "使用受限只读工具按需检索上述输入；不得访问或修改其他工作区文件。\n"
                    "按 audit-output-schema.json 输出 AuditResult JSON，"
                    "round_number=2，cross_module_issues 字段包含跨模块发现。\n"
                ),
                "workspace": str(workspace),
                "inputs": audit_inputs,
                "output_file": "audit-results/cross-module-audit.json",
            }

            result = await runner.run(
                config,
                task_ctx,
                tools=build_audit_readonly_registry(workspace, audit_inputs),
            )

            if result.raw_text:
                try:
                    text = M1M5ParallelStage._extract_json(result.raw_text)
                    cross_audit = json.loads(text)
                    audit_result = AuditResult(**cross_audit)
                    round2_verdict = audit_result.verdict
                    # AuditResult.verdict 是 property，model_dump() 不含顶层 verdict；
                    # 写入兼容字段供 Web/历史消费者读取。
                    cross_audit = audit_result.model_dump(mode="json")
                    cross_audit["verdict"] = round2_verdict
                    bus.write_json(
                        "audit-results/cross-module-audit.json",
                        cross_audit,
                    )

                    telemetry.log_stage_event(
                        pipeline_id, "CROSS_AUDIT", "ai_audit_complete",
                        verdict=round2_verdict,
                    )
                except Exception as e:
                    telemetry.log_stage_event(
                        pipeline_id, "CROSS_AUDIT", "ai_audit_parse_error",
                        error=str(e),
                    )
        except Exception as e:
            telemetry.log_stage_event(
                pipeline_id, "CROSS_AUDIT", "ai_audit_error",
                error=str(e),
            )

        # 6. 发行真实的 round-2 outcome token。
        # 已有 HIGH/CRITICAL 确定性矛盾时，即使 AI 给出 ACCEPT 也必须人工复核；
        # 它们没有“已处理”字段，不能由管线擅自视作已关闭。
        outcome, blocking_issues = self._determine_round2_outcome(
            round2_verdict, cross_issues,
        )
        if blocking_issues and outcome == "FLAGGED" and round2_verdict == "ACCEPT":
            bus.write_json(
                "audit-results/cross-module-review-note.json",
                {
                    "verdict": "FLAGGED",
                    "reason": "存在未处理的确定性 HIGH/CRITICAL 跨模块矛盾",
                    "blocking_issues": blocking_issues,
                },
            )

        record_audit_outcome(bus, "ROUND2", outcome)
        telemetry.log_stage_event(
            pipeline_id, "CROSS_AUDIT", "complete",
            cross_issues=len(cross_issues),
            verdict=outcome,
            blocking_issues=len(blocking_issues),
        )

    # ===== 确定性跨模块检查 =====

    @staticmethod
    def _determine_round2_outcome(
        audit_verdict: str,
        cross_issues: list[dict],
    ) -> tuple[str, list[dict]]:
        """合并 AI 审计结论与确定性跨模块矛盾。

        HIGH/CRITICAL issue 没有自动“已处理”语义，因此即使 AI 返回 ACCEPT
        也只能进入 REVIEW_REQUIRED（以 FLAGGED outcome 表示）。
        """
        blocking = [
            issue for issue in cross_issues
            if issue.get("severity") in ("CRITICAL", "HIGH")
        ]
        verdict = str(audit_verdict).upper()
        if blocking and verdict == "ACCEPT":
            return "FLAGGED", blocking
        if verdict in ("ACCEPT", "FLAGGED", "REJECT"):
            return verdict, blocking
        return "ERROR", blocking

    @staticmethod
    def _check_inheritance_chain(
        all_evidence: dict[str, dict],
    ) -> list[dict]:
        """检查继承链一致性。

        规则: 如果父条款 (如 5.5-1 在 M1 中) 标记为 PASS，
        但子条款 (如 M3 中依赖 5.5-1 的条款) 标记为 FAIL，
        且 FAIL 理由与父条款矛盾 → 标记为 inheritance_broken。
        """
        issues: list[dict] = []

        # 已知继承关系 (ETSI EN 303 645):
        # 5.5-1 (M3) → 基于 5.5-2 (M1) 的端口发现
        # 5.6-6/7/8 (M1) → 需要认证模块 M2 支持
        inheritance_pairs = [
            ("5.5-1", "5.5-2", "M3", "M1", "TLS 需要先发现开放端口"),
            ("5.6-6", "5.1-1", "M1", "M2", "接口认证需要先验证认证机制"),
            ("5.6-7", "5.1-2", "M1", "M2", "接口认证需要先验证认证机制"),
        ]

        for child_clause, parent_clause, child_mod, parent_mod, desc in inheritance_pairs:
            child_verdict = CrossModuleAuditStage._find_clause_verdict(
                all_evidence.get(child_mod, {}), child_clause
            )
            parent_verdict = CrossModuleAuditStage._find_clause_verdict(
                all_evidence.get(parent_mod, {}), parent_clause
            )

            if parent_verdict == "PASS" and child_verdict == "FAIL":
                issues.append({
                    "type": "inheritance_broken",
                    "severity": "HIGH",
                    "parent": f"{parent_mod}:{parent_clause}",
                    "child": f"{child_mod}:{child_clause}",
                    "parent_verdict": parent_verdict,
                    "child_verdict": child_verdict,
                    "description": f"父条款 PASS 但子条款 FAIL: {desc}",
                    "suggestion": "核实子条款 FAIL 理由是否确实独立于父条款，或父条款结果应传递到子条款",
                })

        return issues

    @staticmethod
    def _check_cross_module_contradictions(
        all_evidence: dict[str, dict],
    ) -> list[dict]:
        """检查跨模块矛盾。

        示例:
        - M2 声称「设备使用 HTTPS 登录」，但 M3 发现明文 HTTP 通信
        - M1 端口扫描未发现 443，但 M3 声称 TLS 已配置
        """
        issues: list[dict] = []

        # 矛盾对定义: (模块A, 条款A, 预期, 模块B, 条款B, 矛盾条件)
        contradiction_checks = [
            # M2 认证加密 ↔ M3 通信加密
            {
                "pair": ("M2", "M3"),
                "description": "认证模块与通信加密模块的 TLS 声明一致性",
                "check": "如果在 M2 中发现 HTTPS 登录，M3 应确认 TLS 已启用",
            },
            # M1 端口 ↔ M3 加密
            {
                "pair": ("M1", "M3"),
                "description": "端口发现与加密声明的矛盾",
                "check": "M1 发现开放端口 80/8080 (HTTP) 但 M3 声称所有通信已加密 → 矛盾",
            },
        ]

        for check in contradiction_checks:
            mod_a, mod_b = check["pair"]
            ev_a = all_evidence.get(mod_a, {})
            ev_b = all_evidence.get(mod_b, {})

            # 简化检查: 查找两个模块中是否有矛盾的 verdict
            a_clauses = ev_a.get("clauses", [])
            b_clauses = ev_b.get("clauses", [])

            # 如果模块 A 中任何涉及 'HTTPS', 'TLS', 'encrypt' 的条款 PASS
            # 但模块 B 中发现明文通信 → 标记
            a_crypto_pass = any(
                "HTTPS" in c.get("reason", "") or "TLS" in c.get("reason", "") or "encrypt" in c.get("reason", "").lower()
                for c in a_clauses if c.get("verdict") == "PASS"
            )
            b_plaintext_found = any(
                "HTTP" in c.get("reason", "") and "HTTPS" not in c.get("reason", "")
                for c in b_clauses
            )

            if a_crypto_pass and b_plaintext_found:
                issues.append({
                    "type": "cross_module_contradiction",
                    "severity": "CRITICAL",
                    "modules": f"{mod_a} ↔ {mod_b}",
                    "description": check["description"],
                    "detail": check["check"],
                })

        return issues

    @staticmethod
    def _check_escape_clause_consistency(
        all_evidence: dict[str, dict],
    ) -> list[dict]:
        """检查 escape clause 跨模块一致性。

        同一条款如果在不同模块中被引用，escape clause 的适用性应一致。
        """
        issues: list[dict] = []

        # 收集所有带 escape-clause 标签的条款
        escape_clauses: dict[str, list[dict]] = {}
        for mod_id, ev in all_evidence.items():
            for clause in ev.get("clauses", []):
                tags = clause.get("tags", [])
                if "escape-clause" in tags:
                    cid = clause.get("clause_id", "")
                    if cid not in escape_clauses:
                        escape_clauses[cid] = []
                    escape_clauses[cid].append({
                        "module": mod_id,
                        "verdict": clause.get("verdict", ""),
                        "reason": clause.get("reason", "")[:100],
                    })

        # 检查同一 escape clause 在不同模块中是否一致
        for cid, refs in escape_clauses.items():
            verdicts = set(r["verdict"] for r in refs)
            if len(verdicts) > 1:
                issues.append({
                    "type": "escape_clause_inconsistent",
                    "severity": "MEDIUM",
                    "clause_id": cid,
                    "modules": [r["module"] for r in refs],
                    "verdicts": list(verdicts),
                    "description": f"escape clause '{cid}' 在不同模块中裁决不一致: {verdicts}",
                })

        return issues

    @staticmethod
    def _find_clause_verdict(evidence: dict, clause_id: str) -> str | None:
        """在 evidence JSON 中查找指定 clause_id 的 verdict。"""
        for clause in evidence.get("clauses", []):
            if clause.get("clause_id") == clause_id:
                return clause.get("verdict")
        return None

    def describe(self) -> str:
        return "跨模块一致性审计 (Round 2)"


class ReportGenerationStage(Stage):
    """报告生成 — 汇总 evidence + 审计结果生成 ETSI TS 103 701 格式报告。

    从 ixit.json 动态提取产品信息，从 pipeline_state.json 提取检测日期。
    """

    async def execute(self, workspace, registry, pipeline):
        bus = pipeline.bus
        telemetry = pipeline.telemetry
        pipeline_id = pipeline._state.pipeline_id if pipeline._state else "?"

        # 1. 从 ixit.json 提取产品信息
        product_info = self._extract_product_info(workspace)

        # 2. 从 pipeline state 提取检测日期
        test_date = self._extract_test_date(workspace)
        traffic_summary = TrafficStateStore(workspace).read()

        # 3. 加载所有证据和审计结果
        all_clauses: list[dict] = []
        audit_summaries: list[dict] = []
        total_pass = 0
        total_fail = 0
        total_na = 0
        total_pending = 0

        for ev_file in bus.list_evidence_files():
            # PhaseEngine 中间产物 (pre-Mx-phase_A-evidence.json) 只含子集条款，
            # 主文件 (pre-Mx-evidence.json) 已是合并后全量 → 跳过避免重复计数。
            if "phase_" in ev_file.stem:
                continue
            try:
                data = bus.read_json(f"evidence/{ev_file.name}")
                module_id = ev_file.stem.replace("pre-", "").replace("-evidence", "")
                for clause in data.get("clauses", []):
                    clause["_module"] = module_id
                    all_clauses.append(clause)
                    v = clause.get("verdict", "?")
                    if v == "PASS":
                        total_pass += 1
                    elif v == "FAIL":
                        total_fail += 1
                    elif v in ("NA", "N/A"):
                        total_na += 1
                    elif v in ("PENDING_MANUAL", "INCONCLUSIVE"):
                        total_pending += 1
            except Exception:
                pass

        # 加载审计汇总 (audit-result_Mx.json 顶层为 AuditResult 嵌套结构,
        # 模块名/裁决在 audit{} 内, 顶层无 module_id)
        for au_file in bus.list_audit_results():
            try:
                au_data = bus.read_json(f"audit-results/{au_file.name}")
                audit_info = au_data.get("audit", au_data)
                audit_summaries.append({
                    "module": audit_info.get("moduleId", audit_info.get("module_id", au_file.stem)),
                    "verdict": audit_info.get("verdict", "?"),
                    "summary": audit_info.get("summary", ""),
                    "finding_count": len(au_data.get("findings", [])),
                })
            except Exception:
                pass

        # 4. 生成报告
        # 对齐 skill 报告规范 (report-template.md): 任务编号 + 样品/测试信息 +
        # 结果汇总 + 审计意见 + 逐条款(含证据/手工标注) + 手工测试指引 + 附录。
        task_id = f"HCTL-{test_date.replace('-', '')}"
        total_all = total_pass + total_fail + total_na + total_pending
        total_judged = total_pass + total_fail
        pct = lambda n: f"{n / total_all * 100:.1f}%" if total_all else "-"
        pass_rate = f"{total_pass / total_judged * 100:.1f}%" if total_judged else "-"

        lines = [
            f"# ETSI TS 103 701 认证检测报告",
            "",
            f"> 任务编号：**{task_id}** · 检测日期：**{test_date}**",
            "",
        ]
        if pipeline._state and pipeline._state.review_required:
            lines.extend([
                "> ⚠️ **部分报告 / 待人工复核**：本次运行存在未通过的阶段闸门，"
                "不得作为认证通过结论。",
                "> 原因：" + "；".join(pipeline._state.review_reasons),
                "",
            ])
        lines.extend([
            "## 1. 样品与测试信息",
            "",
            f"| 项目 | 内容 |",
            f"|------|------|",
            f"| **产品名称** | {product_info['product_name']} |",
            f"| **产品型号** | {product_info['model']} |",
            f"| **产品版本** | {product_info['product_version']} |",
            f"| **硬件版本** | {product_info['hardware_version']} |",
            f"| **固件版本** | {product_info['firmware']} |",
            f"| **厂商** | {product_info['vendor']} |",
            f"| **设备类型** | {product_info['device_type']} |",
            f"| **检测日期** | {test_date} |",
            f"| **检测依据** | ETSI EN 303 645 V2.1.1 / ETSI TS 103 701 V1.1.1 |",
            f"| **检测工具** | nmap, tshark, Burp Suite, Python |",
            "",
        ])
        if traffic_summary:
            lines.extend([
                "## 2. 阶段 3.1 流量采集取证",
                "",
                f"- **状态**：`{traffic_summary.get('status', 'UNKNOWN')}`",
                f"- **采集 attempt**：`{traffic_summary.get('attempt_id', '?')}`",
                f"- **Checklist 版本**：`{traffic_summary.get('checklist_version', '?')}`",
                f"- **PCAP**：`{traffic_summary.get('capture_pcap', 'capture.pcap')}`",
            ])
            if traffic_summary.get("review_reason"):
                lines.append(f"- **待复核原因**：{traffic_summary['review_reason']}")
            lines.extend([
                "",
                "| 操作项 | 记录状态 | 时间 | 备注 | 证据引用 |",
                "|------|:--------:|------|------|----------|",
            ])
            for item in traffic_summary.get("checklist", []):
                label = str(item.get("label", "")).replace("|", "\\|")
                item_status = item.get("status", "pending")
                updated = item.get("updated_at") or "-"
                note = str(item.get("note") or "-").replace("|", "\\|")
                evidence = " · ".join(item.get("evidence") or []) or "-"
                lines.append(f"| {label} | {item_status} | {updated} | {note} | {evidence} |")
            lines.extend(["", "## 3. 检测结果汇总", ""])
        else:
            lines.extend(["## 3. 检测结果汇总", ""])
        lines.extend([
            "",
            f"| 裁决 | 数量 | 占比 |",
            f"|------|:----:|:----:|",
            f"| ✅ PASS | {total_pass} | {pct(total_pass)} |",
            f"| ❌ FAIL | {total_fail} | {pct(total_fail)} |",
            f"| ⬜ N/A | {total_na} | {pct(total_na)} |",
            f"| ⏳ PENDING | {total_pending} | {pct(total_pending)} |",
            f"| **总计** | **{total_all}** | — |",
            f"| **通过率 (PASS/已判定)** | **{pass_rate}** | — |",
            "",
            "## 4. 审计意见",
            "",
        ])

        for au in audit_summaries:
            lines.append(f"- **{au['module']}**: `{au['verdict']}` — {au['summary']} ({au['finding_count']} 发现)")
        lines.append("")

        lines.extend([
            "## 5. 逐条款检测结果",
            "",
            "| 模块 | 条款 | 裁决 | 理由 | 证据 | 备注 |",
            "|:----:|------|:---:|------|------|------|",
        ])

        for clause in sorted(all_clauses, key=lambda c: (c.get("_module", ""), c.get("clause_id", ""))):
            cid = clause.get("clause_id", "?")
            verdict = clause.get("verdict", "?")
            reason = (clause.get("reason", "") or "").replace("|", "\\|")[:80]
            module = clause.get("_module", "?")
            ev_summary = self._clause_evidence_summary(clause)
            note = ""
            if self._is_manual_clause(cid):
                note = "⚠ 需手工测试"
            elif clause.get("warnings"):
                note = "; ".join(str(w) for w in clause["warnings"][:2])[:60].replace("|", "\\|")
            lines.append(f"| {module} | {cid} | {verdict} | {reason} | {ev_summary} | {note} |")

        # 手工测试条款指引 (SKILL.md: 手工条款附详细步骤)
        manual_clauses = [
            c for c in all_clauses
            if self._is_manual_clause(c.get("clause_id", "")) or c.get("manualSteps")
        ]
        if manual_clauses:
            lines.extend(["", "## 6. 手工测试条款指引", ""])
            for c in sorted(manual_clauses, key=lambda c: (c.get("_module", ""), c.get("clause_id", ""))):
                cid = c.get("clause_id", "?")
                ms = c.get("manualSteps") or c.get("warnings") or []
                lines.append(f"### {cid}（{c.get('_module', '?')}）")
                if isinstance(ms, str):
                    lines.append(ms)
                elif ms:
                    for i, step in enumerate(ms, 1):
                        lines.append(f"{i}. {step}")
                else:
                    lines.append("该条款需人工操作，详见操作手册。")
                lines.append("")

        lines.extend([
            "## 附录 A：证据文件清单",
            "",
        ])
        for ev_file in bus.list_evidence_files():
            lines.append(f"- `evidence/{ev_file.name}`")

        lines.extend([
            "",
            "## 附录 B：审计结果清单",
            "",
        ])
        for au_file in bus.list_audit_results():
            lines.append(f"- `audit-results/{au_file.name}`")

        lines.extend([
            "",
            "---",
            "",
            f"*报告由 ETSI Agent Framework 自动生成于 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*",
        ])

        report = "\n".join(lines)
        report_name = (
            f"认证检测报告_{product_info['model']}_{test_date.replace('-', '')}.md"
        )
        report_path = workspace / report_name
        report_path.write_text(report, encoding="utf-8")

        # 报告网页、条款证据包和下载索引使用同一份结构化数据。Markdown 仍保留为
        # 原始记录交付件，避免在已验证的模板上做破坏性替换。
        from framework.reporting import write_report_bundle
        bundle = write_report_bundle(workspace)

        telemetry.log_stage_event(
            pipeline_id, "REPORT", "generated",
            path=str(report_path),
            product=product_info["model"],
            clauses=len(all_clauses),
            report_data=bundle["report_data"],
            html=bundle["html"],
            evidence_packages=bundle["packages"],
        )

    @staticmethod
    def _extract_product_info(workspace: Path) -> dict:
        """从 ixit.json 提取产品信息。"""
        default = {
            "product_name": "Unknown",
            "model": "Unknown-Model",
            "product_version": "Unknown",
            "hardware_version": "Unknown",
            "firmware": "Unknown",
            "vendor": "Unknown",
            "device_type": "IoT 设备",
        }

        ixit_path = workspace / "ixit.json"
        if not ixit_path.exists():
            return default

        try:
            data = json.loads(ixit_path.read_text(encoding="utf-8"))
            # 新 schema: meta.dut_identification 为 {section: {field: value}} 嵌套结构
            dut_id = data.get("meta", {}).get("dut_identification", {})
            flat = {}
            if isinstance(dut_id, dict):
                for fields in dut_id.values():
                    if isinstance(fields, dict):
                        for field, value in fields.items():
                            if field and value:
                                flat[str(field).lower()] = str(value)

            def grab(*keywords):
                for key, val in flat.items():
                    if any(kw in key for kw in keywords):
                        return val
                return None

            return {
                "product_name": grab("product name", "device name") or "Unknown",
                "model": grab("model") or "Unknown-Model",
                "product_version": grab("product version", "device version") or "Unknown",
                "hardware_version": grab("hardware version", "hardware revision") or "Unknown",
                "firmware": grab("firmware", "software version") or "Unknown",
                "vendor": grab("vendor", "manufacturer", "supplier", "brand", "trade name", "organisation", "organization") or "Unknown",
                "device_type": grab("device type", "product category") or "IoT 设备",
            }
        except Exception:
            return default

    @staticmethod
    def _extract_test_date(workspace: Path) -> str:
        """从 pipeline_state.json 提取检测开始日期。"""
        state_path = workspace / "pipeline_state.json"
        if state_path.exists():
            try:
                state = json.loads(state_path.read_text(encoding="utf-8"))
                started = state.get("started_at", "")
                if started:
                    return started[:10]  # YYYY-MM-DD
            except Exception:
                pass
        return datetime.now().strftime("%Y-%m-%d")

    # 需人工测试条款（SKILL.md §汇总规则 + 逐条款自动化策略的 ❌ 手工项）
    _MANUAL_CLAUSE_IDS = {
        "5.1-4", "5.3-6", "5.3-15", "5.3-16",
        "5.6-3", "5.6-4", "5.9-1", "5.9-2",
    }
    _MANUAL_CLAUSE_PREFIXES = ("5.4-", "5.7-", "5.11")

    @classmethod
    def _is_manual_clause(cls, cid: str) -> bool:
        """SKILL.md 标记的需人工测试条款 → 报告标 ⚠ 需手工测试。"""
        if not cid:
            return False
        return cid in cls._MANUAL_CLAUSE_IDS or any(
            cid.startswith(p) for p in cls._MANUAL_CLAUSE_PREFIXES
        )

    @staticmethod
    def _clause_evidence_summary(clause: dict) -> str:
        """从 clause.evidence[] 提取证据摘要（path / description）。"""
        evs = clause.get("evidence")
        if not evs:
            return ""
        parts = []
        for ev in evs[:2]:
            p = ev.get("path") or ev.get("description") or ""
            if p:
                parts.append(str(p))
        return " · ".join(parts)[:120].replace("|", "\\|")

    def describe(self) -> str:
        return "汇总生成认证检测报告"


# ============================================================
# ETSI 管线
# ============================================================

class ETSIPipeline(Pipeline):
    """ETSI TS 103 701 认证检测管线。

    持有 AgentRunner / FileBus / Telemetry / PipelineDef 引用，
    Stage 通过 pipeline.xxx 访问。

    流程 (2026-08-07 更新):
      INIT → ENV_CHECK → ICS_PARSE → M0 → TRAFFIC
      → M1_M5 (Work Agent + 触发式 Round-1 审计)
      → CROSS (Round-2 跨模块审计)
      → REPORT → DONE
    """

    def __init__(self, workspace, registry, runner, bus, telemetry, pipe_def,
                 tool_registry=None, path_resolver=None, non_interactive=False,
                 mcp_manager=None, control_mode="terminal", run_plan=None):
        super().__init__(workspace, registry)
        self.runner = runner
        self.bus = bus
        self.telemetry = telemetry
        self.pipe_def = pipe_def
        self.tool_registry = tool_registry
        self.non_interactive = non_interactive  # 跳过 input() 等待
        self.control_mode = control_mode  # "terminal" | "web" — 流量采集确认方式
        self.mcp_manager = mcp_manager  # MCPClientManager (可选)
        self.run_plan = run_plan
        from framework.path_resolver import PathResolver as _PR
        self.path_resolver = path_resolver or _PR()

    @property
    def pipeline_name(self) -> str:
        return "etsi-ts103701"

    @property
    def initial_state(self) -> PipelineState:
        if self.run_plan and not self.run_plan.certification_claim:
            return PipelineState.TRAFFIC_COLLECT
        return PipelineState.INIT

    @property
    def run_profile_name(self) -> str:
        return self.run_plan.profile.value if self.run_plan else "certification-full"

    @property
    def certification_claim(self) -> bool:
        return bool(not self.run_plan or self.run_plan.certification_claim)

    @property
    def stages(self) -> Dict[PipelineState, Stage]:
        return {
            PipelineState.INIT: InitStage(),
            PipelineState.ENV_CHECK: EnvCheckStage(),
            PipelineState.ICS_PARSE: IcsParseStage(),
            PipelineState.M0_ICS_VALIDATION: M0Stage(),
            PipelineState.M0_CONCEPT: M0ConceptStage(),
            PipelineState.M0_L1: M0L1Stage(),
            PipelineState.M0_AUDIT: M0AuditStage(),
            PipelineState.TRAFFIC_COLLECT: TrafficCollectStage(),
            PipelineState.M1_M5_PARALLEL: M1M5ParallelStage(),
            PipelineState.CROSS_MODULE_AUDIT: CrossModuleAuditStage(),
            PipelineState.REPORT_GENERATION: ReportGenerationStage(),
        }

    @property
    def transitions(self) -> List[StageTransition]:
        # 非认证功能性 profile 只执行其 RunPlan：从 Traffic 开始，模块内仍保留
        # Work/L1/L2 质量检查，但不伪造 M0 或跨模块认证 gate，也不生成认证报告。
        if self.run_plan and not self.run_plan.certification_claim:
            return [
                StageTransition(PipelineState.TRAFFIC_COLLECT, PipelineState.M1_M5_PARALLEL),
                StageTransition(PipelineState.M1_M5_PARALLEL, PipelineState.DONE),
            ]
        # 动态构建审计令牌列表 (基于实际模块, 而非硬编码 M1-M5)
        active_audit_tokens = [
            f".audit_{m.id}_ACCEPTED"
            for m in self.pipe_def.modules
            if m.id in ("M1", "M2", "M3", "M4", "M5")
        ]
        if not active_audit_tokens:
            active_audit_tokens = [".audit_M1_ACCEPTED"]  # fallback

        return [
            StageTransition(PipelineState.INIT, PipelineState.ENV_CHECK),
            StageTransition(PipelineState.ENV_CHECK, PipelineState.ICS_PARSE,
                            on_failure=PipelineState.FAILED),
            StageTransition(PipelineState.ICS_PARSE, PipelineState.M0_ICS_VALIDATION,
                            on_failure=PipelineState.FAILED),
            StageTransition(PipelineState.M0_ICS_VALIDATION, PipelineState.M0_CONCEPT,
                            on_failure=PipelineState.M0_ICS_VALIDATION),
            StageTransition(PipelineState.M0_CONCEPT, PipelineState.M0_L1,
                            on_failure=PipelineState.FAILED),
            StageTransition(PipelineState.M0_L1, PipelineState.M0_AUDIT,
                            gate=PhaseGate("m0_l1_done", [".l1_M0_PASSED"]),
                            on_failure=PipelineState.M0_CONCEPT,
                            max_gate_failures=2,
                            on_exhaustion=PipelineState.FAILED),
            # M0 审计闸门: 拿不到 .audit_M0_ACCEPTED 令牌不得派发 M1-M5
            # (SKILL.md 阶段 2 + 阶段 4 硬闸门)。REJECT → 仅回 M0 概念条款定点重做。
            StageTransition(PipelineState.M0_AUDIT, PipelineState.TRAFFIC_COLLECT,
                            gate=PhaseGate("m0_audit_done", [".audit_M0_ACCEPTED"]),
                            on_failure=PipelineState.M0_CONCEPT,
                            max_gate_failures=2,
                            on_exhaustion=PipelineState.FAILED),
            StageTransition(PipelineState.TRAFFIC_COLLECT, PipelineState.M1_M5_PARALLEL),
            # M1-M5 完成 (含 round-1 审计) → Round-2 跨模块审计
            StageTransition(
                PipelineState.M1_M5_PARALLEL, PipelineState.CROSS_MODULE_AUDIT,
                gate=PhaseGate("m1_m5_audit_done", active_audit_tokens),
                on_failure=PipelineState.M1_M5_PARALLEL,
                # 模块内已经有 2 次 Work/Audit 重试；阶段层最多再重进一次。
                # 仍缺令牌时生成部分报告并 needs_review，绝不无限重跑或伪造 ACCEPTED。
                max_gate_failures=1,
                on_exhaustion=PipelineState.REPORT_GENERATION,
                review_on_exhaustion=True,
            ),
            # Round-2 只有 ACCEPT 才能走正式通过链路；其他 outcome 仍可生成
            # 部分报告，但状态必须为 needs_review，而非 DONE。
            StageTransition(
                PipelineState.CROSS_MODULE_AUDIT, PipelineState.REPORT_GENERATION,
                gate=PhaseGate("round2_audit_done", [".audit_ROUND2_ACCEPTED"]),
                max_gate_failures=0,
                on_exhaustion=PipelineState.REPORT_GENERATION,
                review_on_exhaustion=True,
            ),
            StageTransition(PipelineState.REPORT_GENERATION, PipelineState.DONE),
        ]
