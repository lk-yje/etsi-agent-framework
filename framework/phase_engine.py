"""Phase 感知执行引擎 — 数据驱动的模块阶段拆分与调度。

设计原则:
1. 数据驱动: Phase 定义从 JSON 配置加载, 框架代码零硬编码
2. 向后兼容: has_phases() 门控, 无 phase 定义的模块走 fallback
3. Pool 集成: Phase 间通过 ContextPool 通信, 上游数据自动注入 task_ctx
4. Evidence 合并: 多 Phase 产出合并为单份 evidence (与 Audit 流程兼容)

用法:
    engine = PhaseExecutionEngine(workspace, pool, runner, bus, telemetry, pipe_def)
    engine.load_definitions(Path("framework/phase_definitions.json"))
    if engine.has_phases("M3"):
        evidence = await engine.execute_module(m3_module, workspace, pipeline, pipe_def)
"""

import asyncio
import json
import logging
import os
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from contracts.evidence import EvidenceManifest
from framework.context_pool import ContextPool, ProviderSpec, Scope

logger = logging.getLogger(__name__)


# ============================================================
# 数据结构
# ============================================================

@dataclass(frozen=True)
class PhaseDef:
    """阶段定义 — 从 JSON 配置加载。"""
    id: str                                # "phase_A"
    name: str                              # "端口扫描与服务发现"
    clauses: Tuple[str, ...]
    depends_on: Tuple[str, ...]            # 同模块内的前置 phase
    wait_for_pool_keys: Tuple[str, ...]    # 等待其他模块的 pool key
    tools: Tuple[str, ...]
    knowledge_additions: Tuple[str, ...]   # 额外的 knowledge 文件路径
    pool_outputs: Tuple[dict, ...]         # [{"key": "...", "scope": "..."}]
    providers_used: Tuple[str, ...]
    max_tool_turns: Optional[int] = None


@dataclass(frozen=True)
class ModulePhaseDef:
    """模块的 Phase 定义集合。"""
    module_id: str
    phases: Tuple[PhaseDef, ...]


# ============================================================
# Phase 定义加载器
# ============================================================

class PhaseDefinitionLoader:
    """从 JSON 配置加载 Phase 定义。"""

    @staticmethod
    def load(config_path: Path) -> Tuple[Dict[str, ModulePhaseDef], Dict[str, ProviderSpec]]:
        """解析 JSON → Dict[module_id, ModulePhaseDef] + Dict[provider_name, ProviderSpec]。"""
        data = json.loads(config_path.read_text(encoding="utf-8"))

        # 解析 providers
        providers: Dict[str, ProviderSpec] = {}
        for p in data.get("providers", []):
            spec = ProviderSpec(
                name=p["name"],
                callable_ref=p["callable_ref"],
                scope=Scope(p.get("scope", "MODULE")),
                ttl_seconds=p.get("ttl_seconds", 60),
                output_key=p.get("output_key", ""),
                description=p.get("description", ""),
            )
            providers[spec.name] = spec

        # 解析 modules
        modules: Dict[str, ModulePhaseDef] = {}
        for mod_id, mod_data in data.get("modules", {}).items():
            phases = []
            for ph in mod_data.get("phases", []):
                phase = PhaseDef(
                    id=ph["id"],
                    name=ph.get("name", ph["id"]),
                    clauses=tuple(ph.get("clauses", [])),
                    depends_on=tuple(ph.get("depends_on", [])),
                    wait_for_pool_keys=tuple(ph.get("wait_for_pool_keys", [])),
                    tools=tuple(ph.get("tools", [])),
                    knowledge_additions=tuple(ph.get("knowledge_additions", [])),
                    pool_outputs=tuple(ph.get("pool_outputs", [])),
                    providers_used=tuple(ph.get("providers_used", [])),
                    max_tool_turns=ph.get("max_tool_turns"),
                )
                phases.append(phase)

            modules[mod_id] = ModulePhaseDef(
                module_id=mod_id,
                phases=tuple(phases),
            )

        logger.info(
            "[PhaseEngine] loaded %d modules, %d providers from %s",
            len(modules), len(providers), config_path.name,
        )
        return modules, providers

    @staticmethod
    def topological_sort_phases(phases: List[PhaseDef]) -> List[List[PhaseDef]]:
        """同模块内 Phase 拓扑排序 (基于 depends_on)。

        Returns:
            List of batches, 每个 batch 内的 phase 可并行执行。
            当前实现为顺序执行 (batch 内不并行), 但保留批量结构以支持未来并行化。
        """
        if not phases:
            return []

        # 构建邻接表
        phase_map = {p.id: p for p in phases}
        in_degree = defaultdict(int)
        dependents = defaultdict(list)

        for p in phases:
            if p.id not in in_degree:
                in_degree[p.id] = 0
            for dep in p.depends_on:
                in_degree[p.id] += 1
                dependents[dep].append(p.id)

        # Kahn 算法
        batches = []
        remaining = set(in_degree.keys())

        while remaining:
            # 找入度为 0 的节点
            batch_ids = [pid for pid in remaining if in_degree[pid] == 0]
            if not batch_ids:
                raise ValueError(f"Phase 循环依赖: {remaining}")

            batch = [phase_map[pid] for pid in batch_ids]
            batches.append(batch)

            for pid in batch_ids:
                remaining.discard(pid)
                for dep_id in dependents[pid]:
                    in_degree[dep_id] -= 1

        return batches


# ============================================================
# Phase 执行引擎
# ============================================================

class PhaseExecutionEngine:
    """Phase 感知执行引擎。

    职责:
    1. 加载 Phase 定义
    2. 拓扑排序 Phase
    3. 按阶段执行 Work Agent
    4. Pool 数据读写 (wait_for + invoke_provider + put outputs)
    5. 合并 Phase evidence 为单份
    """

    MAX_WORK_RETRIES = 2  # 与 M1M5ParallelStage 一致

    def __init__(
        self,
        workspace: Path,
        context_pool: ContextPool,
        runner,          # AgentRunner
        bus,             # FileBus
        telemetry,       # Telemetry
        pipe_def,        # PipelineDef
    ):
        self.workspace = workspace
        self.pool = context_pool
        self.runner = runner
        self.bus = bus
        self.telemetry = telemetry
        self.pipe_def = pipe_def

        self._modules: Dict[str, ModulePhaseDef] = {}
        self._providers: Dict[str, ProviderSpec] = {}

    def load_definitions(self, config_path: Path) -> None:
        """加载 Phase 定义 JSON 配置。"""
        self._modules, self._providers = PhaseDefinitionLoader.load(config_path)
        # 注册 providers 到 pool
        for spec in self._providers.values():
            self.pool.register_provider(spec)

    def has_phases(self, module_id: str) -> bool:
        """该模块是否有 Phase 定义。"""
        return module_id in self._modules and len(self._modules[module_id].phases) > 0

    def _resolve_phase_knowledge(self, additions: Tuple[str, ...]) -> Tuple[Path, ...]:
        """将 Phase 的知识相对路径解析为 skills/ 下的受限文件。

        ``knowledge_additions`` 是 Phase 定义中的运行时知识挂载点。它只接受
        相对于 skills 根目录的文件路径，例如
        ``etsi-ts103701-report/references/pcap-analyzer-reference.md``；不接受
        绝对路径、工作区路径或目录穿越，避免 Phase JSON 成为任意本地文件读取入口。
        """
        if not additions:
            return ()
        if self.pipe_def is None:
            raise ValueError("Phase knowledge requires a PipelineDef")

        skills_root = None
        for knowledge_path in self.pipe_def.shared_knowledge:
            # 现有知识路径格式为 <skills>/<skill>/references/<file>。
            if knowledge_path.parent.name == "references":
                skills_root = knowledge_path.parent.parent.parent.resolve()
                break
        if skills_root is None:
            raise ValueError("Cannot infer skills root from PipelineDef knowledge paths")

        resolved: List[Path] = []
        for raw_path in additions:
            relative_path = Path(raw_path)
            if relative_path.is_absolute():
                raise ValueError(f"Phase knowledge must be relative to skills/: {raw_path}")

            candidate = (skills_root / relative_path).resolve()
            try:
                candidate.relative_to(skills_root)
            except ValueError as exc:
                raise ValueError(f"Phase knowledge escapes skills/: {raw_path}") from exc
            if not candidate.is_file():
                raise FileNotFoundError(f"Phase knowledge file does not exist: {candidate}")
            resolved.append(candidate)

        return tuple(resolved)

    async def execute_module(
        self,
        module,          # ModuleDef
        workspace: Path,
        pipeline,        # Pipeline 实例
        pipe_def,        # PipelineDef
    ) -> Optional[dict]:
        """执行模块: 分阶段运行 Work Agent, 合并 evidence。

        Returns:
            合并后的 evidence dict, 或 None (失败时)。
        """
        mod_phases = self._modules.get(module.id)
        if not mod_phases:
            return None

        pipeline_id = pipeline._state.pipeline_id if pipeline._state else "?"

        # 拓扑排序
        phase_batches = PhaseDefinitionLoader.topological_sort_phases(
            list(mod_phases.phases)
        )

        self.telemetry.log_stage_event(
            pipeline_id, "PHASE_ENGINE", "start",
            module=module.id,
            phases=str([p.id for batch in phase_batches for p in batch]),
        )

        # 按批次执行 Phase
        phase_evidences: List[dict] = []
        for batch_idx, batch in enumerate(phase_batches):
            for phase in batch:
                evidence = await self._execute_phase(
                    phase, module, workspace, pipeline, pipe_def,
                    phase_idx=batch_idx,
                )
                if evidence:
                    phase_evidences.append(evidence)

        if not phase_evidences:
            self.telemetry.log_stage_event(
                pipeline_id, "PHASE_ENGINE", "all_phases_failed",
                module=module.id,
            )
            return None

        # 合并 evidence
        merged = self._merge_phase_evidences(phase_evidences, module)

        # 写入合并后的 evidence (与现有流程一致)
        self.bus.write_json(
            f"evidence/pre-{module.id}-evidence.json",
            merged,
        )

        self.telemetry.log_stage_event(
            pipeline_id, "PHASE_ENGINE", "complete",
            module=module.id,
            phase_count=len(phase_evidences),
            clause_count=len(merged.get("clauses", [])),
        )

        return merged

    async def _execute_phase(
        self,
        phase: PhaseDef,
        module,
        workspace: Path,
        pipeline,
        pipe_def,
        phase_idx: int,
    ) -> Optional[dict]:
        """执行单个 Phase: wait → providers → agent → pool outputs。"""
        from framework.agent_runner import AgentConfig

        pipeline_id = pipeline._state.pipeline_id if pipeline._state else "?"
        runner = pipeline.runner

        self.telemetry.log_stage_event(
            pipeline_id, "PHASE_ENGINE", "phase_start",
            module=module.id, phase=phase.id, clauses=len(phase.clauses),
        )

        # 1. 等待上游 pool keys
        for key in phase.wait_for_pool_keys:
            self.telemetry.log_stage_event(
                pipeline_id, "PHASE_ENGINE", "waiting_for_key",
                module=module.id, phase=phase.id, key=key,
            )
            result = await self.pool.wait_for(
                key, module.id, phase.id, timeout=600,
            )
            if result is None:
                self.telemetry.log_stage_event(
                    pipeline_id, "PHASE_ENGINE", "key_timeout",
                    module=module.id, phase=phase.id, key=key,
                )
                # 不阻断: 继续执行, 但记录 warning

        # 2. 调用 providers
        for provider_name in phase.providers_used:
            await self.pool.invoke_provider(
                provider_name, module.id, phase.id,
                tools=pipeline.tool_registry,
            )

        # 3. 获取 pool 快照 (注入 task_ctx)
        pool_snapshot = self.pool.get_snapshot_for_phase(module.id, phase.id)

        # 4. 构建 AgentConfig + task_ctx
        phase_knowledge = self._resolve_phase_knowledge(phase.knowledge_additions)
        # 同一资料可能同时被模块 ammo 和 Phase 指定；保持顺序并去重。
        knowledge_paths = tuple(dict.fromkeys(
            pipe_def.shared_knowledge + module.ammo_paths + phase_knowledge
        ))

        config = AgentConfig(
            agent_id=f"work_{module.id}_{phase.id}_v1",
            agent_type="work",
            persona_path=pipe_def.work_agent_persona,
            knowledge_paths=knowledge_paths,
            tool_manifest=phase.tools if phase.tools else module.tools,
            forbidden_patterns=_get_work_agent_forbidden(),
            model=os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5"),
            max_tool_turns=phase.max_tool_turns or 30,
        )

        task_ctx = self._build_phase_task_ctx(phase, module, pool_snapshot)

        # 5. 运行 Work Agent (含重试)
        evidence_data = None
        for attempt in range(self.MAX_WORK_RETRIES + 1):
            try:
                attempt_task_ctx = {**task_ctx, "attempt": attempt + 1}
                result = await runner.run(
                    config, attempt_task_ctx,
                    tools=pipeline.tool_registry,
                    output_schema=EvidenceManifest,
                )

                if result.raw_text:
                    try:
                        evidence_data = json.loads(
                            _extract_json(result.raw_text)
                        )
                        break
                    except json.JSONDecodeError as e:
                        self.telemetry.log_stage_event(
                            pipeline_id, "PHASE_ENGINE", "json_parse_error",
                            module=module.id, phase=phase.id, attempt=attempt + 1,
                            error=str(e),
                        )
            except Exception as e:
                self.telemetry.log_stage_event(
                    pipeline_id, "PHASE_ENGINE", "phase_error",
                    module=module.id, phase=phase.id,
                    attempt=attempt + 1, error=str(e),
                )

            if attempt < self.MAX_WORK_RETRIES:
                await asyncio.sleep(2 * (attempt + 1))

        if evidence_data is None:
            # 响亮失败: 不静默回退到 sample fixture 冒充真实证据。
            # 所有重试均未产出合法 evidence，返回 None 让上层标记该 phase 失败。
            self.telemetry.log_stage_event(
                pipeline_id, "PHASE_ENGINE", "phase_evidence_exhausted",
                module=module.id, phase=phase.id,
            )
            return None

        # 6. 写入 pool outputs
        for output in phase.pool_outputs:
            out_key = output["key"]
            out_scope = Scope(output.get("scope", "MODULE"))
            # 尝试从 evidence 中提取对应数据 (best-effort)
            out_value = evidence_data.get(out_key, evidence_data)
            self.pool.put(
                key=out_key,
                value=out_value,
                scope=out_scope,
                module_id=module.id,
                phase_id=phase.id,
            )

        # 7. 写入 phase evidence 文件 (单独存档)
        self.bus.write_json(
            f"evidence/pre-{module.id}-{phase.id}-evidence.json",
            evidence_data,
        )

        self.telemetry.log_stage_event(
            pipeline_id, "PHASE_ENGINE", "phase_complete",
            module=module.id, phase=phase.id,
            clause_count=len(evidence_data.get("clauses", [])),
        )

        return evidence_data

    def _build_phase_task_ctx(
        self,
        phase: PhaseDef,
        module,
        pool_snapshot: Dict[str, Any],
    ) -> dict:
        """构建 Phase 的 task_context。"""
        all_clauses = ", ".join(phase.clauses)

        task_text = (
            f"执行 {module.name} ({module.id}) — {phase.name} 阶段检测。\n"
            f"条款范围: {all_clauses}\n"
            f"按 evidence-schema.json 格式输出 pre-{module.id}-{phase.id}-evidence.json\n"
        )

        # 注入条款 recipe (脚本→工具→方法)
        from pipelines.etsi.agents import build_clause_recipe_text
        recipe = build_clause_recipe_text(phase.clauses)
        if recipe:
            task_text += recipe + "\n"

        # 如果有上游 pool 数据, 加入提示
        if pool_snapshot:
            keys_str = ", ".join(pool_snapshot.keys())
            task_text += f"\n上下文池已有数据: {keys_str}\n请参考 pool_data 中的上游分析结果。\n"

        # 如果有上游文件依赖 (如 M3 需要 M2 evidence)
        task_inputs = ["ixit.json"]
        if module.upstream_inputs:
            task_inputs.extend(module.upstream_inputs)

        return {
            "task": task_text,
            "workspace": str(self.workspace),
            "module_id": module.id,
            "phase_id": phase.id,
            "clause_ids": list(phase.clauses),
            "inputs": task_inputs,
            "output_file": f"evidence/pre-{module.id}-{phase.id}-evidence.json",
            "pool_data": pool_snapshot if pool_snapshot else None,
            # evidence-schema.json 是字段语义来源；在执行点从同一
            # Pydantic 合约导出 machine-readable schema，确保 Work Agent
            # 可实际生成 L1/L2 能解析的完整 EvidenceManifest。
            "output_schema": json.dumps(
                EvidenceManifest.model_json_schema(by_alias=True),
                ensure_ascii=False,
            ),
        }

    def _merge_phase_evidences(
        self,
        phase_evidences: List[dict],
        module,
    ) -> dict:
        """合并多 Phase evidence 为单份。

        策略:
        - clauses: 按 clause_id 去重合并
        - execution_trace: 拼接 (带 phase tag)
        - selfCheck: 重新计算
        - meta: 使用第一份的 meta, 添加 phase_count
        """
        if not phase_evidences:
            return {}

        if len(phase_evidences) == 1:
            return phase_evidences[0]

        # 合并 clauses (去重)
        seen_clause_ids = set()
        all_clauses = []
        for ev in phase_evidences:
            for clause in ev.get("clauses", []):
                cid = clause.get("clauseId", clause.get("clause_id", ""))
                if cid and cid not in seen_clause_ids:
                    seen_clause_ids.add(cid)
                    all_clauses.append(clause)

        # 合并 execution_trace
        all_traces = []
        for ev in phase_evidences:
            traces = ev.get("execution_trace", ev.get("executionTrace", []))
            all_traces.extend(traces)

        # 重新计算 selfCheck
        expected_clauses = list(module.clauses)
        actual_clause_ids = [
            c.get("clauseId", c.get("clause_id", ""))
            for c in all_clauses
        ]
        missing = [c for c in expected_clauses if c not in actual_clause_ids]

        self_check = {
            "totalExpected": len(expected_clauses),
            "actualInJson": len(all_clauses),
            "missingClauses": missing,
            "hasErrors": len(missing) > 0,
        }

        # meta
        meta = phase_evidences[0].get("meta", {})
        meta["phaseCount"] = len(phase_evidences)

        return {
            "meta": meta,
            "clauses": all_clauses,
            "execution_trace": all_traces,
            "selfCheck": self_check,
            "self_check": self_check,  # 兼容两种格式
        }


# ============================================================
# 工具函数
# ============================================================

def _extract_json(text: str) -> str:
    """从 Agent 输出中提取 JSON (处理 markdown 代码块包裹)。"""
    if "```json" in text:
        return text.split("```json")[1].split("```")[0]
    elif "```" in text:
        return text.split("```")[1].split("```")[0]
    return text


def _get_work_agent_forbidden() -> tuple:
    """获取 Work Agent 禁止模式 (与 pipeline.py 保持一致)。"""
    try:
        from pipelines.etsi.pipeline import WORK_AGENT_FORBIDDEN
        return WORK_AGENT_FORBIDDEN
    except ImportError:
        return ()
