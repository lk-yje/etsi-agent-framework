"""M0 纯概念性测试执行器。

每次调用只处理目录中的一个条款：skill 资料被裁成该条款的最小片段，
IXIT 由受限只读工具按需读取。执行器只返回 EvidenceManifest 片段；最终
M0 evidence 的归并、L1/L2 与令牌仍由 ETSI Pipeline 负责。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from contracts.evidence import ClauseResult, EvidenceManifest, ExecutionStep
from framework.agent_runner import AgentConfig
from framework.conceptual_catalog import ConceptualClause
from framework.ixit_tools import IXIT_READONLY_CATEGORY
from framework.model_config import get_configured_model
from pipelines.etsi.agents import WORK_AGENT_FORBIDDEN, build_clause_recipe_text


# 兼容网关（如 DeepSeek）的结构化输出是概率性的；空输出常因输出超限被截断，
# 最多重试这么多次。
_CONCEPT_OUTPUT_RETRIES = 2


def _write_invalid_output_diagnostic(workspace: Path, clause_id: str, result) -> None:
    """Preserve the last invalid model reply for schema debugging and audit."""
    directory = workspace / "diagnostics" / "m0-invalid-output"
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"{clause_id}.json"
    payload = {
        "clause_id": clause_id,
        "model": result.trace.model,
        "reason": "模型响应未通过 EvidenceManifest schema 校验；未纳入测试证据。",
        "raw_text": result.raw_text or "",
    }
    temporary = target.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(target)


_CONCEPT_FRAMEWORK = """\
概念性测试只基于本任务给出的权威测试单元、通过判据、条款 recipe、ICS 与 IXIT 声明进行判断，不连接 DUT，
不调用网络、Burp、shell、Python 或写文件工具。逐项回答：
1. IXIT 描述的设计是否逻辑自洽地满足裁决条件？
2. IXIT 的相关表之间是否存在矛盾？
3. 信息是否足以判断？不足时必须写 INCONCLUSIVE，并列出缺失信息。
ICS=N/A 且理由成立时写 NA；纯概念结论不得伪装为功能实测结果。
每个 IXIT 证据必须写明表名和工具返回的 JSON Pointer；无 IXIT 表的文档类条款必须引用 ICS JSON Pointer；使用 L2 级 ixit evidence，
不得使用 L4/L5。读取任何 IXIT 表或 ICS 时，必须检查工具返回的 total_chars 与 offset：若 offset + 本次返回长度 < total_chars，说明内容被截断，
必须继续用 offset 翻页读完为止；未读完的表不得据此下裁决，只能判 INCONCLUSIVE 并列出缺失。需要检查 ICS 全部建议项（如文档完整性条款）时，用 read_ics_list 分页读取完整 ICS 列表，不要用 read_ics_clause 按单条款 ID 过滤。所有 reason、warnings、expected_behavior、actual_behavior 一律用中文书写；仅保留条款 ID、IXIT 表名、JSON Pointer、技术术语及被引用的 ICS/IXIT 原文为英文原样。最终只输出一个 EvidenceManifest JSON，且只含本任务条款。
"""


def _find_shared_path(paths: Iterable[Path], needle: str) -> Path | None:
    return next((path for path in paths if path.name == needle), None)


def _table_row_excerpt(path: Path | None, clause_id: str) -> str:
    if path is None or not path.exists():
        return ""
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith(f"| {clause_id} |"):
            return line
    return ""


def _verdict_excerpt(path: Path | None, clause: ConceptualClause) -> str:
    if path is None or not path.exists():
        return ""
    text = path.read_text(encoding="utf-8")
    # 5.10 is the framework clause ID; its verdict heading is 5.10-1.
    candidates = (clause.clause_id, clause.test_case_id.rsplit("-", 1)[0])
    for candidate in candidates:
        marker = f"### {candidate}"
        start = text.find(marker)
        if start < 0:
            continue
        end = text.find("\n### ", start + len(marker))
        return text[start:] if end < 0 else text[start:end]
    return ""


def build_concept_task(
    clause: ConceptualClause,
    shared_knowledge: Iterable[Path],
) -> str:
    """从现有 skill 裁出一个可审计、低 token 的条款任务包。"""
    paths = tuple(shared_knowledge)
    clause_reference = _find_shared_path(paths, "clause-reference.md")
    verdict_criteria = _find_shared_path(paths, "verdict-criteria.md")
    row = _table_row_excerpt(clause_reference, clause.clause_id)
    verdict = _verdict_excerpt(verdict_criteria, clause)
    recipe = build_clause_recipe_text((clause.clause_id,))
    required_tables = ", ".join(clause.ixit_tables) or "（本条无 IXIT 表；仅读取 ICS）"

    return "\n".join(part for part in (
        "# M0 纯概念性条款评估",
        f"规范条款：{clause.clause_id}；权威测试组：{clause.source_clause_id}；测试案例：{clause.test_case_id}",
        (
            f"正式输出的 clauses[0].clauseId 必须严格等于规范条款 ID "
            f"`{clause.clause_id}`；`{clause.test_case_id}` 仅用于测试案例追溯，"
            "不得写入 clauseId。"
        ),
        f"必须读取的 IXIT 表：{required_tables}；并读取本条款 ICS 条目。",
        "## 权威测试目的\n" + clause.test_purpose,
        "## 权威测试单元（逐项执行）\n" + clause.test_units,
        "## 权威通过判据\n" + clause.pass_criteria,
        _CONCEPT_FRAMEWORK.strip(),
        "## 条款速查表片段\n" + row if row else "",
        "## 裁决表片段\n" + verdict if verdict else "",
        recipe,
    ) if part)


async def execute_conceptual_clause(
    clause: ConceptualClause,
    workspace: Path,
    pipeline,
    rework_context: str = "",
) -> tuple[ClauseResult, list[ExecutionStep]]:
    """以最小工具面执行一条纯概念性条款并返回候选结果。"""
    task = build_concept_task(clause, pipeline.pipe_def.shared_knowledge)
    if rework_context:
        task += (
            "\n\n## L2 审计定点复核意见\n"
            + rework_context
            + "\n必须自行核对 IXIT 与本条款证据；审计意见不是结论指令。"
              "若不同意，需在 reason 中说明可复核依据。"
        )
    config = AgentConfig(
        agent_id=f"work_M0_concept_{clause.clause_id.replace('-', '_')}_v1",
        agent_type="work",
        persona_path=pipeline.pipe_def.work_agent_persona,
        knowledge_paths=(),
        tool_manifest=(IXIT_READONLY_CATEGORY,),
        forbidden_patterns=WORK_AGENT_FORBIDDEN,
        model=get_configured_model(),
        max_tool_turns=max(3, len(clause.ixit_tables) + 2),
    )
    task_context = {
        "task": task,
        "workspace": str(workspace),
        "module_id": "M0",
        "phase_id": "concept",
        "clause_ids": [clause.clause_id],
        "attempt": 0,
        "include_task_in_system": False,
        "output_schema": json.dumps(EvidenceManifest.model_json_schema(by_alias=True), ensure_ascii=False),
    }
    result = await pipeline.runner.run(
        config,
        task_context,
        tools=pipeline.tool_registry,
        output_schema=EvidenceManifest,
    )
    for _ in range(_CONCEPT_OUTPUT_RETRIES):
        if result.output:
            break
        # 空输出通常是 JSON 被输出上限截断，或模型未按 schema 输出；重试时
        # 附加“精炼输出”提示，避免长条款再次超限。
        task_context = {
            **task_context,
            "task": task_context["task"] + (
                "\n\n【重试】上次未产出可解析的 EvidenceManifest JSON。"
                "直接输出完整 JSON 对象，字段不得省略，推理保持精炼。"
            ),
        }
        result = await pipeline.runner.run(
            config,
            task_context,
            tools=pipeline.tool_registry,
            output_schema=EvidenceManifest,
        )
    if not result.output:
        _write_invalid_output_diagnostic(workspace, clause.clause_id, result)
        raise ValueError(
            f"{clause.clause_id}: 连续 {1 + _CONCEPT_OUTPUT_RETRIES} 次未返回有效 "
            f"EvidenceManifest (raw_text={len(result.raw_text or '')} 字符)"
        )
    manifest = EvidenceManifest(**result.output)
    if len(manifest.clauses) != 1 or manifest.clauses[0].clause_id != clause.clause_id:
        actual_ids = [item.clause_id for item in manifest.clauses]
        raise ValueError(f"{clause.clause_id}: 返回条款范围错误: {actual_ids}")
    candidate = manifest.clauses[0]
    tags = list(dict.fromkeys([
        *candidate.tags,
        "case-type:conceptual",
        f"test-case:{clause.test_case_id}",
        f"qbfw-group:{clause.source_clause_id}",
    ]))
    candidate = candidate.model_copy(update={
        "tags": tags,
        "ixit_references": list(dict.fromkeys([*candidate.ixit_references, *clause.ixit_tables])),
    })
    return candidate, manifest.execution_trace
