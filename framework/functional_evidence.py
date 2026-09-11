"""M1–M5 功能性证据边界。"""

from __future__ import annotations

from typing import Any


_CONCEPTUAL_MARKERS = (
    "概念性分析", "概念分析", "概念性测试", "概念测试", "概念上",
    "conceptual analysis", "conceptual test", "concept-level",
)

# 这些文件用于 M0 的概念判定或 Audit 裁决。它们不应作为 M1–M5 Work
# Agent 的上下文；否则模型会把概念性框架误当成当前功能测试的执行步骤。
_FUNCTIONAL_EXCLUDED_KNOWLEDGE = frozenset({
    "clause-reference.md",
    "verdict-criteria.md",
})


def functional_knowledge_paths(paths: Any) -> tuple:
    """返回可安全注入 M1–M5 Work Agent 的知识路径，保持原有顺序。"""
    return tuple(
        path for path in paths
        if getattr(path, "name", "") not in _FUNCTIONAL_EXCLUDED_KNOWLEDGE
    )


def conceptual_verdict_markers(evidence: dict[str, Any]) -> list[str]:
    """返回 M1–M5 clause 裁决文本中的禁止概念性标记。"""
    found: list[str] = []
    for clause in evidence.get("clauses", []) or []:
        if not isinstance(clause, dict):
            continue
        text = "\n".join(
            str(clause.get(field) or "")
            for field in ("reason", "conclusion", "actual_behavior", "expected_behavior")
        ).lower()
        for marker in _CONCEPTUAL_MARKERS:
            if marker.lower() in text:
                found.append(f"{clause.get('clause_id', clause.get('clauseId', '?'))}: {marker}")
    return found
