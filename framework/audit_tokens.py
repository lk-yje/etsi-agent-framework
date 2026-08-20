"""审计裁决到 FileBus token 的统一映射。

ACCEPTED 是唯一的阶段通行凭证。FLAGGED/REJECT/ERROR 都是可观察的
终结状态，但不能被误当作通过审计。
"""

from __future__ import annotations

import re

from framework.file_bus import FileBus


_OUTCOME_SUFFIXES = {
    "ACCEPT": "ACCEPTED",
    "FLAGGED": "REVIEW_REQUIRED",
    "REJECT": "REJECTED",
    "ERROR": "ERROR",
}


def audit_outcome_token(module_id: str, verdict: str) -> str:
    """返回审计模块的唯一结果 token；未知裁决一律归为 ERROR。"""
    if not re.fullmatch(r"[A-Za-z0-9_]+", module_id):
        raise ValueError(f"Invalid audit module id: {module_id!r}")
    suffix = _OUTCOME_SUFFIXES.get(str(verdict).upper(), "ERROR")
    return f".audit_{module_id}_{suffix}"


def record_audit_outcome(bus: FileBus, module_id: str, verdict: str) -> str:
    """原子化地记录一个模块的当前审计结论。

    同一模块的旧结果 token 会被清理，保证工作区不会同时表现为 ACCEPTED
    与 REVIEW_REQUIRED。此函数只操作 FileBus token 目录中的精确 token 名称。
    """
    selected = audit_outcome_token(module_id, verdict)
    for suffix in _OUTCOME_SUFFIXES.values():
        (bus.token_dir / f".audit_{module_id}_{suffix}").unlink(missing_ok=True)
    bus.touch_token(selected)
    return selected
