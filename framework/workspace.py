"""工作区管理 — 创建、查询、状态。

Skill 通过 CLI 调用:
    python -m etsi_agent_framework workspace init --path D:/Auto-TEST/20260807_test
    python -m etsi_agent_framework workspace status --path D:/Auto-TEST/20260807_test
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional


DEFAULT_SUBDIRS = ["evidence", "audit-results", "tokens", "logs", "pcap_analysis", "context"]


def init_workspace(path: str | Path, subdirs: Optional[list[str]] = None) -> dict:
    """初始化工作区目录结构。

    Args:
        path: 工作区根路径。若不存在则创建。
        subdirs: 要创建的子目录列表。默认使用 DEFAULT_SUBDIRS。

    Returns:
        {"status": "ok", "path": "...", "dirs": [...]}
    """
    root = Path(path)
    dirs_to_create = subdirs or DEFAULT_SUBDIRS
    created = []

    for d in dirs_to_create:
        dir_path = root / d
        dir_path.mkdir(parents=True, exist_ok=True)
        created.append(str(dir_path))

    return {
        "status": "ok",
        "path": str(root.resolve()),
        "created": created,
    }


def workspace_status(path: str | Path) -> dict:
    """查询工作区状态。

    Returns:
        {
            "path": "...",
            "evidence_count": 3,
            "audit_count": 1,
            "tokens_present": [".audit_M1_ACCEPTED", ...],
            "tokens_missing": [".audit_M2_ACCEPTED", ...],
            "has_ixit": true/false,
            "has_pcap": true/false,
        }
    """
    root = Path(path)

    evidence_dir = root / "evidence"
    audit_dir = root / "audit-results"
    token_dir = root / "tokens"

    evidence_files = sorted(evidence_dir.glob("*.json")) if evidence_dir.exists() else []
    audit_files = sorted(audit_dir.glob("*.json")) if audit_dir.exists() else []
    token_files = sorted(token_dir.glob("*")) if token_dir.exists() else []

    # 常见期望令牌
    expected_tokens = [
        ".evidence_M0_complete",
        ".evidence_M1_complete", ".evidence_M2_complete",
        ".evidence_M3_complete", ".evidence_M4_complete", ".evidence_M5_complete",
        ".audit_M0_ACCEPTED",
        ".audit_M1_ACCEPTED", ".audit_M2_ACCEPTED",
        ".audit_M3_ACCEPTED", ".audit_M4_ACCEPTED", ".audit_M5_ACCEPTED",
        ".audit_ROUND2_ACCEPTED",
    ]
    present = [t.name for t in token_files if t.name in expected_tokens]
    missing = [t for t in expected_tokens if t not in present]

    return {
        "path": str(root.resolve()),
        "evidence_count": len(evidence_files),
        "evidence_files": [f.name for f in evidence_files],
        "audit_count": len(audit_files),
        "audit_files": [f.name for f in audit_files],
        "tokens_present": present,
        "tokens_missing": missing,
        "has_ixit": (root / "ixit.json").exists(),
        "has_pcap": (root / "capture.pcap").exists(),
    }


def resolve_workspace(explicit_path: Optional[str] = None) -> Path:
    """解析工作区路径。优先级: 显式 > 环境变量 > 默认时间戳目录。

    默认路径: D:/Auto-TEST/<YYYYMMDD_HHMMSS>/
    """
    import os

    if explicit_path:
        return Path(explicit_path)

    env_ws = os.environ.get("ETSI_WORKSPACE")
    if env_ws:
        return Path(env_ws)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    root = os.environ.get("AUTO_TEST_ROOT", "D:/Auto-TEST")
    return Path(root) / ts
