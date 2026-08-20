"""文件总线 — Agent 间通信的唯一通道。

Agent 不直接知道彼此的存在。所有通信通过文件系统：
写文件到约定路径 + 等待约定路径出现文件。
"""

import asyncio
import json
from pathlib import Path
from typing import List, Optional

from contracts.evidence import EvidenceManifest
from contracts.audit import AuditResult


class FileBus:
    """文件总线。

    设计保证:
    1. 写入原子化（临时文件 + rename）→ 读方不会读到半成品
    2. 读取方轮询等待文件就绪（存在且非空）
    3. 所有路径从 workspace 派生，不跨 workspace 通信
    4. 支持令牌机制（空文件 = 信号量）
    """

    def __init__(self, workspace: Path):
        self.workspace = Path(workspace)
        self.evidence_dir = self.workspace / "evidence"
        self.audit_dir = self.workspace / "audit-results"
        self.token_dir = self.workspace / "tokens"
        self.log_dir = self.workspace / "logs"

        for d in [self.evidence_dir, self.audit_dir, self.token_dir, self.log_dir]:
            d.mkdir(parents=True, exist_ok=True)

    # ===== 原子写入 =====

    def write_atomic(self, path: Path, content: str) -> Path:
        """原子写入 — 先写 .tmp，再 rename。防止读方读到半成品。"""
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(content, encoding="utf-8")
        tmp.replace(path)
        return path

    def write_json(self, relative_path: str, data: dict) -> Path:
        """写入 JSON 文件到工作区相对路径"""
        path = self.workspace / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        return self.write_atomic(path, json.dumps(data, indent=2, ensure_ascii=False))

    # ===== 结构化写入（含 Pydantic 验证） =====

    def write_evidence(self, module_id: str, evidence: EvidenceManifest) -> Path:
        """写入模块 evidence JSON（Pydantic 验证后写入）"""
        return self.write_json(
            f"evidence/pre-{module_id}-evidence.json",
            evidence.model_dump(mode="json"),
        )

    def write_audit_result(self, module_id: str, result: AuditResult) -> Path:
        """写入审计结果 JSON"""
        return self.write_json(
            f"audit-results/audit-result_{module_id}.json",
            result.model_dump(mode="json"),
        )

    # ===== 令牌机制 =====

    def touch_token(self, token_name: str) -> Path:
        """发行通行令牌（空文件 = 信号量，存在即通过）"""
        token = self.token_dir / token_name
        token.touch()
        return token

    def has_token(self, token_name: str) -> bool:
        return (self.token_dir / token_name).exists()

    def missing_tokens(self, required: List[str]) -> List[str]:
        return [t for t in required if not self.has_token(t)]

    # ===== 读取 =====

    def read_json(self, relative_path: str) -> dict:
        """读取 JSON 文件"""
        path = self.workspace / relative_path
        if not path.exists():
            raise FileNotFoundError(f"文件不存在: {path}")
        return json.loads(path.read_text(encoding="utf-8"))

    def read_evidence(self, module_id: str) -> EvidenceManifest:
        """读取 evidence JSON 并解析为 EvidenceManifest"""
        data = self.read_json(f"evidence/pre-{module_id}-evidence.json")
        return EvidenceManifest(**data)

    def read_audit_result(self, module_id: str) -> AuditResult:
        """读取审计结果 JSON 并解析为 AuditResult"""
        data = self.read_json(f"audit-results/audit-result_{module_id}.json")
        return AuditResult(**data)

    # ===== 轮询等待 =====

    async def wait_for_file(
        self,
        relative_path: str,
        timeout_seconds: int = 300,
        poll_interval: float = 5.0,
    ) -> Optional[Path]:
        """轮询等待文件就绪（存在且非空）。超时返回 None。"""
        path = self.workspace / relative_path
        elapsed = 0.0
        while elapsed < timeout_seconds:
            if path.exists() and path.stat().st_size > 0:
                return path
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval
        return None

    # ===== 查询 =====

    def list_evidence_files(self) -> List[Path]:
        """列出所有 evidence JSON 文件（按修改时间排序）"""
        return sorted(self.evidence_dir.glob("pre-*-evidence.json"), key=lambda p: p.stat().st_mtime)

    def list_audit_results(self) -> List[Path]:
        """列出所有审计结果 JSON 文件"""
        return sorted(self.audit_dir.glob("audit-result_*.json"), key=lambda p: p.stat().st_mtime)

    def evidence_count(self) -> int:
        return len(list(self.evidence_dir.glob("pre-*-evidence.json")))

    def audit_count(self) -> int:
        return len(list(self.audit_dir.glob("audit-result_*.json")))

    # ===== 工作区状态查询 =====

    def get_pipeline_state_path(self) -> Path:
        return self.workspace / "pipeline_state.json"

    def get_ixit_path(self) -> Path:
        return self.workspace / "ixit.json"
