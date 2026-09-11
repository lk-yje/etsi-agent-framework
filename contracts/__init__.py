"""数据合约层 — Agent 间通信的数据结构定义。"""

from contracts.evidence import (
    EvidenceLevel,
    EvidenceItem,
    ClauseResult,
    ExecutionStep,
    SelfCheck,
    EvidenceMeta,
    ExecutionTrace,
    EvidenceManifest,
)
from contracts.audit import (
    TriangulationResult,
    AuditFinding,
    RetryInstruction,
    HarnessReport,
    AuditMeta,
    CrossModuleIssue,
    AuditResult,
)
from contracts.module import ModuleDef, PipelineDef
from contracts.agent_result import TokenUsage, AgentTrace, AgentResult
from contracts.pipeline import (
    StageStatus,
    ModuleVerdict,
    PipelineState,
    PipelineSnapshot,
)

__all__ = [
    # evidence
    "EvidenceLevel",
    "EvidenceItem",
    "ClauseResult",
    "ExecutionStep",
    "SelfCheck",
    "EvidenceMeta",
    "ExecutionTrace",
    "EvidenceManifest",
    # audit
    "TriangulationResult",
    "AuditFinding",
    "RetryInstruction",
    "HarnessReport",
    "AuditMeta",
    "CrossModuleIssue",
    "AuditResult",
    # module
    "ModuleDef",
    "PipelineDef",
    # agent result
    "TokenUsage",
    "AgentTrace",
    "AgentResult",
    # pipeline
    "StageStatus",
    "ModuleVerdict",
    "PipelineState",
    "PipelineSnapshot",
]
