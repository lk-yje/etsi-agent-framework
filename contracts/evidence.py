"""工作 Agent 产出合约 — EvidenceManifest, ClauseResult, EvidenceItem。

字段使用 snake_case (Python 惯例)，通过 alias 同时支持 ETSI JSON schema 的 camelCase。
"""

from pydantic import BaseModel, Field, field_validator, ConfigDict
from enum import Enum
from typing import List, Optional


class EvidenceLevel(str, Enum):
    """证据分级"""
    L1 = "L1"  # 完整可复现：命令+参数+完整输出+frame编号
    L2 = "L2"  # 完整，缺工具版本号
    L3 = "L3"  # 部分覆盖：有结论但缺中间步骤
    L4 = "L4"  # 仅文档引用，无实测证据
    L5 = "L5"  # 无证据，仅声称


class EvidenceItem(BaseModel):
    """单条证据"""
    model_config = ConfigDict(populate_by_name=True)

    type: str = Field(description="证据类型: nmap|tshark|traffic_intelligence|burp|curl|sqlmap|xray|playwright|ixit|netstat|other")
    path: Optional[str] = Field(None, description="证据文件路径（工作区内）")
    level: EvidenceLevel = Field(description="证据分级 L1-L5")
    description: str = Field(description="证据描述，必须含 frame 编号/Burp 序号/命令+参数，第三者可直接索引")
    flow_ids: List[str] = Field(
        default_factory=list,
        alias="flowIds",
        max_length=100,
        description="Traffic Intelligence 稳定 Flow ID；仅用于结构化证据引用",
    )
    frame_numbers: List[int] = Field(
        default_factory=list,
        alias="frameNumbers",
        max_length=500,
        description="Traffic Intelligence/TShark 明确返回的帧号；不得从描述文本猜测",
    )
    expected_vs_actual: Optional[str] = Field(
        None, alias="expectedVsActual",
        description="预期 vs 实际对照（FAIL 时必填）"
    )

    @field_validator("description")
    @classmethod
    def description_not_empty(cls, v: str) -> str:
        assert len(v.strip()) >= 10, "证据描述至少 10 字符，包含可索引信息"
        return v

    @field_validator("flow_ids")
    @classmethod
    def normalize_flow_ids(cls, values: List[str]) -> List[str]:
        normalized = [str(value).strip() for value in values]
        if any(not value for value in normalized):
            raise ValueError("flowIds 不得包含空值")
        return sorted(set(normalized))

    @field_validator("frame_numbers")
    @classmethod
    def normalize_frame_numbers(cls, values: List[int]) -> List[int]:
        if any(value < 1 for value in values):
            raise ValueError("frameNumbers 必须大于 0")
        return sorted(set(values))


class ClauseResult(BaseModel):
    """单条款的测试结果"""
    model_config = ConfigDict(populate_by_name=True)

    clause_id: str = Field(alias="clauseId", description="条款 ID，如 5.6-1")
    provision_text: str = Field(alias="provisionText", description="条款原文 (1 句话概要)")
    ics_status: str = Field(alias="icsStatus", description="ICS Status: M|R|M C(...)|R C(...)")
    ics_support: str = Field(alias="icsSupport", description="ICS 声明: Y|N|N/A")
    ics_detail: Optional[str] = Field(None, alias="icsDetail", description="ICS Detail/Justification 原文摘要")
    verdict: str = Field(description="综合裁决: PASS|FAIL|NA|INCONCLUSIVE|PENDING_MANUAL")
    reason: str = Field(description="完整推理链：概念分析 + 功能验证")
    expected_behavior: Optional[str] = Field(None, alias="expectedBehavior", description="预期行为（FAIL 时必填）")
    actual_behavior: Optional[str] = Field(None, alias="actualBehavior", description="实际行为（FAIL 时必填）")
    evidence: List[EvidenceItem] = Field(default_factory=list)
    ixit_references: List[str] = Field(default_factory=list, alias="ixitReferences", description="引用的 IXIT 表名")
    tags: List[str] = Field(default_factory=list, description="标签: escape-clause|all-conditions|manual-only|inherited|constrained-device|conditional|pass-without-evidence|ics-na")
    warnings: List[str] = Field(default_factory=list)
    manual_steps: Optional[str] = Field(None, alias="manualSteps", description="手工测试步骤（PENDING_MANUAL 时必填）")
    retry_history: List[dict] = Field(default_factory=list, alias="retryHistory", description="打回重测历史记录")
    adjudications: List[dict] = Field(
        default_factory=list, alias="adjudications",
        description="审计分歧的结构化裁决记录；不替代原始 Work 结果的可追溯性",
    )


class ExecutionStep(BaseModel):
    """执行轨迹中的单步 — 支持 ETSI fc-loop-spec 的 6 种 phase"""
    model_config = ConfigDict(populate_by_name=True)

    seq: int = Field(default=1, ge=1)
    phase: str = Field(description="preflight | tool_call | reasoning | pivot | self_check | delivery")
    summary: str = Field(default="", alias="summary", description="一句话发生了什么")
    clause_ids: List[str] = Field(default_factory=list, alias="clauseIds", description="本步涉及的条款")
    tool: Optional[str] = Field(None, alias="tool", description="使用的工具")
    finding: Optional[str] = Field(None, alias="finding", description="关键发现")
    duration_sec: int = Field(default=0, alias="durationSec", ge=0)
    error: Optional[dict] = Field(None, alias="error", description="工具失败时的降级决策 (phase=pivot 时必填)")


class SelfCheck(BaseModel):
    """Agent 自检结果"""
    model_config = ConfigDict(populate_by_name=True)

    total_expected: int = Field(alias="totalExpected", description="应覆盖的条款总数")
    actual_in_json: int = Field(alias="actualInJson", description="JSON 中实际条目数")
    missing_clauses: List[str] = Field(default_factory=list, alias="missingClauses")
    uncertain_clauses: List[str] = Field(default_factory=list, alias="uncertainClauses", description="INCONCLUSIVE 的条款 ID")
    fail_count: int = Field(default=0, alias="failCount")
    fail_clauses: List[dict] = Field(default_factory=list, alias="failClauses", description="FAIL 条款及 hasExpectedVsActual")
    pending_manual: int = Field(default=0, alias="pendingManual")
    pending_manual_clauses: List[str] = Field(default_factory=list, alias="pendingManualClauses")
    ics_na_clauses: List[str] = Field(default_factory=list, alias="icsNAClauses", description="ICS=N/A 的条款")
    has_errors: bool = Field(default=False, alias="hasErrors")
    error_details: List[str] = Field(default_factory=list)


class EvidenceMeta(BaseModel):
    """Evidence 元信息"""
    model_config = ConfigDict(populate_by_name=True)

    module_id: str = Field(alias="moduleId")
    module_name: str = Field(default="", alias="moduleName")
    dut_ip: str = Field(default="unknown", alias="dutIp")
    ixit_json_path: str = Field(default="", alias="ixitJsonPath")
    generated_at: str = Field(default="", alias="generatedAt")
    clause_count: int = Field(default=0, alias="clauseCount", ge=1)
    retry_count: int = Field(default=0, alias="retryCount", ge=0, le=2)
    status: str = Field(default="pending_audit")


class ExecutionTrace(BaseModel):
    """完整的执行轨迹"""
    model_config = ConfigDict(populate_by_name=True)

    started_at: str = Field(default="", alias="startedAt")
    completed_at: str = Field(default="", alias="completedAt")
    total_rounds: int = Field(default=0, alias="totalRounds", ge=0)
    self_reported_budget_used: int = Field(default=0, alias="selfReportedBudgetUsed", ge=0)
    steps: List[ExecutionStep] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)


class EvidenceManifest(BaseModel):
    """工作 Agent 产出的完整 evidence JSON"""
    model_config = ConfigDict(populate_by_name=True)

    meta: dict = Field(description="元数据: moduleId, status, retryCount, timestamp 等")
    execution_trace: List[ExecutionStep] = Field(
        default_factory=list, alias="executionTrace",
        description="完整执行轨迹，每步含条款+工具+结果"
    )
    clauses: List[ClauseResult] = Field(description="逐条款测试结果")
    self_check: SelfCheck = Field(alias="selfCheck", description="自检清单")

    @field_validator("execution_trace")
    @classmethod
    def trace_not_empty(cls, v: list) -> list:
        assert len(v) > 0, "execution_trace 不能为空（无轨迹 = 无法审计过程）"
        return v

    def has_l4_l5_evidence(self) -> bool:
        """检查是否存在 L4/L5 级别证据（L1 闸门直接打回）"""
        for clause in self.clauses:
            for ev in clause.evidence:
                if ev.level in (EvidenceLevel.L4, EvidenceLevel.L5):
                    return True
        return False

    def fail_clauses_without_expected_vs_actual(self) -> List[str]:
        """检查 FAIL 但缺少 expectedBehavior 的条款"""
        return [
            c.clause_id for c in self.clauses
            if c.verdict == "FAIL" and (not c.expected_behavior or not c.actual_behavior)
        ]

    def pending_manual_without_steps(self) -> List[str]:
        """检查 PENDING_MANUAL 但缺少 manualSteps 的条款"""
        return [
            c.clause_id for c in self.clauses
            if c.verdict == "PENDING_MANUAL" and not c.manual_steps
        ]
