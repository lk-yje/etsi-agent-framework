"""审计 Agent 产出合约 — 匹配 ETSI audit-output-schema.json 嵌套结构。

字段使用 snake_case (Python)，通过 alias 支持 ETSI JSON 的 camelCase。

结构:
  audit (meta) + findings + retryInstruction + harnessReport + crossModuleIssues
"""

from pydantic import BaseModel, Field, ConfigDict
from datetime import datetime
from typing import List, Optional


# ============================================================
# 嵌套模型
# ============================================================


class TriangulationResult(BaseModel):
    """三角对照结果"""
    model_config = ConfigDict(populate_by_name=True)

    standard_vs_ixit: str = Field(alias="standardVsIxit", description="标准 vs IXIT")
    standard_vs_evidence: str = Field(alias="standardVsEvidence", description="标准 vs 证据")
    ixit_vs_evidence: str = Field(alias="ixitVsEvidence", description="IXIT vs 证据")


class AuditFinding(BaseModel):
    """单条审计发现"""
    model_config = ConfigDict(populate_by_name=True)

    clause_id: str = Field(alias="clauseId")
    severity: str = Field(description="CRITICAL | HIGH | MEDIUM | LOW")
    category: str = Field(description="harness_violation | verdict_wrong | escape_ignored | all_conditions_relaxed | ics_ixit_contradiction | inheritance_broken | evidence_insufficient | evidence_overreach | na_circular | cross_module_contradiction")
    triangulation: TriangulationResult
    description: str = Field(description="问题一句话描述")
    fix: str = Field(description="修正建议")
    affected_fields: List[str] = Field(default_factory=list, alias="affectedFields", description="涉及的 JSON 字段路径")


class RetryInstruction(BaseModel):
    """重测任务指令"""
    model_config = ConfigDict(populate_by_name=True)

    target_clause_ids: List[str] = Field(alias="targetClauseIds")
    memo: str = Field(description="可直接注入修正 Agent prompt 的任务描述")


class HarnessReport(BaseModel):
    """Harness 合规报告"""
    model_config = ConfigDict(populate_by_name=True)

    execution_trace_complete: bool = Field(default=True, alias="executionTraceComplete")
    total_rounds_ok: bool = Field(default=True, alias="totalRoundsOk")
    preflight_steps_present: bool = Field(default=True, alias="preflightStepsPresent")
    all_clauses_traced: bool = Field(default=True, alias="allClausesTraced")
    rounds_within_budget: bool = Field(default=True, alias="roundsWithinBudget")
    issues: List[str] = Field(default_factory=list)

    @property
    def has_violations(self) -> bool:
        return bool(self.issues) or not all([
            self.execution_trace_complete, self.all_clauses_traced,
        ])


class CrossModuleIssue(BaseModel):
    """跨模块矛盾 (Round 2)"""
    model_config = ConfigDict(populate_by_name=True)

    module_pair: List[str] = Field(alias="modulePair", min_length=2, max_length=2)
    clause_pair: List[str] = Field(alias="clausePair", min_length=2, max_length=2)
    contradiction: str
    recommendation: str


class AuditMeta(BaseModel):
    """审计元信息 — 对应 ETSI schema audit 嵌套对象"""
    model_config = ConfigDict(populate_by_name=True)

    module_id: str = Field(alias="moduleId")
    # 初次审计 + 最多两次定点重做，因此最多会有第 3 轮审计。
    round: int = Field(default=1, ge=1, le=3)
    retry_count: int = Field(default=0, alias="retryCount", ge=0, le=2)
    audited_at: str = Field(default_factory=lambda: datetime.now().isoformat(), alias="auditedAt")
    verdict: str = Field(description="ACCEPT | REJECT | FLAGGED")
    summary: str = Field(default="")


# ============================================================
# 顶层模型
# ============================================================


class AuditResult(BaseModel):
    """审计 Agent 的完整输出 — 匹配 ETSI audit-output-schema.json。

    顶层字段: audit (meta) + findings + retryInstruction + harnessReport + crossModuleIssues
    """
    model_config = ConfigDict(populate_by_name=True)

    audit: AuditMeta = Field(description="审计元信息")
    findings: List[AuditFinding] = Field(default_factory=list)
    retry_instruction: Optional[RetryInstruction] = Field(None, alias="retryInstruction")
    harness_report: Optional[HarnessReport] = Field(None, alias="harnessReport")
    cross_module_issues: List[CrossModuleIssue] = Field(default_factory=list, alias="crossModuleIssues")

    # ---- 便捷属性 ----

    @property
    def verdict(self) -> str:
        return self.audit.verdict

    @property
    def module_id(self) -> str:
        return self.audit.module_id

    @property
    def summary(self) -> str:
        return self.audit.summary

    @property
    def is_accepted(self) -> bool:
        return self.verdict == "ACCEPT"

    @property
    def is_rejected(self) -> bool:
        return self.verdict == "REJECT"

    @property
    def is_flagged(self) -> bool:
        return self.verdict == "FLAGGED"

    @property
    def critical_findings(self) -> List[AuditFinding]:
        return [f for f in self.findings if f.severity == "CRITICAL"]
