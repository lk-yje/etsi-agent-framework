"""运行意图合约：把“为什么运行、运行哪些节点”从认证状态机中分离出来。"""

from enum import Enum
from typing import List
from pydantic import BaseModel, Field


class RunProfile(str, Enum):
    CERTIFICATION_FULL = "certification-full"
    FUNCTIONAL_SMOKE = "functional-smoke"
    FUNCTIONAL_MODULE = "functional-module"
    AUDIT_ONLY = "audit-only"
    REPORT_REBUILD = "report-rebuild"


class RunNode(BaseModel):
    id: str
    label: str
    depends_on: List[str] = Field(default_factory=list, alias="dependsOn")
    certification_gate: bool = Field(default=False, alias="certificationGate")


class RunPlan(BaseModel):
    profile: RunProfile
    certification_claim: bool = Field(alias="certificationClaim")
    nodes: List[RunNode]
    selected_modules: List[str] = Field(default_factory=list, alias="selectedModules")
    required_inputs: List[str] = Field(default_factory=list, alias="requiredInputs")
    skipped_gates: List[str] = Field(default_factory=list, alias="skippedGates")
    risks: List[str] = Field(default_factory=list)

