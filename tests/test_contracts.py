"""合约验证测试 — Pydantic models 的验证规则"""

import pytest
from contracts.evidence import (
    EvidenceManifest, ClauseResult, EvidenceItem, EvidenceLevel,
    SelfCheck, ExecutionStep,
)
from contracts.audit import AuditResult, AuditMeta, AuditFinding, TriangulationResult


class TestEvidenceManifestValidation:
    """EvidenceManifest 验证规则"""

    def test_valid_manifest_passes(self):
        """合法 evidence → 创建成功"""
        m = EvidenceManifest(
            meta={"moduleId": "M1", "status": "pending_audit", "retryCount": 0},
            self_check=SelfCheck(
                total_expected=1,
                actual_in_json=1,
            ),
            execution_trace=[
                ExecutionStep(
                    phase="work",
                    round_number=1,
                    clause_ids=["5.6-1"],
                    action="nmap scan",
                    tool="bash",
                    outcome="found 5 open ports",
                )
            ],
            clauses=[
                ClauseResult(
                    clause_id="5.6-1",
                    provision_text="All interfaces shall be documented",
                    ics_status="M",
                    ics_support="Y",
                    verdict="FAIL",
                    reason="nmap found 5 ports but IXIT 15-Intf only lists 1",
                    expected_behavior="All ports in IXIT 15-Intf",
                    actual_behavior="Only SSH 22 listed, 80/443/554/8000/8443 missing",
                    evidence=[
                        EvidenceItem(
                            type="nmap",
                            path="nmap_tcp.txt",
                            level=EvidenceLevel.L1,
                            description="nmap -sS -sV --top-ports 2000 10.19.199.26: 5 open ports found",
                        )
                    ],
                    ixit_references=["15-Intf"],
                )
            ],
        )

        assert m.clauses[0].verdict == "FAIL"
        assert not m.has_l4_l5_evidence()

    def test_empty_trace_fails(self):
        """空 execution_trace → 验证失败"""
        with pytest.raises(Exception):  # field_validator 抛 AssertionError
            EvidenceManifest(
                meta={"moduleId": "M1", "status": "pending_audit"},
                self_check=SelfCheck(total_expected=1, actual_in_json=1),
                execution_trace=[],  # 空 trace
                clauses=[
                    ClauseResult(
                        clause_id="5.6-1",
                        provision_text="test",
                        ics_status="M",
                        ics_support="Y",
                        verdict="PASS",
                        reason="test",
                    )
                ],
            )

    def test_l4_evidence_detected(self):
        """L4 证据被正确检测"""
        m = EvidenceManifest(
            meta={"moduleId": "M1", "status": "pending_audit"},
            self_check=SelfCheck(total_expected=1, actual_in_json=1),
            execution_trace=[
                ExecutionStep(
                    phase="work",
                    round_number=1,
                    clause_ids=["5.6-1"],
                    action="check ixidoc",
                    tool="read",
                    outcome="done",
                )
            ],
            clauses=[
                ClauseResult(
                    clause_id="5.6-1",
                    provision_text="test",
                    ics_status="M",
                    ics_support="Y",
                    verdict="PASS",
                    reason="test",
                    evidence=[
                        EvidenceItem(
                            type="ixit",
                            level=EvidenceLevel.L4,
                            description="Referenced IXIT 15-Intf but did not verify against nmap",
                        )
                    ],
                )
            ],
        )

        assert m.has_l4_l5_evidence()

    def test_traffic_evidence_accepts_and_normalizes_structured_refs(self):
        evidence = EvidenceItem(
            type="traffic_intelligence",
            level=EvidenceLevel.L1,
            description="Traffic Intelligence Flow 和代表帧已完成结构化引用",
            flowIds=["flow-b", "flow-a", "flow-a"],
            frameNumbers=[8, 7, 8],
        )

        assert evidence.flow_ids == ["flow-a", "flow-b"]
        assert evidence.frame_numbers == [7, 8]
        dumped = evidence.model_dump(mode="json", by_alias=True)
        assert dumped["flowIds"] == ["flow-a", "flow-b"]
        assert dumped["frameNumbers"] == [7, 8]

    def test_fail_without_expected_behavior_detected(self):
        """FAIL 缺少 expectedBehavior → 被检测"""
        m = EvidenceManifest(
            meta={"moduleId": "M1", "status": "pending_audit"},
            self_check=SelfCheck(total_expected=1, actual_in_json=1),
            execution_trace=[
                ExecutionStep(
                    phase="work",
                    round_number=1,
                    clause_ids=["5.6-1"],
                    action="scan",
                    tool="bash",
                    outcome="done",
                )
            ],
            clauses=[
                ClauseResult(
                    clause_id="5.6-1",
                    provision_text="test",
                    ics_status="M",
                    ics_support="Y",
                    verdict="FAIL",
                    reason="failed",
                    # 缺少 expected_behavior 和 actual_behavior
                )
            ],
        )

        violations = m.fail_clauses_without_expected_vs_actual()
        assert "5.6-1" in violations


class TestAuditResultValidation:
    """AuditResult 验证规则 (V2 嵌套结构)"""

    def test_accepted_audit(self):
        """ACCEPT 审计结果 → 创建成功"""
        r = AuditResult(
            audit=AuditMeta(
                moduleId="M1",
                verdict="ACCEPT",
                summary="All clauses consistent",
            ),
        )
        assert r.is_accepted
        assert not r.is_rejected

    def test_rejected_with_findings(self):
        """REJECT + 审计发现 → 创建成功"""
        r = AuditResult(
            audit=AuditMeta(
                moduleId="M1",
                verdict="REJECT",
                summary="3 findings",
            ),
            findings=[
                AuditFinding(
                    clause_id="5.6-1",
                    severity="HIGH",
                    category="evidence_insufficient",
                    triangulation=TriangulationResult(
                        standardVsIxit="OK",
                        standardVsEvidence="MISMATCH: no nmap output referenced",
                        ixitVsEvidence="OK",
                    ),
                    description="Evidence L5 — 仅引用 IXIT 文档，无实测 nmap",
                    fix="补充 nmap 扫描结果作为证据",
                    affectedFields=["evidence[0].level"],
                )
            ],
        )

        assert r.is_rejected
        assert len(r.findings) == 1


class TestModuleDefImmutability:
    """ModuleDef frozen dataclass — 不可修改"""

    def test_module_def_is_hashable(self):
        from contracts.module import ModuleDef
        m = ModuleDef(
            id="M1",
            name="test",
            clauses=("5.6-1",),
            ammo_paths=(),
            tools=(),
        )
        # frozen dataclass 应该是 hashable 的
        assert hash(m) is not None


class TestPipelineDef:
    """PipelineDef frozen dataclass"""

    def test_pipeline_def_creation(self):
        from contracts.module import PipelineDef, ModuleDef
        from pathlib import Path

        p = PipelineDef(
            name="test-pipeline",
            description="Test",
            modules=(
                ModuleDef(id="M0", name="m0", clauses=(), ammo_paths=(), tools=()),
            ),
            work_agent_persona=Path("work.md"),
            audit_agent_persona=Path("audit.md"),
            shared_knowledge=(),
            audit_only_knowledge=(),
            work_ammo_knowledge=(),
            required_tokens=(".token1",),
            phase_gate_script=Path("gate.py"),
            pipeline_class="pipelines.test.TestPipeline",
        )
        assert p.name == "test-pipeline"
        assert len(p.modules) == 1
        assert p.pipeline_class == "pipelines.test.TestPipeline"


class TestAgentResultContracts:
    """AgentResult / TokenUsage / AgentTrace 合约"""

    def test_token_usage(self):
        from contracts.agent_result import TokenUsage
        t = TokenUsage(input_tokens=100, output_tokens=50)
        assert t.total_tokens == 150

    def test_agent_trace(self):
        from contracts.agent_result import AgentTrace
        t = AgentTrace(trace_id="t1", agent_id="work_M1_v1", agent_type="work", tools_used=["bash", "read_file"])
        assert t.agent_type == "work"

    def test_agent_result(self):
        from contracts.agent_result import AgentResult, AgentTrace
        trace = AgentTrace(trace_id="t1", agent_id="work_M1_v1", agent_type="work", outcome="success")
        r = AgentResult(trace=trace, raw_text="some evidence JSON")
        assert r.is_success
        assert r.raw_text == "some evidence JSON"


class TestPipelineContracts:
    """PipelineState / PipelineSnapshot 合约"""

    def test_pipeline_state_enum(self):
        from contracts.pipeline import PipelineState
        assert PipelineState.INIT.value == "init"
        assert PipelineState.DONE.value == "done"
        assert PipelineState.FAILED.value == "failed"

    def test_pipeline_snapshot(self):
        from contracts.pipeline import PipelineSnapshot, PipelineState
        s = PipelineSnapshot(
            pipeline_id="test-001",
            pipeline_name="etsi-ts103701",
            current_state=PipelineState.M1_M5_PARALLEL,
            workspace_path="/tmp/test",
        )
        assert s.pipeline_id == "test-001"
        assert not s.is_terminal()
