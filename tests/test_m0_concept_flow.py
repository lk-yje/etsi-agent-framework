import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

from contracts.audit import AuditFinding, AuditMeta, AuditResult, RetryInstruction, TriangulationResult
from contracts.evidence import ClauseResult, EvidenceManifest, ExecutionStep
from framework.file_bus import FileBus
from framework.telemetry import Telemetry
from framework.conceptual_catalog import load_conceptual_catalog
from pipelines.etsi.pipeline import M0AuditStage, M0ConceptStage, M0L1Stage, M0Stage


def _baseline() -> EvidenceManifest:
    return EvidenceManifest(
        meta={"moduleId": "M0", "retryCount": 0, "status": "pending_concept"},
        execution_trace=[ExecutionStep(
            seq=1, phase="preflight", summary="ICS 逻辑验证", clause_ids=["M0_0"],
        )],
        clauses=[ClauseResult(
            clauseId="M0_0", provisionText="ICS item", icsStatus="M", icsSupport="Y",
            verdict="PASS", reason="ICS mandatory declaration is present.",
        )],
        selfCheck={"totalExpected": 1, "actualInJson": 1},
    )


def _candidate(clause_id: str, label: str) -> tuple[ClauseResult, list[ExecutionStep]]:
    return (
        ClauseResult(
            clauseId=clause_id, provisionText=f"{clause_id} conceptual assessment",
            icsStatus="R", icsSupport="Y", verdict="PASS",
            reason=f"{label}: IXIT declaration is logically self-consistent.",
            ixitReferences=["fixture-table"],
        ),
        [ExecutionStep(
            seq=1, phase="reasoning", summary=f"{label}: constrained IXIT assessment",
            clauseIds=[clause_id], tool="read_ixit_table",
        )],
    )


def _pipeline(tmp_path):
    pipe = SimpleNamespace(
        bus=FileBus(tmp_path),
        telemetry=Telemetry(tmp_path / "logs"),
        _state=SimpleNamespace(pipeline_id="m0-test"),
        pipe_def=SimpleNamespace(shared_knowledge=(), audit_agent_persona=Path(__file__)),
        runner=object(),
    )
    pipe.request_needs_review = lambda current, reason: None
    return pipe


def _full_m0_evidence() -> EvidenceManifest:
    baseline = _baseline()
    concepts = [_candidate(item.clause_id, "fixture")[0] for item in load_conceptual_catalog().clauses]
    traces = list(baseline.execution_trace) + [
        _candidate(item.clause_id, "fixture")[1][0]
        for item in load_conceptual_catalog().clauses
    ]
    return EvidenceManifest(
        meta={"moduleId": "M0", "retryCount": 0, "status": "pending_audit"},
        executionTrace=traces,
        clauses=list(baseline.clauses) + concepts,
        selfCheck={"totalExpected": len(baseline.clauses) + len(concepts),
                   "actualInJson": len(baseline.clauses) + len(concepts)},
    )


def test_m0_concept_initial_and_targeted_retry(monkeypatch, tmp_path):
    pipe = _pipeline(tmp_path)
    pipe.bus.write_evidence("M0", _baseline())
    calls = []

    async def fake_execute(clause, workspace, pipeline, rework_context=""):
        calls.append(clause.clause_id)
        return _candidate(clause.clause_id, "initial")

    monkeypatch.setattr("pipelines.etsi.pipeline.execute_conceptual_clause", fake_execute)
    asyncio.run(M0ConceptStage().execute(tmp_path, None, pipe))

    initial = pipe.bus.read_evidence("M0")
    assert len(initial.clauses) == 1 + len(load_conceptual_catalog().clauses)
    assert len(calls) == len(load_conceptual_catalog().clauses)
    untouched_reason = next(item.reason for item in initial.clauses if item.clause_id == "5.2-2")

    pipe.bus.write_json("rework/M0/pending.json", {
        "retry_count": 1,
        "target_clause_ids": ["5.6-6"],
    })
    calls.clear()

    async def retry_execute(clause, workspace, pipeline, rework_context=""):
        calls.append(clause.clause_id)
        return _candidate(clause.clause_id, "retry")

    monkeypatch.setattr("pipelines.etsi.pipeline.execute_conceptual_clause", retry_execute)
    asyncio.run(M0ConceptStage().execute(tmp_path, None, pipe))

    retried = pipe.bus.read_evidence("M0")
    assert calls == ["5.6-6"]
    assert next(item.reason for item in retried.clauses if item.clause_id == "5.2-2") == untouched_reason
    target = next(item for item in retried.clauses if item.clause_id == "5.6-6")
    assert target.retry_history and target.retry_history[-1]["retry_count"] == 1
    assert retried.meta["retryCount"] == 1
    assert (tmp_path / "rework/M0/round_1.json").exists()
    assert not (tmp_path / "rework/M0/pending.json").exists()


def test_m0_l1_issues_evidence_token_only_after_pass(tmp_path):
    pipe = _pipeline(tmp_path)
    pipe.bus.write_evidence("M0", _baseline())

    asyncio.run(M0L1Stage().execute(tmp_path, None, pipe))

    assert pipe.bus.has_token(".l1_M0_PASSED")
    assert pipe.bus.has_token(".evidence_M0_complete")


def test_m0_ics_conditional_na_is_not_false_failed_and_all_entries_are_traced(tmp_path):
    """The XLSX's M F (x) marker is conditional, not an unconditional M."""
    pipe = _pipeline(tmp_path)
    pipe.bus.write_json("ixit.json", {
        "ics": [
            {
                "reference": "Provision 5.1-2 conditional password rule",
                "status": "M F (b)", "support": "N/A",
                "detail_justification": "No pre-installed password.",
            },
            {
                "reference": "Provision 5.2-1 unconditional disclosure",
                "status": "M", "support": "N/A",
                "detail_justification": "Missing disclosure policy.",
            },
        ],
        "ixit_tables": {},
    })

    asyncio.run(M0Stage().execute(tmp_path, None, pipe))

    evidence = pipe.bus.read_evidence("M0")
    assert [item.verdict for item in evidence.clauses] == ["PASS", "FAIL"]
    assert evidence.self_check.fail_count == 1
    assert evidence.execution_trace[0].phase == "preflight"
    assert evidence.execution_trace[0].clause_ids == ["M0_0", "M0_1"]


def test_m0_reject_creates_at_most_two_targeted_retry_requests(monkeypatch, tmp_path):
    pipe = _pipeline(tmp_path)
    evidence = _full_m0_evidence().model_dump(mode="json")
    evidence["meta"]["retryCount"] = 0
    pipe.bus.write_json("evidence/pre-M0-evidence.json", evidence)

    class RejectingGate:
        def __init__(self, module_id):
            assert module_id == "M0"

        async def run_audit(self, workspace, runner, pipe_def, **kwargs):
            return AuditResult(
                audit=AuditMeta(moduleId="M0", verdict="REJECT", summary="rework one clause"),
                findings=[AuditFinding(
                    clauseId="5.6-6", severity="HIGH", category="verdict_wrong",
                    triangulation=TriangulationResult(
                        standardVsIxit="a", standardVsEvidence="b", ixitVsEvidence="c",
                    ),
                    description="fixture audit fact", fix="re-evaluate", evidencePaths=["ixit.json#/fixture"],
                )],
                retryInstruction=RetryInstruction(targetClauseIds=["5.6-6"], memo="inject into Work Agent"),
            )

    monkeypatch.setattr("pipelines.etsi.pipeline.L2AuditGate", RejectingGate)
    asyncio.run(M0AuditStage().execute(tmp_path, None, pipe))

    request = json.loads((tmp_path / "rework/M0/pending.json").read_text(encoding="utf-8"))
    assert request["retry_count"] == 1
    assert request["target_clause_ids"] == ["5.6-6"]
    assert "fixture audit fact" in request["rework_notes"]["5.6-6"]
    assert (tmp_path / "evidence/revisions/M0/revision-0.json").exists()
    assert (tmp_path / "audit-results/revisions/M0/round-1.json").exists()

    evidence["meta"]["retryCount"] = 2
    pipe.bus.write_json("evidence/pre-M0-evidence.json", evidence)
    (tmp_path / "rework/M0/pending.json").unlink()
    asyncio.run(M0AuditStage().execute(tmp_path, None, pipe))

    assert not (tmp_path / "rework/M0/pending.json").exists()
    assert (tmp_path / "audit-results/M0-needs-review.json").exists()


def test_m0_exhausted_reject_applies_only_supported_fail_and_requests_review(monkeypatch, tmp_path):
    pipe = _pipeline(tmp_path)
    pipe._state.current_state = None  # The lightweight fixture does not execute Pipeline.run().
    evidence = _full_m0_evidence()
    evidence.meta["retryCount"] = 2
    target = next(item for item in evidence.clauses if item.clause_id == "5.6-6")
    target.verdict = "INCONCLUSIVE"
    target.expected_behavior = "The product protects the fixture secret."
    target.actual_behavior = "IXIT says the fixture secret is exposed."
    pipe.bus.write_evidence("M0", evidence)

    class RejectingGate:
        def __init__(self, module_id): pass
        async def run_audit(self, workspace, runner, pipe_def, **kwargs):
            return AuditResult(
                audit=AuditMeta(moduleId="M0", verdict="REJECT", summary="supported fail"),
                findings=[AuditFinding(
                    clauseId="5.6-6", severity="HIGH", category="verdict_wrong",
                    triangulation=TriangulationResult(standardVsIxit="a", standardVsEvidence="b", ixitVsEvidence="c"),
                    description="IXIT directly records exposed secret.", fix="mark fail",
                    recommendedVerdict="FAIL", evidencePaths=["ixit.json#/fixture/secret"], overrideEligible=True,
                )],
                retryInstruction=RetryInstruction(targetClauseIds=["5.6-6"], memo="mark fail"),
            )

    requested = []
    def needs_review(current, reason):
        requested.append((current, reason))
    pipe.request_needs_review = needs_review
    monkeypatch.setattr("pipelines.etsi.pipeline.L2AuditGate", RejectingGate)
    asyncio.run(M0AuditStage().execute(tmp_path, None, pipe))

    updated = next(item for item in pipe.bus.read_evidence("M0").clauses if item.clause_id == "5.6-6")
    assert updated.verdict == "FAIL"
    assert updated.adjudications[0]["work_verdict"] == "INCONCLUSIVE"
    assert requested and "预算已耗尽" in requested[0][1]


def test_m0_audit_uses_bounded_conceptual_slices_and_issues_one_token(monkeypatch, tmp_path):
    pipe = _pipeline(tmp_path)
    pipe.bus.write_evidence("M0", _full_m0_evidence())
    calls = []

    class AcceptingGate:
        def __init__(self, module_id):
            assert module_id == "M0"

        async def run_audit(self, workspace, runner, pipe_def, **kwargs):
            calls.append(kwargs)
            return AuditResult(audit=AuditMeta(moduleId="M0", verdict="ACCEPT", summary="slice accepted"))

    monkeypatch.setattr("pipelines.etsi.pipeline.L2AuditGate", AcceptingGate)
    asyncio.run(M0AuditStage().execute(tmp_path, None, pipe))

    catalog = load_conceptual_catalog()
    assert len(calls) == 8
    assert [item["audit_label"] for item in calls] == [f"batch_{index:02d}" for index in range(1, 9)]
    assert all(item["evidence_path"].startswith("audit-inputs/M0/round-1/") for item in calls)
    assert pipe.bus.has_token(".audit_M0_ACCEPTED")
    assert pipe.bus.read_audit_result("M0").verdict == "ACCEPT"
