from framework.functional_evidence import conceptual_verdict_markers


def test_functional_evidence_rejects_conceptual_clause_verdicts():
    evidence = {"clauses": [{"clause_id": "5.5-1", "reason": "概念性分析：IXIT 声称 TLS"}]}
    assert conceptual_verdict_markers(evidence) == ["5.5-1: 概念性分析"]


def test_functional_evidence_allows_ixit_as_expected_behavior_reference():
    evidence = {"clauses": [{
        "clause_id": "5.5-1",
        "expected_behavior": "IXIT 声称 TLS；本次以此作为抓包对照。",
        "reason": "capture.pcap 显示 TLS ServerHello，来自本次采集。",
    }]}
    assert conceptual_verdict_markers(evidence) == []


def test_work_persona_has_no_legacy_two_stage_conceptual_instruction():
    from pipelines.etsi.agents import WORK_AGENT_PERSONA

    text = WORK_AGENT_PERSONA.read_text(encoding="utf-8")
    assert "每条条款执行两步: 概念性测试" not in text
    assert "M1–M5 只执行功能性验证" in text
